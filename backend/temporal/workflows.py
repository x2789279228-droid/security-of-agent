"""
temporal.workflows — Temporal Workflow 定义(确定性编排)

AuditPipelineWorkflow: 按轮次迭代执行 audit_round(整轮 L1-L4), 直至无遗漏或达 max_rounds;
收尾依次执行 save_result(合并+落库)、trigger_response(命中则)、cad_verify。

确定性约束: Workflow 内不做任何非确定性操作(datetime/随机/time), 全部副作用在 Activity。
"""
from dataclasses import dataclass, field as dataclass_field
from datetime import timedelta
from typing import Any, Dict, List

from temporalio import workflow
from temporalio.common import RetryPolicy


@dataclass
class AuditWorkflowInput:
    """Workflow 入参(JSON 可序列化)。"""
    session_id: str = ""
    event_id: int = 0
    log_data: Dict[str, Any] = dataclass_field(default_factory=dict)
    anomaly_score: float = 0.0
    anomaly_reasons: List[str] = dataclass_field(default_factory=list)
    max_rounds: int = 3


@workflow.defn
class AuditPipelineWorkflow:
    """4 层 Agent 编排 Workflow: 逐个 round 执行 audit_round, 收尾落库/CAD/响应。"""

    @workflow.run
    async def run(self, inp: AuditWorkflowInput) -> Dict[str, Any]:
        event_id = inp.event_id
        session_id = inp.session_id

        all_rounds: List[dict] = []
        missed: List[dict] = []
        final_verdict_raw: Dict[str, Any] = {}

        # r6 修复:单轮 900s×3 会把 TEMPORAL_CONCURRENCY 槽占死数十分钟。
        # 下调到 300s、最多 2 次; short_circuit(预算耗尽)立即收口不再补审。
        retry_round = RetryPolicy(
            initial_interval=timedelta(seconds=5),
            maximum_interval=timedelta(seconds=60),
            maximum_attempts=2,
            non_retryable_error_types=["BudgetExhaustedError"],
        )

        for round_num in range(1, inp.max_rounds + 1):
            mode = "supplement" if round_num > 1 else "full"
            round_input = {
                "event_id": event_id,
                "log_data": inp.log_data,
                "session_id": session_id,
                "anomaly_score": inp.anomaly_score,
                "anomaly_reasons": inp.anomaly_reasons,
                "missed_threats": missed,
                "round_num": round_num,
                "mode": mode,
            }
            rd = await workflow.execute_activity(
                "audit_round",
                args=[round_input],
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=retry_round,
            )
            all_rounds.append(rd)
            if rd.get("short_circuit"):
                break
            missed = rd.get("missed_threats") or []
            if rd.get("verdict_full"):
                final_verdict_raw = rd["verdict_full"]
            if not missed:
                break

        # 收尾: 合并+落库
        save_input = {
            "event_id": event_id,
            "log_data": inp.log_data,
            "all_rounds": all_rounds,
            "final_verdict": final_verdict_raw,
            "max_rounds": inp.max_rounds,
        }
        merged = await workflow.execute_activity(
            "save_result",
            args=[save_input],
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=5),
                maximum_interval=timedelta(seconds=60),
                maximum_attempts=3,
            ),
        )

        # 命中威胁 → 响应引擎
        # v5 修复(A):触发条件与 async 路径(log_ingestion._audit_pipeline_inner)
        # 对齐 — confirmed 与 faithfulness 软降级后的 suspicious(+threat=True)
        # 都允许策略层处置; 此前仅 confirmed, 53 条软降级威胁永远不触发响应
        if (
            merged.get("threat_detected")
            and merged.get("verdict") in ("confirmed", "suspicious")
            and float(merged.get("confidence", 0) or 0) >= 0.4
            and not merged.get("response_blocked")
        ):
            threat_info = {
                "threat_type": (
                    merged.get("threat_type")
                    or inp.log_data.get("threat_type")
                    or inp.log_data.get("event", inp.log_data.get("type", "UNKNOWN"))
                ),
                "event": inp.log_data.get("event", inp.log_data.get("type", "UNKNOWN")),
                "confidence": merged.get("confidence", 0),
                "severity": merged.get("severity", "info"),
                "src_ip": inp.log_data.get("src_ip", ""),
                "dst_ip": inp.log_data.get("dst_ip", ""),
                "message": inp.log_data.get("message", ""),
                "session_id": session_id,
                "event_id": event_id,
                "policy_name": f"audit_llm_rounds_{len(all_rounds)}",
            }
            await workflow.execute_activity(
                "trigger_response",
                args=[{"threat_info": threat_info, "event_id": event_id, "session_id": session_id, "merged": merged}],
                start_to_close_timeout=timedelta(seconds=120),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=5),
                    maximum_interval=timedelta(seconds=60),
                    maximum_attempts=2,
                ),
            )

        # CAD 独立审计 — save_result 已把完整 `_audit_llm`(含 evidence_trail)
        # 落库; cad_verify 入参留空并由 activity 从 DB 回源。
        # 切勿把 merged 嵌进 audit_llm 再回传(易触发 Circular reference)。
        await workflow.execute_activity(
            "cad_verify",
            args=[{
                "event_id": event_id,
                "session_id": session_id,
                "audit_llm": {},
            }],
            start_to_close_timeout=timedelta(seconds=180),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=5),
                maximum_interval=timedelta(seconds=60),
                maximum_attempts=2,
            ),
        )

        return {"event_id": event_id, "session_id": session_id,
                "rounds": len(all_rounds), "merged": merged}


@dataclass
class SelfPlayWorkflowInput:
    """红蓝自博弈 Workflow 入参。"""
    match_id: str = ""
    rounds: int = 8
    curriculum: bool = True
    start_level: int = 0
    inject: bool = False
    wait_audit: bool = False
    wait_audit_s: float = 8.0
    use_llm: bool = False
    decoy_ratio: float = 0.2
    persist: bool = True
    persist_kb: bool = False


@workflow.defn
class SelfPlayWorkflow:
    """红队规划 → 仿真物化 → 蓝队观察 → 学习,循环 N 回合。"""

    @workflow.run
    async def run(self, inp: SelfPlayWorkflowInput) -> Dict[str, Any]:
        retry = RetryPolicy(
            initial_interval=timedelta(seconds=2),
            maximum_interval=timedelta(seconds=20),
            maximum_attempts=2,
        )
        cfg = {
            "match_id": inp.match_id,
            "rounds": int(inp.rounds or 8),
            "curriculum": bool(inp.curriculum),
            "start_level": int(inp.start_level or 0),
            "inject": bool(inp.inject),
            "wait_audit": bool(inp.wait_audit),
            "wait_audit_s": float(inp.wait_audit_s or 8.0),
            "use_llm": bool(inp.use_llm),
            "decoy_ratio": float(inp.decoy_ratio or 0.0),
            "persist": bool(inp.persist),
            "persist_kb": bool(inp.persist_kb),
        }
        state = await workflow.execute_activity(
            "selfplay_init",
            args=[cfg],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=retry,
        )
        total = max(1, int(inp.rounds or 8))
        for _ in range(total):
            state = await workflow.execute_activity(
                "selfplay_round",
                args=[state],
                start_to_close_timeout=timedelta(
                    seconds=180 if (inp.wait_audit or inp.use_llm) else 60
                ),
                retry_policy=retry,
            )
            if state.get("stopped"):
                break
        return await workflow.execute_activity(
            "selfplay_finalize",
            args=[state],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=retry,
        )
