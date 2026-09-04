"""
temporal.activities — Temporal Activity 实现

把 4 层 Agent 编排(Decomposer→ToolBuilder→Executor→Reviewer)包装为
可重试/超时的 Activity。整轮(audit_round)+收尾(save_result/cad_verify/trigger_response)。

设计:
  - 每个 Activity 为独立 async 函数, 内部自开 DB session(不依赖外部传入, 保证可重试与 Recovery)。
  - audit_round 返回 JSON 安全的 round dict(含 audit/verdict 摘要 + 供落库的完整 grounding 字段)。
  - 保留 pipeline_tracer.span(OTel→Jaeger) 与 trace_hook 调用, 与现有可视化一致。
"""
import json
import logging
import time

from temporalio import activity

logger = logging.getLogger(__name__)


# ── 单轮: Decomposer→ToolBuilder→Executor→Reviewer ──

@activity.defn
async def audit_round(inp: dict) -> dict:
    """执行一轮 4 层审计流水线。inp: {event_id, log_data, session_id, anomaly_score,
    anomaly_reasons, missed_threats, round_num, mode} → round dict"""
    from agents import decomposer, tool_builder, executor, reviewer
    from observability.pipeline_tracer import pipeline_tracer
    from models import async_session as db_session
    from trace_hook import set_trace_context

    event_id = int(inp["event_id"])
    log_data = inp["log_data"]
    session_id = inp["session_id"]
    anomaly_score = float(inp.get("anomaly_score", 0.0))
    anomaly_reasons = list(inp.get("anomaly_reasons", []))
    missed_threats = list(inp.get("missed_threats", []))
    round_num = int(inp.get("round_num", 1))
    mode = inp.get("mode", "full")

    set_trace_context(caller="audit_pipeline", event_id=event_id, session_id=session_id)

    # 分层预算: 仅非 P0 在硬预算下 short-circuit; P0 保留最小 LLM hop
    from agents.llm_fallback import should_short_circuit_for_tier
    _triage = (log_data or {}).get("_audit_triage") or {}
    _tier = str(_triage.get("tier") or "P2")
    if should_short_circuit_for_tier(_tier):
        logger.warning(
            f"[Temporal-audit_round] budget hard — short-circuit "
            f"event#{event_id} tier={_tier} round{round_num}"
        )
        return {
            "round": round_num,
            "mode": mode,
            "depth": mode,
            "sub_tasks": 0,
            "tool_calls": 0,
            "audit": {},
            "verdict": {},
            "missed_threats": [],
            "short_circuit": "budget_exhausted",
            "audit_full": {
                "grounding_score": 0.0,
                "kb_verification": {},
                "schema_valid": False,
                "confidence": 0.0,
                "threat_detected": False,
                "severity": (log_data or {}).get("severity", "info"),
                "needs_human_review": True,
                "threat_type": "",
            },
            "verdict_full": {
                "conclusion": "insufficient_evidence",
                "confidence": 0.0,
                "final_summary": f"硬预算短路(tier={_tier}),非P0不占LLM槽",
            },
            "evidence": [],
        }

    # decompose 不需要 DB session; execute 需要 → 内部开 session
    with pipeline_tracer.span("decomposer", event_id=event_id, session_id=session_id):
        decomp_output = await decomposer.decompose(
            event=log_data,
            session_id=session_id,
            anomaly_score=anomaly_score,
            anomaly_reasons=anomaly_reasons,
            mode=mode,
            missed_threats=missed_threats,
        )
    depth = decomp_output.get("audit_depth", mode)
    sub_tasks = decomp_output["sub_tasks"]

    if not sub_tasks:
        logger.info(f"[Temporal-audit_round] event#{event_id} round{round_num}: no sub-tasks")
        return {"round": round_num, "mode": mode, "depth": depth, "sub_tasks": 0,
                "tool_calls": 0, "audit": {}, "verdict": {}, "missed_threats": [],
                "audit_full": None, "verdict_full": None, "evidence": []}

    with pipeline_tracer.span("tool_builder", event_id=event_id, session_id=session_id):
        tool_calls = tool_builder.build(sub_tasks, session_id)

    async with db_session() as session:
        with pipeline_tracer.span("executor", event_id=event_id, session_id=session_id):
            audit_result = await executor.execute(
                tool_calls=tool_calls,
                session=session,
                session_id=session_id,
                raw_event=log_data,
                depth=depth,
            )
        tool_data_text = "\n".join(
            f"[{tr.tool}] {'OK' if tr.success else 'FAIL'}: "
            f"{str(tr.data)[:200] if tr.data else tr.error}"
            for tr in audit_result.tool_results
        )
        with pipeline_tracer.span("reviewer", event_id=event_id, session_id=session_id):
            verdict = await reviewer.review(
                raw_event=log_data,
                decomposer_output=decomp_output,
                audit_result=audit_result,
                tool_data_raw=tool_data_text,
            )

    missed = [
        {
            "description": mt.get("description", "")[:200],
            "evidence": mt.get("evidence", "")[:200],
            "severity": mt.get("severity", ""),
        }
        for mt in verdict.missed_threats
    ]
    # hop-budget early-stop → 禁止补审轮(与 async 路径对齐)
    hop_trace = getattr(audit_result, "hop_trace", None) or []
    if any(isinstance(h, dict) and h.get("skip_reasoning") for h in hop_trace):
        logger.info(
            f"[Temporal-audit_round] hop-budget early-stop → no supplement "
            f"event#{event_id} cleared_missed={len(missed)}"
        )
        missed = []

    return {
        "round": round_num,
        "mode": mode,
        "depth": depth,
        "sub_tasks": len(sub_tasks),
        "tool_calls": len(tool_calls),
        "audit": audit_result.to_dict(),
        "verdict": verdict.to_dict(),
        "missed_threats": missed,
        # 供 save_result 落库的完整字段(dict 可序列化)
        "audit_full": {
            "grounding_score": float(getattr(audit_result, "grounding_score", 1.0) or 1.0),
            "kb_verification": (getattr(audit_result, "kb_verification", None) or {}),
            "schema_valid": bool(getattr(audit_result, "schema_valid", True)),
            "confidence": float(getattr(audit_result, "confidence", 0.0) or 0.0),
            "threat_detected": bool(getattr(audit_result, "threat_detected", False)),
            "severity": getattr(audit_result, "severity", "info"),
            "needs_human_review": bool(getattr(audit_result, "needs_human_review", False)),
            "threat_type": getattr(audit_result, "threat_type", ""),
        },
        "verdict_full": {
            "conclusion": getattr(verdict, "conclusion", ""),
            "confidence": float(getattr(verdict, "confidence", 0.0) or 0.0),
            "final_summary": getattr(verdict, "final_summary", ""),
        },
        "evidence": audit_result.evidence,
    }


# ── 合并 + 落库 ──

def _merge_rounds(all_rounds: list[dict], log_data: dict = None) -> dict:
    """合并多轮审核结果(纯函数, 与 log_ingestion._merge_rounds / veto_gates 一致)。"""
    from veto_gates import merge_audit_rounds, extract_non_llm_signals
    signals = extract_non_llm_signals(log_data or {})
    return merge_audit_rounds(all_rounds, signals)


@activity.defn
async def save_result(inp: dict) -> dict:
    """合并所有轮结果并落库(analyzed=True + _audit_llm), 返回 merged。"""
    from models import SecurityEvent, async_session as db_session
    from event_bus import event_bus
    from datetime import datetime, timezone
    from log_ingestion import AUDIT_PROMPT_VERSION

    event_id = int(inp["event_id"])
    log_data = inp["log_data"]
    all_rounds = inp["all_rounds"]
    final_verdict = inp.get("final_verdict") or {}
    max_rounds = int(inp.get("max_rounds", 3))

    merged = _merge_rounds(all_rounds, log_data)
    try:
        from faithfulness_gate import apply_faithfulness_gate, contexts_from_audit
        answer_text = str((final_verdict or {}).get("final_summary") or "")
        evidence_for_gate = []
        for rd in all_rounds:
            for claim in (rd.get("audit") or {}).get("evidence") or []:
                if isinstance(claim, dict) and "threat_claims" in claim:
                    evidence_for_gate.extend(claim.get("threat_claims") or [])
        _sigma = log_data.get("_sigma") or {} if isinstance(log_data, dict) else {}
        _anomaly = log_data.get("_anomaly") or {} if isinstance(log_data, dict) else {}
        merged = apply_faithfulness_gate(
            merged,
            answer=answer_text,
            contexts=contexts_from_audit(log_data, evidence_for_gate),
            query=str(log_data.get("message") or ""),
            abstain=bool((final_verdict or {}).get("abstain") or merged.get("verdict") == "insufficient_evidence"),
            non_llm_signals={
                "sigma_detected": bool(_sigma.get("detected")),
                "hits": _sigma.get("hits") or [],
                "anomaly_score": _anomaly.get("score") if isinstance(_anomaly, dict) else 0,
                "event_type": (log_data or {}).get("event") or (log_data or {}).get("type") or "",
                "event_severity": (log_data or {}).get("severity") or "",
                "sigma_severity": _sigma.get("max_severity") or _sigma.get("severity") or "",
            },
        )
    except Exception:
        merged.setdefault("response_blocked", False)

    # 合并证据链
    all_evidence = []
    for rd in all_rounds:
        ev = rd.get("evidence")
        if isinstance(ev, list):
            for claim in ev:
                if isinstance(claim, dict) and "threat_claims" in claim:
                    for c in claim.get("threat_claims", []):
                        all_evidence.append({
                            "claim": c.get("summary", "")[:100],
                            "type": c.get("type", ""),
                            "confidence": c.get("confidence", 0),
                            "evidence_ids": c.get("evidence_ids", []),
                            "evidence_quotes": c.get("evidence_quotes", [])[:3],
                            "severity": c.get("severity", ""),
                            "round": rd.get("round", 0),
                        })
        elif isinstance(ev, dict):
            # audit_result.evidence 也可能是带 score 的 dict 结构 → 仅保留可序列化摘要
            for k, v in list(ev.items())[:100]:
                if isinstance(v, dict):
                    all_evidence.append({"keyword": str(k), **{kk: str(vv)[:200] for kk, vv in list(v.items())[:8]}})
                elif isinstance(v, list):
                    for c in v:
                        if isinstance(c, dict):
                            all_evidence.append({"keyword": str(k), "claim": str(c.get("summary", ""))[:200]})

    last_audit_full = None
    for rd in reversed(all_rounds):
        if rd.get("audit_full"):
            last_audit_full = rd["audit_full"]
            break
    ga_score = last_audit_full["grounding_score"] if last_audit_full else 1.0
    ga_kb = last_audit_full["kb_verification"] if last_audit_full else {}
    ga_schema = last_audit_full["schema_valid"] if last_audit_full else True

    # 审计结论的威胁类型: 审计产出为中文词表(如 "数据外泄"), 统一转换为
    # 响应策略匹配用的英文枚举(如 DATA_EXFIL); 审计未给出时回退日志侧推断值
    audit_threat_raw = str((last_audit_full or {}).get("threat_type") or "")
    _fallback_name = ""
    if isinstance(log_data, dict):
        _fallback_name = str(
            log_data.get("threat_type") or log_data.get("event")
            or log_data.get("type") or ""
        )
    threat_type_enum = ""
    try:
        from correlation_engine import infer_threat_type
        threat_type_enum = (
            infer_threat_type(audit_threat_raw) or infer_threat_type(_fallback_name)
        )
    except Exception:
        threat_type_enum = ""
    if threat_type_enum:
        merged["threat_type"] = threat_type_enum

    short_circuit = ""
    for rd in all_rounds:
        if rd.get("short_circuit"):
            short_circuit = str(rd.get("short_circuit") or "")
            break
    audit_status = "fallback" if short_circuit else "completed"

    audit_payload = {
        "prompt_version": AUDIT_PROMPT_VERSION,
        # v5 修复:补 status 字段 — 此前 Temporal 路径落库缺 status,
        # /api/logs 审计统计与前端全部显示为空 (100/100 "无状态")
        "status": audit_status,
        "fallback": bool(short_circuit),
        "fallback_reason": short_circuit or "",
        "threat_type": threat_type_enum,
        "threat_type_raw": audit_threat_raw,
        "rounds": len(all_rounds),
        "max_rounds": max_rounds,
        "merged": merged,
        "rounds_detail": [
            {
                "round": r.get("round"),
                "mode": r.get("mode"),
                "threat_detected": r.get("audit", {}).get("threat_detected"),
                "confidence": r.get("audit", {}).get("confidence"),
                "missed_count": len(r.get("missed_threats", [])),
            }
            for r in all_rounds
        ],
        "final_verdict": final_verdict,
        "evidence_trail": all_evidence,
        "hallucination": {
            "risk": merged.get("confidence", 0) < 0.3,
            "rounds": len(all_rounds),
            "needs_human": merged.get("needs_human", False),
        },
        "grounding": {
            "score": ga_score,
            "kb_verification": ga_kb,
            "schema_valid": ga_schema,
        },
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    async with db_session() as session:
        db_evt = await session.get(SecurityEvent, event_id)
        if db_evt:
            db_evt.analyzed = True
            db_evt.raw_data = {
                **(db_evt.raw_data or {}),
                "_audit_llm": audit_payload,
            }
            await session.commit()

    # 跨进程: 丢弃 backend 热缓存,否则 /audit-llm/pipeline 永远读到 ingest 空快照
    try:
        from event_store import event_store
        event_store.invalidate(event_id, broadcast=True)
    except Exception as inv_err:
        logger.debug(f"[Temporal-save] cache invalidate skipped: {inv_err}")

    # 归还 in-flight 名额(start_audit_workflow 时 acquire)
    try:
        from temporal.client import inflight_release, pop_workflow_tier
        _tier = await pop_workflow_tier(event_id)
        if not _tier:
            _tier = str((log_data or {}).get("_audit_triage", {}).get("tier") or "")
        await inflight_release(tier=_tier)
    except Exception:
        pass

    event_bus.publish("audit_complete", {
        "event_id": event_id,
        "event_type": log_data.get("event", log_data.get("type", "UNKNOWN")),
        "threat_detected": merged.get("threat_detected", False),
        "confidence": merged.get("confidence", 0),
        "severity": merged.get("severity", "info"),
        "rounds": len(all_rounds),
        "duration_s": round(time.time() - (inp.get("t_start") or time.time()), 1),
        "src_ip": log_data.get("src_ip", ""),
        "stage": "pipeline_complete",
        "agent_id": "reviewer",
        "agents_completed": [
            "decomposer", "tool_builder", "executor", "reviewer",
        ],
        "threat_type": threat_type_enum or merged.get("threat_type", ""),
        "verdict": merged.get("verdict", ""),
        "summary": str((final_verdict or {}).get("final_summary") or "")[:200],
    })
    # 注意: 不可把 audit_payload(内含 merged) 再挂回 merged,否则 Temporal
    # JSON 序列化报 Circular reference,save_result 三连失败 → CAD 永不执行。
    # cad_verify 会从 DB 回源 `_audit_llm`(已在上方 commit)。
    return merged


@activity.defn
async def trigger_response(inp: dict) -> dict:
    """触发响应引擎(独立 session)。"""
    from response_engine import get_orchestrator
    from models import async_session as db_session
    from observability.pipeline_tracer import pipeline_tracer
    from event_bus import event_bus

    threat_info = inp["threat_info"]
    event_id = int(inp["event_id"])
    session_id = inp["session_id"]
    merged = inp.get("merged") or {}

    # v5 修复(A):响应来源标记,写入 policy_match 日志供追溯(封禁是谁决定的)
    threat_info.setdefault("response_source", "audit_llm")
    threat_info.setdefault("allow_blocking", True)

    try:
        _resp_orch = get_orchestrator()
        async with db_session() as s:
            with pipeline_tracer.span("response", event_id=event_id, session_id=session_id):
                await _resp_orch.on_threat_detected(
                    session=s, threat_info=threat_info,
                    event_id=event_id, session_id=session_id,
                )
        event_bus.publish("response_action", {
            "event_id": event_id,
            "threat_type": threat_info.get("threat_type", ""),
            "severity": threat_info.get("severity", "info"),
            "src_ip": threat_info.get("src_ip", ""),
            "confidence": threat_info.get("confidence", merged.get("confidence", 0)),
            "status": "triggered",
            "stage": "response",
            "agent_id": "response",
        })
        return {"triggered": True}
    except Exception as e:
        logger.warning(f"[Temporal-response] failed for event#{event_id}: {e}")
        return {"triggered": False, "error": str(e)}


@activity.defn
async def cad_verify(inp: dict) -> dict:
    """CAD 独立审计(独立 session, 不参与内容生产)。

    v6 修复: 此前 workflow 传入 audit_llm={} → CAD 永远 0/0 verified、
    证据完整度 0.00、熔断器持续 tripped。优先用入参,缺省则从 DB 读
    save_result 刚写回的 `_audit_llm`(含 evidence_trail)。
    """
    from agents.agent_cad import cad_agent
    from models import SecurityEvent, async_session as db_session
    from observability.pipeline_tracer import pipeline_tracer

    event_id = int(inp["event_id"])
    session_id = inp["session_id"]
    audit_llm_data = inp.get("audit_llm") or {}

    try:
        async with db_session() as session:
            db_evt = await session.get(SecurityEvent, event_id)
            if not audit_llm_data and db_evt:
                audit_llm_data = (db_evt.raw_data or {}).get("_audit_llm") or {}
            # 入参若只有 merged 摘要而无 evidence_trail,同样回源 DB
            if audit_llm_data and not audit_llm_data.get("evidence_trail") and db_evt:
                db_audit = (db_evt.raw_data or {}).get("_audit_llm") or {}
                if db_audit.get("evidence_trail"):
                    audit_llm_data = db_audit

            with pipeline_tracer.span("cad_verify", event_id=event_id, session_id=session_id):
                cad_report = await cad_agent.audit_pipeline(session, event_id, audit_llm_data)
            if db_evt:
                db_evt.raw_data = {
                    **(db_evt.raw_data or {}),
                    "_cad_audit": {
                        "penetrating_verification": cad_report["penetrating_verification"],
                        "circuit_breaker": cad_report["circuit_breaker"],
                        "audit_timestamp": cad_report["audit_timestamp"],
                        "duration_ms": cad_report["duration_ms"],
                    },
                }
                await session.commit()
                try:
                    from event_store import event_store
                    event_store.invalidate(event_id, broadcast=True)
                except Exception:
                    pass
            tripped = bool(cad_report["circuit_breaker"].get("tripped", False))
            if tripped:
                logger.critical(f"[CAD] CIRCUIT BREAKER for event #{event_id}: {cad_report['circuit_breaker'].get('reason')}")
            return {"circuit_tripped": tripped, "report": cad_report}
    except Exception as e:
        logger.warning(f"[Temporal-cad] failed for event#{event_id}: {e}")
        return {"circuit_tripped": False, "error": str(e)}
