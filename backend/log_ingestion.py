"""
高性能安全日志接入服务 — Audit-LLM 架构

数据流:
  Log → event_store.store()          # 全量存储（热+温+冷）
      → anomaly_detector.analyze()   # 统计偏离度检测
      → memory_tree.add_leaf()        # 关联索引（无压缩）
      → sliding_window.add_message()  # 短期窗口
      → audit_pipeline()             # ★ Audit-LLM 四层流水线
          → Decomposer  (分析事件→分解子任务)
          → Tool Builder(子任务→具体工具调用)
          → Executor    (并行执行工具 + LLM综合)
          → Reviewer    (复核结论完整性)
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import SecurityEvent
from event_store import event_store
from anomaly_detector import anomaly_detector
from sliding_window import sliding_window
from memory_tree import memory_tree
from event_bus import event_bus
from observability.pipeline_tracer import pipeline_tracer

logger = logging.getLogger(__name__)

# Prompt 版本追踪（修改 prompt 时递增）
AUDIT_PROMPT_VERSION = "v2.1.0"


class LogIngestor:
    def __init__(self):
        self._last_analysis = {}
        self._analysis_lock = asyncio.Lock()
        self._review_semaphore = asyncio.Semaphore(5)

    def _merge_rounds(self, all_rounds: list[dict]) -> dict:
        """
        合并多轮审核结果

        策略:
        - 任意一轮发现威胁 → 最终为有威胁
        - 置信度取加权平均（轮次越靠后权重越低: 0.6, 0.3, 0.1）
        - severity 取最高严重度
        - 所有遗漏合并去重
        """
        if not all_rounds:
            return {"threat_detected": False, "confidence": 0.0, "needs_human": False}

        # 任意一轮发现威胁
        threat_detected = any(
            r["audit"].get("threat_detected", False) for r in all_rounds
        )

        # 加权置信度（轮次权重递减）
        weights = [0.6, 0.3, 0.1]
        total_weight = 0.0
        weighted_conf = 0.0
        for i, r in enumerate(all_rounds):
            w = weights[i] if i < len(weights) else 0.05
            weighted_conf += r["audit"].get("confidence", 0) * w
            total_weight += w
        confidence = weighted_conf / total_weight if total_weight > 0 else 0.0

        # 最高严重度
        severity_order = ["critical", "high", "medium", "low", "info"]
        max_sev_idx = 4
        for r in all_rounds:
            sev = r["audit"].get("severity", "info")
            if sev in severity_order:
                idx = severity_order.index(sev)
                if idx < max_sev_idx:
                    max_sev_idx = idx
        severity = severity_order[max_sev_idx]

        # 需要人工介入（任意一轮要求）
        needs_human = any(
            r["audit"].get("needs_human_review", False) for r in all_rounds
        )

        # 合并所有遗漏（去重）
        seen_descriptions = set()
        all_missed = []
        for r in all_rounds:
            for mt in r.get("missed_threats", []):
                desc = mt.get("description", "")
                if desc and desc not in seen_descriptions:
                    seen_descriptions.add(desc)
                    all_missed.append(mt)

        return {
            "threat_detected": threat_detected,
            "confidence": round(min(confidence, 1.0), 4),
            "severity": severity,
            "needs_human": needs_human,
            "total_rounds": len(all_rounds),
            "all_missed_count": len(all_missed),
        }

    def _normalize_fields(self, log_data: dict) -> dict:
        """归一化字段名：兼容 camelCase、snake_case、中文名"""
        field_map = {
            "event": ["event", "name", "type", "事件类型", "alertRuleId"],
            "type": ["type", "event", "事件类型"],
            "severity": ["severity", "级别", "风险等级", "riskLevel"],
            "src_ip": ["src_ip", "srcIp", "源IP", "sourceIp", "源地址"],
            "dst_ip": ["dst_ip", "dstIp", "目标IP", "destIp", "目标地址", "destinationIp"],
            "message": ["message", "msg", "告警内容", "description", "描述"],
            "confidence": ["confidence", "置信度", "可信度"],
            "protocol": ["protocol", "协议"],
        }
        normalized = dict(log_data)
        for target, candidates in field_map.items():
            if target not in normalized or not normalized.get(target):
                for c in candidates:
                    val = log_data.get(c)
                    if val is None or val == "":
                        continue
                    # 列表取第一个值（如 srcIp: ["192.168.1.100"] → "192.168.1.100"）
                    if isinstance(val, list):
                        val = val[0] if val else ""
                    if val is not None and val != "":
                        normalized[target] = val
                        break
        return normalized

    async def ingest(
        self, session: AsyncSession, session_id: str, log_data: dict
    ) -> dict:
        """接入一条日志 → 异常检测 → 全量存储 → Audit-LLM 流水线"""
        log_data = self._normalize_fields(log_data)
        event_type = log_data.get("event", log_data.get("type", "UNKNOWN"))
        severity = log_data.get("severity", "info")
        # 兼容数字 severity（如 50 → "medium"）
        if isinstance(severity, (int, float)):
            sev_map = {10: "info", 30: "low", 50: "medium", 70: "high", 90: "critical"}
            severity = sev_map.get(int(severity), "medium")
            log_data["severity"] = severity

        # 1. 异常检测
        with pipeline_tracer.span("anomaly_detect", session_id=session_id):
            anomaly_report = await anomaly_detector.analyze(log_data)
        log_data["_anomaly"] = {
            "score": anomaly_report.anomaly_score,
            "is_anomaly": anomaly_report.is_anomaly,
            "reasons": anomaly_report.reasons,
            "sigma": anomaly_report.deviation_sigma,
        }

        # 1b. Sigma 规则检测（与统计异常检测互补）
        try:
            from sigma_detector import sigma_detector
            sigma_result = sigma_detector.detect_for_event(log_data)
            log_data["_sigma"] = sigma_result
            if sigma_result["detected"]:
                logger.info(
                    f"[Sigma] {event_type}: {sigma_result['rule_count']} rules hit, "
                    f"types={sigma_result['attack_types']}, "
                    f"severity={sigma_result['max_severity']}"
                )
        except Exception as e:
            logger.warning(f"Sigma detection failed: {e}")
            log_data["_sigma"] = {"detected": False}

        # 2. 全量存储
        stored = await event_store.store(
            session, log_data, session_id,
            anomaly_score=anomaly_report.anomaly_score,
        )

        # 2b. 案例自动聚合
        try:
            from case_manager import case_manager
            await case_manager.auto_create_case(session, stored)
        except Exception as case_err:
            logger.warning(f"[Case] Auto-aggregation failed: {case_err}")

        # 3. 记忆树索引
        event_text = json.dumps(log_data, ensure_ascii=False)
        await memory_tree.add_leaf(
            session, session_id, log_data, event_text,
            correlation_group="anomaly" if anomaly_report.is_anomaly else "",
        )

        # 4. 滑动窗口
        await sliding_window.add_message(session_id, "ingestor", "log", event_text)

        # 5. 快速响应：异常分数极高 或 严重度为 critical 或 Sigma 命中 critical 时立即触发
        _sigma_critical = (
            log_data.get("_sigma", {}).get("detected", False)
            and log_data.get("_sigma", {}).get("max_severity") == "critical"
        )
        _fp_trigger = (
            anomaly_report.anomaly_score >= 0.5
            or anomaly_report.deviation_sigma >= 3
            or severity == "critical"
            or _sigma_critical
        )
        if _fp_trigger:
            try:
                from response_engine import get_orchestrator
                _resp_orch = get_orchestrator()
                fast_threat = {
                    "threat_type": event_type,
                    "confidence": min(1.0, anomaly_report.anomaly_score * 1.2),
                    "severity": severity if severity in ("critical", "high") else "high",
                    "src_ip": log_data.get("src_ip", ""),
                    "dst_ip": log_data.get("dst_ip", ""),
                    "message": log_data.get("message", f"异常检测快速响应: {', '.join(anomaly_report.reasons)}"),
                    "session_id": session_id,
                    "event_id": stored.id,
                    "anomaly_reasons": anomaly_report.reasons,
                }
                # 独立 session 后台执行，避免与请求 session 并发冲突
                async def _fast_response(threat_info: dict, evt_id: int, sid: str):
                    from models import async_session as db_session
                    async with db_session() as s:
                        try:
                            await _resp_orch.on_threat_detected(
                                session=s, threat_info=threat_info,
                                event_id=evt_id, session_id=sid,
                            )
                        except Exception as fp_err:
                            logger.warning(f"[FastPath] Quick response failed: {fp_err}")

                asyncio.create_task(_fast_response(fast_threat, stored.id, session_id))
                logger.warning(f"[FastPath] Quick response triggered for event #{stored.id}: score={anomaly_report.anomaly_score:.2f}")
            except Exception as fp_err:
                logger.warning(f"[FastPath] Quick response setup failed: {fp_err}")

        # 6. Audit-LLM 流水线（异步后台审核）
        task = asyncio.create_task(self._audit_pipeline(
            session_id, stored.id, log_data, anomaly_report
        ))
        task.add_done_callback(self._audit_task_done)

        event_bus.publish("security_event", {
            "event_id": stored.id,
            "event_type": event_type,
            "severity": severity,
            "src_ip": log_data.get("src_ip", ""),
            "dst_ip": log_data.get("dst_ip", ""),
            "message": log_data.get("message", "")[:100],
            "anomaly_score": anomaly_report.anomaly_score,
            "is_anomaly": anomaly_report.is_anomaly,
        })

        return {
            "status": "review_queued",
            "event_id": stored.id,
            "event_type": event_type,
            "severity": severity,
            "anomaly": {
                "score": anomaly_report.anomaly_score,
                "is_anomaly": anomaly_report.is_anomaly,
                "reasons": anomaly_report.reasons,
            },
            "sigma": log_data.get("_sigma", {"detected": False}),
        }

    def _audit_task_done(self, task: asyncio.Task):
        """asyncio.create_task 的 done 回调 — 捕获被静默吞掉的异常"""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            logger.error(
                f"[Audit-LLM] Unhandled exception in audit task: {exc}",
                exc_info=exc,
            )

    async def _audit_pipeline(
        self,
        session_id: str,
        event_id: int,
        log_data: dict,
        anomaly_report,
        max_rounds: int = 3,
    ):
        """
        Audit-LLM 迭代审核流水线（多次审核，补充遗漏）
        整体超时 900 秒（深度审核单轮约 3-7 分钟，3 轮补审需足够预算），
        超时后标记为已分析并记录错误。
        """
        try:
            await asyncio.wait_for(
                self._audit_pipeline_inner(
                    session_id, event_id, log_data, anomaly_report, max_rounds
                ),
                timeout=900,
            )
        except asyncio.TimeoutError:
            logger.error(f"[Audit-LLM] Pipeline TIMEOUT (900s) for event #{event_id}")
            await self._mark_analyzed(event_id, error="pipeline_timeout_900s")
            await self._fallback_analysis(event_id, log_data, anomaly_report, "timeout")
        except Exception as e:
            logger.error(
                f"[Audit-LLM] Pipeline crashed for event #{event_id}: {e}",
                exc_info=True,
            )
            await self._mark_analyzed(event_id, error=str(e))
            await self._fallback_analysis(event_id, log_data, anomaly_report, "crash")

    async def _mark_analyzed(self, event_id: int, error: str = ""):
        """确保事件被标记为已分析（即使管道失败）"""
        try:
            from models import async_session as db_session
            async with db_session() as session:
                db_evt = await session.get(SecurityEvent, event_id)
                if db_evt and not db_evt.analyzed:
                    db_evt.analyzed = True
                    if error:
                        db_evt.raw_data = {
                            **(db_evt.raw_data or {}),
                            "_audit_llm_error": error,
                        }
                    await session.commit()
                    logger.info(f"[Audit-LLM] Event #{event_id} marked analyzed (error={error})")
        except Exception as e:
            logger.error(f"[Audit-LLM] Failed to mark event #{event_id} as analyzed: {e}")

    async def _fallback_analysis(
        self, event_id: int, log_data: dict, anomaly_report, reason: str
    ):
        """LLM 失败降级：用统计异常 + Sigma 结果生成轻量分析结论"""
        try:
            from models import async_session as db_session
            sigma = log_data.get("_sigma", {})
            threat_detected = (
                anomaly_report.anomaly_score >= 0.6
                or sigma.get("detected", False)
            )
            fallback_result = {
                "prompt_version": AUDIT_PROMPT_VERSION,
                "fallback": True,
                "fallback_reason": reason,
                "threat_detected": threat_detected,
                "confidence": round(anomaly_report.anomaly_score, 4),
                "severity": log_data.get("severity", "info"),
                "anomaly_score": anomaly_report.anomaly_score,
                "anomaly_reasons": anomaly_report.reasons[:5],
                "sigma_detected": sigma.get("detected", False),
                "sigma_attack_types": sigma.get("attack_types", []),
                "note": f"LLM 管道失败({reason})，降级为统计+规则分析",
            }
            async with db_session() as session:
                db_evt = await session.get(SecurityEvent, event_id)
                if db_evt:
                    db_evt.raw_data = {
                        **(db_evt.raw_data or {}),
                        "_audit_llm": fallback_result,
                    }
                    await session.commit()
            logger.info(
                f"[Audit-LLM] Fallback analysis for #{event_id}: "
                f"threat={threat_detected} reason={reason}"
            )
        except Exception as e:
            logger.error(f"[Audit-LLM] Fallback analysis failed for #{event_id}: {e}")

    async def _audit_pipeline_inner(
        self,
        session_id: str,
        event_id: int,
        log_data: dict,
        anomaly_report,
        max_rounds: int = 3,
    ):
        """
        Audit-LLM 迭代审核流水线（多次审核，补充遗漏）

        策略:
          Round 1: 全面审核（Decomposer full mode）
          Round 2-N: 补审模式，只查 Reviewer 发现的遗漏
          当 no missed threats 或达 max_rounds 时终止

        合并策略:
          - 任意一轮发现威胁 → 最终结论为有威胁
          - 置信度取加权平均（轮次越大权重越低）
          - 所有轮的 evidence_trail 合并
        """
        async with self._review_semaphore:
            from agents import decomposer, tool_builder, executor, reviewer
            from agents.agent_cad import cad_agent
            from models import async_session as db_session
            from trace_hook import set_trace_context, clear_trace_context

            set_trace_context(
                caller="audit_pipeline",
                event_id=event_id,
                session_id=session_id,
            )

            async with db_session() as session:
                t_start = time.time()
                all_rounds = []        # 所有轮次结果
                missed_threats = []    # 上轮的遗漏
                final_verdict = None
                final_audit = None

                try:
                    for round_num in range(1, max_rounds + 1):
                        mode = "supplement" if round_num > 1 else "full"
                        logger.info(
                            f"[Audit-LLM] Round {round_num}/{max_rounds} "
                            f"({mode}) for event #{event_id}"
                        )

                        # ── Layer 1: Decomposer ──
                        with pipeline_tracer.span("decomposer", event_id=event_id, session_id=session_id):
                            decomp_output = await decomposer.decompose(
                                event=log_data,
                                session_id=session_id,
                                anomaly_score=anomaly_report.anomaly_score,
                                anomaly_reasons=anomaly_report.reasons,
                                mode=mode,
                                missed_threats=missed_threats,
                            )
                        depth = decomp_output.get("audit_depth", mode)
                        sub_tasks = decomp_output["sub_tasks"]

                        # 补审模式没有子任务 → 终止
                        if not sub_tasks:
                            logger.info(f"[Audit-LLM] Round {round_num}: no sub-tasks, stopping")
                            break

                        # ── Layer 2: Tool Builder ──
                        with pipeline_tracer.span("tool_builder", event_id=event_id, session_id=session_id):
                            tool_calls = tool_builder.build(sub_tasks, session_id)

                        # ── Layer 3: Executor ──
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

                        # ── Layer 4: Reviewer ──
                        with pipeline_tracer.span("reviewer", event_id=event_id, session_id=session_id):
                            verdict = await reviewer.review(
                                raw_event=log_data,
                                decomposer_output=decomp_output,
                                audit_result=audit_result,
                                tool_data_raw=tool_data_text,
                            )

                        # 记录本轮结果
                        round_data = {
                            "round": round_num,
                            "mode": mode,
                            "depth": depth,
                            "sub_tasks": len(sub_tasks),
                            "tool_calls": len(tool_calls),
                            "audit": audit_result.to_dict(),
                            "verdict": verdict.to_dict(),
                            "missed_threats": [
                                {
                                    "description": mt.get("description", "")[:200],
                                    "evidence": mt.get("evidence", "")[:200],
                                    "severity": mt.get("severity", ""),
                                }
                                for mt in verdict.missed_threats
                            ],
                        }
                        all_rounds.append(round_data)
                        missed_threats = verdict.missed_threats
                        final_verdict = verdict
                        final_audit = audit_result

                        logger.info(
                            f"[Audit-LLM] Round {round_num} done: "
                            f"threat={audit_result.threat_detected}, "
                            f"confidence={audit_result.confidence:.2f}, "
                            f"missed={len(missed_threats)}"
                        )

                        # 没有遗漏 → 终止迭代
                        if not missed_threats:
                            logger.info(f"[Audit-LLM] No missed threats, stopping after round {round_num}")
                            break

                    # ── 合并所有轮次结果 ──
                    merged = self._merge_rounds(all_rounds)

                    # ── 写入 DB ──
                    db_evt = await session.get(SecurityEvent, event_id)
                    if db_evt:
                        db_evt.analyzed = True

                        # 合并证据链
                        all_evidence = []
                        for rd in all_rounds:
                            for claim in rd.get("audit", {}).get("evidence", []):
                                if isinstance(claim, dict) and "threat_claims" in claim:
                                    for c in claim.get("threat_claims", []):
                                        all_evidence.append({
                                            "claim": c.get("summary", "")[:100],
                                            "type": c.get("type", ""),
                                            "confidence": c.get("confidence", 0),
                                            "evidence_ids": c.get("evidence_ids", []),
                                            "evidence_quotes": c.get("evidence_quotes", [])[:3],
                                            "severity": c.get("severity", ""),
                                            "round": rd["round"],
                                        })

                        db_evt.raw_data = {
                            **(db_evt.raw_data or {}),
                            "_audit_llm": {
                                "prompt_version": AUDIT_PROMPT_VERSION,
                                "rounds": len(all_rounds),
                                "max_rounds": max_rounds,
                                "merged": merged,
                                "rounds_detail": [
                                    {
                                        "round": r["round"],
                                        "mode": r["mode"],
                                        "threat_detected": r["audit"].get("threat_detected"),
                                        "confidence": r["audit"].get("confidence"),
                                        "missed_count": len(r["missed_threats"]),
                                    }
                                    for r in all_rounds
                                ],
                                "final_verdict": final_verdict.to_dict() if final_verdict else {},
                                "evidence_trail": all_evidence,
                                "hallucination": {
                                    "risk": merged.get("confidence", 0) < 0.3,
                                    "rounds": len(all_rounds),
                                    "needs_human": merged.get("needs_human", False),
                                },
                                "grounding": {
                                    "score": final_audit.grounding_score if final_audit else 1.0,
                                    "kb_verification": final_audit.kb_verification if final_audit else {},
                                    "schema_valid": final_audit.schema_valid if final_audit else True,
                                },
                                "pipeline_duration_s": round(time.time() - t_start, 2),
                                "completed_at": datetime.now(timezone.utc).isoformat(),
                            },
                        }
                        await session.commit()

                    duration = time.time() - t_start
                    logger.info(
                        f"[Audit-LLM] Pipeline complete for event #{event_id}: "
                        f"{duration:.1f}s, {len(all_rounds)} rounds, "
                        f"threat={merged.get('threat_detected')}, "
                        f"confidence={merged.get('confidence', 0):.2f}"
                    )

                    event_bus.publish("audit_complete", {
                        "event_id": event_id,
                        "event_type": log_data.get("event", log_data.get("type", "UNKNOWN")),
                        "threat_detected": merged.get("threat_detected", False),
                        "confidence": merged.get("confidence", 0),
                        "severity": merged.get("severity", "info"),
                        "rounds": len(all_rounds),
                        "duration_s": round(duration, 1),
                        "src_ip": log_data.get("src_ip", ""),
                    })

                    # ── 触发响应引擎（独立 session，避免与流水线 session 并发）──
                    if merged.get("threat_detected") and merged.get("confidence", 0) >= 0.4:
                        try:
                            from response_engine import get_orchestrator
                            _resp_orch = get_orchestrator()
                            threat_info = {
                                "threat_type": log_data.get("event", log_data.get("type", "UNKNOWN")),
                                "confidence": merged.get("confidence", 0),
                                "severity": merged.get("severity", "info"),
                                "src_ip": log_data.get("src_ip", ""),
                                "dst_ip": log_data.get("dst_ip", ""),
                                "message": log_data.get("message", ""),
                                "session_id": session_id,
                                "event_id": event_id,
                                "policy_name": f"audit_llm_rounds_{len(all_rounds)}",
                            }
                            async def _audit_response(threat_info: dict, evt_id: int, sid: str):
                                from models import async_session as db_session
                                async with db_session() as s:
                                    try:
                                        with pipeline_tracer.span("response", event_id=evt_id, session_id=sid):
                                            await _resp_orch.on_threat_detected(
                                                session=s, threat_info=threat_info,
                                                event_id=evt_id, session_id=sid,
                                            )
                                    except Exception as resp_err:
                                        logger.warning(f"[Response] Trigger failed for event #{evt_id}: {resp_err}")

                            asyncio.create_task(_audit_response(threat_info, event_id, session_id))
                            logger.info(f"[Response] Triggered for event #{event_id}: {threat_info['threat_type']}")
                            event_bus.publish("response_action", {
                                "event_id": event_id,
                                "threat_type": threat_info["threat_type"],
                                "severity": threat_info["severity"],
                                "src_ip": threat_info.get("src_ip", ""),
                                "confidence": threat_info["confidence"],
                                "status": "triggered",
                            })
                        except Exception as resp_err:
                            logger.warning(f"[Response] Trigger setup failed for event #{event_id}: {resp_err}")

                    # ── CAD 独立审计 ──
                    try:
                        with pipeline_tracer.span("cad_verify", event_id=event_id, session_id=session_id):
                            cad_report = await cad_agent.audit_pipeline(
                                session, event_id, db_evt.raw_data["_audit_llm"]
                            )
                        db_evt.raw_data["_cad_audit"] = {
                            "penetrating_verification": cad_report["penetrating_verification"],
                            "circuit_breaker": cad_report["circuit_breaker"],
                            "audit_timestamp": cad_report["audit_timestamp"],
                            "duration_ms": cad_report["duration_ms"],
                        }
                        await session.commit()
                        if cad_report["circuit_breaker"]["tripped"]:
                            logger.critical(
                                f"[CAD] CIRCUIT BREAKER for event #{event_id}: "
                                f"{cad_report['circuit_breaker']['reason']}"
                            )
                    except Exception as cad_err:
                        logger.warning(f"[CAD] audit_pipeline failed: {cad_err}")

                except Exception as e:
                    logger.error(
                        f"[Audit-LLM] Pipeline failed for event #{event_id}: {e}",
                        exc_info=True,
                    )
                    await self._mark_analyzed(event_id, error=str(e))

    async def _run_batch_analysis(self, session_id: str):
        """批量分析未处理的安全事件（使用 Audit-LLM 流水线）"""
        async with self._analysis_lock:
            from models import async_session as db_session
            from sqlalchemy import select

            async with db_session() as session:
                stmt = (
                    select(SecurityEvent)
                    .where(
                        SecurityEvent.session_id == session_id,
                        SecurityEvent.analyzed == False,
                    )
                    .order_by(SecurityEvent.created_at)
                    .limit(settings.log_batch_size)
                )
                result = await session.execute(stmt)
                events = result.scalars().all()
                if not events:
                    return

                logger.info(f"Batch analyzing {len(events)} events for {session_id}")

                for evt in events:
                    raw = evt.raw_data or {}
                    anomaly_info = raw.get("_anomaly", {})
                    # 模拟 AnomalyReport
                    class FakeReport:
                        anomaly_score = anomaly_info.get("score", 0)
                        is_anomaly = anomaly_info.get("is_anomaly", False)
                        reasons = anomaly_info.get("reasons", [])
                        deviation_sigma = anomaly_info.get("sigma", 0)
                    await self._audit_pipeline(
                        session_id, evt.id, raw, FakeReport()
                    )

                self._last_analysis[session_id] = time.time()

    async def ingest_batch(
        self, session: AsyncSession, session_id: str, logs: list[dict]
    ) -> dict:
        """批量接入"""
        results = []
        for log_data in logs:
            r = await self.ingest(session, session_id, log_data)
            results.append(r)
        return {
            "status": "batch_ingested",
            "count": len(results),
            "session_id": session_id,
        }

    async def get_status(
        self, session: AsyncSession, session_id: str
    ) -> dict:
        """获取接入状态"""
        from sqlalchemy import select, func
        total_q = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id
            )
        )
        analyzed_q = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id,
                SecurityEvent.analyzed == True,
            )
        )
        total_val = total_q.scalar() or 0
        analyzed_val = analyzed_q.scalar() or 0

        store_stats = await event_store.get_stats(session, session_id)

        return {
            "session_id": session_id,
            "total_events": total_val,
            "analyzed": analyzed_val,
            "pending": total_val - analyzed_val,
            "by_severity": store_stats.get("by_severity", {}),
        }


log_ingestor = LogIngestor()
