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
AUDIT_PROMPT_VERSION = "v2.2.0"


class LogIngestor:
    def __init__(self):
        self._last_analysis = {}
        self._analysis_lock = asyncio.Lock()
        # v4 复现:5 并发下 200 events / 5 min 完成 0%(8-28 修复)
        # 默认 20 满足 v4 压测场景,可由环境变量 AUDIT_REVIEW_CONCURRENCY 调优
        import os
        self._review_semaphore = asyncio.Semaphore(
            int(os.environ.get("AUDIT_REVIEW_CONCURRENCY", "20"))
        )
        # v4 复现:Temporal 挂掉时降级路径仍用上面的 Semaphore,200 events 卡 5 min
        # 降级路径用独立的、宽松的 Semaphore,避免被 Temporal 异常拖累
        # 可由环境变量 AUDIT_FALLBACK_CONCURRENCY 调优
        self._review_semaphore_fallback = asyncio.Semaphore(
            int(os.environ.get("AUDIT_FALLBACK_CONCURRENCY", "20"))
        )
        # v4 修复(2026-09-01):审计状态可观测性
        # 之前 analyzed=False 黑洞:事件在 Semaphore 队列里永远 analyzed=False,看不到也排不到
        # 内存 cache 追踪 pending/running/completed/failed,定期清理(只保留 running/pending)
        self._audit_status_cache: dict[int, dict] = {}
        # 上限:cache 不超过 10000 条,防止内存爆
        self._audit_status_cache_max = 10000
        # FastPath 冷却去重:同 src_ip+threat_type 在冷却窗口内只编排一次响应链路,
        # 防止大量高分事件涌入时同源事件重复挂起 N 条响应编排(策略+DB+webhook/SSH)
        self._fastpath_cooldown: dict[str, float] = {}
        self._fastpath_cooldown_ttl = float(os.environ.get("FASTPATH_COOLDOWN_S", "60"))
        self._fastpath_cooldown_max = 1000

    def _fastpath_allow(self, key: str) -> bool:
        """冷却窗口内首次调用返回 True 并记录时刻；窗口内重复调用返回 False。"""
        now = time.time()
        if now - self._fastpath_cooldown.get(key, 0.0) < self._fastpath_cooldown_ttl:
            return False
        if len(self._fastpath_cooldown) >= self._fastpath_cooldown_max:
            # 简化清理:淘汰最早的一半
            for k in list(self._fastpath_cooldown.keys())[: self._fastpath_cooldown_max // 2]:
                self._fastpath_cooldown.pop(k, None)
        self._fastpath_cooldown[key] = now
        return True

    async def _index_background(
        self, session_id: str, log_data: dict, event_text: str, is_anomaly: bool,
    ) -> None:
        """记忆树索引 + 滑动窗口写入（后台执行，独立 session）。

        与紧随其后的 Audit-LLM 流水线并行：流水线首轮有多次 LLM 调用，
        索引写入（毫秒级）几乎总是先于工具查询完成，竞态窗口可忽略。
        """
        from models import async_session as db_session
        try:
            async with db_session() as s:
                await memory_tree.add_leaf(
                    s, session_id, log_data, event_text,
                    correlation_group="anomaly" if is_anomaly else "",
                )
        except Exception as leaf_err:
            logger.warning(f"[Index] memory_tree.add_leaf failed: {leaf_err}")
        try:
            await sliding_window.add_message(session_id, "ingestor", "log", event_text)
        except Exception as win_err:
            logger.warning(f"[Index] sliding_window.add_message failed: {win_err}")

    def _merge_rounds(self, all_rounds: list[dict], log_data: dict = None) -> dict:
        """
        合并多轮审核结果（PR1 / P0-4）

        禁止 OR 合并。confirmed 必须绑定非 LLM 信号。
        """
        from veto_gates import merge_audit_rounds, extract_non_llm_signals
        signals = extract_non_llm_signals(log_data or {})
        return merge_audit_rounds(all_rounds, signals)

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
            # HTTP 方法/状态: 供 SigmaHQ SQLi/XSS/SSTI 等 web 规则(selection: cs-method='GET', filter: sc-status)命中。
            "method": ["method", "http_method", "csMethod", "requestMethod", "methodType", "httpMethod"],
            "status": ["status", "status_code", "httpStatus", "http_response_status", "sc-status", "httpCode"],
            "url": ["url", "http_url", "requestUrl", "request_uri", "cs-uri-query", "uri"],
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
        # rawData 兜底: web 日志的 HTTP 元数据常透传在 rawData 子对象中, 从其中提取 method/status/url。
        raw = log_data.get("rawData") or log_data.get("raw_data") or {}
        if isinstance(raw, dict) and raw:
            for target, keys in (("method", ["method", "requestMethod", "httpMethod"]),
                                 ("status", ["status", "statusCode", "httpStatus"]),
                                 ("url", ["url", "requestUrl", "request_uri", "path"])):
                if target in normalized and normalized.get(target):
                    continue
                for k in keys:
                    v = raw.get(k)
                    if v is None or v == "":
                        continue
                    if isinstance(v, list):
                        v = v[0] if v else ""
                    if v is not None and v != "":
                        normalized[target] = v
                        break
        # 语义推断: event 名常为自然语言(如 "C2 通信"), 推断标准威胁类型枚举。
        # 上游已显式提供 threat_type 枚举时尊重不覆盖。
        if not normalized.get("threat_type"):
            try:
                from correlation_engine import infer_threat_type
                normalized["threat_type"] = infer_threat_type(
                    str(normalized.get("event") or normalized.get("type") or "")
                )
            except Exception as infer_err:
                logger.debug(f"threat_type inference skipped: {infer_err}")
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
                # Sigma 命中抬升异常分，避免「规则已命中但异常层全绿」
                sev_floor = {
                    "critical": 0.75, "high": 0.65, "medium": 0.55, "low": 0.45,
                }.get(str(sigma_result.get("max_severity") or "").lower(), 0.55)
                if anomaly_report.anomaly_score < sev_floor:
                    anomaly_report.anomaly_score = sev_floor
                anomaly_report.is_anomaly = True
                if "sigma_hit" not in (anomaly_report.reasons or []):
                    anomaly_report.reasons = list(anomaly_report.reasons or []) + [
                        f"Sigma命中:{','.join(sigma_result.get('attack_types') or [])}"
                    ]
                log_data["_anomaly"] = {
                    "score": anomaly_report.anomaly_score,
                    "is_anomaly": True,
                    "reasons": anomaly_report.reasons,
                    "sigma": anomaly_report.deviation_sigma,
                }
        except Exception as e:
            logger.warning(f"Sigma detection failed: {e}")
            log_data["_sigma"] = {"detected": False}

        # 2. 全量存储
        stored = await event_store.store(
            session, log_data, session_id,
            anomaly_score=anomaly_report.anomaly_score,
        )

        # 2b. 记忆树索引 + 滑动窗口 → 后台执行（此前在 ingest 关键路径同步串行，
        #     是单事件多 DB/Redis 往返的一部分；案例聚合已由 _audit_pipeline 覆盖）
        event_text = json.dumps(log_data, ensure_ascii=False)
        asyncio.create_task(self._index_background(
            session_id, log_data, event_text, anomaly_report.is_anomaly,
        ))

        # 3. 快速响应：异常分数极高 或 严重度为 critical 或 Sigma 命中 critical 时立即触发
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
        # 冷却去重：同源(源IP+威胁类型)事件在窗口内不重复编排响应链路
        _fp_key = f"{log_data.get('src_ip', '')}|{log_data.get('threat_type') or event_type}"
        if _fp_trigger and not self._fastpath_allow(_fp_key):
            logger.debug(f"[FastPath] cooldown skip: {_fp_key}")
            _fp_trigger = False
        if _fp_trigger:
            try:
                from response_engine import get_orchestrator
                _resp_orch = get_orchestrator()
                sigma_info = log_data.get("_sigma") or {}
                _sigma_conf_map = {"high": 0.85, "medium": 0.65, "low": 0.45}
                _sigma_conf = 0.0
                for hit in (sigma_info.get("hits") or []):
                    _sigma_conf = max(
                        _sigma_conf,
                        _sigma_conf_map.get(str(hit.get("confidence") or "").lower(), 0.5),
                    )
                if sigma_info.get("detected") and sigma_info.get("max_severity") == "critical":
                    _sigma_conf = max(_sigma_conf, 0.85)
                _evt_conf = log_data.get("confidence", 0)
                try:
                    _evt_conf_f = float(_evt_conf)
                    if _evt_conf_f > 1:
                        _evt_conf_f = _evt_conf_f / 100.0
                except (TypeError, ValueError):
                    _evt_conf_f = 0.0
                _fused_conf = min(1.0, max(
                    float(anomaly_report.anomaly_score or 0) * 1.2,
                    _sigma_conf,
                    _evt_conf_f,
                ))
                # v5 修复(A):双轨封禁门槛
                #   强信号(Sigma critical 命中 或 融合置信度>=0.7) → FastPath 可封禁
                #   仅 severity=critical(无检测器佐证) → 仅告警，封禁等 Audit-LLM confirmed
                # 此前 severity=critical 直接触发完整响应，152/152 事件绕过
                # 审计与 veto 门控由 ANY 兜底策略封禁假事件。
                _strong_signal = bool(
                    (sigma_info.get("detected") and sigma_info.get("max_severity") == "critical")
                    or _fused_conf >= 0.7
                )
                # v5 修复:不再把 low/info 抬成 high(此前良性低危事件被抬级后
                # 通过护栏拿到封禁资格,误封正常用户)。未知级别下限取 medium
                # (护栏下 medium 仍只允许告警/限速,不会封禁)。
                _fp_sev = severity if severity in ("critical", "high", "medium") else "medium"
                _fp_msg = log_data.get(
                    "message",
                    f"异常检测快速响应: {', '.join(anomaly_report.reasons)}",
                )
                fast_threat = {
                    "threat_type": log_data.get("threat_type") or event_type,
                    "event": event_type,
                    "confidence": _fused_conf,
                    "severity": _fp_sev,
                    "threat_level": _fp_sev,
                    "src_ip": log_data.get("src_ip", ""),
                    "dst_ip": log_data.get("dst_ip", ""),
                    "message": _fp_msg,
                    "reason": (
                        f"FastPath: {event_type} severity={_fp_sev} "
                        f"confidence={_fused_conf:.2f} "
                        f"sigma={bool(sigma_info.get('detected'))} "
                        f"anomaly={float(anomaly_report.anomaly_score or 0):.2f}"
                    ),
                    "session_id": session_id,
                    "event_id": stored.id,
                    "anomaly_reasons": anomaly_report.reasons,
                    # v5 修复(A):响应来源与双轨门槛标记（写入 policy_match 日志可追溯）
                    "response_source": (
                        "fastpath_strong" if _strong_signal else "fastpath_severity"
                    ),
                    "allow_blocking": _strong_signal,
                }
                # 独立 session 后台执行，避免与请求 session 并发冲突
                async def _fast_response(threat_info: dict, evt_id: int, sid: str):
                    from models import async_session as db_session
                    async with db_session() as s:
                        try:
                            await _resp_orch.on_threat_detected(
                                session=s, threat_info=threat_info,
                                event_id=evt_id, session_id=sid,
                                allow_blocking=bool(threat_info.get("allow_blocking", True)),
                            )
                        except Exception as fp_err:
                            logger.warning(f"[FastPath] Quick response failed: {fp_err}")

                asyncio.create_task(_fast_response(fast_threat, stored.id, session_id))
                logger.warning(
                    f"[FastPath] Quick response triggered for event #{stored.id}: "
                    f"score={anomaly_report.anomaly_score:.2f} "
                    f"mode={'strong(block-capable)' if _strong_signal else 'severity(alert-only)'}"
                )
            except Exception as fp_err:
                logger.warning(f"[FastPath] Quick response setup failed: {fp_err}")

        # 4. Audit-LLM 流水线（异步后台审核）
        # v4 修复(2026-09-01):先标记 pending,避免事件在 Semaphore 队列里 analyzed=False 黑洞
        self._track_audit_status(stored.id, "pending", event_type=event_type)
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

    def _track_audit_status(self, event_id: int, status: str, **extra):
        """v4 修复(2026-09-01):记录事件在审计流水线中的状态。

        status 取值:
          - "pending"     Semaphore 队列中等待
          - "running"     正在 LLM 审计
          - "completed"   成功完成(由 _mark_analyzed 调)
          - "failed"      失败(由 _mark_analyzed 调)
          - "skipped"     跳过(如 anomaly_score 为 None)

        cache 上限 10000,防止长跑内存爆。
        """
        if event_id is None:
            return
        if len(self._audit_status_cache) >= self._audit_status_cache_max:
            # LRU 简化:清掉最早的 20%
            n = self._audit_status_cache_max // 5
            for k in list(self._audit_status_cache.keys())[:n]:
                self._audit_status_cache.pop(k, None)
        self._audit_status_cache[event_id] = {
            "status": status,
            "ts": time.time(),
            **extra,
        }
        # 每 100 条打印一次聚合,避免日志爆
        if event_id % 100 == 0:
            stats = self.get_audit_stats()
            logger.info(
                f"[Audit-Stats] pending={stats['pending']} "
                f"running={stats['running']} "
                f"completed={stats['completed']} "
                f"failed={stats['failed']} "
                f"total={stats['total']}"
            )

    def get_audit_stats(self) -> dict:
        """v4 修复:对外暴露审计状态聚合,供 /api/logs/audit-stats 等查询使用"""
        agg = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0, "total": 0}
        for v in self._audit_status_cache.values():
            s = v.get("status", "unknown")
            if s in agg:
                agg[s] += 1
            agg["total"] += 1
        return agg

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
        Audit-LLM 迭代审核流水线（多次审核，补充遗漏）。

        编排: 优先走 Temporal Workflow(AuditPipelineWorkflow) 获得可靠性/长任务/可视化;
        不可用/失败时降级回本进程 async 兜底(带 900s 整体超时)。
        """
        # ── 案例自动聚合 (Kafka enriched/audit + HTTP 兜底共用入口) ──
        # 此前 auto_create_case 仅在 ingest()(HTTP 直连) 被调用, Kafka 路径绕过→从不自动建 case。
        # 在此调用覆盖全部非 ingest 审计路径; auto_create_case 幂等(同源聚合复用, 不重复建)。
        try:
            from models import async_session as db_session
            from case_manager import case_manager
            async with db_session() as case_session:
                db_evt = await case_session.get(SecurityEvent, event_id)
                if db_evt:
                    await case_manager.auto_create_case(case_session, db_evt)
        except Exception as e:
            logger.debug(f"[Case] audit-pipeline case aggregation skipped: {e}")

        # ── 审计分流 (LLM 通道分层) ──
        # 废除全局 budget 一刀切: P0 始终可走最小 LLM; 低优降级 tools_only/rule_close
        from audit_triage import (
            score_event, admit, needs_llm,
            LANE_RULE_CLOSE, LANE_TOOLS_ONLY,
        )
        from agents.llm_fallback import budget_usage_pct, budget_exhausted
        from config import settings as _cfg

        _fp_strong = bool(
            (log_data.get("_sigma") or {}).get("detected")
            and str((log_data.get("_sigma") or {}).get("max_severity") or "").lower() == "critical"
        ) or float(getattr(anomaly_report, "anomaly_score", 0) or 0) >= 0.7
        triage = score_event(
            log_data,
            float(getattr(anomaly_report, "anomaly_score", 0) or 0),
            fastpath_strong=_fp_strong and bool(getattr(_cfg, "audit_fastpath_demote", True)),
        )
        triage = admit(
            triage,
            usage_pct=budget_usage_pct(),
            over_budget=budget_exhausted(),
            soft_pct=float(getattr(_cfg, "audit_soft_budget_pct", 70.0) or 70.0),
            hard_pct=float(getattr(_cfg, "audit_hard_budget_pct", 95.0) or 95.0),
            inflight_full=False,  # 真正满载在 start 返回 shed 时再处理
        )
        log_data = {**log_data, "_audit_triage": triage.to_dict()}
        try:
            from metrics import inc_audit_lane_admit
            inc_audit_lane_admit(triage.lane, triage.tier)
        except Exception:
            pass
        logger.info(
            f"[Audit-Triage] event #{event_id} tier={triage.tier} "
            f"lane={triage.lane} pri={triage.priority} "
            f"reasons={triage.reasons[:4]}"
        )

        if not needs_llm(triage.lane):
            # tools_only / rule_close: 规则+统计收口,不占 LLM 槽
            await self._fallback_analysis(
                event_id, log_data, anomaly_report,
                f"triage:{triage.lane}:{triage.tier}",
            )
            await self._mark_analyzed(
                event_id, error=f"triage_{triage.lane}", status="fallback"
            )
            return

        # ── Temporal 优先: 启动 4 层 Agent 编排 Workflow ──
        # 标志:本次调用是否走降级路径(决定 _audit_pipeline_inner 用哪个 Semaphore)
        # v4 复现:Temporal 容器持续 Restarting 时所有调用都走降级,降级路径仍用主 Semaphore=5
        #         → 200 events / 5 min 完成 0%。修复:降级走独立、宽松的 Semaphore。
        _fallback_routed = False
        if getattr(anomaly_report, "anomaly_score", 0) is not None:
            try:
                from temporal.client import start_audit_workflow
                started = await start_audit_workflow(
                    session_id=session_id,
                    event_id=event_id,
                    log_data=log_data,
                    anomaly_score=(getattr(anomaly_report, "anomaly_score", 0.0) or 0.0),
                    anomaly_reasons=getattr(anomaly_report, "reasons", []) or [],
                    max_rounds=max_rounds,
                    tier=triage.tier,
                )
                if started == "shed":
                    # Phase C: P0/P1 → 优先级队列等待槽位; P2/P3 → 立即降级收口
                    if triage.tier in ("P0", "P1"):
                        from audit_pq import audit_pq
                        ttl = int(getattr(_cfg, "audit_pq_ttl_s", 900) or 900)
                        ok = await audit_pq.enqueue(
                            event_id=event_id,
                            session_id=session_id,
                            log_data=log_data,
                            anomaly_score=(getattr(anomaly_report, "anomaly_score", 0.0) or 0.0),
                            anomaly_reasons=getattr(anomaly_report, "reasons", []) or [],
                            max_rounds=max_rounds,
                            priority=triage.priority,
                            tier=triage.tier,
                            ttl_s=ttl,
                        )
                        if ok:
                            self._track_audit_status(
                                event_id, "pending",
                                queued="audit_pq", tier=triage.tier,
                            )
                            logger.warning(
                                f"[Audit-LLM] shed→PQ event #{event_id} "
                                f"tier={triage.tier} pri={triage.priority}"
                            )
                            return
                    logger.warning(
                        f"[Audit-LLM] shed event #{event_id} tier={triage.tier} "
                        f"→ triage close (inflight full, no PQ)"
                    )
                    await self._fallback_analysis(
                        event_id, log_data, anomaly_report,
                        f"shed_load:{triage.tier}",
                    )
                    await self._mark_analyzed(
                        event_id, error="shed_load", status="fallback"
                    )
                    return
                if started:
                    logger.info(
                        f"[Audit-LLM] routed event #{event_id} to Temporal "
                        f"(tier={triage.tier} lane={triage.lane})"
                    )
                    return
                # started is False: Temporal 不可用/start 失败(非异常路径)
                # 必须走 fallback Semaphore,否则与主槽争抢 → 降级时再次卡死
                _fallback_routed = True
                logger.info(
                    f"[Audit-LLM] Temporal unavailable for #{event_id}, "
                    f"async fallback with fallback-semaphore"
                )
            except Exception as e:
                logger.warning(f"[Audit-LLM] Temporal route failed, fallback async: {e}")
                _fallback_routed = True  # ← 标记走降级,后续用 fallback Semaphore

        # ── 降级兜底: 原 async 编排(整体 900s 超时) ──
        try:
            await asyncio.wait_for(
                self._audit_pipeline_inner(
                    session_id, event_id, log_data, anomaly_report, max_rounds,
                    use_fallback_semaphore=_fallback_routed,
                ),
                timeout=900,
            )
        except asyncio.TimeoutError:
            logger.error(f"[Audit-LLM] Pipeline TIMEOUT (900s) for event #{event_id}")
            await self._mark_analyzed(event_id, error="pipeline_timeout_900s", status="failed")
            await self._fallback_analysis(event_id, log_data, anomaly_report, "timeout")
        except Exception as e:
            logger.error(
                f"[Audit-LLM] Pipeline crashed for event #{event_id}: {e}",
                exc_info=True,
            )
            await self._mark_analyzed(event_id, error=str(e), status="failed")
            await self._fallback_analysis(event_id, log_data, anomaly_report, "crash")

    async def _mark_analyzed(self, event_id: int, error: str = "", status: str = ""):
        """确保事件被标记为已分析（即使管道失败）。

        status: completed | failed | fallback；失败时不得伪装成空成功结果。
        """
        # v4 修复(2026-09-01):同步写内存 cache,让可观测性追上 DB
        # 注意:即使 DB 写失败,cache 仍要更新,避免事件永远卡在 pending/running
        cache_status = "failed" if error else (status or "completed")
        try:
            self._track_audit_status(event_id, cache_status, error=error)
        except Exception as cache_err:
            logger.warning(f"[Audit-LLM] cache status update failed for #{event_id}: {cache_err}")

        try:
            from models import async_session as db_session
            async with db_session() as session:
                db_evt = await session.get(SecurityEvent, event_id)
                if db_evt and not db_evt.analyzed:
                    db_evt.analyzed = True
                    raw = dict(db_evt.raw_data or {})
                    if error:
                        raw["_audit_llm_error"] = error
                        audit = dict(raw.get("_audit_llm") or {})
                        audit.setdefault("status", status or "failed")
                        audit["error"] = error
                        raw["_audit_llm"] = audit
                    elif status:
                        audit = dict(raw.get("_audit_llm") or {})
                        audit["status"] = status
                        raw["_audit_llm"] = audit
                    db_evt.raw_data = raw
                    await session.commit()
                    event_store.invalidate(event_id)
                    logger.info(
                        f"[Audit-LLM] Event #{event_id} marked analyzed "
                        f"(status={status or ('failed' if error else 'completed')}, error={error})"
                    )
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
            conf = round(
                max(
                    float(anomaly_report.anomaly_score or 0),
                    0.75 if sigma.get("max_severity") == "critical" else 0,
                    0.65 if sigma.get("max_severity") == "high" else 0,
                    0.55 if sigma.get("detected") else 0,
                ),
                4,
            )
            fallback_result = {
                "prompt_version": AUDIT_PROMPT_VERSION,
                "status": "fallback",
                "fallback": True,
                "fallback_reason": reason,
                "error": reason,
                "threat_detected": threat_detected,
                "confidence": conf,
                "severity": log_data.get("severity", "info"),
                "anomaly_score": anomaly_report.anomaly_score,
                "anomaly_reasons": (anomaly_report.reasons or [])[:5],
                "sigma_detected": sigma.get("detected", False),
                "sigma_attack_types": sigma.get("attack_types", []),
                "evidence_trail": [
                    {
                        "claim": f"sigma:{t}",
                        "type": t,
                        "confidence": conf,
                        "evidence_ids": [event_id],
                        "severity": sigma.get("max_severity", ""),
                        "round": 0,
                    }
                    for t in (sigma.get("attack_types") or [])[:5]
                ],
                "reviewer": {
                    "conclusion": "suspicious" if threat_detected else "insufficient_evidence",
                    "notes": f"pipeline fallback ({reason})",
                },
                "note": f"LLM 管道失败({reason})，降级为统计+规则分析",
            }
            async with db_session() as session:
                db_evt = await session.get(SecurityEvent, event_id)
                if db_evt:
                    db_evt.analyzed = True
                    db_evt.raw_data = {
                        **(db_evt.raw_data or {}),
                        "_audit_llm": fallback_result,
                        "_audit_llm_error": reason,
                    }
                    await session.commit()
                    event_store.invalidate(event_id)
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
        use_fallback_semaphore: bool = False,  # v4 修复:Temporal 降级时走独立 Semaphore
    ):
        """
        Audit-LLM 迭代审核流水线（多次审核，补充遗漏）

        策略:
          Round 1: 全面审核（Decomposer full mode）
          Round 2-N: 补审模式，只查 Reviewer 发现的遗漏
          当 no missed threats 或达 max_rounds 时终止

        合并策略 (PR1):
          - 禁止 OR 合并；confirmed 必须绑定非 LLM 信号
          - 置信度取加权平均（轮次越大权重越低）
          - 所有轮的 evidence_trail 合并
        """
        # v4 修复:Temporal 降级路径走独立 Semaphore(默认 20),避免被主 Semaphore 拥堵
        _sem = self._review_semaphore_fallback if use_fallback_semaphore else self._review_semaphore
        async with _sem:
            # v4 修复:Semaphore 拿到后,状态从 pending → running
            self._track_audit_status(event_id, "running", use_fallback=use_fallback_semaphore)
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
                        from veto_gates import filter_missed_threats
                        missed_threats = filter_missed_threats(verdict.missed_threats)
                        # hop-budget early-stop: 禁止补审轮 — 证据已差时再开
                        # supplement 只会继续占槽空转(r6 根因之一)
                        hop_trace = getattr(audit_result, "hop_trace", None) or []
                        if any(
                            isinstance(h, dict) and h.get("skip_reasoning")
                            for h in hop_trace
                        ):
                            logger.info(
                                f"[Audit-LLM] hop-budget early-stop → finalize "
                                f"(cleared {len(missed_threats)} missed)"
                            )
                            missed_threats = []
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
                    merged = self._merge_rounds(all_rounds, log_data)

                    from faithfulness_gate import apply_faithfulness_gate, contexts_from_audit
                    answer_text = ""
                    if final_audit is not None:
                        answer_text = getattr(final_audit, "summary", "") or ""
                    if final_verdict is not None:
                        answer_text = answer_text or getattr(final_verdict, "final_summary", "") or ""
                    evidence_for_gate = []
                    for rd in all_rounds:
                        for claim in (rd.get("audit") or {}).get("evidence") or []:
                            if isinstance(claim, dict) and "threat_claims" in claim:
                                evidence_for_gate.extend(claim.get("threat_claims") or [])
                    _sigma = log_data.get("_sigma") or {}
                    _anomaly = log_data.get("_anomaly") or {}
                    _non_llm = {
                        "sigma_detected": bool(_sigma.get("detected")),
                        "hits": _sigma.get("hits") or [],
                        "anomaly_score": (
                            _anomaly.get("score")
                            if _anomaly.get("score") is not None
                            else getattr(anomaly_report, "anomaly_score", 0)
                        ),
                        "confirmation_admitted": bool(
                            (merged.get("confirmation") or {}).get("admitted")
                            or merged.get("has_admitted_claims")
                        ),
                        "event_type": log_data.get("event") or log_data.get("type") or "",
                        "event_severity": log_data.get("severity") or "",
                        "sigma_severity": (
                            _sigma.get("max_severity") or _sigma.get("severity") or ""
                        ),
                        "cep_chain": bool(
                            (merged.get("non_llm_signal"))
                            or log_data.get("_chain")
                        ),
                    }
                    merged = apply_faithfulness_gate(
                        merged,
                        answer=answer_text,
                        contexts=contexts_from_audit(log_data, evidence_for_gate),
                        query=str(log_data.get("message") or ""),
                        abstain=bool(
                            getattr(final_verdict, "abstain", False)
                            or merged.get("verdict") == "insufficient_evidence"
                        ),
                        non_llm_signals=_non_llm,
                    )

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
                                "status": "completed",
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
                                        "hop_trace": r["audit"].get("hop_trace") or [],
                                    }
                                    for r in all_rounds
                                ],
                                "hop_trace": (
                                    (final_audit.to_dict().get("hop_trace") if final_audit else None)
                                    or []
                                ),
                                "final_verdict": final_verdict.to_dict() if final_verdict else {},
                                "reviewer": final_verdict.to_dict() if final_verdict else {},
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
                                "faithfulness": merged.get("faithfulness") or {},
                                "response_blocked": bool(merged.get("response_blocked")),
                            },
                        }
                        await session.commit()
                        event_store.invalidate(event_id)

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
                        "stage": "pipeline_complete",
                        "agent_id": "reviewer",
                        "agents_completed": [
                            "decomposer", "tool_builder", "executor", "reviewer",
                        ],
                    })

                    # ── 触发响应引擎（独立 session，避免与流水线 session 并发）──
                    # confirmed：完整自动响应；suspicious + 未 blocked：软降级后仍允许策略层处置
                    _verdict = merged.get("verdict")
                    if (
                        merged.get("threat_detected")
                        and _verdict in ("confirmed", "suspicious")
                        and merged.get("confidence", 0) >= 0.4
                        and not merged.get("response_blocked")
                    ):
                        try:
                            from response_engine import get_orchestrator
                            _resp_orch = get_orchestrator()
                            _audit_event_name = log_data.get("event", log_data.get("type", "UNKNOWN"))
                            threat_info = {
                                "threat_type": (
                                    merged.get("threat_type")
                                    or log_data.get("threat_type")
                                    or _audit_event_name
                                ),
                                "event": _audit_event_name,
                                "confidence": merged.get("confidence", 0),
                                "severity": merged.get("severity", "info"),
                                "src_ip": log_data.get("src_ip", ""),
                                "dst_ip": log_data.get("dst_ip", ""),
                                "message": log_data.get("message", ""),
                                "session_id": session_id,
                                "event_id": event_id,
                                "policy_name": f"audit_llm_rounds_{len(all_rounds)}",
                                # v5 修复(A):响应来源标记
                                "response_source": "audit_llm",
                                "allow_blocking": True,
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
                                "stage": "response",
                                "agent_id": "response",
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
                    await self._mark_analyzed(event_id, error=str(e), status="failed")
                    await self._fallback_analysis(event_id, log_data, anomaly_report, str(e))
                finally:
                    # 防止 trace context 泄漏: 同任务内后续辅助 LLM 调用
                    # (watchdog/post_mortem/rerank 等) 不会继承本事件的 event_id
                    clear_trace_context()

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
