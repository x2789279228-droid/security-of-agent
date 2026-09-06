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
from collections import OrderedDict
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


def _quality_from_reason(reason: str, status: str = "") -> str:
    r = (reason or "").lower()
    if "rate_limited" in r or "429" in r:
        return "rate_limited"
    if "budget" in r:
        return "budget"
    if "shed" in r or "overflow" in r or "queue_overflow" in r:
        return "shed"
    if "tools_only" in r:
        return "tools"
    if "rule_close" in r:
        return "rule"
    if status == "completed" and not reason:
        return "llm"
    return "fallback"


class LogIngestor:
    def __init__(self):
        self._last_analysis = {}
        self._analysis_lock = asyncio.Lock()
        import os
        # 审计状态: OrderedDict 真 LRU,满容逐条淘汰最旧,不再砍最早 20%
        self._audit_status_cache: "OrderedDict[int, dict]" = OrderedDict()
        self._audit_status_cache_max = 10000
        # FastPath 冷却去重:同 src_ip+threat_type 在冷却窗口内只编排一次响应链路
        self._fastpath_cooldown: "OrderedDict[str, float]" = OrderedDict()
        self._fastpath_cooldown_ttl = float(os.environ.get("FASTPATH_COOLDOWN_S", "60"))
        self._fastpath_cooldown_max = 5000

    def _fastpath_allow(self, key: str) -> bool:
        """冷却窗口内首次调用返回 True 并记录时刻；窗口内重复调用返回 False。"""
        now = time.time()
        prev = self._fastpath_cooldown.get(key)
        if prev is not None and now - prev < self._fastpath_cooldown_ttl:
            self._fastpath_cooldown.move_to_end(key)
            return False
        self._fastpath_cooldown[key] = now
        self._fastpath_cooldown.move_to_end(key)
        while len(self._fastpath_cooldown) > self._fastpath_cooldown_max:
            self._fastpath_cooldown.popitem(last=False)
        return True

    async def _index_background(
        self, session_id: str, log_data: dict, event_text: str, is_anomaly: bool,
    ) -> None:
        """记忆树索引 + 滑动窗口写入（后台执行，独立 session）。

        与紧随其后的 Audit-LLM 流水线并行：流水线首轮有多次 LLM 调用，
        索引写入（毫秒级）几乎总是先于工具查询完成，竞态窗口可忽略。
        """
        from models import async_session_bg as db_session
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

    async def _auto_create_case_bg(self, event_id: int) -> None:
        """入流水线前不再同步占用连接; 失败不影响审计。"""
        try:
            from models import async_session as db_session
            from case_manager import case_manager
            async with db_session() as case_session:
                db_evt = await case_session.get(SecurityEvent, event_id)
                if db_evt:
                    await case_manager.auto_create_case(case_session, db_evt)
        except Exception as e:
            logger.debug(f"[Case] audit-pipeline case aggregation skipped: {e}")

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
        """接入一条日志 → 事件驱动流水线 (detect → persist_batch → dispatch)。

        P1 facade: 保留字段归一化 + 数字 severity 映射, 检测/落库/FastPath/
        审计提交收敛到 ingest_pipeline 单实现 (避免 HTTP 回退与 Kafka 双份逻辑)。
        """
        from ingest_pipeline import run_one
        log_data = self._normalize_fields(log_data)
        severity = log_data.get("severity", "info")
        # 兼容数字 severity（如 50 → "medium"）
        if isinstance(severity, (int, float)):
            sev_map = {10: "info", 30: "low", 50: "medium", 70: "high", 90: "critical"}
            severity = sev_map.get(int(severity), "medium")
            log_data["severity"] = severity
        result = await run_one(session, session_id, log_data, ingestor=self)
        return result.as_http_dict()

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
        self._audit_status_cache[event_id] = {
            "status": status,
            "ts": time.time(),
            **extra,
        }
        self._audit_status_cache.move_to_end(event_id)
        while len(self._audit_status_cache) > self._audit_status_cache_max:
            # 优先丢掉已完成/失败,尽量保住 pending/running 的可见性
            dropped = False
            for k, v in list(self._audit_status_cache.items()):
                if v.get("status") not in ("pending", "running"):
                    self._audit_status_cache.pop(k, None)
                    dropped = True
                    break
            if not dropped:
                self._audit_status_cache.popitem(last=False)
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
        agg = {
            "pending": 0, "running": 0, "completed": 0, "failed": 0,
            "skipped": 0, "fallback": 0, "shed": 0, "total": 0,
        }
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
        # 案例自动聚合: 不挡 LLM 准入,后台短租 OLTP 连接
        asyncio.create_task(self._auto_create_case_bg(event_id))

        # ── 审计分流 (LLM 通道分层) ──
        # 废除全局 budget 一刀切: P0 始终可走最小 LLM; 低优降级 tools_only/rule_close
        from audit_triage import (
            score_event, admit, needs_llm, uses_llm_single, uses_temporal,
            lane_max_rounds, lane_timeout_s,
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

        max_rounds = lane_max_rounds(triage.lane, max_rounds)
        timeout_s = lane_timeout_s(triage.tier)

        # ── R-E: 结论缓存 — 同签名(事件类型|src_ip|Sigma规则|级别)命中 → 0 LLM / 0 Temporal ──
        cached = None
        try:
            from audit_cache import get as _cache_get, inc_hit_metric as _cache_inc_hit
            cached = await _cache_get(log_data)
        except Exception as _cache_err:
            logger.debug(f"[Audit-Cache] lookup failed for #{event_id}: {_cache_err}")
        if cached:
            _cache_inc_hit()
            _cached_td = bool(cached.get("threat_detected"))
            _cached_verdict = str(
                cached.get("verdict") or ("suspicious" if _cached_td else "benign")
            )
            _cached_payload = {
                "prompt_version": AUDIT_PROMPT_VERSION,
                "status": "completed",
                "quality": "cache",
                "lane": "cache",
                "completed_by": "cache",
                "cache_hit": True,
                "threat_detected": _cached_td,
                "confidence": max(0.0, min(1.0, float(cached.get("confidence") or 0))),
                "severity": str(
                    cached.get("severity") or log_data.get("severity") or "info"
                ),
                "verdict": _cached_verdict,
                "summary": "结论缓存命中: 复用同签名历史 LLM verdict (0 LLM 调用)",
                "reviewer": {
                    "conclusion": _cached_verdict,
                    "agent": "cache",
                    "notes": "cached verdict reuse",
                },
                "note": "同签名(事件类型|源IP|Sigma规则|级别)缓存命中, 直接复用结论",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            # 先经 _mark_analyzed 落 analyzed/status/metrics(quality=cache),
            # 再合并轻量 verdict 载荷(它保留既有 quality/status)。
            await self._mark_analyzed(event_id, status="completed", quality="cache")
            try:
                from models import async_session as _db_session
                async with _db_session() as _session:
                    _db_evt = await _session.get(SecurityEvent, event_id)
                    if _db_evt:
                        _db_evt.raw_data = {
                            **(dict(_db_evt.raw_data or {})),
                            "_audit_llm": {
                                **(
                                    dict(
                                        (_db_evt.raw_data or {}).get("_audit_llm")
                                        or {}
                                    )
                                ),
                                **_cached_payload,
                            },
                        }
                        await _session.commit()
                        event_store.invalidate(event_id)
            except Exception as _persist_err:
                logger.warning(
                    f"[Audit-Cache] payload persist failed for #{event_id}: {_persist_err}"
                )
            logger.info(
                f"[Audit-Cache] HIT event #{event_id} tier={triage.tier} "
                f"lane={triage.lane} verdict={_cached_verdict}"
            )
            try:
                event_bus.publish("audit_complete", {
                    "event_id": event_id,
                    "quality": "cache",
                    "cache": True,
                    "threat_detected": _cached_td,
                    "confidence": cached.get("confidence"),
                    "severity": _cached_payload["severity"],
                    "verdict": _cached_verdict,
                })
            except Exception:
                pass
            return

        if not needs_llm(triage.lane):
            # tools_only / rule_close: 规则+统计收口,不占 LLM 槽
            reason = f"triage:{triage.lane}:{triage.tier}"
            q = _quality_from_reason(reason, "fallback")
            if any("budget" in str(r) for r in (triage.reasons or [])):
                q = "budget"
                try:
                    event_bus.publish("audit_degraded", {
                        "reason": "budget_exhausted",
                        "event_id": event_id,
                        "tier": triage.tier,
                        "lane": triage.lane,
                    })
                except Exception:
                    pass
            await self._fallback_analysis(
                event_id, log_data, anomaly_report, reason,
            )
            await self._mark_analyzed(
                event_id, error=reason, status="fallback", quality=q,
            )
            return

        # ── llm_single 车道: 本进程 1 次 LLM 快审, 禁止 start_audit_workflow (R-B) ──
        # P1 默认单 hop; 硬预算下 P0 降级到 llm_single 也在此; 其余 needs_llm 但
        # 非 llm_agent 的车道(如未来新增)同样收口到单次快审, 不进 Temporal。
        if uses_llm_single(triage.lane) or (
            needs_llm(triage.lane) and not uses_temporal(triage.lane)
        ):
            try:
                from agents import audit_single
                _single_timeout = float(
                    getattr(_cfg, "audit_llm_single_timeout_s", 15.0) or 15.0
                )
                result = await audit_single.run(
                    event_id=event_id,
                    session_id=session_id,
                    log_data=log_data,
                    anomaly_report=anomaly_report,
                    timeout_s=_single_timeout,
                )
                if not isinstance(result, dict) or result.get("fallback"):
                    raise RuntimeError(
                        str((result or {}).get("error") or "audit_single fallback")
                    )
            except Exception as e:
                logger.warning(
                    f"[Audit-LLM] llm_single failed for #{event_id} "
                    f"tier={triage.tier} lane={triage.lane}: {e}"
                )
                await self._fallback_analysis(
                    event_id, log_data, anomaly_report,
                    f"llm_single:{e}",
                )
                await self._mark_analyzed(
                    event_id, error=f"llm_single:{e}",
                    status="fallback", quality="fallback",
                )
                return
            # 成功: quality=llm / lane=llm_single 落库, 结论写缓存 (R-D)
            await self._mark_analyzed(event_id, status="completed", quality="llm")
            try:
                from models import async_session as _db_session
                async with _db_session() as _session:
                    _db_evt = await _session.get(SecurityEvent, event_id)
                    if _db_evt:
                        _db_evt.raw_data = {
                            **(dict(_db_evt.raw_data or {})),
                            "_audit_llm": {
                                **(dict((_db_evt.raw_data or {}).get("_audit_llm") or {})),
                                **(result or {}),
                            },
                        }
                        await _session.commit()
                        event_store.invalidate(event_id)
            except Exception as _persist_err:
                logger.warning(
                    f"[Audit-LLM] llm_single persist failed for #{event_id}: {_persist_err}"
                )
            try:
                from audit_cache import put as _cache_put
                await _cache_put(log_data, result)
            except Exception as _put_err:
                logger.debug(f"[Audit-Cache] put failed for #{event_id}: {_put_err}")
            logger.info(
                f"[Audit-LLM] llm_single completed #{event_id} "
                f"tier={triage.tier} verdict={result.get('verdict')} "
                f"threat={result.get('threat_detected')} conf={result.get('confidence')}"
            )
            try:
                event_bus.publish("audit_complete", {
                    "event_id": event_id,
                    "quality": "llm",
                    "lane": "llm_single",
                    "threat_detected": result.get("threat_detected"),
                    "confidence": result.get("confidence"),
                    "severity": result.get("severity"),
                    "verdict": result.get("verdict"),
                    "fallback": False,
                })
            except Exception:
                pass
            return

        # ── Temporal 优先(llm_agent 车道): 启动 4 层 Agent 编排 Workflow ──
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
                        from audit_pq import audit_pq, pq_ttl_for_tier
                        ttl = pq_ttl_for_tier(triage.tier)
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
                        event_id, error="shed_load", status="fallback", quality="shed",
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

        # ── 降级兜底: 原 async 编排(按档位超时,不再空占 900s) ──
        try:
            await asyncio.wait_for(
                self._audit_pipeline_inner(
                    session_id, event_id, log_data, anomaly_report, max_rounds,
                    use_fallback_semaphore=_fallback_routed,
                ),
                timeout=max(8.0, timeout_s),
            )
        except asyncio.TimeoutError:
            logger.error(
                f"[Audit-LLM] Pipeline TIMEOUT ({timeout_s:.0f}s) for event #{event_id}"
            )
            await self._mark_analyzed(
                event_id, error="pipeline_timeout", status="failed", quality="fallback",
            )
            await self._fallback_analysis(event_id, log_data, anomaly_report, "timeout")
        except Exception as e:
            logger.error(
                f"[Audit-LLM] Pipeline crashed for event #{event_id}: {e}",
                exc_info=True,
            )
            await self._mark_analyzed(
                event_id, error=str(e), status="failed", quality="fallback",
            )
            await self._fallback_analysis(event_id, log_data, anomaly_report, "crash")

    async def _mark_analyzed(
        self, event_id: int, error: str = "", status: str = "", quality: str = "",
    ):
        """确保事件被标记为已分析（即使管道失败）。

        status: completed | failed | fallback；失败时不得伪装成空成功结果。
        quality: llm | tools | rule | fallback | shed | budget | rate_limited
        """
        cache_status = status or ("failed" if error else "completed")
        if cache_status not in ("completed", "failed", "fallback", "pending", "running", "skipped"):
            cache_status = "failed" if error else "completed"
        q = quality or _quality_from_reason(error, cache_status)
        try:
            self._track_audit_status(event_id, cache_status, error=error, quality=q)
        except Exception as cache_err:
            logger.warning(f"[Audit-LLM] cache status update failed for #{event_id}: {cache_err}")

        try:
            from models import async_session as db_session
            async with db_session() as session:
                db_evt = await session.get(SecurityEvent, event_id)
                if db_evt and not db_evt.analyzed:
                    db_evt.analyzed = True
                    try:
                        from stats_counter import inc_analyzed_done
                    except Exception:
                        pass
                    else:
                        try:
                            await inc_analyzed_done()
                        except Exception:
                            pass
                    raw = dict(db_evt.raw_data or {})
                    audit = dict(raw.get("_audit_llm") or {})
                    if error:
                        raw["_audit_llm_error"] = error
                        audit.setdefault("status", status or "failed")
                        audit["error"] = error
                    elif status:
                        audit["status"] = status
                    audit["quality"] = q
                    raw["_audit_llm"] = audit
                    db_evt.raw_data = raw
                    await session.commit()
                    event_store.invalidate(event_id)
                    try:
                        from metrics import inc_audit_complete
                        _tier = str((audit.get("triage") or {}).get("tier") or "?")
                        inc_audit_complete(q, _tier)
                    except Exception:
                        pass
                    logger.info(
                        f"[Audit-LLM] Event #{event_id} marked analyzed "
                        f"(status={status or ('failed' if error else 'completed')}, "
                        f"quality={q}, error={error})"
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
            q = _quality_from_reason(reason, "fallback")
            fallback_result = {
                "prompt_version": AUDIT_PROMPT_VERSION,
                "status": "fallback",
                "fallback": True,
                "quality": q,
                "completed_by": "fallback",
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
                    try:
                        from stats_counter import inc_analyzed_done
                    except Exception:
                        pass
                    else:
                        try:
                            await inc_analyzed_done()
                        except Exception:
                            pass
                    db_evt.raw_data = {
                        **(db_evt.raw_data or {}),
                        "_audit_llm": fallback_result,
                        "_audit_llm_error": reason,
                    }
                    await session.commit()
                    event_store.invalidate(event_id)
            logger.info(
                f"[Audit-LLM] Fallback analysis for #{event_id}: "
                f"threat={threat_detected} reason={reason} quality={q}"
            )
            try:
                event_bus.publish("audit_complete", {
                    "event_id": event_id,
                    "quality": q,
                    "fallback": True,
                    "reason": reason,
                    "threat_detected": threat_detected,
                })
            except Exception:
                pass
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
        # Slot 由 AuditWorkerPool / Temporal activity 提供,不再叠 Semaphore。
        self._track_audit_status(event_id, "running", use_fallback=use_fallback_semaphore)
        if True:
            from agents import decomposer, tool_builder, executor, reviewer
            from agents.agent_cad import cad_agent
            from models import async_session as db_session
            from trace_hook import set_trace_context, clear_trace_context

            set_trace_context(
                caller="audit_pipeline",
                event_id=event_id,
                session_id=session_id,
                log_data=log_data,
            )
            from observability.thought_events import (
                attach_to_audit,
                emit_cad,
                emit_executor,
                emit_plan,
                emit_rag_chunks,
                emit_response,
                emit_review,
                emit_signals,
                emit_tool_map,
            )
            emit_signals(log_data, event_id=event_id, session_id=session_id)

            t_start = time.time()
            if True:
                all_rounds = []        # 所有轮次结果
                missed_threats = []    # 上轮的遗漏
                final_verdict = None
                final_audit = None

                try:
                    for round_num in range(1, max_rounds + 1):
                        mode = "supplement" if round_num > 1 else "full"
                        set_trace_context(round=round_num)
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
                        emit_plan(
                            decomp_output,
                            event_id=event_id, session_id=session_id, round_num=round_num,
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
                        emit_tool_map(
                            sub_tasks, tool_calls,
                            event_id=event_id, session_id=session_id, round_num=round_num,
                        )

                        # ── Layer 3: Executor ──
                        with pipeline_tracer.span("executor", event_id=event_id, session_id=session_id):
                            audit_result = await executor.execute(
                                tool_calls=tool_calls,
                                session=None,
                                session_id=session_id,
                                raw_event=log_data,
                                depth=depth,
                            )
                        emit_rag_chunks(
                            audit_result,
                            event_id=event_id, session_id=session_id, round_num=round_num,
                        )
                        emit_executor(
                            audit_result,
                            event_id=event_id, session_id=session_id, round_num=round_num,
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
                        emit_review(
                            verdict,
                            event_id=event_id, session_id=session_id, round_num=round_num,
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

                    await self._persist_audit_result(
                        event_id=event_id,
                        session_id=session_id,
                        log_data=log_data,
                        all_rounds=all_rounds,
                        merged=merged,
                        final_audit=final_audit,
                        final_verdict=final_verdict,
                        max_rounds=max_rounds,
                        t_start=t_start,
                    )

                except Exception as e:
                    logger.error(
                        f"[Audit-LLM] Pipeline failed for event #{event_id}: {e}",
                        exc_info=True,
                    )
                    await self._mark_analyzed(
                        event_id, error=str(e), status="failed", quality="fallback",
                    )
                    await self._fallback_analysis(event_id, log_data, anomaly_report, str(e))
                finally:
                    # 防止 trace context 泄漏: 同任务内后续辅助 LLM 调用
                    # (watchdog/post_mortem/rerank 等) 不会继承本事件的 event_id
                    clear_trace_context()

    async def _persist_audit_result(
        self,
        *,
        event_id: int,
        session_id: str,
        log_data: dict,
        all_rounds: list,
        merged: dict,
        final_audit,
        final_verdict,
        max_rounds: int,
        t_start: float,
    ) -> None:
        """LLM 全部结束后短租连接写库 + CAD + 响应触发。"""
        from agents.agent_cad import cad_agent
        from models import async_session as db_session
        from observability.thought_events import attach_to_audit, emit_cad, emit_response
        from observability.thought_events import snapshot as thought_snapshot

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
        payload = attach_to_audit({
            "prompt_version": AUDIT_PROMPT_VERSION,
            "status": "completed",
            "quality": "llm",
            "completed_by": "worker",
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
                (final_audit.to_dict().get("hop_trace") if final_audit else None) or []
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
        }, event_id)

        async with db_session() as session:
            db_evt = await session.get(SecurityEvent, event_id)
            if db_evt:
                db_evt.analyzed = True
                try:
                    from stats_counter import inc_analyzed_done
                    await inc_analyzed_done()
                except Exception:
                    pass
                db_evt.raw_data = {**(db_evt.raw_data or {}), "_audit_llm": payload}
                await session.commit()
                event_store.invalidate(event_id)
                try:
                    with pipeline_tracer.span("cad_verify", event_id=event_id, session_id=session_id):
                        cad_report = await cad_agent.audit_pipeline(
                            session, event_id, db_evt.raw_data["_audit_llm"]
                        )
                    emit_cad(cad_report, event_id=event_id, session_id=session_id)
                    from observability.thought_events import merge_thought_into_raw, snapshot
                    db_evt.raw_data = merge_thought_into_raw({
                        **(db_evt.raw_data or {}),
                        "_cad_audit": {
                            "penetrating_verification": cad_report["penetrating_verification"],
                            "circuit_breaker": cad_report["circuit_breaker"],
                            "audit_timestamp": cad_report["audit_timestamp"],
                            "duration_ms": cad_report["duration_ms"],
                        },
                    }, snapshot(event_id))
                    await session.commit()
                    if cad_report["circuit_breaker"]["tripped"]:
                        logger.critical(
                            f"[CAD] CIRCUIT BREAKER for event #{event_id}: "
                            f"{cad_report['circuit_breaker']['reason']}"
                        )
                except Exception as cad_err:
                    logger.warning(f"[CAD] audit_pipeline failed: {cad_err}")

        self._track_audit_status(event_id, "completed", quality="llm")
        try:
            from metrics import inc_audit_complete
            _tier = str(((log_data or {}).get("_audit_triage") or {}).get("tier") or "?")
            inc_audit_complete("llm", _tier)
        except Exception:
            pass

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
            "thought_count": len(thought_snapshot(event_id)),
            "severity": merged.get("severity", "info"),
            "rounds": len(all_rounds),
            "duration_s": round(duration, 1),
            "src_ip": log_data.get("src_ip", ""),
            "quality": "llm",
            "stage": "pipeline_complete",
            "agent_id": "reviewer",
            "agents_completed": ["decomposer", "tool_builder", "executor", "reviewer"],
        })

        _verdict = merged.get("verdict")
        if merged.get("response_blocked"):
            emit_response(
                {
                    "event_id": event_id,
                    "status": "blocked",
                    "reason": "faithfulness / 否决闸阻止自动响应",
                    "threat_type": merged.get("threat_type") or "",
                    "confidence": merged.get("confidence", 0),
                },
                event_id=event_id, session_id=session_id,
            )
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
                    "response_source": "audit_llm",
                    "allow_blocking": True,
                }

                async def _audit_response(threat_info: dict, evt_id: int, sid: str):
                    from models import async_session as db_s
                    async with db_s() as s:
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
                emit_response(
                    {
                        "event_id": event_id,
                        "status": "triggered",
                        "threat_type": threat_info["threat_type"],
                        "confidence": threat_info["confidence"],
                    },
                    event_id=event_id, session_id=session_id,
                )
            except Exception as resp_err:
                logger.warning(f"[Response] Trigger setup failed for event #{event_id}: {resp_err}")

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
        """Batch ingest.

        sqlite / 单条: 串行 ingest, 复用调用方 session (内存库测试语义)。
        其它: ingest_pipeline.run_many (detect 并行 + store_batch 单事务)。
        """
        _url = str(getattr(settings, "database_url", "") or "")
        _sqlite = _url.startswith("sqlite")
        if _sqlite or len(logs) <= 1:
            results = []
            for log_data in logs:
                results.append(await self.ingest(session, session_id, log_data))
            return {"status": "batch_ingested", "count": len(results),
                    "session_id": session_id}

        # P1: 非 sqlite 多事件 → 事件驱动流水线 (detect 全批并行 + store_batch 单事务,
        # 单 session 单 commit); sqlite/单条路径走串行 ingest 保留测试语义
        from ingest_pipeline import run_many
        await run_many(session, [(session_id, d) for d in logs], ingestor=self)
        return {"status": "batch_ingested", "count": len(logs),
                "session_id": session_id}

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
