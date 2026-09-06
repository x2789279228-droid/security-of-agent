"""In-process event-driven ingest pipeline (Phase 1 contract).

North-star topology (same process, Kafka as buffer — not new microservices):

    HTTP ──validate/sanitize──► Kafka(security-events-ingest) ──202
                                      │
                                      ▼
                               detect (anomaly ∥ sigma, isolated)
                                      │
                                      ▼
                               persist (batch PG commit)
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              FastPath (async)   AuditWorker      event_bus
              强信号可封禁        P0/P1 never-drop

This module is the single owner of detect / persist_batch / dispatch.
`log_ingestion.LogIngestor.ingest` is a thin facade for the single-event path.
Kafka python-ingest consumer uses `run_many` for the batch path.

See: docs/upgrade-proposals/2026-q3-ingest-event-driven.md
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError

from anomaly_detector import AnomalyReport, anomaly_detector
from config import settings
from event_store import event_store

logger = logging.getLogger(__name__)

# 数字 severity → 枚举 (与 log_ingestion.ingest facade 保持一致)
_SEV_MAP = {10: "info", 30: "low", 50: "medium", 70: "high", 90: "critical"}

# Sigma 命中抬升异常分的下限 (与 log_ingestion.ingest EXACT 同源, 禁止改)
_SIGMA_FLOORS = {
    "critical": 0.75, "high": 0.65, "medium": 0.55, "low": 0.45,
}
_SIGMA_FLOOR_DEFAULT = 0.55


@dataclass
class DetectorError:
    detector: str          # "anomaly" | "sigma"
    message: str


@dataclass
class DetectResult:
    """Per-event detection output. Always returned; detector crashes do not abort ingest."""
    log_data: dict
    anomaly: AnomalyReport
    sigma: dict
    detect_ms: float = 0.0
    errors: list[DetectorError] = field(default_factory=list)


@dataclass
class PersistItem:
    session_id: str
    log_data: dict
    anomaly_score: float = 0.0
    correlation_id: str = ""


@dataclass
class PersistResult:
    stored: Any            # event_store.StoredEvent
    log_data: dict
    anomaly: AnomalyReport
    session_id: str
    persist_ms: float = 0.0
    idempotent: bool = False


@dataclass
class DispatchResult:
    event_id: int
    fastpath: bool = False
    audit_accepted: str = ""   # queued | shed | overflow | deferred | direct
    dispatch_ms: float = 0.0


@dataclass
class RunResult:
    """HTTP/sync facade payload (single event)."""
    status: str
    event_id: int
    event_type: str
    severity: str
    anomaly: dict
    sigma: dict
    detect_ms: float = 0.0
    persist_ms: float = 0.0
    dispatch_ms: float = 0.0
    detector_errors: list[str] = field(default_factory=list)

    def as_http_dict(self) -> dict:
        return {
            "status": self.status,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "anomaly": self.anomaly,
            "sigma": self.sigma,
        }


def empty_anomaly(reasons: Optional[list[str]] = None) -> AnomalyReport:
    return AnomalyReport(
        event_id=0,
        anomaly_score=0.0,
        is_anomaly=False,
        deviation_sigma=0.0,
        reasons=list(reasons or []),
    )


def empty_sigma() -> dict:
    return {"detected": False, "rule_count": 0, "attack_types": [], "max_severity": "", "hits": []}


# ── 内部 helpers ──

def _ingestor(ingestor: Any):
    """解析调用方传入的 LogIngestor; None → 进程内单例 (懒 import 防循环)。"""
    if ingestor is None:
        from log_ingestion import log_ingestor
        return log_ingestor
    return ingestor


def _normalize_event(log_data: dict) -> dict:
    """字段归一化 + 数字 severity 映射 (与 LogIngestor.ingest facade 同语义)。

    单事件路径的 facade 已归一化; Kafka 批量路径直接进 run_many,
    必须在这里补齐归一化, 否则检测器/FastPath 看到 camelCase/数字 severity。
    归一化幂等, 双重调用无副作用。
    """
    from log_ingestion import log_ingestor
    normalized = log_ingestor._normalize_fields(log_data)
    severity = normalized.get("severity", "info")
    if isinstance(severity, (int, float)):
        severity = _SEV_MAP.get(int(severity), "medium")
        normalized["severity"] = severity
    return normalized


def _anomaly_payload(report: AnomalyReport) -> dict:
    """HTTP facade 返回的 anomaly 子对象 (与旧 ingest 返回一致)。"""
    return {
        "score": report.anomaly_score,
        "is_anomaly": bool(report.is_anomaly),
        "reasons": list(report.reasons or []),
    }


def _build_run_result(log_data: dict, persist: PersistResult, dispatch_res: DispatchResult,
                      detect_ms: float = 0.0, errors: Optional[list[str]] = None) -> RunResult:
    return RunResult(
        status="review_queued",
        event_id=persist.stored.id,
        event_type=log_data.get("event", log_data.get("type", "UNKNOWN")),
        severity=log_data.get("severity", "info"),
        anomaly=_anomaly_payload(persist.anomaly),
        sigma=log_data.get("_sigma", {"detected": False}),
        detect_ms=detect_ms,
        persist_ms=persist.persist_ms,
        dispatch_ms=dispatch_res.dispatch_ms,
        detector_errors=list(errors or []),
    )


# ── Public API ──

async def detect(log_data: dict) -> DetectResult:
    """Run anomaly + sigma with isolation.

    Rules:
      - Never raise to the caller. Detector exceptions become DetectorError.
      - When settings.ingest_parallel_detect: asyncio.gather both.
      - Fuse Sigma hit into anomaly score using the SAME floors as
        log_ingestion.ingest (critical=0.75, high=0.65, medium=0.55, low=0.45).
      - Write fused `_anomaly` and `_sigma` onto log_data (in-place) so FastPath
        and audit_triage keep working.
      - Record detect_ms.
    """
    t0 = time.perf_counter()
    errors: list[DetectorError] = []
    anomaly_report: AnomalyReport = None
    sigma_result: dict = None

    async def _run_anomaly():
        nonlocal anomaly_report, errors
        try:
            report = await anomaly_detector.analyze(log_data)
        except Exception as e:  # 隔离: 检测器崩溃不拖垮 ingest
            logger.warning(f"[Pipeline] anomaly detection failed: {e}")
            errors.append(DetectorError(detector="anomaly", message=str(e)))
            report = empty_anomaly(reasons=["anomaly_error"])
        anomaly_report = report

    async def _run_sigma():
        nonlocal sigma_result, errors
        try:
            from sigma_detector import sigma_detector  # 懒 import: pySigma 构建失败也隔离
            result = sigma_detector.detect_for_event(log_data)
        except Exception as e:
            logger.warning(f"[Pipeline] sigma detection failed: {e}")
            errors.append(DetectorError(detector="sigma", message=str(e)))
            result = empty_sigma()
        sigma_result = result

    if bool(getattr(settings, "ingest_parallel_detect", True)):
        await asyncio.gather(_run_anomaly(), _run_sigma())
    else:
        # 顺序路径 (可测): 先 anomaly 后 sigma, 与旧 log_ingestion.ingest 一致
        await _run_anomaly()
        await _run_sigma()

    # ── Sigma 命中融合 (与旧 log_ingestion.ingest 逐字段同源) ──
    if anomaly_report is None:
        anomaly_report = empty_anomaly(reasons=["anomaly_error"])
        errors.append(DetectorError(detector="anomaly", message="no_result"))
    if sigma_result is None:
        sigma_result = empty_sigma()
        errors.append(DetectorError(detector="sigma", message="no_result"))

    if sigma_result.get("detected"):
        event_type = log_data.get("event", log_data.get("type", "UNKNOWN"))
        logger.info(
            f"[Sigma] {event_type}: {sigma_result.get('rule_count')} rules hit, "
            f"types={sigma_result.get('attack_types')}, "
            f"severity={sigma_result.get('max_severity')}"
        )
        sev_floor = _SIGMA_FLOORS.get(
            str(sigma_result.get("max_severity") or "").lower(), _SIGMA_FLOOR_DEFAULT,
        )
        if anomaly_report.anomaly_score < sev_floor:
            anomaly_report.anomaly_score = sev_floor
        anomaly_report.is_anomaly = True
        if "sigma_hit" not in (anomaly_report.reasons or []):
            anomaly_report.reasons = list(anomaly_report.reasons or []) + [
                f"Sigma命中:{','.join(sigma_result.get('attack_types') or [])}"
            ]

    # 融合结果写回 log_data (in-place), FastPath / audit_triage / persist 同源读取
    log_data["_anomaly"] = {
        "score": anomaly_report.anomaly_score,
        "is_anomaly": anomaly_report.is_anomaly,
        "reasons": anomaly_report.reasons,
        "sigma": anomaly_report.deviation_sigma,
    }
    log_data["_sigma"] = sigma_result

    detect_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage, inc_detector_error
        observe_ingest_stage("detect", detect_ms / 1000.0)
        for err in errors:
            inc_detector_error(err.detector)
    except Exception:
        pass
    return DetectResult(
        log_data=log_data, anomaly=anomaly_report, sigma=sigma_result,
        detect_ms=detect_ms, errors=errors,
    )


async def persist_batch(session, items: list[tuple[DetectResult, str]]) -> list[PersistResult]:
    """Batch-insert DetectResults.

    items: list of (DetectResult, session_id)
    Must call event_store.store_batch (single commit). On IntegrityError, fall
    back to per-item event_store.store. Preserve eventId idempotency.
    Empty items → [].
    """
    if not items:
        return []
    t0 = time.perf_counter()
    rows = []
    for dr, session_id in items:
        rows.append((
            dr.log_data,
            session_id,
            float(dr.anomaly.anomaly_score or 0.0),
            dr.log_data.get("correlation_id", "") or "",
        ))
    try:
        stored_list = await event_store.store_batch(session, rows)
    except IntegrityError:
        # store_batch 内部已 rollback + 逐条回退; 这里双保险不丢已成功行
        logger.warning("[Pipeline] store_batch raised IntegrityError — per-item store() fallback")
        stored_list = []
        for event_data, session_id, anomaly_score, correlation_id in rows:
            stored_list.append(await event_store.store(
                session, event_data, session_id,
                anomaly_score=anomaly_score, correlation_id=correlation_id,
            ))
    persist_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage
        observe_ingest_stage("persist", persist_ms / 1000.0)
    except Exception:
        pass
    results = []
    for (dr, session_id), stored in zip(items, stored_list):
        results.append(PersistResult(
            stored=stored, log_data=dr.log_data, anomaly=dr.anomaly,
            session_id=session_id, persist_ms=persist_ms,
        ))
    return results


async def dispatch(
    session_id: str,
    persist: PersistResult,
    *,
    ingestor: Any = None,
) -> DispatchResult:
    """Index background + FastPath (create_task, retries) + audit_worker.submit + event_bus.

    FastPath trigger/cooldown/dual-track (allow_blocking) MUST match current
    log_ingestion.ingest semantics. Retry on_threat_detected up to
    settings.ingest_fastpath_retries. Do not await SSH.
    """
    t0 = time.perf_counter()
    ingestor = _ingestor(ingestor)
    stored = persist.stored
    log_data = persist.log_data
    anomaly_report = persist.anomaly
    event_type = log_data.get("event", log_data.get("type", "UNKNOWN"))
    severity = log_data.get("severity", "info")
    fastpath_triggered = False
    audit_accepted = ""

    # 2b. 记忆树索引 + 滑动窗口 → 后台执行 (不阻塞 ingest 返回)
    event_text = json.dumps(log_data, ensure_ascii=False)
    try:
        asyncio.create_task(ingestor._index_background(
            session_id, log_data, event_text, bool(anomaly_report.is_anomaly),
        ))
    except Exception as ie:
        logger.warning(f"[Pipeline] index background task spawn failed: {ie}")

    # 3. 快速响应: 异常分数极高 / severity=critical / Sigma 命中 critical → create_task
    #    (语义逐行迁移自 log_ingestion.ingest; FastPath 只此一份实现)
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
    # 冷却去重: 同源(源IP+威胁类型)事件在窗口内不重复编排响应链路
    _fp_key = f"{log_data.get('src_ip', '')}|{log_data.get('threat_type') or event_type}"
    if _fp_trigger and not ingestor._fastpath_allow(_fp_key):
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
            #   仅 severity=critical(无检测器佐证) → 仅告警, 封禁等 Audit-LLM confirmed
            _strong_signal = bool(
                (sigma_info.get("detected") and sigma_info.get("max_severity") == "critical")
                or _fused_conf >= 0.7
            )
            # v5 修复:不再把 low/info 抬成 high。未知级别下限取 medium
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
                "response_source": (
                    "fastpath_strong" if _strong_signal else "fastpath_severity"
                ),
                "allow_blocking": _strong_signal,
            }
            # P1-H: 失败按 ingest_fastpath_retries 重试后打日志; create_task → ingest/run_many
            # 不等待 SSH/响应编排
            _fp_retries = max(0, int(getattr(settings, "ingest_fastpath_retries", 2) or 0))

            # 独立 session 后台执行, 避免与请求 session 并发冲突
            async def _fast_response(threat_info: dict, evt_id: int, sid: str):
                from models import async_session as db_session
                attempts = _fp_retries + 1
                for attempt in range(attempts):
                    try:
                        async with db_session() as s:
                            await _resp_orch.on_threat_detected(
                                session=s, threat_info=threat_info,
                                event_id=evt_id, session_id=sid,
                                allow_blocking=bool(threat_info.get("allow_blocking", True)),
                            )
                        return
                    except Exception as fp_err:
                        logger.warning(
                            f"[FastPath] Quick response attempt {attempt + 1}/{attempts} "
                            f"failed for event #{evt_id}: {fp_err}"
                        )
                        if attempt + 1 < attempts:
                            await asyncio.sleep(0.2)
                logger.error(
                    f"[FastPath] Quick response failed after {attempts} attempts "
                    f"for event #{evt_id}"
                )

            asyncio.create_task(_fast_response(fast_threat, stored.id, session_id))
            fastpath_triggered = True
            logger.warning(
                f"[FastPath] Quick response triggered for event #{stored.id}: "
                f"score={anomaly_report.anomaly_score:.2f} "
                f"mode={'strong(block-capable)' if _strong_signal else 'severity(alert-only)'}"
            )
        except Exception as fp_err:
            logger.warning(f"[FastPath] Quick response setup failed: {fp_err}")

    # 4. Audit-LLM 流水线 (有界 worker,禁止无界 create_task)
    ingestor._track_audit_status(stored.id, "pending", event_type=event_type)
    from audit_worker import audit_worker
    audit_accepted = await audit_worker.submit(
        session_id=session_id,
        event_id=stored.id,
        log_data=log_data,
        anomaly_report=anomaly_report,
    )
    if audit_accepted == "overflow":
        await ingestor._fallback_analysis(
            stored.id, log_data, anomaly_report, "queue_overflow",
        )
        await ingestor._mark_analyzed(
            stored.id, error="queue_overflow", status="fallback", quality="shed",
        )
    elif audit_accepted == "shed":
        ingestor._track_audit_status(
            stored.id, "pending", queued="audit_pq",
        )
    elif audit_accepted == "deferred":
        ingestor._track_audit_status(
            stored.id, "pending", queued="audit_overflow",
        )

    _publish_security_event(stored.id, event_type, severity, log_data, anomaly_report)

    dispatch_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage
        observe_ingest_stage("dispatch", dispatch_ms / 1000.0)
    except Exception:
        pass
    return DispatchResult(
        event_id=stored.id,
        fastpath=fastpath_triggered,
        audit_accepted=audit_accepted or "",
        dispatch_ms=dispatch_ms,
    )


def _publish_security_event(event_id: int, event_type: str, severity: str,
                             log_data: dict, anomaly_report: AnomalyReport) -> None:
    """security_event 总线广播 (同步, 与旧 ingest 相同载荷)。"""
    try:
        from event_bus import event_bus
        event_bus.publish("security_event", {
            "event_id": event_id,
            "event_type": event_type,
            "severity": severity,
            "src_ip": log_data.get("src_ip", ""),
            "dst_ip": log_data.get("dst_ip", ""),
            "message": log_data.get("message", "")[:100],
            "anomaly_score": anomaly_report.anomaly_score,
            "is_anomaly": anomaly_report.is_anomaly,
        })
    except Exception as eb_err:
        logger.warning(f"[Pipeline] event_bus publish failed: {eb_err}")


async def run_one(session, session_id: str, log_data: dict, *, ingestor: Any = None) -> RunResult:
    """Single-event path: detect → persist_batch([one]) → dispatch.

    Used by LogIngestor.ingest (HTTP sync fallback and any one-shot caller).
    """
    log_data = _normalize_event(log_data)
    dr = await detect(log_data)
    persists = await persist_batch(session, [(dr, session_id)])
    persist = persists[0]
    dispatch_res = await dispatch(session_id, persist, ingestor=ingestor)
    return _build_run_result(
        log_data, persist, dispatch_res,
        detect_ms=dr.detect_ms,
        errors=[f"{e.detector}:{e.message}" for e in dr.errors],
    )


async def run_many(
    session,
    events: list[tuple[str, dict]],
    *,
    ingestor: Any = None,
) -> list[RunResult]:
    """Batch path for Kafka python-ingest: detect all (gather) → persist_batch → dispatch each.

    events: list of (session_id, log_data)
    One DB session / one commit for the batch. Dispatch is per-event and must
    not fail the batch if FastPath/audit submit raises (log + continue).
    """
    prepped = [(sid, _normalize_event(d)) for sid, d in events]
    detected = await asyncio.gather(*(detect(d) for _, d in prepped))
    items = [(dr, sid) for (sid, _d), dr in zip(prepped, detected)]
    persists = await persist_batch(session, items)

    results: list[RunResult] = []
    for (sid, _d), persist, dr in zip(prepped, persists, detected):
        try:
            dispatch_res = await dispatch(sid, persist, ingestor=ingestor)
        except Exception as e:
            # dispatch 异常不拖垮整批: 事件已落库, 记日志继续
            logger.error(
                f"[Pipeline] dispatch failed for event #{persist.stored.id} "
                f"(session={sid}): {e}", exc_info=True,
            )
            dispatch_res = DispatchResult(event_id=persist.stored.id)
        results.append(_build_run_result(
            persist.log_data, persist, dispatch_res,
            detect_ms=dr.detect_ms,
            errors=[f"{e.detector}:{e.message}" for e in dr.errors],
        ))
    return results
