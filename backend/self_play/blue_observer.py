"""观察蓝队对红队仿真事件的响应。

默认用 Sigma + overlay(学到的规则)即时评分,不阻塞 Audit-LLM。
inject=True 时把事件送进现有 ingest → Decomposer→Executor→Reviewer。
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from self_play.overlay import overlay
from self_play.types import EventObservation, MaterializedEvent

logger = logging.getLogger(__name__)


def _sigma_detect(event: dict) -> dict:
    try:
        from sigma_detector import sigma_detector
        return sigma_detector.detect_for_event(event) or {}
    except Exception as e:
        logger.debug("[BlueObserver] sigma skipped: %s", e)
        return {"detected": False, "hits": []}


class BlueObserver:
    async def observe_one(
        self,
        match_id: str,
        evt: MaterializedEvent,
        *,
        inject: bool = False,
        session_id: str = "",
        wait_audit: bool = False,
        wait_audit_s: float = 8.0,
        eval_channel: str = "sim",
    ) -> EventObservation:
        channel = str(eval_channel or "sim")
        log = evt.to_log()
        t0 = evt.injected_at or time.time()
        sigma = _sigma_detect(log)
        # P1-B/P4-C: 评分只认 overlay/shadow/promoted/production;candidate 仅评估
        over = overlay.detect_scoring(match_id, log)
        cand = overlay.detect_candidates(match_id, log)
        obs = EventObservation()
        obs.eval_channel = channel

        if sigma.get("detected"):
            obs.detected = True
            obs.detector = "sigma"
            hits = sigma.get("hits") or []
            obs.rule_ids = [
                str(h.get("rule_id") or h.get("id") or "")
                for h in hits if isinstance(h, dict)
            ]
            obs.attack_types = list(sigma.get("attack_types") or [])
            obs.detected_at = time.time()
            obs.mttd_ms = max(0.0, (obs.detected_at - t0) * 1000.0)
        if over.get("detected"):
            # overlay 命中视为蓝队已从自博弈中学会;覆盖 detector 标签以便 compounding 统计
            if not obs.detected:
                obs.detected = True
                obs.detected_at = time.time()
                obs.mttd_ms = max(0.0, (obs.detected_at - t0) * 1000.0)
            obs.detector = "overlay" if obs.detector != "sigma" else "sigma+overlay"
            obs.rule_ids = list(dict.fromkeys(obs.rule_ids + list(over.get("rule_ids") or [])))
            obs.attack_types = list(dict.fromkeys(obs.attack_types + list(over.get("attack_types") or [])))
        # candidate 命中只进评估通道,绝不计入 obs.detected
        if cand.get("detected"):
            obs.candidate_detected = True
            obs.candidate_rule_ids = list(cand.get("rule_ids") or [])

        if inject:
            stored_id = await self._inject(log, session_id or f"selfplay-{match_id}")
            obs.event_id = int(stored_id or 0)
            if wait_audit and stored_id:
                audit = await self._wait_audit(int(stored_id), wait_audit_s)
                if audit:
                    obs.verdict = str(audit.get("verdict") or audit.get("conclusion") or "")
                    try:
                        obs.confidence = float(audit.get("confidence") or 0.0)
                    except (TypeError, ValueError):
                        obs.confidence = 0.0
                    threat = bool(audit.get("threat_detected"))
                    conclusion = obs.verdict.lower()
                    if threat or conclusion in ("confirmed", "suspicious"):
                        # audit 命中单独记录,默认(sim 通道)不混进 TP/FN
                        obs.audit_detected = True
                        if channel == "audit" and not obs.detected:
                            obs.detected = True
                            obs.detector = "audit_llm"
                            obs.detected_at = time.time()
                            obs.mttd_ms = max(0.0, (obs.detected_at - t0) * 1000.0)
        if obs.detected and not obs.detected_at:
            obs.detected_at = time.time()
            obs.mttd_ms = max(0.0, (obs.detected_at - t0) * 1000.0)
        return obs

    async def observe_many(
        self,
        match_id: str,
        events: list[MaterializedEvent],
        **kwargs: Any,
    ) -> list[EventObservation]:
        out: list[EventObservation] = []
        for evt in events:
            out.append(await self.observe_one(match_id, evt, **kwargs))
        return out

    async def _inject(self, log: dict, session_id: str) -> int:
        from models import async_session
        from log_ingestion import log_ingestor
        async with async_session() as session:
            result = await log_ingestor.ingest(session, session_id, log)
        return int((result or {}).get("event_id") or 0)

    async def _wait_audit(self, event_id: int, timeout_s: float) -> Optional[dict]:
        import asyncio
        from models import SecurityEvent, async_session

        deadline = time.time() + max(0.2, float(timeout_s or 0))
        while time.time() < deadline:
            async with async_session() as session:
                row = await session.get(SecurityEvent, event_id)
                if row is not None and bool(getattr(row, "analyzed", False)):
                    raw = row.raw_data if isinstance(row.raw_data, dict) else {}
                    audit = raw.get("_audit_llm") or raw.get("audit_llm") or {}
                    merged = audit.get("merged") if isinstance(audit, dict) else {}
                    if isinstance(merged, dict) and merged:
                        return merged
                    if isinstance(audit, dict):
                        return audit
                    return {"analyzed": True}
            await asyncio.sleep(0.25)
        return None
