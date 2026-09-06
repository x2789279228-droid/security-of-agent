"""可选演示流量 — 仅仿真事件，打 _demo，默认不启用。"""
from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

DEMO_EVENT: dict[str, Any] = {
    "event": "C2_BEACON",
    "severity": "critical",
    "src_ip": "192.168.1.105",
    "dst_ip": "23.129.64.33",
    "message": "演示审查：内部主机疑似与C2服务器通信",
    "confidence": 85,
    "_demo": True,
}


async def inject_demo_event(session, session_id: str = "") -> dict:
    """把一条带 _demo 的仿真日志送进 ingest。不写生产 Sigma。"""
    from log_ingestion import log_ingestor

    sid = session_id or f"demo-monitor-{uuid.uuid4().hex[:8]}"
    result = await log_ingestor.ingest(session, sid, dict(DEMO_EVENT))
    out = {"session_id": sid, **(result or {})}
    logger.info("[DemoTraffic] ingested event_id=%s session=%s", out.get("event_id"), sid)
    return out
