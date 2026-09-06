"""Self-Play SSE 事件。"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def publish(event_type: str, data: dict[str, Any]) -> None:
    try:
        from event_bus import event_bus
        event_bus.publish(event_type, data)
    except Exception as e:
        logger.debug("[self_play] sse skipped: %s", e)
