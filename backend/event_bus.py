"""
实时事件总线 — 用于 SSE 推送

各模块通过 publish() 发布事件，SSE 端点通过 subscribe() 接收。
基于 asyncio.Queue，支持多个并发订阅者。
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BusEvent:
    type: str           # "security_event" | "audit_complete" | "response_action" | "alert" | "status"
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_sse(self) -> dict:
        return {
            "event": self.type,
            "data": json.dumps({
                **self.data,
                "_ts": self.timestamp,
            }, ensure_ascii=False),
        }


class EventBus:
    def __init__(self, max_subscribers: int = 20):
        self._subscribers: list[asyncio.Queue] = []
        self._max = max_subscribers
        self._history: list[BusEvent] = []
        self._history_max = 200

    def publish(self, event_type: str, data: dict):
        evt = BusEvent(type=event_type, data=data)
        self._history.append(evt)
        if len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.remove(q)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        if len(self._subscribers) >= self._max:
            self._subscribers.pop(0)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    def recent(self, limit: int = 50) -> list[dict]:
        return [e.to_sse() for e in self._history[-limit:]]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


event_bus = EventBus()
