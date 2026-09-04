"""
实时事件总线 — 用于 SSE 推送

各模块通过 publish() 发布事件，SSE 端点通过 subscribe() 接收。
基于 asyncio.Queue，支持多个并发订阅者。

跨进程(Temporal worker → FastAPI):
  接入 Redis 后 publish() 同时 PUBLISH 到 soc:event_bus;
  backend start_redis_bridge() 订阅后注入本进程订阅者。
  没有 Redis 时行为与原先纯内存总线一致。
"""
import asyncio
import itertools
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 进程纪元：用于客户端识别服务端重启导致的 seq 重置
BOOT_TS = time.time()
REDIS_CHANNEL = "soc:event_bus"


@dataclass
class BusEvent:
    seq: int = 0        # 全局递增序号，publish() 时赋值；作为 SSE id 行供断线续传
    type: str = ""      # "security_event" | "audit_complete" | "response_action" | "alert" | "pipeline_health" | ...
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_sse(self) -> dict:
        return {
            "event": self.type,
            "id": str(self.seq),
            "data": json.dumps({
                **self.data,
                "_seq": self.seq,
                "_ts": self.timestamp,
            }, ensure_ascii=False),
        }


class EventBus:
    def __init__(self, max_subscribers: int = 100):
        self._subscribers: list[asyncio.Queue] = []
        self._max = max_subscribers
        self._history: list[BusEvent] = []
        # agent_stage 使单事件约 +12 条，提高到 500 保证断线续传仍能看到接力过程
        self._history_max = 500
        self._seq = itertools.count(1)
        self._redis = None
        self._bridge_task: Optional[asyncio.Task] = None
        self._origin_id = uuid.uuid4().hex[:12]
        # 订阅队列上限：慢消费者在此积压，满则被 publish 丢弃移除（由前端 ping-seq 检测兜底）
        self._queue_max = int(os.environ.get("EVENT_BUS_QUEUE_MAX", "500"))

    def set_redis(self, redis_client) -> None:
        """接入 Redis，启用跨进程事件广播(Temporal worker → backend SSE)。"""
        self._redis = redis_client
        logger.info("EventBus: Redis bridge enabled (channel=%s)", REDIS_CHANNEL)

    def publish(self, event_type: str, data: dict, *, _from_redis: bool = False):
        evt = BusEvent(seq=next(self._seq), type=event_type, data=data)
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

        # 本进程产生的事件广播到 Redis; 从 Redis 回流的不再二次广播
        if not _from_redis and self._redis is not None:
            self._broadcast_redis(event_type, data)

    def _broadcast_redis(self, event_type: str, data: dict) -> None:
        try:
            payload = json.dumps(
                {
                    "origin": self._origin_id,
                    "type": event_type,
                    "data": data,
                    "ts": time.time(),
                },
                ensure_ascii=False,
                default=str,
            )
            result = self._redis.publish(REDIS_CHANNEL, payload)
            if asyncio.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    pass
        except Exception as e:
            logger.debug("EventBus redis broadcast failed: %s", e)

    async def start_redis_bridge(self) -> None:
        """订阅 Redis 通道,把其他进程的事件注入本进程 SSE 订阅者。"""
        if self._redis is None or self._bridge_task is not None:
            return
        try:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(REDIS_CHANNEL)
        except Exception as e:
            logger.warning("EventBus redis bridge subscribe failed: %s", e)
            return

        async def _listen():
            try:
                async for msg in pubsub.listen():
                    if not msg or msg.get("type") != "message":
                        continue
                    raw = msg.get("data")
                    try:
                        if isinstance(raw, bytes):
                            raw = raw.decode()
                        envelope = json.loads(raw)
                    except Exception:
                        continue
                    if envelope.get("origin") == self._origin_id:
                        continue  # 自己发的,本地 publish 已投递
                    et = envelope.get("type") or ""
                    ed = envelope.get("data") or {}
                    if not isinstance(ed, dict):
                        ed = {"raw": ed}
                    self.publish(et, ed, _from_redis=True)
            except Exception as e:
                logger.warning("EventBus redis bridge stopped: %s", e)

        self._bridge_task = asyncio.create_task(_listen(), name="event-bus-redis")
        logger.info("EventBus: redis bridge listener started")

    def subscribe(self) -> Optional[asyncio.Queue]:
        """注册订阅队列。

        满员时返回 None（拒绝新订阅）而非踢出最老订阅者：
        被踢连接此前并未关闭，客户端只收 ping 不收数据，会变成
        "僵尸流"（看门狗被 ping 重置，永远不触发重连）。
        拒绝新连接让 SSE 端点返回 503 + Retry-After，客户端明确感知。
        """
        if len(self._subscribers) >= self._max:
            logger.warning(
                "EventBus: subscriber slots full (%d), rejecting new subscription",
                self._max,
            )
            return None
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_max)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    def recent(self, limit: int = 50, since_seq: int = 0) -> list[dict]:
        """按 seq 升序返回 recent 事件；since_seq>0 时仅返回比它新的（断线补发）"""
        evts = [e for e in self._history if e.seq > since_seq]
        return [
            {**e.to_sse(), "seq": e.seq, "ts": e.timestamp}
            for e in evts[-limit:]
        ]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def last_seq(self) -> int:
        return self._history[-1].seq if self._history else 0

    @property
    def oldest_seq(self) -> int:
        return self._history[0].seq if self._history else 0


event_bus = EventBus()
