"""
滑动窗口 — 安全审计改造版

核心变更：
  - 去掉 LLM 压缩注入（_summarize_and_inject）
  - 被挤出的消息只在窗口内移除，原始数据完整保留在 DB 中
  - 新增标记系统：记录哪些消息被"窗口淘汰"，Agent 可据此查询完整数据
"""
import json
import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Awaitable, Optional

from config import settings

logger = logging.getLogger(__name__)

WINDOW_KEY = "sliding_window:{session_id}"
EVICTED_KEY = "window_evicted:{session_id}"

# ── Storage Backend Abstraction ──

class StorageBackend(ABC):
    @abstractmethod
    async def connect(self): ...
    @abstractmethod
    async def ping(self): ...
    @abstractmethod
    async def rpush(self, key: str, value: str): ...
    @abstractmethod
    async def lpush(self, key: str, value: str): ...
    @abstractmethod
    async def lpop(self, key: str) -> str | None: ...
    @abstractmethod
    async def llen(self, key: str) -> int: ...
    @abstractmethod
    async def lrange(self, key: str, start: int, stop: int) -> list[str]: ...
    @abstractmethod
    async def delete(self, key: str): ...
    @abstractmethod
    async def setex(self, key: str, ttl: int, value: str): ...
    @abstractmethod
    async def get(self, key: str) -> str | None: ...
    @abstractmethod
    async def dbsize(self) -> int: ...

class RedisBackend(StorageBackend):
    def __init__(self, url: str):
        self.url = url
        self.redis = None

    async def connect(self):
        import redis.asyncio as aioredis
        self.redis = await aioredis.from_url(self.url, decode_responses=True)
        await self.redis.ping()
        logger.info("RedisBackend connected")

    async def ping(self):
        await self.redis.ping()

    async def rpush(self, key, value):
        await self.redis.rpush(key, value)

    async def lpush(self, key, value):
        await self.redis.lpush(key, value)

    async def lpop(self, key):
        return await self.redis.lpop(key)

    async def llen(self, key):
        return await self.redis.llen(key)

    async def lrange(self, key, start, stop):
        return await self.redis.lrange(key, start, stop)

    async def delete(self, key):
        await self.redis.delete(key)

    async def setex(self, key, ttl, value):
        await self.redis.setex(key, ttl, value)

    async def get(self, key):
        return await self.redis.get(key)

    async def dbsize(self):
        return await self.redis.dbsize()

class DequeBackend(StorageBackend):
    def __init__(self):
        self._lists: dict[str, deque] = {}
        self._kv: dict[str, tuple[str, float]] = {}

    async def connect(self):
        logger.info("DequeBackend connected (in-memory)")

    async def ping(self):
        pass

    async def rpush(self, key, value):
        if key not in self._lists:
            self._lists[key] = deque()
        self._lists[key].append(value)

    async def lpush(self, key, value):
        if key not in self._lists:
            self._lists[key] = deque()
        self._lists[key].appendleft(value)

    async def lpop(self, key):
        d = self._lists.get(key)
        return d.popleft() if d else None

    async def llen(self, key):
        return len(self._lists.get(key, deque()))

    async def lrange(self, key, start, stop):
        d = self._lists.get(key, deque())
        l = len(d)
        if stop == -1 or stop >= l:
            stop = l
        return list(d)[start:stop]

    async def delete(self, key):
        self._lists.pop(key, None)
        self._kv.pop(key, None)

    async def setex(self, key, ttl, value):
        self._kv[key] = (value, time.time() + ttl)

    async def get(self, key):
        entry = self._kv.get(key)
        if entry is None:
            return None
        val, expiry = entry
        if time.time() < expiry:
            return val
        del self._kv[key]
        return None

    async def dbsize(self):
        now = time.time()
        expired = [k for k, (_, e) in self._kv.items() if now >= e]
        for k in expired:
            del self._kv[k]
        return len(self._lists) + len(self._kv)

# ── Sliding Window ──

class SlidingWindow:
    """
    滑动窗口 — 安全审计版
    
    改造点：
    1. 不再调用 LLM 压缩被挤出的消息
    2. 被挤出的消息记录到 evicted 列表（查询回溯用）
    3. 原始数据保存在 DB（SecurityEvent 表 / EventStore）中
    """
    def __init__(self):
        self.backend: StorageBackend | None = None
        self.max_size = settings.sliding_window_size
        self.window_minutes = settings.sliding_window_minutes
        # 不再需要 summarizer
        self.summarizer: Optional[Callable[[list[dict], int], Awaitable[str]]] = None

    def set_summarizer(self, summarizer: Callable[[list[dict], int], Awaitable[str]]):
        """保留接口兼容性，但不再调用"""
        self.summarizer = summarizer

    async def connect(self):
        if settings.storage_backend == "deque":
            self.backend = DequeBackend()
        else:
            self.backend = RedisBackend(settings.redis_url)
        await self.backend.connect()

    async def add_message(
        self, session_id: str, agent_id: str, role: str, content: str
    ) -> list[dict]:
        key = WINDOW_KEY.format(session_id=session_id)
        now = datetime.now(timezone.utc)
        msg = {
            "agent_id": agent_id,
            "role": role,
            "content": content,
            "summary_depth": 0,
            "timestamp": now.isoformat(),
        }
        await self.backend.rpush(key, json.dumps(msg, ensure_ascii=False))

        # 1. Time-based eviction
        await self._evict_by_time(session_id, key)

        # 2. Count-based eviction
        length = await self.backend.llen(key)
        if length > self.max_size:
            await self._evict_by_count(session_id, key)

        return await self.get_window(session_id)

    async def _evict_by_time(self, session_id: str, key: str):
        cutoff_ts = datetime.now(timezone.utc).timestamp() - self.window_minutes * 60
        popped = []
        while True:
            items = await self.backend.lrange(key, 0, 0)
            if not items:
                break
            msg = json.loads(items[0])
            msg_ts = datetime.fromisoformat(msg["timestamp"]).timestamp()
            if msg_ts >= cutoff_ts:
                break
            item = await self.backend.lpop(key)
            if item:
                popped.append(json.loads(item))
        if popped:
            logger.info(f"Time-evicted {len(popped)} messages for {session_id}")
            await self._record_evicted(session_id, popped)

    async def _evict_by_count(self, session_id: str, key: str):
        pop_count = max(1, self.max_size // 4)
        popped = []
        for _ in range(pop_count):
            item = await self.backend.lpop(key)
            if item:
                popped.append(json.loads(item))
        if popped:
            logger.info(f"Count-evicted {len(popped)} messages for {session_id}")
            await self._record_evicted(session_id, popped)

    async def _record_evicted(self, session_id: str, evicted: list[dict]):
        """
        记录被挤出的消息到 evicted 列表。
        Agent 可以通过 get_evicted() 回溯这些消息。
        """
        key = EVICTED_KEY.format(session_id=session_id)
        for msg in evicted:
            # 标记来源为窗口淘汰
            msg["_evicted"] = True
            msg["_evicted_at"] = datetime.now(timezone.utc).isoformat()
            await self.backend.rpush(key, json.dumps(msg, ensure_ascii=False))
        # 保留最多 10000 条被淘汰记录
        length = await self.backend.llen(key)
        if length > 10000:
            for _ in range(length - 10000):
                await self.backend.lpop(key)

    async def get_window(self, session_id: str) -> list[dict]:
        key = WINDOW_KEY.format(session_id=session_id)
        items = await self.backend.lrange(key, 0, -1)
        return [json.loads(item) for item in items]

    async def get_evicted(self, session_id: str, limit: int = 100) -> list[dict]:
        """获取被窗口淘汰的历史消息（供 Agent 回溯）"""
        key = EVICTED_KEY.format(session_id=session_id)
        items = await self.backend.lrange(key, -limit, -1)
        return [json.loads(item) for item in items]

    async def clear_window(self, session_id: str):
        key = WINDOW_KEY.format(session_id=session_id)
        await self.backend.delete(key)
        logger.info(f"Cleared sliding window for {session_id}")

    async def set_summary(self, session_id: str, summary_text: str):
        """保留接口兼容，但不再使用"""
        pass

    async def get_summary(self, session_id: str) -> str | None:
        """保留接口兼容，返回空"""
        return None

    async def get_redis(self):
        if isinstance(self.backend, RedisBackend):
            return self.backend.redis
        return None

    async def dbsize(self):
        return await self.backend.dbsize()


sliding_window = SlidingWindow()
