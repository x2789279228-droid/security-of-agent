"""全平台 LLM HTTP 并发闸。

Audit / enhancer / RAG 全部经 LLMClient.chat 进入本闸。
P0 预留槽: 非 P0 最多占用 (limit - reserve); P0 可占用任意空闲槽。
acquire 超时抛 LlmSlotTimeout — 调用方 nack,闸内不 sleep。
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from config import settings

logger = logging.getLogger(__name__)


class LlmSlotTimeout(Exception):
    """等不到 LLM 槽。"""


class LlmLimiter:
    def __init__(self) -> None:
        self._lock: Optional[asyncio.Lock] = None
        self._cv: Optional[asyncio.Condition] = None
        self._used = 0
        self._p0_used = 0
        self._waiters = 0

    def _ensure(self) -> asyncio.Condition:
        if self._cv is None:
            self._lock = asyncio.Lock()
            self._cv = asyncio.Condition(self._lock)
        return self._cv

    def _limit(self) -> int:
        return max(1, int(getattr(settings, "llm_global_concurrency", 8) or 8))

    def _reserve(self) -> int:
        n = self._limit()
        r = max(0, int(getattr(settings, "llm_p0_reserve", 2) or 0))
        return min(r, max(0, n - 1))

    def inflight(self) -> int:
        return self._used

    def waiters(self) -> int:
        return self._waiters

    def snapshot(self) -> dict:
        return {
            "used": self._used,
            "p0_used": self._p0_used,
            "waiters": self._waiters,
            "limit": self._limit(),
            "reserve": self._reserve(),
        }

    def _can_enter(self, is_p0: bool) -> bool:
        limit = self._limit()
        reserved = self._reserve()
        if self._used >= limit:
            return False
        if is_p0:
            return True
        non_p0 = max(0, self._used - self._p0_used)
        return non_p0 < max(0, limit - reserved)

    async def _enter(self, *, tier: str, timeout: float) -> None:
        is_p0 = str(tier or "").upper() == "P0"
        cv = self._ensure()
        deadline = time.monotonic() + max(0.05, float(timeout))
        async with cv:
            self._waiters += 1
            try:
                while not self._can_enter(is_p0):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LlmSlotTimeout(
                            f"llm slot timeout tier={tier} used={self._used}/{self._limit()}"
                        )
                    try:
                        await asyncio.wait_for(cv.wait(), timeout=remaining)
                    except asyncio.TimeoutError:
                        raise LlmSlotTimeout(
                            f"llm slot timeout tier={tier} used={self._used}/{self._limit()}"
                        )
                self._used += 1
                if is_p0:
                    self._p0_used += 1
            finally:
                self._waiters = max(0, self._waiters - 1)
        try:
            from metrics import set_llm_inflight
            set_llm_inflight(self._used, self._waiters)
        except Exception:
            pass

    async def _leave(self, *, tier: str) -> None:
        is_p0 = str(tier or "").upper() == "P0"
        cv = self._ensure()
        async with cv:
            self._used = max(0, self._used - 1)
            if is_p0:
                self._p0_used = max(0, self._p0_used - 1)
            cv.notify_all()
        try:
            from metrics import set_llm_inflight
            set_llm_inflight(self._used, self._waiters)
        except Exception:
            pass

    @asynccontextmanager
    async def acquire(self, *, tier: str = "P2", timeout: Optional[float] = None) -> AsyncIterator[None]:
        to = float(timeout if timeout is not None else getattr(settings, "llm_slot_timeout_s", 30) or 30)
        await self._enter(tier=tier, timeout=to)
        try:
            yield
        finally:
            await self._leave(tier=tier)


_LIMITER: Optional[LlmLimiter] = None


def get_llm_limiter() -> LlmLimiter:
    global _LIMITER
    if _LIMITER is None:
        _LIMITER = LlmLimiter()
    return _LIMITER


def reset_llm_limiter() -> LlmLimiter:
    global _LIMITER
    _LIMITER = LlmLimiter()
    return _LIMITER
