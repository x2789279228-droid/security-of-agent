"""全局 LLM 闸: 并发硬顶 + acquire 超时。"""
import asyncio

import pytest

from llm_limiter import LlmSlotTimeout, reset_llm_limiter


@pytest.mark.asyncio
async def test_limiter_caps_concurrency(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "llm_global_concurrency", 3)
    monkeypatch.setattr(settings, "llm_p0_reserve", 0)
    lim = reset_llm_limiter()
    current = 0
    peak = 0

    async def one():
        nonlocal current, peak
        async with lim.acquire(tier="P2", timeout=2):
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.05)
            current -= 1

    await asyncio.gather(*[one() for _ in range(12)])
    assert peak <= 3


@pytest.mark.asyncio
async def test_limiter_timeout():
    from config import settings
    settings.llm_global_concurrency = 1
    settings.llm_p0_reserve = 0
    lim = reset_llm_limiter()

    async def hold():
        async with lim.acquire(tier="P2", timeout=2):
            await asyncio.sleep(0.4)

    t = asyncio.create_task(hold())
    await asyncio.sleep(0.05)
    with pytest.raises(LlmSlotTimeout):
        async with lim.acquire(tier="P2", timeout=0.1):
            pass
    await t
    assert lim.inflight() == 0


@pytest.mark.asyncio
async def test_p0_reserve_blocks_non_p0(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "llm_global_concurrency", 2)
    monkeypatch.setattr(settings, "llm_p0_reserve", 1)
    lim = reset_llm_limiter()

    async with lim.acquire(tier="P2", timeout=1):
        # 1 shared slot taken; the reserved slot is P0-only
        with pytest.raises(LlmSlotTimeout):
            async with lim.acquire(tier="P2", timeout=0.1):
                pass
        async with lim.acquire(tier="P0", timeout=0.5):
            assert lim.inflight() == 2
