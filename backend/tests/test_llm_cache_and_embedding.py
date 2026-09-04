"""LLM 缓存饿死修复 + 嵌入缓存命中率可观测 回归测试

覆盖:
  1. 超预算下 chat() 仍命中零成本缓存（缓存查询先于预算门禁的调序修复）
  2. enhance() 对 fallback 降级载荷不写业务缓存且返回 None
  3. embed() 命中/未命中计数 + emit_trace 落 AgentTrace(caller="embedding")
  4. get_trace_stats / get_cache_channel_stats 通道聚合
"""
import asyncio
import hashlib
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from config import settings


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _reset_tables():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── 1. 超预算下缓存命中不被饿死 ──

def test_chat_cache_hit_under_budget_exhaustion(monkeypatch):
    from summary_compression import summary, cost_tracker

    async def t():
        llm = summary.llm
        llm._response_cache.clear()
        messages = [{"role": "user", "content": "cache-starvation-probe"}]
        prompt_text = "\n".join(m.get("content", "") for m in messages)
        key = "llmcache:" + hashlib.md5(f"{prompt_text}:0.3".encode("utf-8")).hexdigest()
        await llm._cache_set(key, "CACHED_CONTENT")

        monkeypatch.setattr(cost_tracker, "is_over_budget", lambda: True)
        result = await llm.chat(messages)
        assert result == "CACHED_CONTENT", (
            "预算耗尽时零成本缓存命中必须可达（缓存查询先于预算门禁）"
        )
        return True

    assert _run(t())


def test_chat_fallback_when_over_budget_and_cache_miss(monkeypatch):
    """门禁语义保持：超预算且缓存未命中 → fallback，不发起真实调用。"""
    from summary_compression import summary, cost_tracker

    async def t():
        llm = summary.llm
        llm._response_cache.clear()
        monkeypatch.setattr(cost_tracker, "is_over_budget", lambda: True)
        result = await llm.chat([{"role": "user", "content": "no-cache-probe"}])
        assert "fallback" in json.loads(result)
        return True

    assert _run(t())


# ── 2. enhance() 不缓存/不返回 fallback 载荷 ──

def test_enhance_discards_fallback_payload(monkeypatch):
    import llm_enhancer as le
    from summary_compression import summary as _summary

    le._BIZ_CACHE.clear()
    le._MODULE_BUDGET.clear()

    class _FakeLLM:
        async def chat(self, messages, temperature=0.3):
            return json.dumps({"error": "每日 LLM 预算已用尽", "fallback": True})

    original_llm = _summary.llm
    monkeypatch.setattr(_summary, "llm", _FakeLLM())
    monkeypatch.setattr(settings, "llm_traffic_enabled", True)
    monkeypatch.setattr(settings, "llm_traffic_budget_jpy_per_day", 10.0)
    try:
        result = _run(le.enhance(
            module="traffic",
            cache_key="fallback-probe",
            prompt_messages=[{"role": "user", "content": "x"}],
            budget_cost_yuan=0.01,
        ))
    finally:
        monkeypatch.setattr(_summary, "llm", original_llm)

    assert result is None, "fallback 载荷不得作为有效业务结果返回"
    assert le._biz_cache_get(le._biz_cache_key("traffic", "fallback-probe")) is None, (
        "fallback 载荷不得写入业务缓存"
    )


# ── 3. embed() 计数器 + trace 落库 ──

def test_embed_counters_and_trace(monkeypatch):
    from summary_compression import embedder
    from models import AgentTrace, async_session

    class _FakeRedis:
        def __init__(self):
            self.store = {}

        async def get(self, k):
            return self.store.get(k)

        async def setex(self, k, ttl, v):
            self.store[k] = v

    class _FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vectors": [[0.1, 0.2, 0.3]]}

    class _FakeClient:
        async def post(self, *a, **kw):
            return _FakeResp()

    async def t():
        await _reset_tables()
        async with async_session() as s:
            await s.execute(AgentTrace.__table__.delete())
            await s.commit()

        monkeypatch.setattr(embedder, "redis", _FakeRedis())
        monkeypatch.setattr(embedder, "api_key", "test-key")
        monkeypatch.setattr(embedder, "base_url", "http://fake-embedding")
        monkeypatch.setattr(embedder, "client", _FakeClient())

        v1 = await embedder.embed("hello", type_="db")   # miss → API
        v2 = await embedder.embed("hello", type_="db")   # hit
        assert v1 == v2 == [0.1, 0.2, 0.3]

        st = embedder.stats()
        assert st["misses"] == 1, st
        assert st["hits"] == 1, st
        assert st["hit_rate"] == 0.5, st

        # 等 fire-and-forget trace 落库
        await asyncio.sleep(0.3)
        async with async_session() as s:
            rows = (await s.execute(
                select(AgentTrace).where(AgentTrace.caller == "embedding")
            )).scalars().all()
        assert len(rows) == 2, [r.__dict__ for r in rows]
        assert sorted(r.cache_hit for r in rows) == [False, True]
        assert all(r.total_tokens == 0 for r in rows)
        return True

    assert _run(t())


# ── 4. 聚合统计：通道划分与命中率 ──

def test_trace_stats_cache_channel():
    from eval_repository import get_trace_stats, get_cache_channel_stats
    from models import AgentTrace, async_session

    async def t():
        await _reset_tables()
        async with async_session() as s:
            await s.execute(AgentTrace.__table__.delete())
            await s.commit()
            now = datetime.now(timezone.utc)
            s.add_all([
                AgentTrace(caller="audit_pipeline", operation="chat", cache_hit=True,
                           status="success", latency_ms=1.0, total_tokens=10, created_at=now),
                AgentTrace(caller="audit_pipeline", operation="chat", cache_hit=False,
                           status="success", latency_ms=2.0, total_tokens=20, created_at=now),
                AgentTrace(caller="embedding", operation="embed", cache_hit=True,
                           status="success", latency_ms=1.0, total_tokens=0, created_at=now),
                AgentTrace(caller="embedding", operation="embed", cache_hit=False,
                           status="success", latency_ms=2.0, total_tokens=0, created_at=now),
            ])
            await s.commit()

        ch = (await get_cache_channel_stats())
        assert ch["llm"]["calls"] == 2 and ch["llm"]["hits"] == 1
        assert abs(ch["llm"]["rate"] - 0.5) < 1e-6
        assert ch["embedding"]["calls"] == 2 and ch["embedding"]["hits"] == 1
        assert abs(ch["embedding"]["rate"] - 0.5) < 1e-6

        stats = await get_trace_stats()
        assert stats["cache_hit_count"] == 2
        assert abs(stats["cache_hit_rate"] - 0.5) < 1e-6
        assert stats["cache_by_channel"]["embedding"]["calls"] == 2

        emb = await get_trace_stats(caller="embedding")
        assert emb["cache_hit_count"] == 1
        assert abs(emb["cache_hit_rate"] - 0.5) < 1e-6
        return True

    assert _run(t())
