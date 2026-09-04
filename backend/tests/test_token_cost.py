"""
Token 成本聚合单元测试 — 运营中心「Token 成本」面板

覆盖:
  - eval_repository.get_event_token_aggregation: 按事件聚合 + 汇总 + 过滤
  - eval_repository.get_daily_token_usage: 每日趋势 (缺失日期补 0)
  - CostTracker 配置化预算 + 费用估算 + 用量恢复

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── 测试环境前置 (在 import models 之前注入) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine
def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)
_sa_async.create_async_engine = _patched_create_async_engine


async def _reset_db():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _seed_event_and_traces(event_id: int = 1, tokens: int = 1500):
    """插入一个安全事件 + 两条 LLM 轨迹 (一条成功一条错误)"""
    from models import SecurityEvent, AgentTrace, async_session

    async with async_session() as s:
        s.add(SecurityEvent(
            id=event_id, session_id="sess-test", event_type="PORT_SCAN",
            severity="high", src_ip="10.0.0.9", message="port scan x",
            raw_data={}, analyzed=True,
        ))
        s.add(AgentTrace(
            caller="audit_pipeline", operation="execute", model="m",
            event_id=event_id, session_id="sess-test",
            prompt_tokens=tokens, completion_tokens=tokens // 2,
            total_tokens=tokens + tokens // 2,
            latency_ms=120.5, status="success",
            created_at=datetime.now(timezone.utc),
        ))
        s.add(AgentTrace(
            caller="audit_pipeline", operation="review", model="m",
            event_id=event_id, session_id="sess-test",
            prompt_tokens=100, completion_tokens=50, total_tokens=150,
            latency_ms=80.0, status="error", error_type="timeout",
            created_at=datetime.now(timezone.utc),
        ))
        await s.commit()


class TestEventTokenAggregation:

    def test_aggregates_per_event(self):
        async def t():
            from eval_repository import get_event_token_aggregation
            await _reset_db()
            await _seed_event_and_traces(event_id=1, tokens=1000)

            data = await get_event_token_aggregation(days=30)
            assert data["total_events"] == 1
            ev = data["events"][0]
            assert ev["event_id"] == 1
            assert ev["calls"] == 2
            assert ev["total_tokens"] == 1000 + 500 + 150
            assert ev["prompt_tokens"] == 1100
            assert ev["completion_tokens"] == 550
            assert ev["errors"] == 1
            assert ev["event_type"] == "PORT_SCAN"
            assert ev["severity"] == "high"
            assert ev["src_ip"] == "10.0.0.9"
            assert data["grand"]["calls"] == 2
            assert data["grand"]["errors"] == 1
        _run(t())

    def test_filters_by_severity_and_min_tokens(self):
        async def t():
            from eval_repository import get_event_token_aggregation
            await _reset_db()
            await _seed_event_and_traces(event_id=2, tokens=300)   # total = 600

            data = await get_event_token_aggregation(days=30, severity="low")
            assert data["total_events"] == 0

            data2 = await get_event_token_aggregation(days=30, min_tokens=700)
            assert data2["total_events"] == 0

            data3 = await get_event_token_aggregation(days=30, min_tokens=500)
            assert data3["total_events"] == 1
        _run(t())


class TestDailyTokenUsage:

    def test_returns_full_range_with_zeros(self):
        async def t():
            from eval_repository import get_daily_token_usage
            await _reset_db()
            await _seed_event_and_traces(event_id=3, tokens=200)  # total = 450

            points = await get_daily_token_usage(days=7)
            assert len(points) == 7
            assert points[-1]["day"] == datetime.now(timezone.utc).date().isoformat()
            assert points[-1]["total_tokens"] == 450
            # 今天之前的日期应补 0
            assert points[0]["total_tokens"] == 0
        _run(t())


class TestCostTracker:

    def test_budget_and_cost_estimate(self):
        from summary_compression import CostTracker

        tracker = CostTracker(
            daily_budget_tokens=1000,
            price_input_per_1k=0.1,
            price_output_per_1k=0.2,
        )
        tracker.record(600, event_id=5, prompt_tokens=400, completion_tokens=200)
        assert tracker.stats()["today_usage"] == 600
        assert tracker.stats()["today_prompt"] == 400
        assert tracker.stats()["today_completion"] == 200
        assert tracker.remaining_budget() == 400
        assert tracker.is_over_budget() is False
        # 输入 1000 tokens × 0.1 + 输出 500 tokens × 0.2 = 0.1 + 0.1
        assert tracker.estimate_cost_yuan(1000, 500) == 0.2
        # 弃用别名与正名等价
        assert tracker.estimate_cost_jpy(1000, 500) == 0.2

        tracker.record(500, event_id=5, prompt_tokens=300, completion_tokens=200)
        assert tracker.is_over_budget() is True
        # 今日: 输入 700 → 0.07, 输出 400 → 0.08, 合计 0.15
        assert tracker.stats()["estimated_cost_yuan"] == 0.15
        # 兼容旧键(一个版本后移除)
        assert tracker.stats()["estimated_cost_jpy"] == 0.15

    def test_restore_today_usage_overrides(self):
        from summary_compression import CostTracker

        tracker = CostTracker(daily_budget_tokens=1000)
        tracker.record(500, prompt_tokens=300, completion_tokens=200)
        tracker.restore_today_usage(
            tokens=900, calls=3, prompt_tokens=600, completion_tokens=300
        )
        assert tracker.stats()["today_usage"] == 900
        assert tracker.stats()["today_prompt"] == 600
        assert tracker.stats()["today_completion"] == 300
        assert tracker.stats()["today_calls"] == 3
        assert tracker.remaining_budget() == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])