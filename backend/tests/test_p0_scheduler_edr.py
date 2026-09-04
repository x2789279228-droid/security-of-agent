"""
P0 修复回归: 长链扫描 30×N 重复分析 + edr_adapter await publish 真 bug

修复前: _scan_long_chains 对同一 session 按天循环 30 次 analyze(1440)，
        每次都是"最近24h"窗口，结果完全相同，纯耗 CPU；返回值只打日志。
修复前: _emit_alert 中 `await event_bus.publish(...)`，publish 返回 None，
        `await None` 必抛 TypeError 被吞，edr_correlation 告警从未发布。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched
import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def _mk_event(session_id: str, src_ip="10.0.0.9"):
    from models import SecurityEvent, async_session
    async with async_session() as s:
        evt = SecurityEvent(
            session_id=session_id, event_type="BRUTE_FORCE", severity="high",
            src_ip=src_ip, dst_ip="172.16.0.5", message="bf",
            raw_data={}, analyzed=False,
        )
        s.add(evt)
        await s.commit()


class TestLongChainScan:
    def test_analyze_called_once_per_session_with_30d_window(self):
        async def t():
            await _reset()
            for sid in ("sess-a", "sess-b"):
                await _mk_event(sid)

            import correlation_engine as ce_mod
            from models import async_session
            from scheduler import Scheduler

            calls = []

            class _FakeResult:
                chains = []

            orig = ce_mod.correlation_engine.analyze

            async def fake_analyze(session, session_id, time_window_minutes=1440):
                calls.append((session_id, time_window_minutes))
                return _FakeResult()

            ce_mod.correlation_engine.analyze = fake_analyze
            try:
                sched = Scheduler()
                async with async_session() as s:
                    await sched._scan_long_chains(s)
            finally:
                ce_mod.correlation_engine.analyze = orig

            assert sorted(sid for sid, _ in calls) == ["sess-a", "sess-b"], \
                "每个 session 应只分析一次"
            assert all(w == 30 * 1440 for _, w in calls), \
                "应使用一次性 30 天窗口，而不是 1440(1天) 重复 30 次"
        _run(t())


class TestEdrAlertPublish:
    def test_emit_alert_publishes_event(self):
        """publish 是同步方法：不能 await，且事件应真正进入总线。"""
        async def t():
            from event_bus import event_bus
            from edr_fusion.edr_adapter import EdrAdapter

            q = event_bus.subscribe()
            try:
                adapter = EdrAdapter()

                class _R:
                    confidence = 0.9

                    def to_dict(self):
                        return {"src_ip": "1.2.3.4", "confidence": 0.9}

                await adapter._emit_alert(_R())

                assert q.qsize() == 1, "edr_correlation 事件应成功发布"
                evt = q.get_nowait()
                assert evt.type == "edr_correlation"
                assert evt.data["src_ip"] == "1.2.3.4"
            finally:
                event_bus.unsubscribe(q)
        _run(t())
