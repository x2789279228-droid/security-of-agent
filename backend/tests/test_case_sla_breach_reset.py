"""
P0 修复回归: 已超期案例 severity 升级时 SLA 重新计时 (#12 相邻缺陷)

修复前: sla_deadline 只在"能收紧"时刷新——已超期案例旧 deadline 在过去,
        永远不满足收紧条件 → 永不刷新 → sla_breached 永久 True,
        污染 compute_case_sla_breach_rate。
修复后: severity 升级且旧 deadline 已过时, 刷新 deadline 并解除 breached
        （更严重的威胁重新计时）。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

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


async def _mk_event(severity: str, src_ip="10.0.0.9", session_id="sess-sla",
                    event_type="PORT_SCAN"):
    from models import SecurityEvent, async_session
    async with async_session() as s:
        evt = SecurityEvent(
            session_id=session_id, event_type=event_type, severity=severity,
            src_ip=src_ip, dst_ip="172.16.0.5", message="sla",
            raw_data={}, analyzed=False,
        )
        s.add(evt)
        await s.commit()
        await s.refresh(evt)
        return evt


class TestSlaBreachRearm:
    def test_breached_case_rearms_on_severity_upgrade(self):
        async def t():
            from models import SecurityEvent, SecurityCase, async_session
            from case_manager import case_manager
            await _reset()

            # 1. medium 事件建案
            e1 = await _mk_event("medium")
            async with async_session() as s:
                case = await case_manager.auto_create_case(
                    s, await s.get(SecurityEvent, e1.id)
                )
                case_id = case.id

            # 2. 人为制造"已超期且已 breach"的粘滞状态
            async with async_session() as s:
                dbc = await s.get(SecurityCase, case_id)
                dbc.sla_deadline = datetime.now(timezone.utc) - timedelta(hours=2)
                dbc.sla_breached = True
                await s.commit()

            # 3. critical 事件聚合同案 → severity 升级
            e2 = await _mk_event("critical", event_type="DATA_EXFIL")
            async with async_session() as s:
                case = await s.get(SecurityCase, case_id)
                evt = await s.get(SecurityEvent, e2.id)
                await case_manager._add_event_to_case(s, case, evt)

            # 4. 断言重新计时
            async with async_session() as s:
                dbc = await s.get(SecurityCase, case_id)
                assert dbc.severity == "critical"
                assert dbc.sla_deadline is not None
                assert dbc.sla_deadline.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc), \
                    "升级后 deadline 应刷新到未来"
                assert dbc.sla_breached is False, "已超期案例升级后应解除 breached 粘滞"

        _run(t())

    def test_unbreached_case_still_only_tightens(self):
        """未超期案例保持原语义: 新 deadline 只有在能收紧时才写入。"""
        async def t():
            from models import SecurityEvent, SecurityCase, async_session
            from case_manager import case_manager
            await _reset()

            e1 = await _mk_event("medium")
            async with async_session() as s:
                case = await case_manager.auto_create_case(
                    s, await s.get(SecurityEvent, e1.id)
                )
                case_id = case.id
                original_deadline = case.sla_deadline
                if original_deadline.tzinfo is None:
                    original_deadline = original_deadline.replace(tzinfo=timezone.utc)

            e2 = await _mk_event("critical", event_type="DATA_EXFIL")
            async with async_session() as s:
                case = await s.get(SecurityCase, case_id)
                evt = await s.get(SecurityEvent, e2.id)
                await case_manager._add_event_to_case(s, case, evt)

            async with async_session() as s:
                dbc = await s.get(SecurityCase, case_id)
                assert dbc.sla_breached is False
                # critical 的 SLA 更短 → deadline 应收紧（更早）
                new_deadline = dbc.sla_deadline
                if new_deadline.tzinfo is None:
                    new_deadline = new_deadline.replace(tzinfo=timezone.utc)
                assert new_deadline <= original_deadline

        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
