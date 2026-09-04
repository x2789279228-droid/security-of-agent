"""
P0 修复回归: 高危端点写入 audit_trail (#20)

修复前: 响应策略修改/审批/手动执行/CEP 切换/reset-stuck 等高危端点
        均不写 AuditTrail，等保要求的操作留痕缺失。
修复后: actor 取 JWT 身份，高危操作统一写 audit_trail。
"""
import asyncio
import os
import sys
from types import SimpleNamespace

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

from routers.response import update_response_policy
from routers.response import PolicyUpdateRequest


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


class _FakeRequest:
    class _Client:
        host = "10.1.1.1"
    client = _Client()
    headers = {"user-agent": "pytest-audit"}

USER_ADMIN = SimpleNamespace(username="bob", role="admin")
USER_VIEWER = SimpleNamespace(username="carol", role="viewer")


class TestPolicyUpdateAudit:
    def test_policy_update_writes_audit_trail(self):
        async def t():
            await _reset()
            from models import async_session
            from sqlalchemy import select
            from models import AuditTrail
            from response_engine import policy_engine

            req = PolicyUpdateRequest(name="C2通信自动封禁", auto_execute=False)
            fake_req = _FakeRequest()
            async with async_session() as s:
                result = await update_response_policy(req, fake_req, s, USER_ADMIN)
                assert result["status"] == "updated"

                audits = (await s.execute(
                    select(AuditTrail).where(AuditTrail.action == "response.policy_update")
                )).scalars().all()
                assert audits, "策略修改必须写 AuditTrail"
                row = audits[-1]
                assert row.actor == "bob" and row.actor_role == "admin"
                assert row.target_id == "C2通信自动封禁"
                # before/after 记录策略字段变化
                assert row.before and row.after
                assert row.after["auto_execute"] is False
                assert row.before["auto_execute"] is True

            # 还原全局单例策略，避免污染其它测试
            policy_engine.get_policy("C2通信自动封禁").auto_execute = True
        _run(t())


class TestResetStuckAudit:
    def test_reset_stuck_writes_audit_trail(self):
        async def t():
            await _reset()
            from datetime import datetime, timezone, timedelta
            from models import SecurityEvent, async_session
            from sqlalchemy import select
            from models import AuditTrail
            from routers.logs import reset_stuck

            # 一条卡住的事件（创建时间早于 minutes 阈值）
            async with async_session() as s:
                s.add(SecurityEvent(
                    session_id="sess-stuck", event_type="BRUTE_FORCE",
                    severity="high", src_ip="10.0.0.9", dst_ip="172.16.0.5",
                    message="stuck", raw_data={}, analyzed=False,
                    created_at=datetime.now(timezone.utc) - timedelta(minutes=30),
                ))
                await s.commit()

            async with async_session() as s:
                out = await reset_stuck(_FakeRequest(), minutes=5, session=s, user=USER_ADMIN)
                assert out["reset_count"] >= 1

                audits = (await s.execute(
                    select(AuditTrail).where(AuditTrail.action == "logs.reset_stuck")
                )).scalars().all()
                assert audits, "reset-stuck 必须写 AuditTrail"
                assert audits[-1].actor == "bob"
                assert audits[-1].after["reset_count"] >= 1
        _run(t())


class TestCepToggleAudit:
    def test_cep_toggle_writes_audit_trail(self):
        async def t():
            await _reset()
            from models import async_session
            from sqlalchemy import select
            from models import AuditTrail
            from routers.kafka import cep_pattern_toggle, _CEP_PATTERNS_CACHE

            async with async_session() as s:
                out = await cep_pattern_toggle(
                    "port_scan_to_c2", _FakeRequest(), s, USER_VIEWER
                )
                assert out["success"] is True

                audits = (await s.execute(
                    select(AuditTrail).where(AuditTrail.action == "cep.pattern_toggle")
                )).scalars().all()
                assert audits, "CEP 模式切换必须写 AuditTrail"
                assert audits[-1].actor == "carol"
                assert audits[-1].before["enabled"] is True
                assert audits[-1].after["enabled"] is False

            # 还原内存模式状态
            _CEP_PATTERNS_CACHE["port_scan_to_c2"]["enabled"] = True
        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
