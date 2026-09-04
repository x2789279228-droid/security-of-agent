"""
P0 修复回归: /api/response/execute 不再绕过安全控制 (#11)

修复前: 端点直连 response_executor.execute_actions，绕过 SecurityGuard
        四项审查/频率限制/审批分级，不写 ResponseLog/audit_trail，
        operator 可手动执行 isolate_host 架空 admin 审批。
修复后: CRITICAL 动作 403；其余动作经 _guarded_execute（守卫）执行，
        写 ResponseLog(manual_execute) 与 AuditTrail(response.manual_execute)。
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

from fastapi import HTTPException

from routers.response import execute_response
from security_guard.security_guard import security_guard


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


class _FakeRequest:
    """直接调用端点函数时的请求 stub（log_from_request 只用 client/headers）"""
    class _Client:
        host = "127.0.0.1"
    client = _Client()
    headers = {"user-agent": "pytest"}


USER_OPERATOR = SimpleNamespace(username="alice", role="operator")


class TestExecuteResponseGuard:
    def test_critical_action_rejected_with_403(self):
        async def t():
            await _reset()
            with _raise_http() as exc_info:
                await execute_response(
                    request=_FakeRequest(),
                    action_name="isolate_host",
                    src_ip="10.0.0.66",
                    reason="测试隔离请求",
                    session=None,
                    user=USER_OPERATOR,
                )
            assert exc_info.value is not None
            assert exc_info.value.status_code == 403
        _run(t())

    def test_manual_execute_goes_through_guard_and_leaves_trail(self):
        async def t():
            await _reset()
            security_guard.reset()
            from models import async_session
            from sqlalchemy import select
            from models import ResponseLog, AuditTrail

            async with async_session() as s:
                result = await execute_response(
                    request=_FakeRequest(),
                    action_name="block_ip",
                    src_ip="10.0.0.77",
                    reason="手动封禁测试来源",
                    session=s,
                    user=USER_OPERATOR,
                )
                assert "rollback_token" in result
                assert result["action"] == "block_ip"

                # ResponseLog 必须留痕（修复前该端点完全不写）
                rows = (await s.execute(
                    select(ResponseLog).where(ResponseLog.action_name == "block_ip")
                )).scalars().all()
                assert rows, "手动执行必须写 ResponseLog"
                assert any(r.approval_status == "manual_execute" for r in rows)

                # AuditTrail 必须留痕且 actor 取 JWT 身份
                audits = (await s.execute(
                    select(AuditTrail).where(AuditTrail.action == "response.manual_execute")
                )).scalars().all()
                assert audits, "手动执行必须写 AuditTrail"
                assert audits[-1].actor == "alice"
                assert audits[-1].actor_role == "operator"
        _run(t())


class _raise_http:
    """捕获 HTTPException 的上下文管理器（不抛出，供断言 status_code）"""

    def __enter__(self):
        self.value = None
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None and issubclass(exc_type, HTTPException):
            self.value = exc
            return True
        return False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
