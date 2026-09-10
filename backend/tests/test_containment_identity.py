"""LDAP disable / mail recall / CRITICAL execute 403 / containment list."""
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

from fastapi import HTTPException

from config import settings
from response_engine.containment.directory_adapter import (
    disable_account,
    is_protected_account,
    register as register_dir,
)
from response_engine.containment.mail_adapter import recall_email, register as register_mail
from response_engine.response_registry import response_registry


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeRequest:
    class _Client:
        host = "127.0.0.1"
    client = _Client()
    headers = {"user-agent": "pytest"}


USER_OPERATOR = SimpleNamespace(username="alice", role="operator")


class _raise_http:
    def __enter__(self):
        self.value = None
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None and issubclass(exc_type, HTTPException):
            self.value = exc
            return True
        return False


class TestDirectory:
    def test_krbtgt_protected(self):
        assert is_protected_account("krbtgt")
        r = _run(disable_account(account="krbtgt"))
        assert r["success"] is False
        assert r["mode"] == "denied"

    def test_override_protected_mock(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(disable_account(account="krbtgt", override_protected=True))
            assert r["success"] is True
        finally:
            settings.execution_mode = old

    def test_live_unconfigured(self):
        old_mode = settings.execution_mode
        old_url = settings.ldap_url
        settings.execution_mode = "live"
        settings.ldap_url = ""
        try:
            r = _run(disable_account(account="jdoe"))
            assert r["success"] is False
            assert r["mode"] == "unconfigured"
        finally:
            settings.execution_mode = old_mode
            settings.ldap_url = old_url

    def test_registered_critical(self):
        register_dir(response_registry)
        action = response_registry.get_action("disable_account")
        assert action is not None
        assert action.severity == "critical"


class TestMail:
    def test_recall_unconfigured_live(self):
        old_mode = settings.execution_mode
        old_t = settings.graph_tenant
        settings.execution_mode = "live"
        settings.graph_tenant = ""
        try:
            r = _run(recall_email(internet_message_id="<a@b>"))
            assert r["success"] is False
            assert r["mode"] == "unconfigured"
        finally:
            settings.execution_mode = old_mode
            settings.graph_tenant = old_t

    def test_recall_mock(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(recall_email(internet_message_id="<a@b>"))
            assert r["success"] is True
        finally:
            settings.execution_mode = old

    def test_registered(self):
        register_mail(response_registry)
        assert response_registry.get_action("recall_email") is not None


class TestExecuteGuard:
    def test_disable_account_403(self):
        from routers.response import execute_response

        async def t():
            with _raise_http() as exc_info:
                await execute_response(
                    request=_FakeRequest(),
                    action_name="disable_account",
                    src_ip="",
                    reason="test",
                    session=None,
                    user=USER_OPERATOR,
                )
            assert exc_info.value is not None
            assert exc_info.value.status_code == 403

        _run(t())


class TestContainmentList:
    def test_list_empty(self):
        from models import Base, engine, async_session
        from routers.response import list_containment

        async def t():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                rows = await list_containment(
                    status="", action_name="", limit=10, session=s, user=USER_OPERATOR,
                )
            assert rows == []

        _run(t())
