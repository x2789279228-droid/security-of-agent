"""Host containment: kill / quarantine / persistence / snapshot prepend."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from config import settings
from response_engine.response_registry import response_registry
from response_engine.containment import host_adapter
from response_engine.containment.host_adapter import (
    kill_process,
    quarantine_file,
    clean_persistence,
    forensic_snapshot,
    restore_file,
    protected_process_reason,
    reject_path,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestRegister:
    def test_actions_registered(self):
        host_adapter.register(response_registry)
        for name in ("kill_process", "quarantine_file", "clean_persistence", "forensic_snapshot"):
            assert response_registry.get_action(name) is not None
        assert response_registry._rollback_fns.get("quarantine_file") is restore_file


class TestKill:
    def test_pid_4_refused(self):
        r = _run(kill_process(pid=4))
        assert r["success"] is False

    def test_pid_mock_ok(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(kill_process(pid=4242))
            assert r["success"] is True
            assert r["mode"] == "mock"
        finally:
            settings.execution_mode = old

    def test_sha256_invalid(self):
        r = _run(kill_process(sha256="deadbeef"))
        assert r["success"] is False
        assert r["mode"] == "invalid"

    def test_sha256_mock_ok(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(kill_process(sha256="a" * 64))
            assert r["success"] is True
        finally:
            settings.execution_mode = old

    def test_lsass_refused(self):
        assert protected_process_reason(name="lsass")
        r = _run(kill_process(pid=4242, name="lsass"))
        assert r["success"] is False
        assert r["mode"] == "denied"

    def test_live_no_ssh_unconfigured(self):
        old = settings.execution_mode
        settings.execution_mode = "live"
        try:
            r = _run(kill_process(pid=4242))
            assert r["success"] is False
            assert r["mode"] == "unconfigured"
        finally:
            settings.execution_mode = old


class TestQuarantine:
    def test_reject_traversal_and_system32(self):
        assert reject_path("C:\\foo\\..\\bar") == "path traversal"
        assert reject_path("C:\\Windows\\System32\\cmd.exe") == "system directory"

    def test_mock_quarantine_and_restore(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(quarantine_file(path="C:\\temp\\evil.exe", sha256="b" * 64))
            assert r["success"] is True
            assert r["original_path"] == "C:\\temp\\evil.exe"
            assert r["quarantine_path"]
            rb = _run(restore_file(original_path=r["original_path"], quarantine_path=r["quarantine_path"]))
            assert rb["success"] is True
        finally:
            settings.execution_mode = old


class TestPersistence:
    def test_unknown_kind(self):
        r = _run(clean_persistence(kind="random", name_or_path="x"))
        assert r["success"] is False

    def test_run_mock(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(clean_persistence(kind="run", name_or_path="Evil"))
            assert r["success"] is True
        finally:
            settings.execution_mode = old


class TestSnapshotPrepend:
    def test_isolate_batch_prepends_snapshot(self):
        from response_engine.response_executor import response_executor

        order = []
        orig = response_registry.execute

        async def fake(name, **kw):
            order.append(name)
            return {"success": True, "result": {"action": name}}

        response_registry.execute = fake
        try:
            _run(response_executor.execute_actions(
                [{"name": "isolate_host", "params": {"host_ip": "10.0.0.8"}}],
                threat_info={"src_ip": "10.0.0.8"},
            ))
        finally:
            response_registry.execute = orig
        assert order[0] == "forensic_snapshot"
        assert "isolate_host" in order

    def test_snapshot_mock(self):
        old = settings.execution_mode
        settings.execution_mode = "mock"
        try:
            r = _run(forensic_snapshot(host_ip="10.0.0.8", pid=4242))
            assert r["success"] is True
            assert r.get("snapshot_id")
        finally:
            settings.execution_mode = old
