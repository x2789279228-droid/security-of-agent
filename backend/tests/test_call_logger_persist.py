"""CallLogger 规范记录 + 消毒 + 持久化（PR1）。

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

from mcp_guard.call_logger import CallLogger
from mcp_guard.call_record import ARG_JSON_MAX, STR_MAX, arg_digest, sanitize_args, sanitize_str
from mcp_guard.guard_server import McpGuardServer, ToolCallRequest


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset_db():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _log(cl: CallLogger, **kw):
    kwargs = {
        "user_role": "admin",
        "tool_name": "alert_only",
        "arguments": {"message": "ok"},
        "decision": "allow",
        "reason": "default",
        "checks": [{"check": "registry", "passed": True}],
    }
    kwargs.update(kw)
    cl.log(**kwargs)


class CaptureSession:
    def __init__(self, fail_add=False, fail_commit=False):
        self.added = []
        self.committed = False
        self.fail_add = fail_add
        self.fail_commit = fail_commit

    def add(self, obj):
        if self.fail_add:
            raise RuntimeError("db down")
        self.added.append(obj)

    async def commit(self):
        if self.fail_commit:
            raise RuntimeError("commit fail")
        self.committed = True

    async def rollback(self):
        return None


# ── 消毒 ──


def test_sanitize_strips_crlf_and_pipe():
    out = sanitize_args({"msg": "hello\nworld|injected"})
    assert "\n" not in out["msg"]
    assert "|" not in out["msg"]
    assert "hello" in out["msg"]
    assert "world" in out["msg"]


def test_sanitize_truncates_long_string():
    out = sanitize_args({"host": "A" * 1000})
    assert len(out["host"]) <= STR_MAX
    assert out["host"].endswith("…")


def test_sanitize_truncates_large_json():
    # 单字段会先被 STR_MAX 截断；用满 32 个键把 JSON 顶过 4KB
    out = sanitize_args({f"k{i}": "V" * 200 for i in range(32)})
    assert out.get("_truncated") is True
    assert "_preview" in out
    assert out["_orig_bytes"] > ARG_JSON_MAX


def test_sanitize_non_dict_and_never_raises():
    out = sanitize_args("not-a-dict\n|x")
    assert "_invalid_args" in out
    assert "|" not in out["_invalid_args"]
    assert sanitize_args(None)
    assert sanitize_args([1, 2, 3])


def test_sanitize_str_collapses_whitespace():
    assert "\x00" not in sanitize_str("a\x00b")
    assert sanitize_str("a\r\nb") == "a b"


def test_arg_digest_stable():
    a = arg_digest({"ip": "1.2.3.4", "duration": 60})
    b = arg_digest({"duration": 60, "ip": "1.2.3.4"})
    assert a == b
    assert len(a) == 32


# ── 内存 ring / 向后兼容 ──


def test_log_backward_compat_fields():
    cl = CallLogger(persist=False)
    _log(cl, user_role="analyst")
    rec = cl.recent(1)[0]
    for k in ("id", "time", "user_role", "tool_name", "arguments", "decision", "reason", "checks", "exec_status"):
        assert k in rec, f"缺 {k}"
    assert rec["user_role"] == "analyst"
    assert rec["caller_role"] == "analyst"
    assert rec["caller"] == "unknown"
    assert rec["source"] == "mcp_guard"
    assert rec["ts"].endswith("+00:00") or rec["ts"].endswith("Z") or "T" in rec["ts"]
    assert rec["arg_digest"]


def test_log_identity_fields():
    cl = CallLogger(persist=False)
    _log(
        cl,
        caller="agent_executor",
        source="audit_llm",
        session_id="s1",
        trace_id="t1",
        event_id=9,
        tool_match_method="fuzzy",
    )
    rec = cl.recent(1)[0]
    assert rec["caller"] == "agent_executor"
    assert rec["source"] == "audit_llm"
    assert rec["session_id"] == "s1"
    assert rec["trace_id"] == "t1"
    assert rec["event_id"] == 9
    assert rec["tool_match_method"] == "fuzzy"


def test_ring_maxlen_500():
    cl = CallLogger(persist=False)
    for i in range(510):
        _log(cl, arguments={"message": str(i)})
    recs = cl.recent(1000)
    assert len(recs) == 500
    assert recs[0]["arguments"]["message"] == "509"
    assert recs[-1]["arguments"]["message"] == "10"


def test_log_sanitizes_arguments_in_ring():
    cl = CallLogger(persist=False)
    _log(cl, arguments={"cmd": "block\n|rm -rf /"}, reason="ok\npipe|here")
    rec = cl.recent(1)[0]
    assert "\n" not in rec["arguments"]["cmd"]
    assert "|" not in rec["arguments"]["cmd"]
    assert "|" not in rec["reason"]
    assert "\n" not in rec["reason"]


def test_log_never_raises_on_insane_input():
    cl = CallLogger(persist=False)
    cl.log(
        user_role="a\nb",
        tool_name=None,  # type: ignore[arg-type]
        arguments=None,  # type: ignore[arg-type]
        decision="allow",
        reason=None,  # type: ignore[arg-type]
        checks=None,  # type: ignore[arg-type]
        exec_status="success",
        exec_result={"status": "success", "detail": "x" * 5000},
    )
    assert cl.recent(1)


# ── 持久化：失败不抛 / 缓冲 / flush ──


def test_sync_log_enqueues_when_no_event_loop():
    cl = CallLogger(persist=True)
    _log(cl)
    stats = cl.stats()
    assert stats["persist_enabled"] is True
    assert stats["persist_queued"] == 1
    assert stats["total"] == 1


def test_persist_false_does_not_enqueue():
    cl = CallLogger(persist=False)
    _log(cl)
    assert cl.stats()["persist_queued"] == 0


def test_async_persist_failure_enqueues_and_does_not_raise():
    async def boom(_row):
        raise RuntimeError("db down")

    cl = CallLogger(persist=True, persist_impl=boom)

    async def t():
        _log(cl, tool_name="block_ip", arguments={"ip": "1.2.3.4"})
        await asyncio.sleep(0.05)
        assert cl.stats()["persist_queued"] == 1

    _run(t())


def test_flush_fallback_writes_via_session():
    cl = CallLogger(persist=True)
    _log(cl, tool_name="block_ip", arguments={"ip": "8.8.8.8"}, caller="human_api")
    assert cl.stats()["persist_queued"] == 1

    async def t():
        cap = CaptureSession()
        n = await cl.flush_fallback(cap)
        assert n == 1
        assert cap.committed is True
        assert len(cap.added) == 1
        obj = cap.added[0]
        assert obj.tool_name == "block_ip"
        assert obj.caller == "human_api"
        assert obj.arguments["ip"] == "8.8.8.8"
        assert cl.stats()["persist_queued"] == 0

    _run(t())


def test_flush_commit_failure_keeps_buffer():
    cl = CallLogger(persist=True)
    _log(cl)
    assert cl.stats()["persist_queued"] == 1

    async def t():
        n = await cl.flush_fallback(CaptureSession(fail_commit=True))
        assert n == 0
        assert cl.stats()["persist_queued"] == 1

    _run(t())


def test_flush_add_failure_keeps_buffer():
    cl = CallLogger(persist=True)
    _log(cl)
    assert cl.stats()["persist_queued"] == 1

    async def t():
        n = await cl.flush_fallback(CaptureSession(fail_add=True))
        assert n == 0
        assert cl.stats()["persist_queued"] == 1

    _run(t())


def test_query_falls_back_to_memory_on_session_error():
    async def t():
        cl = CallLogger(persist=False)
        _log(cl, tool_name="alert_only", source="api")

        class Boom:
            async def execute(self, *_a, **_k):
                raise RuntimeError("query fail")

        rows = await cl.query(Boom(), limit=10)
        assert len(rows) == 1
        assert rows[0]["tool_name"] == "alert_only"

    _run(t())


def test_query_sqlite_roundtrip():
    async def t():
        await _reset_db()
        from models import async_session

        cl = CallLogger(persist=True)

        async def persist_row(row):
            async with async_session() as s:
                from mcp_guard.call_logger import _insert_row
                await _insert_row(s, row)

        cl._persist_impl = persist_row
        _log(
            cl,
            tool_name="isolate_host",
            arguments={"host": "gw-1"},
            caller="response_engine",
            source="response",
        )
        await asyncio.sleep(0.05)
        async with async_session() as s:
            rows = await cl.query(s, limit=10, source="response")
        assert len(rows) == 1
        assert rows[0]["persisted"] is True
        assert rows[0]["tool_name"] == "isolate_host"
        assert rows[0]["caller"] == "response_engine"
        assert rows[0]["arguments"]["host"] == "gw-1"

    _run(t())


def test_guard_server_log_still_works():
    g = McpGuardServer()
    g.logger = CallLogger(persist=False)
    resp = g.call_tool(ToolCallRequest(
        tool_name="alert_only",
        arguments={"message": "hello\n|x"},
        user_role="admin",
        caller="human_api",
        source="api",
    ))
    assert resp["decision"] in ("allow", "require_confirmation")
    rec = g.logger.recent(1)[0]
    assert rec["caller"] == "human_api"
    assert rec["source"] == "api"
    assert "|" not in rec["arguments"].get("message", "")


def test_scheduler_flush_loop_is_wired():
    text = (Path(__file__).resolve().parents[1] / "scheduler.py").read_text(encoding="utf-8")
    assert "_tool_call_log_flush_loop" in text
    assert "create_task(self._tool_call_log_flush_loop" in text


def test_utc_timestamp_on_record():
    cl = CallLogger(persist=False)
    before = datetime.now(timezone.utc)
    _log(cl)
    rec = cl.recent(1)[0]
    ts = datetime.fromisoformat(rec["ts"])
    if ts.tzinfo is None:
        raise AssertionError("ts must be timezone-aware")
    assert ts >= before.replace(microsecond=0)
