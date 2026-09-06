"""PR3: 三链 tool telemetry 汇流（response / audit_llm / self_play）。"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from mcp_guard.behavior_detector import BehaviorDetector
from mcp_guard.call_logger import CallLogger
from mcp_guard.telemetry import args_from_threat, ingest_tool_call
from security_guard.security_guard import SecurityGuard


def test_ingest_tags_source_and_logs():
    log = CallLogger(persist=False)
    det = BehaviorDetector(enabled=True, persist=False, min_samples=30)
    ingest_tool_call(
        tool_name="block_ip",
        arguments={"ip": "8.8.8.8", "duration": 3600},
        caller="response_engine",
        source="response",
        decision="allow",
        exec_status="success",
        logger_obj=log,
        detector=det,
    )
    rec = log.recent(1)[0]
    assert rec["source"] == "response"
    assert rec["caller"] == "response_engine"
    assert rec["tool_name"] == "block_ip"
    assert rec["arguments"]["ip"] == "8.8.8.8"


def test_ingest_audit_llm_and_self_play_not_learned():
    log = CallLogger(persist=False)
    det = BehaviorDetector(enabled=True, persist=False, min_samples=30)
    ingest_tool_call(
        tool_name="event_store.query",
        arguments={"src_ip": "10.0.0.1", "limit": 50},
        caller="agent_executor",
        source="audit_llm",
        decision="allow",
        exec_status="success",
        duration_ms=12.5,
        logger_obj=log,
        detector=det,
    )
    for i in range(10):
        ingest_tool_call(
            tool_name="block_ip",
            arguments={"ip": f"9.9.{i}.1", "duration": 60},
            caller="red_agent",
            source="self_play",
            decision="allow",
            logger_obj=log,
            detector=det,
        )
    recs = log.recent(20)
    sources = {r["source"] for r in recs}
    assert "audit_llm" in sources
    assert "self_play" in sources
    sig = det.get_signature("block_ip", "red_agent")
    assert sig is None or sig["sample_count"] == 0
    audit = next(r for r in recs if r["source"] == "audit_llm")
    assert audit["duration_ms"] == 12.5


def test_args_from_threat_block_ip():
    args = args_from_threat("block_ip", {"src_ip": "10.1.2.3", "severity": "high"})
    assert args["ip"] == "10.1.2.3"


def test_security_guard_record_does_not_block_and_emits():
    log = CallLogger(persist=False)
    det = BehaviorDetector(enabled=True, persist=False, min_samples=30)
    seen = []

    def wrapped(**kw):
        kw.setdefault("logger_obj", log)
        kw.setdefault("detector", det)
        seen.append(kw)
        return ingest_tool_call(**kw)

    import mcp_guard.telemetry as tel
    orig = tel.ingest_tool_call
    tel.ingest_tool_call = wrapped
    try:
        g = SecurityGuard()
        threat = {
            "severity": "high",
            "threat_level": "high",
            "src_ip": "8.8.4.4",
            "message": "C2 beacon detected from host",
            "reason": "C2 beacon detected from host",
        }
        inspected = g.inspect("block_ip", threat)
        assert inspected["allowed"] is True
        g.record("block_ip", threat, {"success": True})
    finally:
        tel.ingest_tool_call = orig

    assert seen
    assert seen[-1]["source"] == "response"
    assert seen[-1]["decision"] == "allow"
    rec = log.recent(1)[0]
    assert rec["source"] == "response"
    assert rec["tool_name"] == "block_ip"


def test_security_guard_inspect_deny_emits_deny():
    log = CallLogger(persist=False)
    det = BehaviorDetector(enabled=True, persist=False, min_samples=30)
    import mcp_guard.telemetry as tel
    orig = tel.ingest_tool_call

    def wrapped(**kw):
        kw.setdefault("logger_obj", log)
        kw.setdefault("detector", det)
        return orig(**kw)

    tel.ingest_tool_call = wrapped
    try:
        g = SecurityGuard()
        # viewer-level: isolate_host vs low threat → intent deny
        out = g.inspect("isolate_host", {
            "threat_level": "low",
            "reason": "just testing isolate",
            "src_ip": "10.0.0.9",
        })
        assert out["allowed"] is False
    finally:
        tel.ingest_tool_call = orig
    rec = log.recent(1)[0]
    assert rec["decision"] == "deny"
    assert rec["source"] == "response"
    assert rec["exec_status"] == "blocked"


def test_executor_emits_audit_llm_source():
    from audit_types import ToolCall
    from agents.agent_executor import Executor

    log = CallLogger(persist=False)
    det = BehaviorDetector(enabled=True, persist=False, min_samples=30)
    import mcp_guard.telemetry as tel
    orig = tel.ingest_tool_call

    def wrapped(**kw):
        kw.setdefault("logger_obj", log)
        kw.setdefault("detector", det)
        return orig(**kw)

    tel.ingest_tool_call = wrapped

    async def fake_exec(name, **kw):
        return [{"id": 1, "event_type": "PORT_SCAN"}]

    import agents.agent_executor as ex_mod
    import models as models_mod
    orig_reg = ex_mod.tool_registry.execute
    orig_session = models_mod.async_session
    ex_mod.tool_registry.execute = fake_exec

    class _CM:
        async def __aenter__(self):
            return object()
        async def __aexit__(self, *a):
            return False

    models_mod.async_session = lambda: _CM()
    try:
        async def t():
            exe = Executor()
            results = await exe._execute_parallel(
                [ToolCall(call_id="c1", task_id="t1", tool="event_store.query",
                          args={"src_ip": "10.0.0.5", "limit": 10})],
                session=None,
            )
            assert results[0].success is True
        asyncio.new_event_loop().run_until_complete(t())
    finally:
        tel.ingest_tool_call = orig
        ex_mod.tool_registry.execute = orig_reg
        models_mod.async_session = orig_session

    rec = log.recent(1)[0]
    assert rec["source"] == "audit_llm"
    assert rec["caller"] == "agent_executor"
    assert rec["tool_name"] == "event_store.query"
    assert rec["exec_status"] == "success"
    assert rec["arguments"]["src_ip"] == "10.0.0.5"
    assert "session" not in rec["arguments"]


def test_ingest_failure_does_not_raise():
    ingest_tool_call(
        tool_name="block_ip",
        arguments={"ip": "1.2.3.4"},
        logger_obj=None,
        detector=None,
    )
