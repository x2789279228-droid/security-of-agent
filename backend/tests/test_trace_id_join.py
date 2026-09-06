"""W3C trace_id 贯通 llm_traces / thought steps；CAD 步骤并入 thought_chain。"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa
_orig = _sa.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa.create_async_engine = _patched


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_set_trace_context_from_log_data_and_event_fallback():
    from trace_hook import clear_trace_context, get_trace_context, set_trace_context
    clear_trace_context()
    set_trace_context(
        caller="audit_pipeline", event_id=7,
        log_data={"_trace_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    )
    ctx = get_trace_context()
    assert ctx["trace_id"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert "log_data" not in ctx
    clear_trace_context()
    set_trace_context(caller="audit_pipeline", event_id=99)
    ctx = get_trace_context()
    assert len(ctx["trace_id"]) == 32
    clear_trace_context()


def test_thought_step_inherits_trace_id():
    from trace_hook import clear_trace_context, set_trace_context
    from observability.thought_events import compact_step, emit_plan, thought_buffer
    thought_buffer.clear()
    clear_trace_context()
    set_trace_context(event_id=5, trace_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    steps = emit_plan(
        {"audit_depth": "standard", "sub_tasks": [{"task_id": "t1", "type": "q"}]},
        event_id=5,
    )
    assert steps[0]["trace_id"] == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    compact = compact_step({"event_id": 5, "kind": "plan", "stage": "decomposer",
                            "trace_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
    assert compact["trace_id"] == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    clear_trace_context()


def test_emit_trace_persists_trace_id():
    from models import AgentTrace, Base, async_session, engine
    from sqlalchemy import select
    from trace_hook import clear_trace_context, emit_trace, set_trace_context

    async def t():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_session() as s:
            await s.execute(AgentTrace.__table__.delete())
            await s.commit()
        clear_trace_context()
        set_trace_context(
            caller="audit_pipeline", event_id=3, session_id="s",
            trace_id="cccccccccccccccccccccccccccccccc",
        )
        emit_trace(operation="review", model="m", total_tokens=1, status="success")
        await asyncio.sleep(0.35)
        async with async_session() as s:
            rows = (await s.execute(
                select(AgentTrace).where(AgentTrace.event_id == 3)
            )).scalars().all()
        assert rows
        assert rows[0].trace_id == "cccccccccccccccccccccccccccccccc"
        clear_trace_context()

    _run(t())


def test_merge_cad_steps_into_thought_chain():
    from observability.thought_events import merge_thought_into_raw
    raw = {"_audit_llm": {"thought_chain": [{"step_id": "a", "kind": "plan"}]}}
    out = merge_thought_into_raw(raw, [
        {"step_id": "a", "kind": "plan"},
        {"step_id": "cad-1", "kind": "cad", "title": "穿透验证"},
    ])
    ids = [s["step_id"] for s in out["_audit_llm"]["thought_chain"]]
    assert ids == ["a", "cad-1"]
