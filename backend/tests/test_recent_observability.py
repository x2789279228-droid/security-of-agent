"""Monitor 空闲 hydration：recent pipelines / thought-chain 摘要不含 prompt。"""
import asyncio
import json
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


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def test_summarize_omits_prompt_bodies():
    from observability.thought_events import summarize_thought_chain

    audit = {
        "status": "completed",
        "prompt": "SECRET_PROMPT",
        "completion": "SECRET_COMPLETION",
        "thinking": "SECRET_THINKING",
        "thought_chain": [
            {"event_id": 7, "kind": "plan", "stage": "decomposer", "title": "plan", "step_id": "e7-plan"},
        ],
    }
    summary = summarize_thought_chain(7, audit)
    blob = json.dumps(summary)
    assert "SECRET_" not in blob
    assert "prompt" not in summary
    assert "completion" not in summary
    assert summary["event_id"] == 7
    assert summary["node_count"] == 1
    assert summary["source"] == "persisted"


def test_summarize_projects_old_audit():
    from observability.thought_events import summarize_thought_chain

    audit = {
        "merged": {"verdict": "confirmed", "threat_detected": True, "confidence": 0.8, "summary": "C2"},
        "rounds_detail": [{"round": 1, "mode": "full", "threat_detected": True, "confidence": 0.8}],
    }
    summary = summarize_thought_chain(11, audit)
    assert summary["source"] == "projected"
    assert summary["node_count"] >= 1


def test_list_recent_thought_chains_skips_prompt():
    async def t():
        await _reset()
        from datetime import datetime, timezone

        from models import SecurityEvent, async_session
        from observability.thought_events import list_recent_thought_chains

        async with async_session() as s:
            s.add(SecurityEvent(
                session_id="t1",
                event_type="C2_BEACON",
                severity="critical",
                src_ip="192.168.1.105",
                message="demo",
                analyzed=True,
                created_at=datetime.now(timezone.utc),
                raw_data={
                    "_audit_llm": {
                        "status": "completed",
                        "prompt": "SECRET_PROMPT",
                        "completion": "do not leak",
                        "thought_chain": [
                            {"event_id": 0, "kind": "plan", "stage": "decomposer", "title": "p"},
                        ],
                    },
                },
            ))
            s.add(SecurityEvent(
                session_id="t2",
                event_type="USER_LOGIN",
                severity="info",
                src_ip="10.0.0.1",
                analyzed=True,
                raw_data={"note": "no audit"},
            ))
            await s.commit()

        async with async_session() as s:
            chains = await list_recent_thought_chains(s, limit=8)
        assert len(chains) == 1
        blob = json.dumps(chains)
        assert "SECRET_PROMPT" not in blob
        assert "do not leak" not in blob
        assert chains[0]["event_type"] == "C2_BEACON"
        assert chains[0]["node_count"] >= 1
        assert "prompt" not in chains[0]
    _run(t())


def test_recent_completed_pipelines_excludes_active():
    from observability.pipeline_tracer import PipelineTracer

    t = PipelineTracer()
    sp = t.start_span("decomposer", event_id=12, session_id="s")
    t.end_span(sp)
    sp2 = t.start_span("executor", event_id=13, session_id="s")
    pipes = t.get_recent_completed_pipelines(limit=8)
    ids = [p["event_id"] for p in pipes]
    assert 12 in ids
    assert 13 not in ids
    done = next(p for p in pipes if p["event_id"] == 12)
    assert done["done"] is True
    assert "decomposer" in done["completed_stages"]
    t.end_span(sp2)


def test_demo_event_is_tagged():
    from demo_traffic import DEMO_EVENT
    assert DEMO_EVENT.get("_demo") is True
    assert DEMO_EVENT.get("event") == "C2_BEACON"
