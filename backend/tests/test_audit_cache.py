"""audit_cache 单测 + _audit_pipeline 缓存路由 (R-A / R-E)。

覆盖:
  - put 后同 log_data get 命中并返回 verdict 字段(lane=cache);
  - 不同 src_ip → 不同签名 → miss;
  - _audit_pipeline: 缓存命中 → quality=cache 打标、复用 verdict,
    **不调** start_audit_workflow / audit_single.run (0 LLM / 0 Temporal)。
"""
import pytest

import audit_cache


def _flush_cache():
    audit_cache._MEM.clear()


def _log(src="192.0.2.55", **over):
    base = {
        "severity": "critical",
        "event": "EXPLOIT",
        "threat_type": "EXPLOIT",
        "src_ip": src,
        "message": "exploit attempt",
        "_sigma": {"detected": True, "max_severity": "critical",
                  "hits": [{"rule_id": "r-c2-1", "confidence": "high"}]},
    }
    base.update(over)
    return base


def _report(score=0.8):
    class _AR:
        pass
    r = _AR()
    r.anomaly_score = score
    r.reasons = ["sig"]
    r.is_anomaly = True
    r.deviation_sigma = 0.0
    return r


async def _reset_db():
    from models import Base, engine, _migrate_existing_tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_existing_tables(conn)


@pytest.mark.asyncio
async def test_put_then_get_same_log_returns_verdict():
    _flush_cache()
    log_data = _log(src="198.51.100.10", event="SIG_EXPLOIT_A", threat_type="SIG_EXPLOIT_A")
    verdict = {
        "threat_detected": True, "confidence": 0.9,
        "severity": "critical", "verdict": "confirmed",
    }
    await audit_cache.put(log_data, verdict)

    got = await audit_cache.get(log_data)
    assert got is not None
    assert got["threat_detected"] is True
    assert got["confidence"] == 0.9
    assert got["verdict"] == "confirmed"
    assert got["severity"] == "critical"
    assert got["lane"] == "cache"


@pytest.mark.asyncio
async def test_different_src_ip_misses():
    _flush_cache()
    src_a = _log(src="198.51.100.11", event="SIG_EXPLOIT_B", threat_type="SIG_EXPLOIT_B")
    src_b = _log(src="198.51.100.12", event="SIG_EXPLOIT_B", threat_type="SIG_EXPLOIT_B")
    await audit_cache.put(src_a, {
        "threat_detected": True, "confidence": 0.8,
        "severity": "high", "verdict": "suspicious",
    })
    assert await audit_cache.get(src_a) is not None
    # 同类型同规则同级别, 仅 src_ip 不同 → 不同签名 → miss
    assert await audit_cache.get(src_b) is None


@pytest.mark.asyncio
async def test_pipeline_cache_hit_skips_temporal_and_llm(monkeypatch):
    """R-E/R-A: 缓存命中 → quality=cache; start_audit_workflow/audit_single 不得调用。

    用 sigma critical 强事件(P0 llm_agent 车道)验证: 即使本会进 Temporal,
    缓存命中也在 Temporal 之前短路。
    """
    await _reset_db()
    _flush_cache()

    from log_ingestion import log_ingestor
    from models import SecurityEvent, async_session

    async def _noop(*a, **k):
        return None
    monkeypatch.setattr(log_ingestor, "_auto_create_case_bg", _noop)

    async def boom_start(*a, **k):
        raise AssertionError("cache hit 不得调用 start_audit_workflow")
    import temporal.client as _tc
    monkeypatch.setattr(_tc, "start_audit_workflow", boom_start)

    async def boom_single(*a, **k):
        raise AssertionError("cache hit 不得调用 audit_single.run")
    import agents.audit_single as _as_mod
    monkeypatch.setattr(_as_mod, "run", boom_single)

    log_data = _log(src="203.0.113.55")
    await audit_cache.put(log_data, {
        "threat_detected": True, "confidence": 0.93,
        "severity": "critical", "verdict": "confirmed",
    })

    async with async_session() as s:
        evt = SecurityEvent(
            event_id="cache-route-1", session_id="sess-c", event_type="EXPLOIT",
            severity="critical", src_ip="203.0.113.55",
            raw_data=dict(log_data), analyzed=False,
        )
        s.add(evt)
        await s.commit()
        await s.refresh(evt)
        evt_id = evt.id

    await log_ingestor._audit_pipeline(
        "sess-c", evt_id, dict(log_data), _report(0.8), max_rounds=3,
    )

    async with async_session() as s:
        db_evt = await s.get(SecurityEvent, evt_id)
        audit = (db_evt.raw_data or {}).get("_audit_llm") or {}
        assert db_evt.analyzed is True
        assert audit.get("quality") == "cache"
        assert audit.get("status") == "completed"
        assert audit.get("lane") == "cache"
        assert audit.get("threat_detected") is True
        assert audit.get("verdict") == "confirmed"
        assert audit.get("confidence") == 0.93
