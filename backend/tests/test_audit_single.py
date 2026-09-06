"""audit_single (llm_single 车道) 单测 + 路由验收 (R-B/R-C/R-D)。

覆盖:
  - summary.llm.chat 返回 JSON → run() 解析出 threat_detected/verdict/confidence;
  - chat 超时(> timeout_s) → 返回 {"fallback": True, "error": "audit_single_timeout"};
  - chat 返回降级/非 JSON → fallback 收口, 不抛裸异常;
  - 路由: llm_single 车道经 _audit_pipeline 只走 audit_single.run,
    **禁止** start_audit_workflow (R-B); 成功打 quality=llm + lane=llm_single (R-D)。
"""
import asyncio
import json

import pytest

import summary_compression as _sc


def _report(score=0.6, reasons=None):
    class _AR:
        pass
    r = _AR()
    r.anomaly_score = score
    r.reasons = list(reasons or ["spike"])
    r.is_anomaly = bool(score >= 0.6)
    r.deviation_sigma = 0.0
    return r


def _log(**over):
    base = {
        "severity": "high",
        "event": "C2_BEACON",
        "threat_type": "C2_BEACON",
        "src_ip": "198.51.100.7",
        "dst_ip": "10.0.0.5",
        "message": "beacon outbound 443",
        "_sigma": {"detected": True, "max_severity": "medium", "hits": []},
    }
    base.update(over)
    return base


async def _reset_db():
    from models import Base, engine, _migrate_existing_tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_existing_tables(conn)


def _flush_cache():
    import audit_cache
    audit_cache._MEM.clear()


@pytest.mark.asyncio
async def test_run_parses_threat_detected(monkeypatch):
    """chat 返回合法 JSON → 解析出字段, 且恰好 1 次 chat(temperature=0.1)。"""
    calls = []

    async def fake_chat(messages, temperature=0.3):
        calls.append({"roles": [m["role"] for m in messages], "temperature": temperature})
        return json.dumps({
            "threat_detected": True,
            "confidence": 0.87,
            "severity": "critical",
            "verdict": "confirmed",
            "summary": "C2 外联与已知信标特征一致",
        }, ensure_ascii=False)

    monkeypatch.setattr(_sc.summary.llm, "chat", fake_chat)

    from agents.audit_single import run
    res = await run(event_id=1, session_id="s1", log_data=_log(),
                    anomaly_report=_report(0.7), timeout_s=5)

    assert res.get("fallback") is not True
    assert res["threat_detected"] is True
    assert res["confidence"] == 0.87
    assert res["verdict"] == "confirmed"
    assert res["status"] == "completed"
    assert res["quality"] == "llm"
    assert res["lane"] == "llm_single"
    assert res["severity"] == "critical"
    assert "summary" in res
    # 恰好 1 次 LLM; roles = [system, user]; temperature=0.1
    assert len(calls) == 1
    assert calls[0]["roles"] == ["system", "user"]
    assert calls[0]["temperature"] == 0.1


@pytest.mark.asyncio
async def test_run_timeout_returns_fallback(monkeypatch):
    """chat 超过 timeout_s → 返回 fallback-ish 结果(不抛裸异常)。"""
    async def slow_chat(messages, temperature=0.3):
        await asyncio.sleep(30)
        return "{}"

    monkeypatch.setattr(_sc.summary.llm, "chat", slow_chat)

    from agents.audit_single import run
    res = await run(event_id=2, session_id="s1", log_data=_log(),
                    anomaly_report=_report(), timeout_s=0.05)

    assert isinstance(res, dict)
    assert res.get("fallback") is True
    assert res.get("status") == "failed"
    assert "timeout" in str(res.get("error") or "").lower()


@pytest.mark.asyncio
async def test_run_degraded_and_parse_fail_return_fallback(monkeypatch):
    """LLM 降级 JSON / 非 JSON 输出 → fallback, 不进入正常 payload。"""
    from agents.audit_single import run

    async def degraded_chat(messages, temperature=0.3):
        return json.dumps({"error": "LLM调用失败", "fallback": True}, ensure_ascii=False)

    monkeypatch.setattr(_sc.summary.llm, "chat", degraded_chat)
    res = await run(event_id=3, session_id="s1", log_data=_log(),
                    anomaly_report=_report(), timeout_s=5)
    assert res.get("fallback") is True
    assert "fallback" in str(res.get("error") or "")

    async def garbage_chat(messages, temperature=0.3):
        return "这不是 JSON 输出, 只是一段散文。"

    monkeypatch.setattr(_sc.summary.llm, "chat", garbage_chat)
    res2 = await run(event_id=4, session_id="s1", log_data=_log(),
                     anomaly_report=_report(), timeout_s=5)
    assert res2.get("fallback") is True
    assert res2.get("error") == "audit_single_parse_error"


@pytest.mark.asyncio
async def test_llm_single_lane_never_starts_temporal(monkeypatch):
    """R-B: P1 llm_single 事件经 _audit_pipeline → audit_single.run, start_audit_workflow 不得被调用。

    同时验证 R-D: 事件打 quality=llm / lane=llm_single, 且结论写入 audit_cache。
    """
    await _reset_db()
    _flush_cache()

    import log_ingestion
    from log_ingestion import log_ingestor
    from models import SecurityEvent, async_session

    # 后台 case 聚合不参与本测试
    async def _noop(*a, **k):
        return None
    monkeypatch.setattr(log_ingestor, "_auto_create_case_bg", _noop)

    # audit_single.run 桩: 返回快审成功 payload
    single_calls = []

    async def fake_run(event_id, session_id, log_data, anomaly_report, timeout_s=15):
        single_calls.append((event_id, timeout_s))
        return {
            "status": "completed", "quality": "llm", "lane": "llm_single",
            "threat_detected": True, "confidence": 0.8, "severity": "high",
            "verdict": "suspicious", "summary": "单测快审结论",
        }

    import agents.audit_single as _as_mod
    monkeypatch.setattr(_as_mod, "run", fake_run)

    # start_audit_workflow 若被调用 → 立即失败
    async def boom_start(*a, **k):
        raise AssertionError("llm_single 车道禁止 start_audit_workflow (R-B)")

    import temporal.client as _tc
    monkeypatch.setattr(_tc, "start_audit_workflow", boom_start)

    # critical severity → P1 / llm_single (非流量型, 无 sigma/强信号)
    log_data = _log(severity="critical", src_ip="203.0.113.9",
                    _sigma={"detected": False, "hits": []})
    async with async_session() as s:
        evt = SecurityEvent(
            event_id="as-route-1", session_id="sess-r", event_type="C2_BEACON",
            severity="critical", src_ip="203.0.113.9",
            raw_data=dict(log_data), analyzed=False,
        )
        s.add(evt)
        await s.commit()
        await s.refresh(evt)
        evt_id = evt.id

    await log_ingestor._audit_pipeline(
        "sess-r", evt_id, dict(log_data), _report(0.2), max_rounds=3,
    )

    # 只走了 audit_single, 没碰 Temporal
    assert len(single_calls) == 1
    assert single_calls[0][0] == evt_id

    async with async_session() as s:
        db_evt = await s.get(SecurityEvent, evt_id)
        audit = (db_evt.raw_data or {}).get("_audit_llm") or {}
        assert db_evt.analyzed is True
        assert audit.get("quality") == "llm"
        assert audit.get("lane") == "llm_single"
        assert audit.get("status") == "completed"
        assert audit.get("threat_detected") is True
        assert audit.get("verdict") == "suspicious"

    # R-D: 结论已写入 audit_cache(同签名可复用)
    import audit_cache
    cached = await audit_cache.get(log_data)
    assert cached is not None
    assert cached.get("verdict") == "suspicious"
    assert cached.get("lane") == "cache"
