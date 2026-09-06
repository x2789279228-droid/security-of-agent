"""P1 事件驱动流水线单测 (ingest_pipeline).

覆盖验收 P1-A..P1-D / P1-G / P1-H:
  - detect: anomaly 抛异常 → empty_anomaly(reasons=['anomaly_error']) + DetectorError,
    sigma 照常执行, persist 不中断;
  - detect: sigma 抛异常 → empty_sigma() + DetectorError, anomaly 结果保留;
  - ingest_parallel_detect=True 走 asyncio.gather; False 时 anomaly→sigma 顺序;
  - Sigma critical 命中把 anomaly_score 抬到 0.75 且 is_anomaly=True (reasons 含 Sigma命中:);
  - run_one / LogIngestor.ingest facade 返回 key 集合与旧 ingest 一致 (P1-G);
  - dispatch FastPath 仍 create_task + 按 ingest_fastpath_retries 重试, 不 await SSH (P1-H).

跟随 tests/conftest + test_arch_unification 模式: sqlite 内存库 + pytest-asyncio。
"""
import asyncio
import sys
import types

import pytest

from anomaly_detector import AnomalyReport


# ── helpers ──

def _report(score=0.0, is_anomaly=False, reasons=None) -> AnomalyReport:
    return AnomalyReport(
        event_id=0, anomaly_score=score, is_anomaly=is_anomaly,
        deviation_sigma=0.0, reasons=list(reasons or []),
    )


def _no_sigma() -> dict:
    return {"detected": False, "rule_count": 0, "attack_types": [],
            "max_severity": "", "hits": []}


async def _reset_db():
    from models import Base, engine, _migrate_existing_tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_existing_tables(conn)


class _StubIngestor:
    """dispatch 依赖的 LogIngestor 侧面最小桩 (无 DB/索引/LLM 副作用)。"""

    def __init__(self, fastpath_allow=False):
        self._fp = fastpath_allow
        self.tracked = []

    async def _index_background(self, session_id, log_data, event_text, is_anomaly):
        return None

    def _fastpath_allow(self, key: str) -> bool:
        return self._fp

    def _track_audit_status(self, event_id: int, status: str, **extra):
        self.tracked.append((event_id, status, dict(extra)))

    async def _fallback_analysis(self, event_id, log_data, anomaly_report, reason):
        return None

    async def _mark_analyzed(self, event_id, **kw):
        return None


def _patch_audit_submit(monkeypatch, result="queued"):
    import audit_worker as _aw

    async def _fake_submit(*, session_id, event_id, log_data, anomaly_report):
        return result

    monkeypatch.setattr(_aw.audit_worker, "submit", _fake_submit)


def _patch_detectors(monkeypatch, anomaly_result=None, sigma_result=None):
    """monkeypatch 两个检测器; 返回 (a_calls, s_calls) 供断言调用次数。"""
    from anomaly_detector import anomaly_detector as _ad
    from sigma_detector import sigma_detector as _sd
    a_calls, s_calls = [], []

    async def _anomaly(event):
        a_calls.append(event)
        return anomaly_result if anomaly_result is not None else _report()

    def _sigma(event):
        s_calls.append(event)
        return sigma_result if sigma_result is not None else _no_sigma()

    monkeypatch.setattr(_ad, "analyze", _anomaly)
    monkeypatch.setattr(_sd, "detect_for_event", _sigma)
    return a_calls, s_calls


def _patch_anomaly_raise(monkeypatch, exc=RuntimeError("anomaly crash")):
    from anomaly_detector import anomaly_detector as _ad

    async def _boom(event):
        raise exc

    monkeypatch.setattr(_ad, "analyze", _boom)


def _patch_sigma_raise(monkeypatch, exc=RuntimeError("sigma crash")):
    from sigma_detector import sigma_detector as _sd

    def _boom(event):
        raise exc

    monkeypatch.setattr(_sd, "detect_for_event", _boom)


# ── P1-A: anomaly 抛异常 → 隔离 + persist 不中断 ──

@pytest.mark.asyncio
async def test_anomaly_raises_persist_still_happens(monkeypatch):
    from sqlalchemy import select, func
    from models import async_session, SecurityEvent
    from ingest_pipeline import run_one

    await _reset_db()
    _patch_anomaly_raise(monkeypatch)
    s_calls = []
    from sigma_detector import sigma_detector as _sd

    def _sigma(event):
        s_calls.append(event)
        return _no_sigma()

    monkeypatch.setattr(_sd, "detect_for_event", _sigma)
    _patch_audit_submit(monkeypatch)

    evt = {"eventId": "p1a-1", "event": "LOGIN", "severity": "high",
           "src_ip": "10.0.0.9", "message": "login"}
    async with async_session() as s:
        res = await run_one(s, "sess-a", evt, ingestor=_StubIngestor())
        total = (await s.execute(
            select(func.count(SecurityEvent.id)))).scalar()

    # persist 照常发生
    assert total == 1
    assert res.status == "review_queued"
    # 隔离: anomaly 失败 → empty_anomaly + DetectorError, 不中断 sigma
    assert res.anomaly["score"] == 0.0
    assert res.anomaly["reasons"] == ["anomaly_error"]
    assert any("anomaly" in e for e in res.detector_errors)
    assert len(s_calls) == 1, "sigma 必须仍然执行"


# ── P1-B: sigma 抛异常 → empty_sigma + error, anomaly 保留 ──

@pytest.mark.asyncio
async def test_sigma_raises_anomaly_kept(monkeypatch):
    from ingest_pipeline import detect
    from anomaly_detector import anomaly_detector as _ad
    from sigma_detector import sigma_detector as _sd

    async def _anomaly(event):
        return _report(score=0.2, is_anomaly=False, reasons=["baseline_ok"])

    monkeypatch.setattr(_ad, "analyze", _anomaly)
    _patch_sigma_raise(monkeypatch)

    dr = await detect({"event": "SCAN", "severity": "low", "message": "m"})
    assert dr.anomaly.anomaly_score == 0.2
    assert dr.anomaly.reasons == ["baseline_ok"]
    assert dr.sigma["detected"] is False
    assert any("sigma" in e.detector for e in dr.errors)
    assert not any("anomaly" in e.detector for e in dr.errors)
    # 融合结果写回 log_data (in-place)
    assert dr.log_data["_anomaly"]["score"] == 0.2
    assert dr.log_data["_sigma"]["detected"] is False


# ── P1-C: parallel flag → asyncio.gather ──

@pytest.mark.asyncio
async def test_parallel_flag_uses_gather(monkeypatch):
    from config import settings
    import ingest_pipeline as ip
    import asyncio as real_asyncio

    real_gather = real_asyncio.gather
    calls = []

    class _Probe:
        def __getattr__(self, name):
            if name == "gather":
                def rec(*a, **k):
                    calls.append(len(a))
                    return real_gather(*a, **k)
                return rec
            return getattr(real_asyncio, name)

    monkeypatch.setattr(settings, "ingest_parallel_detect", True)
    monkeypatch.setattr(ip, "asyncio", _Probe())
    _patch_detectors(monkeypatch)

    await ip.detect({"event": "E1", "severity": "info"})
    assert calls, "ingest_parallel_detect=True 必须经 asyncio.gather"


@pytest.mark.asyncio
async def test_sequential_flag_runs_anomaly_then_sigma(monkeypatch):
    from config import settings
    import ingest_pipeline as ip
    import asyncio as real_asyncio

    calls_gather = []
    real_gather = real_asyncio.gather

    class _Probe:
        def __getattr__(self, name):
            if name == "gather":
                def rec(*a, **k):
                    calls_gather.append(1)
                    return real_gather(*a, **k)
                return rec
            return getattr(real_asyncio, name)

    monkeypatch.setattr(settings, "ingest_parallel_detect", False)
    monkeypatch.setattr(ip, "asyncio", _Probe())

    order = []
    from anomaly_detector import anomaly_detector as _ad
    from sigma_detector import sigma_detector as _sd

    async def _anomaly(event):
        order.append("anomaly")
        return _report()

    def _sigma(event):
        order.append("sigma")
        return _no_sigma()

    monkeypatch.setattr(_ad, "analyze", _anomaly)
    monkeypatch.setattr(_sd, "detect_for_event", _sigma)

    await ip.detect({"event": "E1", "severity": "info"})
    assert not calls_gather, "ingest_parallel_detect=False 不得使用 gather"
    assert order == ["anomaly", "sigma"]


# ── P1-D: Sigma critical 命中融合抬分 ──

@pytest.mark.asyncio
async def test_sigma_critical_hit_lifts_score(monkeypatch):
    from ingest_pipeline import detect
    from anomaly_detector import anomaly_detector as _ad
    from sigma_detector import sigma_detector as _sd

    async def _anomaly(event):
        return _report(score=0.1, is_anomaly=False, reasons=["baseline_ok"])

    def _sigma(event):
        return {
            "detected": True, "rule_count": 2,
            "attack_types": ["t1190", "C2"], "max_severity": "critical",
            "hits": [{"rule_id": "r1", "confidence": "high"}],
        }

    monkeypatch.setattr(_ad, "analyze", _anomaly)
    monkeypatch.setattr(_sd, "detect_for_event", _sigma)

    dr = await detect({"event": "EXPLOIT", "severity": "info", "message": "x"})
    # critical floor = 0.75 (与旧 log_ingestion.ingest EXACT)
    assert dr.anomaly.anomaly_score == 0.75
    assert dr.anomaly.is_anomaly is True
    assert any(r.startswith("Sigma命中:") and "t1190" in r for r in dr.anomaly.reasons)
    assert dr.log_data["_anomaly"]["score"] == 0.75
    assert dr.log_data["_anomaly"]["is_anomaly"] is True
    assert dr.log_data["_sigma"]["detected"] is True


# ── P1-G: run_one / facade 返回 key 与旧 ingest 一致 ──

@pytest.mark.asyncio
async def test_run_one_return_keys_match_facade(monkeypatch):
    from models import async_session
    from ingest_pipeline import run_one
    from log_ingestion import LogIngestor

    await _reset_db()
    _patch_detectors(monkeypatch)
    _patch_audit_submit(monkeypatch)

    evt = {"eventId": "p1g-1", "event": "BRUTE_FORCE", "severity": "high",
           "src_ip": "10.1.1.1", "message": "brute"}
    async with async_session() as s:
        run_result = await run_one(s, "sess-g", evt, ingestor=_StubIngestor())
        http_dict = run_result.as_http_dict()

        assert set(http_dict.keys()) == {
            "status", "event_id", "event_type", "severity", "anomaly", "sigma",
        }
        assert http_dict["status"] == "review_queued"
        assert isinstance(http_dict["event_id"], int) and http_dict["event_id"] > 0
        assert http_dict["event_type"] == "BRUTE_FORCE"
        assert http_dict["severity"] == "high"
        assert http_dict["anomaly"]["score"] == 0.0

        # facade (LogIngestor.ingest) 返回相同 key 集合 (P1-G 旧调用方不断)
        ing = LogIngestor()
        monkeypatch.setattr(ing, "_fastpath_allow", lambda key: False)
        facade_dict = await ing.ingest(s, "sess-g", dict(evt, eventId="p1g-2"))
        assert set(facade_dict.keys()) == set(http_dict.keys())
        assert facade_dict["status"] == "review_queued"
        assert facade_dict["event_type"] == "BRUTE_FORCE"


# ── P1-H: FastPath create_task + 重试, ingest 不 await SSH ──

@pytest.mark.asyncio
async def test_dispatch_fastpath_retries_without_blocking(monkeypatch):
    from models import async_session
    from config import settings
    from ingest_pipeline import run_one
    from anomaly_detector import anomaly_detector as _ad
    from sigma_detector import sigma_detector as _sd

    await _reset_db()
    monkeypatch.setattr(settings, "ingest_fastpath_retries", 2)
    retries = int(getattr(settings, "ingest_fastpath_retries", 2))
    attempts_expected = retries + 1

    async def _anomaly(event):
        return _report(score=0.8, is_anomaly=True, reasons=["spike"])

    monkeypatch.setattr(_ad, "analyze", _anomaly)
    monkeypatch.setattr(_sd, "detect_for_event", _no_sigma)
    _patch_audit_submit(monkeypatch)

    # 桩掉 response_engine, 避免真编排器/SSH
    calls = []

    class _FakeOrch:
        async def on_threat_detected(self, **kw):
            calls.append(kw)
            raise RuntimeError("ssh down")

    stub_mod = types.ModuleType("response_engine")
    stub_mod.get_orchestrator = lambda: _FakeOrch()
    monkeypatch.setitem(sys.modules, "response_engine", stub_mod)

    evt = {"eventId": "p1h-1", "event": "EXPLOIT", "severity": "critical",
           "src_ip": "8.8.8.8", "threat_type": "exploit", "message": "boom"}
    async with async_session() as s:
        res = await run_one(s, "sess-h", evt,
                            ingestor=_StubIngestor(fastpath_allow=True))
        assert res.status == "review_queued"
        # 不阻塞: run_one 返回时后台重试尚未跑满 (create_task 语义)
        assert len(calls) < attempts_expected

    # 后台任务继续重试直到 ingest_fastpath_retries 后打日志
    for _ in range(100):
        if len(calls) >= attempts_expected:
            break
        await asyncio.sleep(0.05)
    assert len(calls) == attempts_expected


@pytest.mark.asyncio
async def test_python_ingest_batch_failure_returns_false(monkeypatch):
    """P1-J: run_many 抛错 → _ingest_python_batch False, 调用方不得 commit。"""
    from kafka_consumer import KafkaConsumerManager

    async def boom(session, events, *, ingestor=None):
        raise RuntimeError("persist down")

    import ingest_pipeline as ip
    monkeypatch.setattr(ip, "run_many", boom)
    mgr = KafkaConsumerManager()
    ok = await mgr._ingest_python_batch([("s", {"event": "SCAN", "severity": "info"})])
    assert ok is False
    assert mgr._stats["python_ingest_consumed"] == 0
