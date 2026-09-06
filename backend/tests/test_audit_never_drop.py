"""P0/P1 审计 never-drop: 内存队列满时
Redis PQ → Kafka overflow topic → 进程内 _p0_overflow deque, 永不 overflow。
P2/P3 队列满仍 overflow (与 test_audit_worker.test_queue_overflow_p3 一致)。
"""
import asyncio

import pytest
from prometheus_client import generate_latest

import log_ingestion
from audit_triage import score_event
from audit_worker import AuditWorkerPool


class _AR_Low:
    anomaly_score = 0.2
    reasons = []
    is_anomaly = False
    deviation_sigma = 0.0


class _AR_High:
    anomaly_score = 0.9
    reasons = ["anomaly:0.90"]
    is_anomaly = True
    deviation_sigma = 0.0


P0_LOG = {"severity": "critical", "_sigma": {"detected": True, "max_severity": "critical"}}
P1_LOG = {"severity": "critical"}
P3_LOG = {"severity": "info"}


def _hanging_ingestor(block: asyncio.Event, calls: list):
    async def hang(session_id, event_id, log_data, anomaly_report, max_rounds=3):
        calls.append(event_id)
        await block.wait()

    class _Ing:
        _audit_pipeline = staticmethod(hang)

        @staticmethod
        def _audit_task_done(_t):
            return None

    return _Ing


@pytest.fixture()
def full_pool_env(monkeypatch):
    """workers=1, queue_max=1, pipeline 挂起 → 1 inflight + 1 queued 即满。"""
    from config import settings
    monkeypatch.setattr(settings, "audit_workers", 1)
    monkeypatch.setattr(settings, "audit_queue_max", 1)
    block = asyncio.Event()
    calls: list = []
    monkeypatch.setattr(log_ingestion, "log_ingestor", _hanging_ingestor(block, calls))
    return block, calls


async def _fill(pool: AuditWorkerPool):
    """占据 1 inflight + 1 queued → queue_depth() >= queue_max()。"""
    st = await pool.submit(session_id="s", event_id=1, log_data=P3_LOG, anomaly_report=_AR_Low())
    assert st == "queued"
    await asyncio.sleep(0.05)  # worker 取走 ev1 → inflight
    st = await pool.submit(session_id="s", event_id=2, log_data=P3_LOG, anomaly_report=_AR_Low())
    assert st == "queued"


@pytest.mark.asyncio
async def test_p0_pq_ok_returns_shed(monkeypatch, full_pool_env):
    assert score_event(P0_LOG, 0.9).tier == "P0"

    block, _calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_ok(**_kw):
        return True

    monkeypatch.setattr(pool, "_enqueue_pq", pq_ok)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High())
        assert st == "shed"
        assert st != "overflow"
        assert not pool._p0_overflow
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_p0_kafka_overflow_returns_deferred(monkeypatch, full_pool_env):
    block, _calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_fail(**_kw):
        return False

    async def kafka_ok(_job):
        return True

    monkeypatch.setattr(pool, "_enqueue_pq", pq_fail)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_ok)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High())
        assert st == "deferred"
        assert st != "overflow"
        assert not pool._p0_overflow
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_p0_deque_fallback_never_overflow(monkeypatch, full_pool_env):
    block, _calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_fail(**_kw):
        return False

    async def kafka_fail(_job):
        return False

    monkeypatch.setattr(pool, "_enqueue_pq", pq_fail)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_fail)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High())
        assert st == "deferred"
        assert st != "overflow"
        assert len(pool._p0_overflow) == 1
        job = pool._p0_overflow[0]
        assert job["event_id"] == 3
        assert job["tier"] == "P0"
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_worker_drains_p0_overflow(monkeypatch, full_pool_env):
    block, calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_fail(**_kw):
        return False

    async def kafka_fail(_job):
        return False

    monkeypatch.setattr(pool, "_enqueue_pq", pq_fail)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_fail)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High())
        assert st == "deferred"
        assert len(pool._p0_overflow) == 1
        # 释放挂起的 pipeline → worker 排空内存队列与本地兜底 deque, 事件不丢
        block.set()
        await asyncio.sleep(0.2)
        assert not pool._p0_overflow
        assert pool.busy == 0
        assert sorted(calls) == [1, 2, 3]
    finally:
        await pool.stop()


@pytest.mark.asyncio
async def test_p1_never_drop_deferred(monkeypatch, full_pool_env):
    assert score_event(P1_LOG, 0.2).tier == "P1"

    block, _calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_fail(**_kw):
        return False

    async def kafka_fail(_job):
        return False

    monkeypatch.setattr(pool, "_enqueue_pq", pq_fail)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_fail)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P1_LOG, anomaly_report=_AR_Low())
        assert st == "deferred"
        assert st != "overflow"
        assert len(pool._p0_overflow) == 1
        assert pool._p0_overflow[0]["tier"] == "P1"
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_p3_still_overflows_when_full(monkeypatch, full_pool_env):
    block, _calls = full_pool_env
    pool = AuditWorkerPool()

    async def pq_should_not_be_called(**_kw):
        raise AssertionError("P3 must not touch Redis PQ")

    async def kafka_should_not_be_called(_job):
        raise AssertionError("P3 must not touch Kafka overflow")

    monkeypatch.setattr(pool, "_enqueue_pq", pq_should_not_be_called)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_should_not_be_called)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P3_LOG, anomaly_report=_AR_Low())
        assert st == "overflow"
        assert not pool._p0_overflow
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_p0_may_overflow_when_never_drop_disabled(monkeypatch, full_pool_env):
    from config import settings
    monkeypatch.setattr(settings, "audit_p0_never_drop", False)

    block, _calls = full_pool_env
    pool = AuditWorkerPool()
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High())
        assert st == "overflow"
        assert not pool._p0_overflow
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_from_overflow_skips_kafka_reproduce(monkeypatch, full_pool_env):
    """overflow 回灌不得再次 produce, 否则 Kafka 环路。"""
    block, _calls = full_pool_env
    pool = AuditWorkerPool()
    kafka_calls = []

    async def pq_fail(**_kw):
        return False

    async def kafka_must_not(_job):
        kafka_calls.append(_job)
        return True

    monkeypatch.setattr(pool, "_enqueue_pq", pq_fail)
    monkeypatch.setattr(pool, "_enqueue_kafka_overflow", kafka_must_not)
    await pool.start()
    try:
        await _fill(pool)
        st = await pool.submit(
            session_id="s", event_id=3, log_data=P0_LOG, anomaly_report=_AR_High(),
            from_overflow=True,
        )
        assert st == "deferred"
        assert kafka_calls == []
        assert len(pool._p0_overflow) == 1
        assert pool._p0_overflow[0]["event_id"] == 3
    finally:
        block.set()
        await pool.stop()


@pytest.mark.asyncio
async def test_enqueue_kafka_overflow_uses_producer(monkeypatch):
    """_enqueue_kafka_overflow 直接走 kafka_producer.produce_raw → overflow topic。"""
    from config import settings
    import kafka_producer as kp_module

    sent = {}

    class _StubProducer:
        is_active = True

        async def produce_raw(self, event, topic="", key_field="sourceId", trace_id=""):
            sent["event"] = event
            sent["topic"] = topic
            sent["key_field"] = key_field
            return True

    class _AR:
        anomaly_score = 0.9
        reasons = ["r1"]

    monkeypatch.setattr(kp_module, "kafka_producer", _StubProducer())
    pool = AuditWorkerPool()
    job = {
        "session_id": "s",
        "event_id": 9,
        "log_data": P0_LOG,
        "anomaly_report": _AR(),
        "tier": "P0",
        "priority": 75,
    }
    assert await pool._enqueue_kafka_overflow(job) is True
    assert sent["topic"] == settings.kafka_topic_audit_overflow
    assert sent["key_field"] == "event_id"
    assert sent["event"]["event_id"] == 9
    assert sent["event"]["tier"] == "P0"
    assert sent["event"]["reasons"] == ["r1"]

    # producer 未启动 → False
    class _InactiveProducer:
        is_active = False

        async def produce_raw(self, *a, **k):  # pragma: no cover
            return True

    monkeypatch.setattr(kp_module, "kafka_producer", _InactiveProducer())
    assert await pool._enqueue_kafka_overflow(job) is False


@pytest.mark.asyncio
async def test_handle_audit_overflow_resubmits_from_overflow(monkeypatch):
    captured = {}

    async def fake_submit(**kw):
        captured.update(kw)
        return "queued"

    import audit_worker as aw
    monkeypatch.setattr(aw.audit_worker, "submit", fake_submit)
    from kafka_consumer import KafkaConsumerManager
    mgr = KafkaConsumerManager()
    await mgr._handle_audit_overflow(
        {
            "event_id": 77,
            "session_id": "s-ov",
            "log_data": P0_LOG,
            "anomaly_score": 0.91,
            "reasons": ["sigma:critical"],
        },
        "",
    )
    assert captured["event_id"] == 77
    assert captured["from_overflow"] is True
    assert captured["session_id"] == "s-ov"
    assert captured["anomaly_report"].anomaly_score == 0.91


def test_audit_shed_metrics_helpers():
    import metrics
    metrics.inc_audit_shed("P0", "pq_ok")
    metrics.inc_audit_shed("P0", "local_deque")
    metrics.observe_ingest_stage("detect", 0.001)
    metrics.inc_detector_error("anomaly")
    text = generate_latest()
    assert b"soc_audit_shed_total" in text
    assert b"soc_ingest_stage_seconds" in text
    assert b"soc_ingest_detector_errors_total" in text
