"""有界审计 worker: 瞬时 running ≤ workers, cancel 释放 slot。"""
import asyncio

import pytest

from audit_worker import AuditWorkerPool


class _AR:
    anomaly_score = 0.2
    reasons = []
    is_anomaly = False
    deviation_sigma = 0.0


@pytest.mark.asyncio
async def test_worker_caps_inflight(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "audit_workers", 2)
    monkeypatch.setattr(settings, "audit_queue_max", 50)

    pool = AuditWorkerPool()
    gate = asyncio.Event()
    running = 0
    peak = 0

    async def fake_pipeline(session_id, event_id, log_data, anomaly_report, max_rounds=3):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await gate.wait()
        running -= 1

    class _Done:
        @staticmethod
        def _audit_task_done(_t):
            return None

        _audit_pipeline = staticmethod(fake_pipeline)

    import log_ingestion
    monkeypatch.setattr(log_ingestion, "log_ingestor", _Done)

    await pool.start()
    try:
        for i in range(8):
            st = await pool.submit(
                session_id="s", event_id=i + 1, log_data={"severity": "info"},
                anomaly_report=_AR(),
            )
            assert st == "queued"
        await asyncio.sleep(0.1)
        assert pool.busy <= 2
        assert peak <= 2
        gate.set()
        await asyncio.sleep(0.15)
        assert pool.busy == 0
    finally:
        await pool.stop()


@pytest.mark.asyncio
async def test_worker_cancel(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "audit_workers", 1)
    pool = AuditWorkerPool()
    started = asyncio.Event()

    async def hang(*_a, **_k):
        started.set()
        await asyncio.sleep(30)

    class _Ing:
        _audit_pipeline = staticmethod(hang)

        @staticmethod
        def _audit_task_done(_t):
            return None

    import log_ingestion
    monkeypatch.setattr(log_ingestion, "log_ingestor", _Ing)
    await pool.start()
    try:
        await pool.submit(session_id="s", event_id=42, log_data={}, anomaly_report=_AR())
        await asyncio.wait_for(started.wait(), timeout=1)
        assert pool.cancel(42) is True
        await asyncio.sleep(0.05)
        assert 42 not in pool.inflight_ids()
    finally:
        await pool.stop()


@pytest.mark.asyncio
async def test_queue_overflow_p3(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "audit_workers", 1)
    monkeypatch.setattr(settings, "audit_queue_max", 1)
    pool = AuditWorkerPool()
    block = asyncio.Event()

    async def hang(*_a, **_k):
        await block.wait()

    class _Ing:
        _audit_pipeline = staticmethod(hang)

        @staticmethod
        def _audit_task_done(_t):
            return None

    import log_ingestion
    monkeypatch.setattr(log_ingestion, "log_ingestor", _Ing)
    await pool.start()
    try:
        await pool.submit(
            session_id="s", event_id=1, log_data={"severity": "info"}, anomaly_report=_AR(),
        )
        await asyncio.sleep(0.05)
        # fill the 1-slot queue
        await pool.submit(
            session_id="s", event_id=2, log_data={"severity": "info"}, anomaly_report=_AR(),
        )
        st = await pool.submit(
            session_id="s", event_id=3, log_data={"severity": "info"}, anomaly_report=_AR(),
        )
        assert st == "overflow"
    finally:
        block.set()
        await pool.stop()
