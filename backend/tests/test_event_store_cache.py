"""PR-E: EventStore 热缓存失效 + 跨进程陈旧快照回源。"""
import pytest
from event_store import EventStore


def test_invalidate_removes_hot_cache_entry():
    store = EventStore()
    store._hot_cache[42] = {"id": 42, "analyzed": False, "raw_data": {}}
    store.invalidate(42, broadcast=False)
    assert 42 not in store._hot_cache


def test_update_hot_cache_merges_fields():
    store = EventStore()
    store._hot_cache[7] = {"id": 7, "analyzed": False}
    store.update_hot_cache(7, analyzed=True, raw_data={"_audit_llm": {"status": "completed"}})
    assert store._hot_cache[7]["analyzed"] is True
    assert store._hot_cache[7]["raw_data"]["_audit_llm"]["status"] == "completed"


def test_invalidate_missing_id_is_noop():
    store = EventStore()
    store.invalidate(999, broadcast=False)
    store.invalidate(None, broadcast=False)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_get_by_id_revalidates_unanalyzed_cache(monkeypatch):
    """ingest 热缓存 analyzed=False 时必须回源 DB,否则 Temporal 写回后 API 永远 pending。"""
    store = EventStore()
    store._hot_cache[9302] = {
        "id": 9302,
        "session_id": "s",
        "event_type": "BRUTE_FORCE",
        "severity": "high",
        "src_ip": "1.2.3.4",
        "dst_ip": "",
        "message": "x",
        "raw_data": {},
        "anomaly_score": 0.9,
        "correlation_id": "",
        "created_at": "2026-09-04T00:00:00+00:00",
        "analyzed": False,
    }

    class FakeEvt:
        id = 9302
        session_id = "s"
        event_type = "BRUTE_FORCE"
        severity = "high"
        src_ip = "1.2.3.4"
        dst_ip = ""
        message = "x"
        raw_data = {"_audit_llm": {"status": "completed", "threat_type": "BRUTE_FORCE"}}
        anomaly_score = 0.9
        analyzed = True
        created_at = None

    class FakeSession:
        async def get(self, model, eid):
            assert eid == 9302
            return FakeEvt()

    stored = await store.get_by_id(FakeSession(), 9302)
    assert stored is not None
    assert stored.analyzed is True
    assert stored.raw_data["_audit_llm"]["status"] == "completed"
    # 回源后热缓存应被刷新
    assert store._hot_cache[9302]["analyzed"] is True


@pytest.mark.asyncio
async def test_get_by_id_prefer_db_bypasses_fresh_cache():
    store = EventStore()
    store._hot_cache[1] = {
        "id": 1,
        "session_id": "s",
        "event_type": "X",
        "severity": "info",
        "src_ip": "",
        "dst_ip": "",
        "message": "",
        "raw_data": {"_audit_llm": {"status": "completed"}},
        "anomaly_score": 0.0,
        "correlation_id": "",
        "created_at": "",
        "analyzed": True,
    }

    class FakeEvt:
        id = 1
        session_id = "s"
        event_type = "X"
        severity = "info"
        src_ip = ""
        dst_ip = ""
        message = "from-db"
        raw_data = {"_audit_llm": {"status": "completed", "note": "db"}}
        anomaly_score = 0.0
        analyzed = True
        created_at = None

    class FakeSession:
        async def get(self, model, eid):
            return FakeEvt()

    stored = await store.get_by_id(FakeSession(), 1, prefer_db=True)
    assert stored.message == "from-db"
    assert stored.raw_data["_audit_llm"]["note"] == "db"
