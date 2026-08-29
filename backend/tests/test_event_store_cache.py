"""PR-E: EventStore 热缓存失效。"""
from event_store import EventStore


def test_invalidate_removes_hot_cache_entry():
    store = EventStore()
    store._hot_cache[42] = {"id": 42, "analyzed": False, "raw_data": {}}
    store.invalidate(42)
    assert 42 not in store._hot_cache


def test_update_hot_cache_merges_fields():
    store = EventStore()
    store._hot_cache[7] = {"id": 7, "analyzed": False}
    store.update_hot_cache(7, analyzed=True, raw_data={"_audit_llm": {"status": "completed"}})
    assert store._hot_cache[7]["analyzed"] is True
    assert store._hot_cache[7]["raw_data"]["_audit_llm"]["status"] == "completed"


def test_invalidate_missing_id_is_noop():
    store = EventStore()
    store.invalidate(999)
    store.invalidate(None)  # type: ignore[arg-type]
