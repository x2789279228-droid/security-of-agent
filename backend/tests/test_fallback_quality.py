"""fallback / shed 必须带 quality,不得伪装成 llm 完成。"""
from log_ingestion import _quality_from_reason, LogIngestor


def test_quality_mapping():
    assert _quality_from_reason("shed_load:P2") == "shed"
    assert _quality_from_reason("queue_overflow") == "shed"
    assert _quality_from_reason("triage:tools_only:P3") == "tools"
    assert _quality_from_reason("triage:rule_close:P3") == "rule"
    assert _quality_from_reason("budget_exhausted") == "budget"
    assert _quality_from_reason("rate_limited_429") == "rate_limited"
    assert _quality_from_reason("timeout") == "fallback"
    assert _quality_from_reason("", "completed") == "llm"


def test_status_cache_lru_keeps_pending():
    ing = LogIngestor()
    ing._audit_status_cache_max = 5
    for i in range(1, 5):
        ing._track_audit_status(i, "completed")
    ing._track_audit_status(99, "pending")
    ing._track_audit_status(100, "running")
    # overflow: drop completed first
    ing._track_audit_status(101, "pending")
    statuses = {k: v["status"] for k, v in ing._audit_status_cache.items()}
    assert statuses.get(99) == "pending"
    assert statuses.get(100) == "running"
    assert statuses.get(101) == "pending"


def test_fastpath_lru_evicts_one_not_half():
    ing = LogIngestor()
    ing._fastpath_cooldown_max = 3
    ing._fastpath_cooldown_ttl = 60
    assert ing._fastpath_allow("a") is True
    assert ing._fastpath_allow("b") is True
    assert ing._fastpath_allow("c") is True
    assert ing._fastpath_allow("d") is True  # evicts oldest (a)
    assert "a" not in ing._fastpath_cooldown
    assert "b" in ing._fastpath_cooldown
    assert ing._fastpath_allow("b") is False  # still cooling
