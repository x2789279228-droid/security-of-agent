# ── CAD 证据口径回归: 单源孤立(不可穿透验证)≠ 幻觉 ──
# A) 无 evidence_ids 的断言 → unverifiable(不计幻觉/不计 0 完整度), sever 低
# B) 带不存在的 ID(真实幻觉/断言失实)→ 仍 verified=False 且 severity=high(保熔断权威)
# C) circuit_breaker.record_na 仅计数不写 0-完整度趋势 → 空批不会由 NA 触发 trip

import asyncio

from cad import PenetratingVerifier, CircuitBreaker


class _StoreEmpty:
    """空断言场景: 不应触发任何事件库查询。"""
    async def get_by_id(self, session, eid):  # pragma: no cover
        raise AssertionError("空 evidence_ids 不应查询事件库")


class _StoreNone:
    """真幻觉场景: 数据库查无该(声称存在的)ID。"""
    async def get_by_id(self, session, eid):
        return None


def _run(verifier, store, session, evidence_ids):
    import cad as _mod
    original = _mod.event_store
    _mod.event_store = store()
    try:
        return asyncio.new_event_loop().run_until_complete(
            verifier.verify_claims(session, "", [{
                "claim": "某安全告警断言", "type": "SANGFOR_ALERT",
                "evidence_ids": evidence_ids, "evidence_quotes": ["x"],
                "severity": "high",
            }])
        )
    finally:
        _mod.event_store = original


def test_empty_evidence_is_unverifiable_not_hallucination():
    v = PenetratingVerifier()
    reports = _run(v, _StoreEmpty, session=None, evidence_ids=[])
    assert len(reports) == 1
    r = reports[0]
    assert r.verified is False and r.unverifiable is True
    assert r.severity == "low"


def test_nonexistent_evidence_is_true_hallucination():
    v = PenetratingVerifier()
    reports = _run(v, _StoreNone, session=None, evidence_ids=[9_999_999_999])
    assert len(reports) == 1
    r = reports[0]
    # 带声称 ID 但库中不存在 → 真实断言失实: 高严重幻觉, 不是 unverifiable
    assert r.verified is False and r.unverifiable is False
    assert r.severity == "high"


def test_record_na_does_not_accumulate_zero_completeness_trend():
    cb = CircuitBreaker()
    cb.reset()
    for _ in range(13):
        cb.record_na(notes="isolated-single-source")
    st = cb.get_status()
    assert st["tripped"] is False                       # 空批(NA)不能触发熔断
    assert st["unverifiable_count"] == 13              # 但被可观测计数
    assert st["audit_count"] == 13


def test_real_hallucination_still_trips_via_trend():
    cb = CircuitBreaker()
    cb.reset()
    # 连续真幻觉(risk=1.0 可透断言) 应在预热(10)后触发
    for _ in range(13):
        cb.record_audit_result(
            hallucination_risk=1.0, evidence_completeness=0.0, anomaly_detected=True
        )
    assert cb.get_status()["tripped"] is True
