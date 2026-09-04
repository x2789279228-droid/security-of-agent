"""LLM 通道分流: 优先级 / 预算分层准入。"""
from audit_triage import (
    score_event,
    admit,
    needs_llm,
    LANE_LLM_DEEP,
    LANE_TOOLS_ONLY,
    LANE_RULE_CLOSE,
    LANE_LLM_LIGHT,
)


def test_critical_sigma_is_p0_deep():
    log = {
        "severity": "critical",
        "event": "BRUTE_FORCE",
        "threat_type": "BRUTE_FORCE",
        "_sigma": {"detected": True, "max_severity": "critical", "hits": [{"confidence": "high"}]},
        "_anomaly": {"score": 0.8},
    }
    t = score_event(log, 0.8)
    assert t.tier == "P0"
    assert t.lane == LANE_LLM_DEEP
    assert needs_llm(t.lane)


def test_info_noise_is_tools_or_close():
    log = {
        "severity": "info",
        "event": "USER_LOGIN",
        "threat_type": "USER_LOGIN",
        "_sigma": {"detected": False},
        "_anomaly": {"score": 0.05},
    }
    t = score_event(log, 0.05)
    assert t.tier == "P3"
    assert t.skip_llm or t.lane in (LANE_TOOLS_ONLY, LANE_RULE_CLOSE, LANE_LLM_LIGHT)


def test_hard_budget_keeps_p0_llm():
    log = {
        "severity": "critical",
        "event": "C2_BEACON",
        "threat_type": "C2_BEACON",
        "_sigma": {"detected": True, "max_severity": "critical", "hits": []},
    }
    t = score_event(log, 0.9)
    admitted = admit(t, usage_pct=99.0, over_budget=True)
    assert admitted.tier == "P0"
    assert needs_llm(admitted.lane)
    assert admitted.skip_llm is False


def test_hard_budget_closes_p3():
    log = {
        "severity": "info",
        "event": "DNS_QUERY",
        "_sigma": {"detected": False},
    }
    t = score_event(log, 0.0)
    admitted = admit(t, usage_pct=99.0, over_budget=True)
    assert admitted.skip_llm is True
    assert admitted.lane in (LANE_RULE_CLOSE, LANE_TOOLS_ONLY)


def test_soft_budget_demotes_light():
    log = {
        "severity": "medium",
        "event": "PORT_SCAN",
        "threat_type": "PORT_SCAN",
        "_sigma": {"detected": False},
    }
    t = score_event(log, 0.35)
    # force light lane for test
    t.lane = LANE_LLM_LIGHT
    t.tier = "P2"
    t.skip_llm = False
    admitted = admit(t, usage_pct=75.0, over_budget=False, soft_pct=70.0, hard_pct=95.0)
    assert admitted.lane == LANE_TOOLS_ONLY
    assert admitted.skip_llm is True


def test_should_short_circuit_spares_p0(monkeypatch):
    import agents.llm_fallback as m
    import summary_compression as sc

    class Fake:
        def is_over_budget(self):
            return True

    monkeypatch.setattr(sc, "cost_tracker", Fake())
    assert m.should_short_circuit_for_tier("P0") is False
    assert m.should_short_circuit_for_tier("P2") is True
