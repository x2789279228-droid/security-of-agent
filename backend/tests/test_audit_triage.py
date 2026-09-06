"""LLM 通道分流: 优先级 / 预算分层准入。"""
from audit_triage import (
    score_event,
    admit,
    needs_llm,
    uses_temporal,
    uses_llm_single,
    lane_max_rounds,
    LANE_LLM_DEEP,
    LANE_LLM_AGENT,
    LANE_LLM_SINGLE,
    LANE_TOOLS_ONLY,
    LANE_RULE_CLOSE,
    LANE_LLM_LIGHT,
    VOLUMETRIC_EVENT_TYPES,
)


def test_critical_sigma_is_p0_agent():
    log = {
        "severity": "critical",
        "event": "BRUTE_FORCE",
        "threat_type": "BRUTE_FORCE",
        "_sigma": {"detected": True, "max_severity": "critical", "hits": [{"confidence": "high"}]},
        "_anomaly": {"score": 0.8},
    }
    t = score_event(log, 0.8)
    assert t.tier == "P0"
    assert t.lane in (LANE_LLM_AGENT, LANE_LLM_DEEP)
    assert needs_llm(t.lane)
    assert uses_temporal(t.lane)
    assert t.strong_count >= 2


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
    assert uses_llm_single(admitted.lane)
    assert not uses_temporal(admitted.lane)


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


def test_lane_max_rounds_caps_agent():
    assert lane_max_rounds(LANE_LLM_AGENT, 9) <= 2
    assert lane_max_rounds(LANE_LLM_DEEP, 9) <= 2
    assert lane_max_rounds(LANE_LLM_SINGLE, 9) == 1
    assert lane_max_rounds(LANE_LLM_LIGHT, 9) == 1


def test_fastpath_demotes_non_critical():
    log = {
        "severity": "high",
        "event": "PORT_SCAN",
        "_sigma": {"detected": False},
    }
    t = score_event(log, 0.5, fastpath_strong=True)
    assert t.fastpath_demoted is True
    assert t.skip_llm is True
    assert t.lane == LANE_TOOLS_ONLY


def test_volumetric_ddos_skips_llm():
    log = {
        "severity": "high",
        "event": "DDOS_TRAFFIC",
        "threat_type": "DDOS_TRAFFIC",
        "_sigma": {"detected": False},
    }
    t = score_event(log, 0.75)
    assert "DDOS_TRAFFIC" in VOLUMETRIC_EVENT_TYPES
    assert t.tier == "P2"
    assert t.skip_llm is True
    assert t.lane == LANE_TOOLS_ONLY
    assert not uses_temporal(t.lane)


def test_high_only_is_not_p1_llm():
    log = {
        "severity": "high",
        "event": "HTTP_ACCESS",
        "threat_type": "HTTP_ACCESS",
        "_sigma": {"detected": False},
    }
    t = score_event(log, 0.55)
    assert t.tier in ("P2", "P3")
    assert t.skip_llm is True


def test_c2_sigma_medium_is_p1_single():
    log = {
        "severity": "high",
        "event": "C2_BEACON",
        "threat_type": "C2_BEACON",
        "_sigma": {"detected": True, "max_severity": "medium", "hits": [{"confidence": "medium"}]},
    }
    t = score_event(log, 0.4)
    assert t.tier in ("P0", "P1")
    if t.tier == "P1":
        assert uses_llm_single(t.lane)
        assert not uses_temporal(t.lane)


def test_soft_budget_keeps_llm_single():
    log = {
        "severity": "critical",
        "event": "SQL_INJECTION",
        "threat_type": "SQL_INJECTION",
        "_sigma": {"detected": True, "max_severity": "low", "hits": []},
    }
    t = score_event(log, 0.2)
    t.lane = LANE_LLM_SINGLE
    t.tier = "P1"
    t.skip_llm = False
    admitted = admit(t, usage_pct=75.0, over_budget=False, soft_pct=70.0, hard_pct=95.0)
    assert admitted.lane == LANE_LLM_SINGLE
    assert admitted.skip_llm is False


def test_should_short_circuit_spares_p0(monkeypatch):
    import agents.llm_fallback as m
    import summary_compression as sc

    class Fake:
        def is_over_budget(self):
            return True

    monkeypatch.setattr(sc, "cost_tracker", Fake())
    assert m.should_short_circuit_for_tier("P0") is False
    assert m.should_short_circuit_for_tier("P2") is True
