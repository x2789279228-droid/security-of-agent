"""PR1 否决闸：主张剥离 / 非 LLM 信号 / 禁止 OR 合并 / 工具精确匹配 / hop 预算。"""
import os
import sys
from pathlib import Path

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from veto_gates import (
    strip_ungrounded_claims,
    apply_confirmation_gate,
    extract_non_llm_signals,
    merge_audit_rounds,
    hop_stats_from_verdicts,
    should_skip_reasoning_hops,
    should_run_llm_reviewer,
    should_run_deep_llm_hops,
    clamp_reviewer_conclusion,
    executor_conclusion_floor,
    filter_missed_threats,
    cap_reported_severity,
    strip_phantom_mitre,
    sanitize_merged_audit,
    NonLlmSignals,
    VERDICT_CONFIRMED,
    VERDICT_SUSPICIOUS,
    VERDICT_INSUFFICIENT,
    VERDICT_FALSE_POSITIVE,
    CONCLUSION_CONFIRMED,
    CONCLUSION_SUSPICIOUS,
    CONCLUSION_FALSE_POSITIVE,
)
from stabilizer.tool_resolver import ToolResolver, RESPONSE_TOOLS


class _FakeReport:
    def __init__(self, verdict, score=0.9):
        self.verdict = verdict
        self.grounding_score = score


class _FakeVerdict:
    def __init__(self, risk, grounding, claims=None, discarded=None):
        self.hallucination_risk = risk
        self.grounding_score = grounding
        self.threat_claims = claims or []
        self.discarded_claims = discarded or []


# ── P0-1 主张剥离 ──

def test_strip_ungrounded_does_not_admit_ungrounded():
    claims = [
        {"type": "C2", "summary": "ok", "evidence_ids": [1], "evidence_quotes": ["x"]},
        {"type": "C2", "summary": "fake", "evidence_ids": [99], "evidence_quotes": ["nope"]},
    ]
    reports = [_FakeReport("grounded"), _FakeReport("ungrounded", 0.1)]
    admitted, discarded = strip_ungrounded_claims(claims, reports)
    assert len(admitted) == 1
    assert admitted[0]["summary"] == "ok"
    assert len(discarded) == 1
    assert discarded[0]["grounding_verdict"] == "ungrounded"


def test_strip_without_reports_requires_evidence_ids():
    admitted, discarded = strip_ungrounded_claims(
        [{"summary": "bare claim", "evidence_ids": []}]
    )
    assert admitted == []
    assert len(discarded) == 1


# ── P0-3 confirmed 必须绑定非 LLM 信号 ──

def test_llm_threat_without_detector_is_suspicious_not_confirmed():
    decision = apply_confirmation_gate(
        llm_threat_detected=True,
        signals=NonLlmSignals(),
        has_admitted_claims=True,
    )
    assert decision.threat_detected is False
    assert decision.verdict == VERDICT_SUSPICIOUS
    assert decision.needs_human_review is True


def test_llm_threat_with_sigma_is_confirmed():
    signals = extract_non_llm_signals({"_sigma": {"detected": True, "rule_count": 1}})
    assert signals.has_signal
    decision = apply_confirmation_gate(
        llm_threat_detected=True,
        signals=signals,
        has_admitted_claims=True,
    )
    assert decision.threat_detected is True
    assert decision.verdict == VERDICT_CONFIRMED


def test_no_admitted_claims_cannot_confirm():
    signals = extract_non_llm_signals({"_sigma": {"detected": True}})
    decision = apply_confirmation_gate(
        llm_threat_detected=True,
        signals=signals,
        has_admitted_claims=False,
    )
    assert decision.threat_detected is False
    assert decision.verdict == VERDICT_INSUFFICIENT


def test_anomaly_below_threshold_is_not_a_signal():
    signals = extract_non_llm_signals({"_anomaly": {"score": 0.2}})
    assert signals.has_signal is False


def test_anomaly_at_threshold_is_a_signal():
    signals = extract_non_llm_signals({"_anomaly": {"score": 0.7}})
    assert signals.anomaly_triggered is True


def test_cep_chain_from_tool_results():
    class TR:
        tool = "correlation.chains"
        success = True
        data = [{"pattern_name": "scan-c2"}]
    signals = extract_non_llm_signals({}, tool_results=[TR()])
    assert signals.cep_chain is True


# ── P0-4 禁止 OR 合并 ──

def test_merge_or_does_not_confirm_without_signal():
    rounds = [
        {"audit": {"threat_detected": True, "confidence": 0.9, "severity": "critical",
                   "needs_human_review": False}},
        {"audit": {"threat_detected": False, "confidence": 0.1, "severity": "info",
                   "needs_human_review": False}},
    ]
    merged = merge_audit_rounds(rounds, NonLlmSignals())
    assert merged["threat_detected"] is False
    assert merged["verdict"] == VERDICT_SUSPICIOUS
    assert merged["needs_human"] is True
    # 无证据不得把 severity 抬到 critical
    assert merged["severity"] != "critical"


def test_merge_confirms_when_signal_and_one_round():
    rounds = [
        {"audit": {"threat_detected": True, "confidence": 0.8, "severity": "high",
                   "needs_human_review": False}},
    ]
    merged = merge_audit_rounds(rounds, NonLlmSignals(sigma_hit=True, reasons=["sigma"]))
    assert merged["threat_detected"] is True
    assert merged["verdict"] == VERDICT_CONFIRMED
    assert merged["severity"] == "high"


def test_merge_uses_round_non_llm_signal_from_cep():
    rounds = [
        {"audit": {"threat_detected": True, "confidence": 0.8, "severity": "high",
                   "non_llm_signal": True}},
    ]
    merged = merge_audit_rounds(rounds, NonLlmSignals())
    assert merged["threat_detected"] is True
    assert merged["verdict"] == VERDICT_CONFIRMED


def test_two_llm_rounds_without_signal_still_not_confirmed():
    rounds = [
        {"audit": {"threat_detected": True, "confidence": 0.9, "severity": "high"}},
        {"audit": {"threat_detected": True, "confidence": 0.8, "severity": "high"}},
    ]
    merged = merge_audit_rounds(rounds, NonLlmSignals())
    assert merged["threat_detected"] is False
    assert merged["verdict"] == VERDICT_SUSPICIOUS


# ── P0-6 工具解析禁止模糊 / 前缀 / 短词响应别名 ──

def test_tool_resolver_exact_and_alias():
    r = ToolResolver()
    name, err, method = r.resolve("event_store.query")
    assert name == "event_store.query" and method == "exact"
    name, err, method = r.resolve("Event-Store.Query")
    assert name == "event_store.query" and method == "exact"
    name, err, method = r.resolve("query_events")
    assert name == "event_store.query" and method == "alias"


def test_tool_resolver_rejects_fuzzy_and_typos():
    r = ToolResolver()
    name, err, method = r.resolve("event_store.querys")  # 旧模糊匹配会命中
    assert name is None and method == "none"
    name, err, method = r.resolve("blok_ip")  # 接近 block_ip
    assert name is None


def test_tool_resolver_rejects_short_response_aliases():
    r = ToolResolver()
    for raw in ("block", "kill", "scan", "alert", "isolate", "limit"):
        name, err, method = r.resolve(raw)
        assert name is None, f"{raw} 不应映射到响应工具，得到 {name}"


def test_tool_resolver_response_tools_still_exact():
    r = ToolResolver()
    for tool in RESPONSE_TOOLS:
        name, err, method = r.resolve(tool)
        assert name == tool and method == "exact"


def test_tool_resolver_prefix_no_longer_matches():
    r = ToolResolver()
    # 旧实现：len>=4 前缀唯一即可命中
    name, err, method = r.resolve("block")
    assert name is None


# ── P0-8 hop 预算 / Reviewer 只准降级 ──

def test_hop_budget_early_stop_on_high_risk():
    stats = hop_stats_from_verdicts([
        _FakeVerdict(0.8, 0.3, claims=[], discarded=[{"x": 1}]),
        _FakeVerdict(0.7, 0.2, claims=[], discarded=[{"y": 1}]),
    ])
    assert should_skip_reasoning_hops(stats) is True
    assert should_run_deep_llm_hops("deep", stats.skip_reasoning) is False


def test_standard_skips_llm_reviewer():
    assert should_run_llm_reviewer("quick") is False
    assert should_run_llm_reviewer("standard") is False
    assert should_run_llm_reviewer("deep") is True


def test_reviewer_cannot_upgrade_to_confirmed():
    clamped = clamp_reviewer_conclusion(CONCLUSION_SUSPICIOUS, CONCLUSION_CONFIRMED)
    assert clamped == CONCLUSION_SUSPICIOUS
    clamped = clamp_reviewer_conclusion(CONCLUSION_CONFIRMED, CONCLUSION_FALSE_POSITIVE)
    assert clamped == CONCLUSION_FALSE_POSITIVE


def test_executor_floor_suspicious_when_needs_human():
    floor = executor_conclusion_floor(
        threat_detected=False, verdict=VERDICT_SUSPICIOUS, needs_human_review=True,
    )
    assert floor == CONCLUSION_SUSPICIOUS


def test_missed_threats_without_ids_are_dropped():
    kept = filter_missed_threats([
        {"description": "I invented a C2", "evidence": "looks bad"},
        {"description": "real", "evidence": "12, 34"},
        {"description": "with ids", "evidence_ids": [7]},
    ])
    assert len(kept) == 2
    assert kept[0]["description"] == "real"


def test_synthesis_schema_accepts_abstain():
    from audit_schemas import SynthesisOutputSchema
    m = SynthesisOutputSchema(
        threat_detected=False, abstain=True, confidence=0.2,
        severity="info", summary="insufficient",
    )
    assert m.abstain is True


def test_port_scan_cannot_inflate_to_critical():
    sev = cap_reported_severity(
        "critical",
        event_type="PORT_SCAN",
        event_severity="medium",
        sigma_severity="medium",
    )
    assert sev == "high"


def test_c2_keeps_critical():
    sev = cap_reported_severity(
        "critical",
        event_type="C2_BEACON",
        event_severity="critical",
        sigma_severity="critical",
    )
    assert sev == "critical"


def test_phantom_mitre_stripped():
    merged = {
        "severity": "critical",
        "mitre_techniques": ["T1046", "T1090.002"],
        "faithfulness": {"phantom_entities": ["T1090.002", "T1132.001"]},
    }
    out = strip_phantom_mitre(merged, evidence="PORT_SCAN T1046 src=45.33.32.156")
    assert "T1046" in [str(x) for x in out["mitre_techniques"]]
    assert "T1090.002" not in [str(x) for x in out["mitre_techniques"]]
    assert "T1090.002" in out["stripped_mitre"]


def test_sanitize_merged_audit_caps_and_strips():
    out = sanitize_merged_audit(
        {
            "severity": "critical",
            "mitre_techniques": [{"id": "T1090.002"}],
            "faithfulness": {"phantom_entities": ["T1090.002"]},
        },
        evidence="PORT_SCAN 45.33.32.156",
        event_type="PORT_SCAN",
        event_severity="medium",
    )
    assert out["severity"] == "high"
    assert out["mitre_techniques"] == []
    assert "T1090.002" in out["stripped_mitre"]
