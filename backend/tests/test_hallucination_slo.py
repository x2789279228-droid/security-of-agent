"""PR3 忠实度闸 + 良性流 LLM FP SLO（≤5%）+ abstain。"""
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

from eval_metrics import (
    LEXICAL_SUPPORT_THRESHOLD,
    claim_is_supported,
    entity_entailment_ok,
    extract_grounding_entities,
)
from faithfulness_gate import (
    BENIGN_LLM_FP_SLO,
    apply_faithfulness_gate,
    compute_faithfulness,
    contexts_from_audit,
    llm_alone_false_positive_rate,
)
from veto_gates import apply_confirmation_gate, extract_non_llm_signals, NonLlmSignals
from audit_schemas import ReviewerOutputSchema, SynthesisOutputSchema


def test_lexical_threshold_raised():
    assert LEXICAL_SUPPORT_THRESHOLD == 0.35
    # 0.18 时代能过的弱重叠，现在应失败
    claim = "检测到针对核心资产的高级持续威胁活动"
    evidence = "用户登录成功 HTTP 200"
    assert lexical_overlap_score_below(claim, evidence)


def lexical_overlap_score_below(claim, evidence):
    from eval_metrics import lexical_overlap_score
    return lexical_overlap_score(claim, evidence) < LEXICAL_SUPPORT_THRESHOLD


def test_phantom_ip_fails_entity_entailment():
    claim = "攻击者 10.0.0.99 对 8.8.8.8 发起 C2，CVE-2024-99999 被利用"
    evidence = "src_ip=10.0.0.5 dst_ip=1.2.3.4 message=NTP query"
    assert "10.0.0.99" in extract_grounding_entities(claim)
    assert entity_entailment_ok(claim, evidence) is False
    assert claim_is_supported(claim, evidence) is False


def test_matching_ip_and_cve_pass_entailment():
    claim = "10.0.0.5 利用 CVE-2024-1234 连接 1.2.3.4 T1071"
    evidence = "src 10.0.0.5 dst 1.2.3.4 CVE-2024-1234 T1071 C2 beacon"
    assert entity_entailment_ok(claim, evidence) is True
    assert claim_is_supported(claim, evidence) is True


def test_faithfulness_gate_blocks_ungrounded_confirmed():
    merged = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.9,
        "severity": "critical",
        "needs_human": False,
    }
    answer = "确认 10.0.0.99 发起数据外泄，建议立即封禁。"
    contexts = [{"content": "HTTP GET /health 200 from 10.0.0.8 ntp.ubuntu.com"}]
    out = apply_faithfulness_gate(merged, answer=answer, contexts=contexts)
    assert out["threat_detected"] is False
    assert out["verdict"] != "confirmed"
    assert out["needs_human"] is True
    assert out["response_blocked"] is True
    assert out["faithfulness"]["passed"] is False


def test_faithfulness_gate_allows_grounded_summary():
    merged = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.8,
        "needs_human": False,
    }
    answer = "10.0.0.5 向 185.244.25.235 发送 C2_BEACON，命中 Sigma。"
    contexts = [{"content": "C2_BEACON src_ip=10.0.0.5 dst_ip=185.244.25.235 message=C2_BEACON sigma hit"}]
    out = apply_faithfulness_gate(merged, answer=answer, contexts=contexts)
    assert out["faithfulness"]["passed"] is True
    assert out.get("response_blocked") is False
    assert out["verdict"] == "confirmed"
    assert out["threat_detected"] is True


def test_abstain_blocks_response_and_demotes():
    merged = {"threat_detected": True, "verdict": "confirmed", "confidence": 0.7}
    out = apply_faithfulness_gate(
        merged,
        answer="证据不足无法确认威胁。",
        contexts=[{"content": "login success"}],
        abstain=True,
    )
    assert out["threat_detected"] is False
    assert out["response_blocked"] is True
    assert out["verdict"] == "insufficient_evidence"
    assert out["needs_human"] is True


def test_soft_demote_keeps_threat_when_sigma_backed():
    """Sigma 已命中时，忠实度失败只降级 verdict，不抹掉威胁。"""
    merged = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.7,
        "needs_human": False,
    }
    answer = "确认 APT 使用 T1090.002 T1132.001 进行隐蔽通信并外泄。"
    contexts = [{"content": "C2_BEACON src_ip=192.168.1.100 dst_ip=23.129.64.33"}]
    out = apply_faithfulness_gate(
        merged,
        answer=answer,
        contexts=contexts,
        non_llm_signals={"sigma_detected": True, "anomaly_score": 0.75},
    )
    assert out["threat_detected"] is True
    assert out["verdict"] == "suspicious"
    assert out["needs_human"] is True
    assert out.get("response_blocked") is False
    assert out.get("demoted_by") == "faithfulness_gate_soft"


def test_faithfulness_gate_caps_port_scan_and_strips_mitre():
    merged = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.73,
        "severity": "critical",
        "mitre_techniques": ["T1090.002"],
        "needs_human": False,
    }
    out = apply_faithfulness_gate(
        merged,
        answer="确认 T1090.002 隐蔽通信。",
        contexts=[{"content": "PORT_SCAN src_ip=45.33.32.156 dst_ip=192.168.1.100"}],
        non_llm_signals={
            "sigma_detected": True,
            "event_type": "PORT_SCAN",
            "event_severity": "medium",
            "sigma_severity": "medium",
        },
    )
    assert out["severity"] == "high"
    assert out["mitre_techniques"] == []
    assert "T1090.002" in (out.get("stripped_mitre") or [])


def _benign_events():
    """一组纯业务/良性日志（NTP、健康检查、正常登录）。"""
    return [
        {"event": "HTTP_OK", "src_ip": f"10.0.0.{i}", "dst_ip": "10.0.0.80",
         "message": "GET /health 200", "severity": "info",
         "_sigma": {"detected": False}, "_anomaly": {"score": 0.05}}
        for i in range(1, 11)
    ] + [
        {"event": "NTP", "src_ip": f"10.1.0.{i}", "dst_ip": "147.231.100.5",
         "message": "NTP query udp/123", "severity": "info",
         "_sigma": {"detected": False}, "_anomaly": {"score": 0.02}}
        for i in range(1, 11)
    ]


def test_benign_llm_alone_fp_slo():
    """
    模拟 LLM 对每条良性日志都喊 threat。
    经确认闸 + 忠实度闸后，confirmed 比例须 ≤ 5%。
    """
    decisions = []
    for ev in _benign_events():
        signals = extract_non_llm_signals(ev)
        gate = apply_confirmation_gate(
            llm_threat_detected=True,
            signals=signals,
            has_admitted_claims=True,
        )
        merged = {
            "threat_detected": gate.threat_detected,
            "verdict": gate.verdict,
            "confidence": 0.9,
            "needs_human": gate.needs_human_review,
        }
        answer = f"确认 {ev['src_ip']} 正在对 {ev['dst_ip']} 发动 APT 攻击 CVE-2099-0001。"
        merged = apply_faithfulness_gate(
            merged,
            answer=answer,
            contexts=contexts_from_audit(ev),
        )
        decisions.append(merged)

    rate = llm_alone_false_positive_rate(decisions)
    assert rate <= BENIGN_LLM_FP_SLO, f"良性 LLM FP={rate:.2%} 超过 SLO {BENIGN_LLM_FP_SLO:.0%}"
    assert all(d.get("verdict") != "confirmed" for d in decisions)


def test_reviewer_and_synthesis_schema_have_abstain():
    r = ReviewerOutputSchema(
        conclusion="insufficient_evidence", confidence=0.2, abstain=True,
    )
    assert r.abstain is True
    s = SynthesisOutputSchema(
        threat_detected=False, confidence=0.1, severity="info",
        summary="abstain", abstain=True,
    )
    assert s.abstain is True


def test_compute_faithfulness_empty_answer_passes():
    report = compute_faithfulness("", [{"content": "anything"}])
    assert report["passed"] is True
    assert report["claim_count"] == 0
