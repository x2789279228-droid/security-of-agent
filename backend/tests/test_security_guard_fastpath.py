"""PR-A: FastPath/策略字段与 SecurityGuard 意图审查对齐。"""
from security_guard.intent_checker import IntentChecker
from response_engine.response_orchestrator import normalize_threat_info_for_guard


def test_resolve_threat_level_from_severity():
    assert IntentChecker.resolve_threat_level({"severity": "high"}) == "high"
    assert IntentChecker.resolve_threat_level({"threat_level": "critical"}) == "critical"
    assert IntentChecker.resolve_threat_level({}) == "unknown"


def test_resolve_reason_falls_back_to_message_then_synth():
    assert "C2 beacon" in IntentChecker.resolve_reason({"message": "C2 beacon detected"})
    synth = IntentChecker.resolve_reason({
        "threat_type": "BRUTE_FORCE",
        "severity": "high",
        "confidence": 0.85,
    })
    assert "BRUTE_FORCE" in synth
    assert "0.85" in synth


def test_send_alert_allowed_for_high():
    checker = IntentChecker()
    result = checker.check("send_alert", {
        "severity": "high",
        "message": "SSH brute force from 1.2.3.4",
    })
    assert result.passed is True


def test_block_ip_allowed_when_severity_present_without_threat_level():
    checker = IntentChecker()
    result = checker.check("block_ip", {
        "severity": "high",
        "threat_type": "BRUTE_FORCE",
        "confidence": 0.88,
        "message": "SSH暴力破解",
    })
    assert result.passed is True
    assert result.details["threat_level"] == "high"


def test_block_ip_blocked_when_severity_unknown():
    checker = IntentChecker()
    result = checker.check("block_ip", {
        "threat_type": "UNKNOWN",
        "message": "something odd",
    })
    assert result.passed is False


def test_normalize_threat_info_for_guard():
    info = normalize_threat_info_for_guard({
        "threat_type": "C2_BEACON",
        "severity": "critical",
        "confidence": 0.9,
        "message": "internal host beacon",
    })
    assert info["threat_level"] == "critical"
    assert len(info["reason"]) >= 3
