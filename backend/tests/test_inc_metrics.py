"""B 类高级能力 metrics — 验证指标定义与计数递增。"""
import pytest


def test_b_metrics_defined():
    """metrics.py 定义 NDR/EDR/intel/sandbox/phishing 指标。"""
    from metrics import (NDR_FLOWS, TLS_SESSIONS, CAPTURE_PACKETS, EDR_EVENTS,
                         INTEL_IOC, IOC_MATCHES, SANDBOX_SUBMISSIONS, PHISHING_DETECTIONS)
    assert NDR_FLOWS._name == "soc_ndr_flows"
    assert TLS_SESSIONS._name == "soc_tls_sessions"
    assert CAPTURE_PACKETS._name == "soc_capture_packets"
    assert EDR_EVENTS._name == "soc_edr_events"
    assert INTEL_IOC._name == "soc_intel_ioc"
    assert IOC_MATCHES._name == "soc_ioc_matches"
    assert SANDBOX_SUBMISSIONS._name == "soc_sandbox_submissions"
    assert PHISHING_DETECTIONS._name == "soc_phishing_detections"


def test_b_metrics_inc_correct():
    """inc_* 函数使指标递增且带正确 label。"""
    from metrics import (inc_ndr_flow, inc_tls_session, inc_edr_event,
                         inc_sandbox_submission, inc_ioc_match, inc_phishing_detection)
    before = inc_sandbox_submission._name if hasattr(inc_sandbox_submission, "_name") else None
    # prometheus_collector 前值
    from prometheus_client import generate_latest
    base = generate_latest().decode()
    inc_ndr_flow("tcp")
    inc_edr_event("sysmon")
    inc_sandbox_submission("file")
    inc_ioc_match()
    inc_phishing_detection("email")
    inc_tls_session()
    out = generate_latest().decode()
    assert "soc_ndr_flows_total" in out
    assert 'soc_edr_events_total{source="sysmon"} 1.0' in out
    assert 'soc_sandbox_submissions_total{kind="file"} 1.0' in out
    assert "soc_ioc_matches_total 1.0" in out
    assert 'soc_phishing_detections_total{category="email"} 1.0' in out
    assert "soc_tls_sessions_total 1.0" in out


def test_capabilities_parse_metric_values():
    """capabilities 接口的指标解析能提取 B 类计数。"""
    from routers.capabilities import _parse_metric_values
    text = (
        "# HELP soc_ndr_flows_total x\n"
        'soc_ndr_flows_total{protocol="tcp"} 3.0\n'
        'soc_ndr_flows_total{protocol="udp"} 2.0\n'
        "soc_edr_events_total{source=\"sysmon\"} 1.0\n"
        "soc_phishing_detections_total{category=\"email\"} 2.0\n"
    )
    assert _parse_metric_values(text, "soc_ndr_flows_") == 5
    assert _parse_metric_values(text, "soc_edr_events_") == 1
    assert _parse_metric_values(text, "soc_phishing_detections_") == 2
