"""ToolBehaviorSignature / 特征抽取 单元测试。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_guard.behavior_signature import (
    Welford,
    classify_ip,
    extract_features,
    ToolBehaviorSignature,
)


def test_classify_ip_buckets():
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("192.168.1.1") == "rfc1918"
    assert classify_ip("10.0.0.5") == "rfc1918"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.1.1") == "link_local"
    assert classify_ip("gw-core") is None
    assert classify_ip("") is None


def test_extract_block_ip_features():
    feat = extract_features({"ip": "8.8.8.8", "duration": 3600})
    assert feat["numeric"]["duration"] == 3600
    assert feat["ip_fields"][0][2] == "public"
    assert "ip" in feat["hashes"]


def test_extract_isolate_categorical():
    feat = extract_features({"host": "gw-1", "isolation_type": "full"})
    assert feat["categorical"]["isolation_type"] == "full"
    assert "host" in feat["hashes"]
    assert feat["ip_fields"] == []


def test_welford_zscore_needs_samples():
    w = Welford()
    for _ in range(10):
        w.update(3600)
    assert w.zscore(3600) == 0.0
    z = w.zscore(60)
    assert z is not None and z >= 8


def test_signature_param_unseen_ip_class():
    sig = ToolBehaviorSignature(tool_name="block_ip", caller="ops")
    for i in range(40):
        feat = extract_features({"ip": f"8.8.{i}.1", "duration": 3600})
        sig.update(ts=1_700_000_000 + i, hour=12, weekday=2, features=feat)
    assert sig.ready(30)
    score, reasons = sig.score_params(extract_features({"ip": "192.168.1.1", "duration": 3600}))
    assert score >= 0.8
    assert any("rfc1918" in r for r in reasons)
