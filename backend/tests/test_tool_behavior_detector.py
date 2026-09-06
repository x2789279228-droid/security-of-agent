"""BehaviorDetector 四维打分（shadow）固定种子测试。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_guard.behavior_detector import BehaviorDetector
from mcp_guard.call_logger import CallLogger
from mcp_guard.call_record import ToolCallRecord
from mcp_guard.guard_server import McpGuardServer, ToolCallRequest


def _rec(**kw):
    base = dict(
        user_role="security_operator",
        tool_name="block_ip",
        arguments={"ip": "8.8.8.8", "duration": 3600},
        decision="allow",
        reason="ok",
        checks=[],
        caller="ops",
        source="mcp_guard",
    )
    base.update(kw)
    return ToolCallRecord.from_kwargs(**base)


def test_public_baseline_then_rfc1918_param_high():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(40):
        det.observe(_rec(arguments={"ip": f"8.8.{i}.1", "duration": 3600}))
    report = det.observe(_rec(arguments={"ip": "192.168.1.1", "duration": 3600}))
    assert report is not None
    assert report.cold_start is False
    assert report.dimensions.get("param", 0) >= 0.8
    assert report.is_anomaly is True
    assert report.reasons
    assert det.recent_anomalies(5)


def test_alert_then_isolate_seq_and_caller_high():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(40):
        det.observe(_rec(
            tool_name="alert_only",
            arguments={"message": f"n{i}"},
            decision="allow",
        ))
    report = det.observe(_rec(
        tool_name="isolate_host",
        arguments={"host": "gw-1", "isolation_type": "network"},
        decision="require_confirmation",
    ))
    assert report is not None
    assert report.dimensions.get("seq", 0) >= 0.8
    assert report.dimensions.get("caller", 0) >= 0.8
    assert report.is_anomaly is True


def test_cold_start_under_min_samples_no_alert():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(29):
        det.observe(_rec(arguments={"ip": f"8.8.{i}.1", "duration": 3600}))
    report = det.observe(_rec(arguments={"ip": "192.168.1.1", "duration": 3600}))
    assert report is not None
    assert report.is_anomaly is False
    # 参数维尚未就绪
    assert "param" not in report.dimensions or report.cold_start


def test_deny_does_not_pollute_fingerprint():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(40):
        det.observe(_rec(arguments={"ip": f"8.8.{i}.1", "duration": 3600}))
    glob = det.get_signature("block_ip", "*")
    assert glob and glob["ip_class"].get("rfc1918", 0) == 0
    det.observe(_rec(
        arguments={"ip": "10.0.0.1", "duration": 3600},
        decision="deny",
    ))
    glob = det.get_signature("block_ip", "*")
    assert glob["ip_class"].get("rfc1918", 0) == 0
    report = det.observe(_rec(arguments={"ip": "10.0.0.2", "duration": 3600}, decision="allow"))
    assert report.dimensions.get("param", 0) >= 0.8


def test_self_play_source_not_learned():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(40):
        det.observe(_rec(
            arguments={"ip": f"8.8.{i}.1", "duration": 3600},
            source="self_play",
        ))
    sig = det.get_signature("block_ip", "ops")
    assert sig is None or sig["sample_count"] == 0


def test_disabled_returns_none():
    det = BehaviorDetector(enabled=False)
    assert det.observe(_rec()) is None


def test_detector_crash_does_not_break_guard():
    class Boom:
        def observe_pre_exec(self, rec):
            raise RuntimeError("score boom")

        def observe_post_exec(self, rec, report=None):
            raise RuntimeError("learn boom")

    g = McpGuardServer()
    g.logger = CallLogger(persist=False)
    g.detector = Boom()
    resp = g.call_tool(ToolCallRequest(
        tool_name="alert_only",
        arguments={"message": "hi"},
        user_role="admin",
        caller="human_api",
        source="api",
    ))
    assert resp["decision"] in ("allow", "require_confirmation")
    assert "execution" in resp


def test_shadow_does_not_change_guard_decision():
    g = McpGuardServer()
    g.logger = CallLogger(persist=False)
    g.detector = BehaviorDetector(min_samples=30, enabled=True, persist=False, mode="shadow")
    for i in range(40):
        g.call_tool(ToolCallRequest(
            tool_name="block_ip",
            arguments={"ip": f"1.1.{i}.1", "duration": 3600},
            user_role="admin",
            caller="ops",
        ))
    resp = g.call_tool(ToolCallRequest(
        tool_name="block_ip",
        arguments={"ip": "192.168.1.1", "duration": 3600},
        user_role="admin",
        caller="ops",
    ))
    # HIGH 工具仍是 policy 的 require_confirmation，shadow 不得改成 deny
    assert resp["decision"] == "require_confirmation"
    sig = resp.get("signature") or {}
    assert sig.get("dimensions", {}).get("param", 0) >= 0.8
    assert sig.get("is_anomaly") is True
    assert any(c.get("check") == "behavior_signature" for c in resp["checks"])


def test_list_signatures_and_anomalies():
    det = BehaviorDetector(min_samples=30, enabled=True, persist=False)
    for i in range(40):
        det.observe(_rec(arguments={"ip": f"8.8.{i}.1", "duration": 3600}))
    det.observe(_rec(arguments={"ip": "192.168.0.1", "duration": 3600}))
    items = det.list_signatures()
    assert any(x["tool_name"] == "block_ip" and x["sample_count"] >= 30 for x in items)
    stats = det.stats()
    assert stats["fingerprints"] >= 1
    assert stats["anomalies"] >= 1
