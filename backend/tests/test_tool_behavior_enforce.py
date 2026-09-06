"""PR4: 行为签名 confirm/deny 改 Guard 决策 + 审批工单 + audit_trail。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_guard.behavior_detector import BehaviorDetector
from mcp_guard.call_logger import CallLogger
from mcp_guard.guard_server import McpGuardServer, ToolCallRequest


def _scan(g, target, caller="ops"):
    return g.call_tool(ToolCallRequest(
        tool_name="vulnerability_scan",
        arguments={"target": target, "scan_type": "fast"},
        user_role="admin",
        caller=caller,
        source="api",
        reason="periodic scan",
    ))


def _guard(mode: str) -> McpGuardServer:
    g = McpGuardServer()
    g.logger = CallLogger(persist=False)
    g.detector = BehaviorDetector(
        min_samples=30, enabled=True, persist=False, mode=mode,
    )
    g.logger.detector = g.detector
    return g


def test_shadow_scan_rfc1918_stays_allow():
    g = _guard("shadow")
    for i in range(40):
        resp = _scan(g, f"8.8.{i}.1")
        assert resp["decision"] == "allow"
    resp = _scan(g, "192.168.1.1")
    assert resp["decision"] == "allow"
    assert (resp.get("signature") or {}).get("is_anomaly") is True
    assert (resp.get("signature") or {}).get("action") == "logged"
    assert not g.approvals.list_pending()


def test_confirm_mode_opens_ticket():
    g = _guard("confirm")
    for i in range(40):
        _scan(g, f"8.8.{i}.1")
    resp = _scan(g, "192.168.10.2")
    assert resp["decision"] == "require_confirmation"
    assert resp.get("ticket_id")
    assert resp["execution"]["status"] == "pending"
    pending = g.approvals.list_pending()
    assert pending
    ticket = pending[0]
    assert ticket["trigger"] == "behavior_signature"
    assert ticket["signature_reasons"]
    assert "rfc1918" in " ".join(ticket["signature_reasons"])
    assert ticket["decision_reason"].startswith("behavior_signature:")


def test_deny_mode_blocks_and_does_not_execute():
    g = _guard("deny")
    for i in range(40):
        _scan(g, f"1.1.{i}.1")
    resp = _scan(g, "10.0.0.9")
    assert resp["decision"] == "deny"
    assert resp["execution"] is None
    assert "behavior_signature" in resp["reason"]
    rec = g.logger.recent(1)[0]
    assert rec["decision"] == "deny"
    # deny 不写入指纹
    glob = g.detector.get_signature("vulnerability_scan", "*")
    assert glob["ip_class"].get("rfc1918", 0) == 0


def test_deny_writes_audit_trail_fallback():
    from audit_trail import _fallback_buffer
    g = _guard("deny")
    for i in range(40):
        _scan(g, f"9.9.{i}.1")
    before = len(_fallback_buffer)
    resp = _scan(g, "192.168.0.8")
    assert resp["decision"] == "deny"
    assert len(_fallback_buffer) >= before + 1
    entry = _fallback_buffer[-1]
    assert entry["action"] == "tool.signature_veto"
    assert entry["after"]["decision"] == "deny"
    assert entry["before"]["decision"] == "allow"


def test_policy_confirm_still_creates_ticket():
    g = _guard("shadow")
    resp = g.call_tool(ToolCallRequest(
        tool_name="isolate_host",
        arguments={"host": "web-1", "isolation_type": "network"},
        user_role="admin",
        caller="ops",
    ))
    assert resp["decision"] == "require_confirmation"
    assert resp.get("ticket_id")
    ticket = g.approvals.get_ticket(resp["ticket_id"])
    assert ticket["trigger"] == "policy"


def test_detector_crash_fail_open_in_deny_mode():
    class Boom:
        def observe_pre_exec(self, rec):
            raise RuntimeError("score boom")

        def observe_post_exec(self, rec, report=None):
            raise RuntimeError("learn boom")

        def mode(self):
            return "deny"

    g = McpGuardServer()
    g.logger = CallLogger(persist=False)
    g.detector = Boom()
    resp = g.call_tool(ToolCallRequest(
        tool_name="alert_only",
        arguments={"message": "hello"},
        user_role="admin",
        caller="ops",
    ))
    assert resp["decision"] == "allow"
    assert resp.get("execution", {}).get("status") == "success"


def test_confirm_does_not_downgrade_policy_deny():
    g = _guard("confirm")
    resp = g.call_tool(ToolCallRequest(
        tool_name="not_a_real_tool",
        arguments={},
        user_role="admin",
        caller="ops",
    ))
    assert resp["decision"] == "deny"


def test_enforce_alias_is_confirm():
    from mcp_guard.behavior_detector import canonical_mode
    assert canonical_mode("enforce") == "confirm"
    assert canonical_mode("CONFIRM") == "confirm"
    g = _guard("enforce")
    for i in range(40):
        _scan(g, f"8.8.{i}.1")
    resp = _scan(g, "192.168.1.8")
    assert resp["decision"] == "require_confirmation"
    assert resp.get("ticket_id")
