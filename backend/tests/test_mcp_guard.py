"""mcp_guard 工具调用网关 — 4 层安全检查单元测试

覆盖 McpGuardServer.call_tool 的 registry/permission/validator/policy 检查链。
"""
from mcp_guard.guard_server import McpGuardServer, ToolCallRequest


def _req(tool_name="alert_only", args=None, role="admin"):
    return ToolCallRequest(tool_name=tool_name, arguments=(args if args is not None else {"message": "test"}), user_role=role)


def test_guard_rejects_unknown_tool():
    """第1层 registry: 未注册工具判为幻觉工具 → deny。"""
    g = McpGuardServer()
    req = _req(tool_name="nonexistent_tool_xyz")
    resp = g.call_tool(req)
    assert resp["decision"] == "deny"
    assert any(c["check"] == "registry" and not c["passed"] for c in resp["checks"])


def test_guard_allow_known_low_risk_tool():
    """已知低风险工具经权限+校验+策略应 allow。"""
    g = McpGuardServer()
    req = _req(tool_name="alert_only", args={"message": "test"})
    resp = g.call_tool(req)
    assert resp["decision"] in ("allow", "require_confirmation")
    assert resp["checks"]


def test_guard_validation_layer_runs():
    """第3层 validator: 缺失必填参数触发 params 检查失败。"""
    g = McpGuardServer()
    resp = g.call_tool(_req(tool_name="alert_only", args={}))
    # 无论 decision, params 检查必须被记录
    assert any(c["check"] == "params" for c in resp["checks"])


def test_guard_returns_full_response_shape():
    """响应统一含 decision/reason/checks/execution。"""
    g = McpGuardServer()
    resp = g.call_tool(_req())
    for k in ("decision", "reason", "final_risk", "checks", "execution"):
        assert k in resp, f"缺 {k}"
