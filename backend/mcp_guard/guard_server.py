"""MCP Guard Server — 可信工具调用控制网关（核心控制层）。

职责：串联 Registry + Permission + Validator + PolicyEngine + Logger，
构成 Agent 与工具之间的唯一安全通道。

调用链（4层检查）：
    Agent ToolCallRequest
        ↓
    1. Registry 查询（工具是否注册，防幻觉工具）
    2. Permission RBAC 检查（角色是否有权调用）
    3. Validator 参数校验（Pydantic 强类型）
    4. PolicyEngine 规则评估（allow / deny / require_confirmation）
        ↓
    5. 放行 → 执行工具 / 拒绝 / 等待人工确认
    6. Logger 记录审计日志

注意：call_tool() 为同步方法，在 async 上下文中通过 asyncio.to_thread 调用。
"""

from dataclasses import dataclass, field
from typing import Optional

from .tool_registry import ToolRegistry
from .permission_manager import PermissionManager
from .validator import ParamValidator
from .policy_engine import PolicyEngine
from .call_logger import CallLogger


@dataclass
class ToolCallRequest:
    """Agent 发起的工具调用请求。"""
    tool_name: str
    arguments: dict
    user_role: str
    reason: str = ""
    request_id: str = ""


@dataclass
class GuardDecision:
    """Guard 决策结果。

    status: allow / deny / require_confirmation
    reason: 决策原因说明
    final_risk: 最终风险等级
    checks: 各层检查明细
    normalized_args: 校验后的规范化参数
    """
    status: str
    reason: str
    final_risk: str = ""
    checks: list = field(default_factory=list)
    normalized_args: dict = None


class McpGuardServer:
    """可信工具调用控制网关。

    Agent 不能直接调用工具，必须通过 McpGuardServer.call_tool() 入口。
    所有调用经过 4 层安全检查后才会被执行。
    """

    def __init__(self):
        # 初始化 4 层检查组件
        self.registry = ToolRegistry()
        self.permission = PermissionManager()
        self.validator = ParamValidator()
        self.policy = PolicyEngine()
        self.logger = CallLogger()

    # ------------------------------------------------------------
    # 工具发现（供 Agent 查询可用工具）
    # ------------------------------------------------------------
    def list_tools(self) -> list:
        """列出所有已注册工具。"""
        return self.registry.list_tools()

    # ------------------------------------------------------------
    # 主入口：工具调用（同步方法）
    # ------------------------------------------------------------
    def call_tool(self, request: ToolCallRequest) -> dict:
        """处理 Agent 的工具调用请求，返回完整结果。

        本方法为同步方法，在 async 上下文中应通过 asyncio.to_thread 调用。

        返回结构：
        {
            "decision": "allow" / "deny" / "require_confirmation",
            "reason": "...",
            "final_risk": "...",
            "checks": [...],
            "execution": {...} or null,
        }
        """
        checks = []
        exec_result = None

        # ===== 第1层：工具注册检查（防幻觉工具） =====
        tool_info = self.registry.get_tool(request.tool_name)
        if tool_info is None:
            msg = f"工具 '{request.tool_name}' 未注册，疑似幻觉工具"
            checks.append({"check": "registry", "passed": False, "message": msg})
            decision = GuardDecision(status="deny", reason=msg, checks=checks)
            self._log(request, decision, None)
            return self._build_response(decision, None)

        checks.append({
            "check": "registry",
            "passed": True,
            "message": f"工具 '{request.tool_name}' 已注册，风险等级={tool_info.risk_level}",
        })

        # ===== 第2层：RBAC 权限检查 =====
        ok, msg = self.permission.check(request.user_role, request.tool_name)
        checks.append({"check": "permission", "passed": ok, "message": msg})
        if not ok:
            decision = GuardDecision(
                status="deny", reason="权限检查失败: " + msg, checks=checks
            )
            self._log(request, decision, None)
            return self._build_response(decision, None)

        # ===== 第3层：参数校验（Pydantic 强类型） =====
        ok, msg, normalized = self.validator.validate(request.tool_name, request.arguments)
        checks.append({"check": "params", "passed": ok, "message": msg})
        if not ok:
            decision = GuardDecision(
                status="deny", reason="参数校验失败: " + msg, checks=checks
            )
            self._log(request, decision, None)
            return self._build_response(decision, None)

        # ===== 第4层：规则引擎评估 =====
        decision_status, reason, hit_rules = self.policy.evaluate(
            tool_name=request.tool_name,
            tool_risk_level=tool_info.risk_level,
            arguments=normalized,
            user_role=request.user_role,
        )
        checks.append({
            "check": "policy",
            "passed": decision_status != "deny",
            "message": f"决策={decision_status}, 命中规则={hit_rules}, {reason}",
        })

        decision = GuardDecision(
            status=decision_status,
            reason=reason,
            final_risk=tool_info.risk_level,
            checks=checks,
            normalized_args=normalized,
        )

        # ===== 执行或拦截 =====
        if decision.status == "allow":
            # 规则放行，直接执行工具
            exec_result = self.registry.execute(request.tool_name, normalized)
        elif decision.status == "require_confirmation":
            # 需要人工确认，暂不执行
            exec_result = {"status": "pending", "message": "等待人工确认，工具暂未执行"}
        else:
            # deny，不执行
            exec_result = None

        # ===== 记录审计日志 =====
        self._log(request, decision, exec_result)
        return self._build_response(decision, exec_result)

    # ------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------
    def _build_response(self, decision: GuardDecision, exec_result: Optional[dict]) -> dict:
        """构建统一响应结构。"""
        return {
            "decision": decision.status,
            "reason": decision.reason,
            "final_risk": decision.final_risk,
            "checks": decision.checks,
            "execution": exec_result,
        }

    def _log(self, request: ToolCallRequest, decision: GuardDecision, exec_result):
        """记录调用审计日志。"""
        exec_status = exec_result.get("status") if exec_result else None
        self.logger.log(
            user_role=request.user_role,
            tool_name=request.tool_name,
            arguments=request.arguments,
            decision=decision.status,
            reason=decision.reason,
            checks=decision.checks,
            exec_status=exec_status,
            exec_result=exec_result,
        )


# 全局单例，供平台各模块直接使用
mcp_guard = McpGuardServer()
