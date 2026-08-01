"""MCP Guard 规则引擎。

职责：基于内联安全规则，对工具调用做最终决策。
输出：allow / deny / require_confirmation

规则评估流程：
1. 按规则ID顺序逐条评估
2. 命中 deny 规则 → 立即拒绝
3. 命中 require_confirmation 规则 → 需人工确认
4. 命中 allow 规则 → 标记允许，继续评估后续规则
5. 全部规则评估完，默认 allow（前置检查已通过）

规则优先级：deny > require_confirmation > allow

默认规则：
- R001: block_ip 作用于内网CIDR → require_confirmation（内网封禁需确认）
- R002: isolate_host 任何调用 → require_confirmation（主机隔离需确认）
- R003: vulnerability_scan → allow（只读扫描直接放行）
- R004: terminate_process → require_confirmation（终止进程需确认）

所有规则内联在代码中，无外部文件依赖。
"""

import ipaddress
from typing import Tuple


# ============================================================
# 内联安全规则定义
# ============================================================
_DEFAULT_RULES = [
    {
        "id": "R001",
        "name": "内网IP封禁需确认",
        "description": "对内网地址(10/172.16/192.168网段)执行封禁操作需人工确认",
        "condition": {
            "tool_name": "block_ip",
            "param": "ip",
            "in_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        },
        "action": "require_confirmation",
    },
    {
        "id": "R002",
        "name": "主机隔离需确认",
        "description": "主机隔离为高危操作，任何调用均需人工确认",
        "condition": {
            "tool_name": "isolate_host",
        },
        "action": "require_confirmation",
    },
    {
        "id": "R003",
        "name": "漏洞扫描直接放行",
        "description": "漏洞扫描为只读操作，风险低，直接放行",
        "condition": {
            "tool_name": "vulnerability_scan",
        },
        "action": "allow",
    },
    {
        "id": "R004",
        "name": "终止进程需确认",
        "description": "终止进程可能影响业务连续性，需人工确认",
        "condition": {
            "tool_name": "terminate_process",
        },
        "action": "require_confirmation",
    },
]

# 风险等级对应的默认策略（用于风险升级判断）
_RISK_POLICY = {
    "LOW": "allow",
    "MEDIUM": "allow",
    "HIGH": "require_confirmation",
    "CRITICAL": "require_confirmation",
}


class PolicyEngine:
    """规则引擎。

    基于内联规则进行决策，支持 CIDR 匹配和风险升级。
    """

    def __init__(self):
        self.rules = list(_DEFAULT_RULES)
        self.risk_policy = dict(_RISK_POLICY)

    def evaluate(self, tool_name: str, tool_risk_level: str,
                 arguments: dict, user_role: str) -> Tuple[str, str, list]:
        """评估规则，返回 (decision, reason, hit_rules)。

        Args:
            tool_name: 工具名称
            tool_risk_level: 工具风险等级 (LOW/MEDIUM/HIGH/CRITICAL)
            arguments: 规范化后的参数
            user_role: 调用者角色

        Returns:
            decision: allow / deny / require_confirmation
            reason: 决策原因
            hit_rules: 命中的规则ID列表
        """
        decision = "allow"
        reason = "默认放行（前置检查已通过）"
        hit_rules = []

        # 逐条评估规则
        for rule in self.rules:
            matched, match_detail = self._match_rule(
                rule, tool_name, tool_risk_level, arguments, user_role
            )
            if not matched:
                continue

            hit_rules.append(rule["id"])
            action = rule["action"]

            if action == "deny":
                # 拒绝优先级最高，立即终止
                decision = "deny"
                reason = f"规则 {rule['id']}({rule['name']}): {rule['description']}"
                break

            elif action == "require_confirmation":
                # 需人工确认（deny 优先于 require_confirmation）
                if decision != "deny":
                    decision = "require_confirmation"
                    reason = (
                        f"规则 {rule['id']}({rule['name']}): "
                        f"{rule['description']} (匹配: {match_detail})"
                    )

            elif action == "allow":
                # 标记允许，继续评估后续规则（后续可能有更严格的规则）
                if decision == "allow":
                    reason = f"规则 {rule['id']}({rule['name']}): {rule['description']}"

        # 风险升级：如果规则未命中但风险等级较高，按风险策略处理
        if not hit_rules and tool_risk_level in self.risk_policy:
            risk_action = self.risk_policy[tool_risk_level]
            if risk_action == "require_confirmation" and decision == "allow":
                decision = "require_confirmation"
                reason = f"风险升级: 工具风险等级={tool_risk_level}，需人工确认"

        return decision, reason, hit_rules

    def _match_rule(self, rule: dict, tool_name: str, tool_risk_level: str,
                    arguments: dict, user_role: str) -> Tuple[bool, str]:
        """判断单条规则是否匹配当前调用。"""
        cond = rule["condition"]
        detail = ""

        # 条件：工具名匹配
        if "tool_name" in cond and cond["tool_name"] != tool_name:
            return False, ""
        detail += f"tool={tool_name}"

        # 条件：工具风险等级匹配
        if "tool_risk_level" in cond:
            if cond["tool_risk_level"] != tool_risk_level:
                return False, ""
            detail += f", risk={tool_risk_level}"

        # 条件：需要特定角色（用于 deny_if_violated 场景）
        if "require_role" in cond:
            if user_role not in cond["require_role"]:
                detail += f", role={user_role}不在{cond['require_role']}"
                return True, detail
            return False, ""

        # 条件：参数值匹配（CIDR / 精确匹配）
        if "param" in cond:
            param_name = cond["param"]
            param_val = arguments.get(param_name)
            if param_val is None:
                return False, ""

            # CIDR 匹配：判断IP是否在指定网段内
            if "in_cidr" in cond and isinstance(param_val, str):
                for cidr in cond["in_cidr"]:
                    try:
                        if ipaddress.ip_address(param_val) in ipaddress.ip_network(cidr):
                            detail += f", {param_name}={param_val} in {cidr}"
                            return True, detail
                    except ValueError:
                        pass
                return False, ""

            # 精确值匹配
            if "equals" in cond:
                if param_val == cond["equals"]:
                    detail += f", {param_name}={param_val}"
                    return True, detail
                return False, ""

        return True, detail
