"""MCP Guard 权限管理模块（RBAC）。

职责：基于角色的访问控制，决定某角色是否有权调用某工具。

角色定义（与平台 RBAC 对齐）：
- admin:              全部工具（最高权限）
- security_operator:  安全运营人员，可执行所有安全响应工具
- analyst:            分析师，仅可执行只读/低风险工具
- viewer:             只读查看者，不可调用任何工具

权限检查逻辑：角色是否存在 → 角色是否有权调用该工具。
所有角色定义内联在代码中，无外部文件依赖。
"""

from typing import Tuple


# ============================================================
# 角色-工具权限映射（内联定义，与平台 RBAC 对齐）
# ============================================================
_RBAC = {
    "admin": {
        "description": "系统管理员，拥有全部工具权限",
        "tools": [
            "block_ip",
            "isolate_host",
            "rate_limit",
            "terminate_process",
            "alert_only",
            "vulnerability_scan",
        ],
    },
    "security_operator": {
        "description": "安全运营人员，可执行所有安全响应工具",
        "tools": [
            "block_ip",
            "isolate_host",
            "rate_limit",
            "terminate_process",
            "alert_only",
            "vulnerability_scan",
        ],
    },
    "analyst": {
        "description": "安全分析师，仅可执行只读/低风险工具",
        "tools": [
            "vulnerability_scan",
            "alert_only",
        ],
    },
    "viewer": {
        "description": "只读查看者，不可调用任何工具",
        "tools": [],
    },
}


class PermissionManager:
    """RBAC 权限管理器。

    基于内联角色定义进行权限检查，无外部文件依赖。
    """

    def __init__(self):
        self.rbac = _RBAC

    def check(self, user_role: str, tool_name: str) -> Tuple[bool, str]:
        """检查用户角色是否有权调用工具。

        Returns:
            (passed, message)
        """
        # 角色不存在 → 拒绝
        if user_role not in self.rbac:
            return False, f"未知角色 '{user_role}'，无任何权限"

        role_desc = self.rbac[user_role].get("description", "")
        allowed_tools = self.rbac[user_role]["tools"]

        # 角色无该工具权限 → 拒绝
        if tool_name not in allowed_tools:
            return False, (
                f"角色 '{user_role}'({role_desc}) 无权调用 '{tool_name}'，"
                f"允许工具: {allowed_tools}"
            )

        return True, f"角色 '{user_role}' 有权调用 '{tool_name}'"

    def get_user_tools(self, user_role: str) -> list:
        """获取角色可用的工具列表。"""
        if user_role not in self.rbac:
            return []
        return list(self.rbac[user_role]["tools"])
