"""
数据库安全与 A4 危险动作策略 (DbSafetyPolicy)

明确 A4 动作的处理规则，禁止向 LLM Agent 注册直接执行破坏性能力的工具。

A4 表示破坏性、不可逆或超大影响范围动作。
A4 仅用于风险识别和策略拦截，不要求项目实现删除数据库、擦除磁盘等工具。

系统不得向 LLM Agent 注册以下直接执行能力:
  - DROP DATABASE
  - DROP TABLE
  - 磁盘擦除
  - 删除备份
  - 批量永久删除账号
  - 修改核心路由
  - 永久封禁大型内部网段

数据库安全事件允许的自动动作仅包括:
  - 查询状态
  - 限制异常连接
  - 切换只读
  - 创建快照
  - 隔离实例
  - 暂停异常账号
  - 生成工单

不得自动删除数据库、数据表、数据库文件或备份。

接入点:
  - TrustedActionGateway 在 PRECHECK 阶段调用 DbSafetyPolicy.check_action
  - 若返回 A4 → 阻止执行 + 记录 + 生成建议 + 创建工单
  - 不可通过分步提权绕过
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── A4 永久禁止注册的工具 (LLM Agent 不可调用) ────────────────

PROHIBITED_TOOLS: frozenset[str] = frozenset({
    # 数据库破坏
    "drop_database",
    "drop_table",
    "drop_schema",
    "truncate_table",
    "delete_database_files",
    "delete_db_backup",
    "delete_backup",
    # 磁盘/文件系统破坏
    "wipe_disk",
    "erase_disk",
    "rm_rf",
    "format_disk",
    "shred_files",
    # 账号批量删除
    "bulk_delete_users",
    "delete_user_permanent",
    "delete_account_permanent",
    # 核心路由
    "modify_core_route",
    "modify_bgp_route",
    "modify_static_route_permanent",
    # 永久封禁大网段
    "block_rfc1918_permanent",
    "block_10_0_0_0_8_permanent",
    "block_internal_subnet_permanent",
    "block_cidr_permanent",   # 永久封禁任意网段
    # 关闭安全设备
    "disable_firewall",
    "disable_ids",
    "disable_audit_logging",
    "clear_audit_log",
})

# A4 永久禁止的命令模式 (正则)
PROHIBITED_COMMAND_PATTERNS: tuple[str, ...] = (
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"DROP\s+SCHEMA",
    r"TRUNCATE\s+TABLE",
    r"DELETE\s+FROM\s+\*",          # 批量删除
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=/dev/zero",
    r"shred\s+-u",
    r":\(\)\{.*\};:",               # fork bomb
    r"iptables\s+-F",                # 清空所有规则
    r"iptables\s+-X",
    r"systemctl\s+stop\s+firewall",
    r"systemctl\s+stop\s+auditd",
    r"history\s+-c",
    r"echo\s+.*>\s*/dev/sda",        # 直接写磁盘
)


# ── 数据库安全事件允许的自动动作白名单 ─────────────────────────

ALLOWED_DB_ACTIONS: frozenset[str] = frozenset({
    # 只读 / 状态查询
    "db_query_status",
    "db_query_connections",
    "db_query_slow_queries",
    "db_query_locks",
    # 限制异常连接
    "db_limit_connections",
    "db_kill_session",
    "db_terminate_backend",
    # 切换只读
    "db_set_readonly",
    "db_unset_readonly",
    # 创建快照
    "db_create_snapshot",
    "db_create_backup",   # 创建备份是允许的
    # 隔离实例
    "db_isolate_instance",
    "db_pause_instance",
    # 暂停异常账号
    "db_disable_account",
    "db_lock_user",
    # 生成工单
    "db_create_ticket",
    "db_alert_dba",
})


# ── 数据模型 ─────────────────────────────────────────────────

@dataclass
class A4Decision:
    """A4 策略决策"""
    is_a4: bool = False
    is_prohibited_tool: bool = False
    is_db_destructive: bool = False
    reason: str = ""
    blocked_by: str = ""
    # 生成处置建议 (不执行, 只生成)
    recommendations: list[str] = field(default_factory=list)
    # 是否需创建人工审批工单
    require_ticket: bool = False
    # 允许的数据库安全动作 (若适用)
    allowed_db_actions: list[str] = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        """是否应该阻止自动执行"""
        return self.is_a4

    def to_dict(self) -> dict:
        return {
            "is_a4": self.is_a4,
            "is_prohibited_tool": self.is_prohibited_tool,
            "is_db_destructive": self.is_db_destructive,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "recommendations": self.recommendations,
            "require_ticket": self.require_ticket,
            "allowed_db_actions": self.allowed_db_actions,
        }


# ── 核心策略 ─────────────────────────────────────────────────

class DbSafetyPolicy:
    """数据库安全与 A4 危险动作策略

    在 TAG PRECHECK 阶段调用 check_action():
      1. 判断是否为永久禁止工具 (PROHIBITED_TOOLS)
      2. 判断是否为数据库破坏性操作
      3. 对数据库安全事件, 限制只能使用 ALLOWED_DB_ACTIONS
      4. 返回 A4Decision, 由 TAG 决定阻止/记录/建议/工单
    """

    def check_action(
        self,
        tool_name: str,
        parameters: Optional[dict] = None,
        target: str = "",
        asset_type: str = "",
    ) -> A4Decision:
        """检查动作是否为 A4 危险动作

        Args:
            tool_name: 工具名
            parameters: 动作参数
            target: 目标 (IP/主机/数据库)
            asset_type: 资产类型 (database/server/firewall/...)

        Returns:
            A4Decision
        """
        params = parameters or {}
        tool = tool_name.lower().strip()

        # 1. 永久禁止工具
        if tool in PROHIBITED_TOOLS:
            # 若是数据库破坏性工具 (drop/truncate/delete_db/delete_backup 等),
            # 额外标记 is_db_destructive=True, 便于上层区分处置路径
            is_db_destructive = self._is_db_destructive_tool(tool)
            return A4Decision(
                is_a4=True,
                is_prohibited_tool=True,
                is_db_destructive=is_db_destructive,
                blocked_by="prohibited_tool",
                reason=(
                    f"工具 '{tool_name}' 在 A4 永久禁止清单中, "
                    "系统不得向 LLM Agent 注册此能力"
                ),
                recommendations=self._generate_recommendations(tool, asset_type),
                require_ticket=True,
                allowed_db_actions=(
                    sorted(ALLOWED_DB_ACTIONS) if is_db_destructive else []
                ),
            )

        # 2. 命令模式匹配 (shell 命令中的危险模式)
        cmd = params.get("command", "") or params.get("sql", "")
        if cmd:
            import re
            for pattern in PROHIBITED_COMMAND_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    return A4Decision(
                        is_a4=True,
                        is_prohibited_tool=True,
                        blocked_by="prohibited_command_pattern",
                        reason=(
                            f"命令匹配 A4 危险模式: {pattern} "
                            f"(命令: {cmd[:80]})"
                        ),
                        recommendations=[
                            "禁止执行此命令",
                            "人工审核后通过工单系统执行",
                        ],
                        require_ticket=True,
                    )

        # 3. 数据库破坏性操作检测
        if asset_type == "database" or self._is_db_target(target, tool):
            return self._check_db_action(tool, params, target)

        # 4. 永久封禁大网段检测
        if tool.startswith("block_") and "permanent" in tool:
            return A4Decision(
                is_a4=True,
                is_prohibited_tool=True,
                blocked_by="permanent_block",
                reason=f"永久封禁操作 '{tool_name}' 属于 A4, 禁止自动执行",
                recommendations=["使用短 TTL 的临时封禁 + 自动回滚"],
                require_ticket=True,
            )

        # 5. 封禁内网大网段检测
        if tool.startswith("block_") and target:
            if self._is_rfc1918_block(target, params):
                return A4Decision(
                    is_a4=True,
                    is_prohibited_tool=True,
                    blocked_by="block_rfc1918",
                    reason=(
                        f"封禁 RFC1918 内网网段 '{target}' 属于 A4, "
                        "禁止 Agent 自动封禁整个内网"
                    ),
                    recommendations=[
                        "定位具体异常主机, 使用 isolate_host 或 rate_limit",
                        "如需封网段, 必须人工审批 + 走防火墙管理员流程",
                    ],
                    require_ticket=True,
                )

        return A4Decision(is_a4=False)

    def _check_db_action(
        self, tool: str, params: dict, target: str,
    ) -> A4Decision:
        """检查数据库相关动作"""
        # 允许的动作
        if tool in ALLOWED_DB_ACTIONS:
            return A4Decision(
                is_a4=False,
                allowed_db_actions=[tool],
                reason=f"数据库安全事件允许动作: {tool}",
            )

        # 破坏性数据库动作
        destructive_patterns = (
            "drop", "delete", "truncate", "wipe", "erase",
            "destroy", "purge", "shred",
        )
        if any(p in tool for p in destructive_patterns):
            return A4Decision(
                is_a4=True,
                is_prohibited_tool=True,
                is_db_destructive=True,
                blocked_by="db_destructive",
                reason=(
                    f"数据库破坏性操作 '{tool}' 属于 A4, "
                    "不得自动删除数据库、数据表、数据库文件或备份"
                ),
                recommendations=[
                    f"使用允许的数据库安全动作: {sorted(ALLOWED_DB_ACTIONS)}",
                    "联系 DBA 人工处理",
                    "若需恢复数据, 通过备份恢复流程",
                ],
                require_ticket=True,
                allowed_db_actions=sorted(ALLOWED_DB_ACTIONS),
            )

        # 未知数据库动作 — 保守拒绝
        return A4Decision(
            is_a4=True,
            is_db_destructive=False,
            blocked_by="db_unknown_action",
            reason=(
                f"未在数据库安全动作白名单中: '{tool}', "
                "保守拒绝自动执行"
            ),
            recommendations=[
                f"确认动作是否在允许列表中: {sorted(ALLOWED_DB_ACTIONS)}",
                "未知数据库动作需 DBA 审核",
            ],
            require_ticket=True,
            allowed_db_actions=sorted(ALLOWED_DB_ACTIONS),
        )

    def _is_db_destructive_tool(self, tool: str) -> bool:
        """判断是否为数据库破坏性工具 (drop/truncate/delete_db/delete_backup 等)"""
        db_destructive_indicators = (
            'drop_database', 'drop_table', 'drop_schema', 'truncate_table',
            'delete_database_files', 'delete_db_backup',
        )
        return tool in db_destructive_indicators

    def _generate_recommendations(
        self, tool: str, asset_type: str,
    ) -> list[str]:
        """生成处置建议"""
        recs: list[str] = []

        if "drop" in tool or "delete" in tool or "truncate" in tool:
            recs.append("数据删除操作必须通过 DBA 工单流程, 禁止自动执行")
            recs.append("如需恢复, 使用备份恢复流程 (db_create_snapshot 先创建快照)")
        if "wipe" in tool or "erase" in tool or "shred" in tool:
            recs.append("磁盘/文件擦除必须物理安全流程, 禁止自动执行")
        if "backup" in tool and "delete" in tool:
            recs.append("删除备份属于灾难性操作, 必须备份管理员审批")
        if "user" in tool and "delete" in tool:
            recs.append("批量删除账号需 IAM 管理员审批, 禁用账号用 disable_account")
        if "route" in tool:
            recs.append("核心路由修改需网络运维团队审批")
        if "block" in tool and "permanent" in tool:
            recs.append("永久封禁大网段需 SOC 主管审批, 使用短 TTL + 自动回滚")
        if "firewall" in tool and "disable" in tool:
            recs.append("关闭防火墙属于安全降级, 必须安全主管审批")

        recs.append("创建人工审批工单, 等 SOC/DBA/网络运维确认后再执行")
        return recs

    def _is_db_target(self, target: str, tool: str) -> bool:
        """判断目标是否为数据库"""
        if not target:
            return False
        db_indicators = ("db", "database", "postgres", "mysql",
                         "mongo", "redis", "oracle", "mssql")
        target_lower = target.lower()
        return any(ind in target_lower for ind in db_indicators)

    def _is_rfc1918_block(self, target: str, params: dict) -> bool:
        """判断是否为 RFC1918 内网网段封禁"""
        import ipaddress

        # 检查目标本身
        cidr_str = target or params.get("cidr", "") or params.get("network", "")
        if not cidr_str:
            return False

        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return False

        rfc1918_networks = [
            ipaddress.ip_network(c, strict=False)
            for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]

        # 完全匹配 /8 /12 /16
        for rfc in rfc1918_networks:
            if net == rfc:
                return True
            # 被包含在 RFC1918 中且前缀 <= 24 (大网段)
            if rfc.supernet_of(net) and net.prefixlen <= 24:
                return True

        return False

    def is_tool_allowed_for_llm(self, tool_name: str) -> bool:
        """判断工具是否允许注册给 LLM Agent"""
        return tool_name.lower().strip() not in PROHIBITED_TOOLS

    def list_prohibited_tools(self) -> list[str]:
        """列出所有 A4 永久禁止的工具"""
        return sorted(PROHIBITED_TOOLS)

    def list_allowed_db_actions(self) -> list[str]:
        """列出数据库安全事件允许的动作"""
        return sorted(ALLOWED_DB_ACTIONS)


# ── 全局单例 ──

db_safety_policy = DbSafetyPolicy()
