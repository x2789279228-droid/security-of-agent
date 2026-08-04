"""
影响范围控制与预算管理

ToolImpactPolicy — 每个有副作用工具的影响策略
ActionBudget — 全局动作预算与熔断
Canary — 批量动作的金丝雀执行
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
import ipaddress

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ActionBudgetState

logger = logging.getLogger(__name__)


@dataclass
class ToolImpactPolicy:
    """工具影响策略"""
    tool_name: str
    max_targets_per_action: int = 1
    max_targets_per_incident: int = 10
    max_actions_per_minute: int = 10
    max_actions_per_hour: int = 100
    max_ttl_seconds: int = 86400
    protected_assets: list = field(default_factory=list)
    protected_asset_tags: list = field(default_factory=list)
    protected_cidrs: list = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    ])
    deny_targets: list = field(default_factory=lambda: [
        "*", "0.0.0.0/0", "::/0", "any", "ALL",
    ])
    allowed_environments: list = field(default_factory=lambda: ["sandbox", "production"])
    require_rollback: bool = True
    require_step_up: bool = False
    require_human_approval: bool = False
    canary_required: bool = False


# 核心资产类型 — 禁止自动处置
PROTECTED_ASSET_TYPES = {
    "database", "domain_controller", "gateway",
    "kafka", "flink", "postgresql", "mcp_server_host",
    "unregistered",  # 未登记资产
}


# 默认工具影响策略
DEFAULT_POLICIES = {
    "block_ip": ToolImpactPolicy(
        tool_name="block_ip",
        max_targets_per_action=5,
        max_targets_per_incident=20,
        max_actions_per_minute=10,
        max_actions_per_hour=50,
        max_ttl_seconds=3600,
        require_rollback=True,
        canary_required=True,
    ),
    "isolate_host": ToolImpactPolicy(
        tool_name="isolate_host",
        max_targets_per_action=1,
        max_targets_per_incident=3,
        max_actions_per_minute=2,
        max_actions_per_hour=10,
        max_ttl_seconds=7200,
        require_rollback=True,
        require_human_approval=True,
        canary_required=True,
    ),
    "rate_limit": ToolImpactPolicy(
        tool_name="rate_limit",
        max_targets_per_action=5,
        max_targets_per_incident=20,
        max_actions_per_minute=5,
        max_actions_per_hour=30,
        max_ttl_seconds=1800,
        require_rollback=True,
    ),
    "terminate_process": ToolImpactPolicy(
        tool_name="terminate_process",
        max_targets_per_action=1,
        max_targets_per_incident=3,
        max_actions_per_minute=2,
        max_actions_per_hour=5,
        require_human_approval=True,
    ),
    "vulnerability_scan": ToolImpactPolicy(
        tool_name="vulnerability_scan",
        max_targets_per_action=1,
        max_targets_per_incident=5,
        max_actions_per_minute=2,
        max_actions_per_hour=10,
        max_ttl_seconds=300,
    ),
    "alert_only": ToolImpactPolicy(
        tool_name="alert_only",
        max_targets_per_action=100,
        max_targets_per_incident=1000,
        max_actions_per_minute=50,
        max_actions_per_hour=500,
    ),
}


class ImpactPolicyManager:
    """影响策略管理器"""

    def __init__(self):
        self._policies = dict(DEFAULT_POLICIES)

    def get_policy(self, tool_name: str) -> ToolImpactPolicy:
        return self._policies.get(tool_name, ToolImpactPolicy(tool_name=tool_name))

    def register_policy(self, policy: ToolImpactPolicy):
        self._policies[policy.tool_name] = policy

    def check_target(
        self, tool_name: str, target: str, asset_info: dict = None,
    ) -> tuple[bool, str]:
        """检查目标是否允许操作"""
        policy = self.get_policy(tool_name)
        asset_info = asset_info or {}

        # 通配符检查
        if target in policy.deny_targets:
            return False, f"通配符目标被禁止: {target}"

        # 核心资产检查
        asset_type = asset_info.get("type", "unregistered")
        if asset_type in PROTECTED_ASSET_TYPES:
            return False, f"核心资产({asset_type})禁止自动处置"
        if asset_info.get("protected", False):
            return False, "受保护资产禁止自动处置"

        # 受保护 CIDR 检查
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_loopback:
                return False, "回环地址禁止操作"
            for cidr in policy.protected_cidrs:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return False, f"目标在受保护 CIDR 范围内: {cidr}"
        except ValueError:
            pass

        return True, ""

    def check_targets_count(self, tool_name: str, targets: list) -> tuple[bool, str]:
        """检查单次动作目标数量"""
        policy = self.get_policy(tool_name)
        if len(targets) > policy.max_targets_per_action:
            return False, f"目标数量超限: {len(targets)} > {policy.max_targets_per_action}"
        return True, ""

    def check_ttl(self, tool_name: str, ttl_seconds: int) -> tuple[bool, str]:
        """检查 TTL"""
        policy = self.get_policy(tool_name)
        if ttl_seconds > policy.max_ttl_seconds:
            return False, f"TTL 超限: {ttl_seconds} > {policy.max_ttl_seconds}"
        return True, ""

    def needs_canary(self, tool_name: str, target_count: int) -> bool:
        """是否需要金丝雀执行"""
        policy = self.get_policy(tool_name)
        return policy.canary_required and target_count > 1


# 全局单例
impact_policy_manager = ImpactPolicyManager()


class ActionBudgetManager:
    """动作预算管理器 — 熔断控制

    作用域:
      - incident: 单事件动作预算
      - agent: 单 Agent 动作预算
      - tool: 单工具时间窗口预算
      - global: 全局自动处置预算
    """

    # 默认预算
    BUDGETS = {
        "incident": {"max_actions": 50, "max_targets": 100, "window_minutes": 60},
        "agent": {"max_actions": 30, "max_targets": 50, "window_minutes": 60},
        "tool": {"max_actions": 20, "max_targets": 30, "window_minutes": 5},
        "global": {"max_actions": 200, "max_targets": 500, "window_minutes": 60},
    }

    async def check_budget(
        self, session: AsyncSession, scope_type: str, scope_key: str,
    ) -> tuple[bool, str, dict]:
        """检查预算是否超限"""
        budget = await self._get_or_create(session, scope_type, scope_key)

        if budget.circuit_state == "open":
            return False, f"熔断中: {budget.tripped_reason}", {
                "circuit_state": budget.circuit_state,
                "action_count": budget.action_count,
                "target_count": budget.target_count,
            }

        limits = self.BUDGETS.get(scope_type, {})
        max_actions = limits.get("max_actions", 100)
        max_targets = limits.get("max_targets", 200)

        if budget.action_count >= max_actions:
            await self._trip_circuit(session, scope_type, scope_key,
                                       f"动作数超限: {budget.action_count}>={max_actions}")
            return False, f"动作数超限: {budget.action_count}>={max_actions}", {
                "circuit_state": "open",
                "action_count": budget.action_count,
            }

        if budget.target_count >= max_targets:
            await self._trip_circuit(session, scope_type, scope_key,
                                       f"目标数超限: {budget.target_count}>={max_targets}")
            return False, f"目标数超限: {budget.target_count}>={max_targets}", {
                "circuit_state": "open",
                "target_count": budget.target_count,
            }

        return True, "", {
            "circuit_state": budget.circuit_state,
            "action_count": budget.action_count,
            "target_count": budget.target_count,
        }

    async def record_action(
        self, session: AsyncSession, scope_type: str, scope_key: str,
        success: bool, target_count: int = 1,
    ):
        """记录一次动作"""
        budget = await self._get_or_create(session, scope_type, scope_key)
        budget.action_count += 1
        budget.target_count += target_count
        if success:
            budget.success_count += 1
        else:
            budget.failure_count += 1
        await session.flush()

    async def check_all_budgets(
        self, session: AsyncSession, incident_id: str, agent_id: str, tool_name: str,
    ) -> tuple[bool, str, dict]:
        """检查所有作用域预算"""
        for scope_type, scope_key in [
            ("incident", incident_id),
            ("agent", agent_id),
            ("tool", tool_name),
            ("global", "global"),
        ]:
            ok, reason, info = await self.check_budget(session, scope_type, scope_key)
            if not ok:
                return False, reason, {"scope": scope_type, **info}
        return True, "", {}

    async def get_circuit_state(self, session: AsyncSession, scope_type: str, scope_key: str) -> dict:
        budget = await self._get_or_create(session, scope_type, scope_key)
        return {
            "scope_type": scope_type,
            "scope_key": scope_key,
            "circuit_state": budget.circuit_state,
            "action_count": budget.action_count,
            "target_count": budget.target_count,
            "tripped_reason": budget.tripped_reason,
            "tripped_at": budget.tripped_at.isoformat() if budget.tripped_at else None,
        }

    async def reset_circuit(
        self, session: AsyncSession, scope_type: str, scope_key: str, reset_by: str = "admin",
    ) -> bool:
        """解除熔断"""
        budget = await self._get_or_create(session, scope_type, scope_key)
        budget.circuit_state = "closed"
        budget.tripped_reason = ""
        budget.tripped_at = None
        budget.reset_by = reset_by
        budget.reset_at = datetime.now(timezone.utc)
        budget.action_count = 0
        budget.target_count = 0
        budget.success_count = 0
        budget.failure_count = 0
        budget.window_start = datetime.now(timezone.utc)
        await session.flush()
        logger.info(f"解除熔断: {scope_type}/{scope_key} by={reset_by}")
        return True

    async def _get_or_create(
        self, session: AsyncSession, scope_type: str, scope_key: str,
    ) -> ActionBudgetState:
        result = await session.execute(
            select(ActionBudgetState).where(and_(
                ActionBudgetState.scope_type == scope_type,
                ActionBudgetState.scope_key == scope_key,
            ))
        )
        budget = result.scalar_one_or_none()
        if not budget:
            budget = ActionBudgetState(
                scope_type=scope_type,
                scope_key=scope_key,
                window_start=datetime.now(timezone.utc),
            )
            session.add(budget)
            await session.flush()
        return budget

    async def _trip_circuit(
        self, session: AsyncSession, scope_type: str, scope_key: str, reason: str,
    ):
        budget = await self._get_or_create(session, scope_type, scope_key)
        budget.circuit_state = "open"
        budget.tripped_reason = reason
        budget.tripped_at = datetime.now(timezone.utc)
        budget.tripped_count += 1
        await session.flush()
        logger.warning(f"熔断触发: {scope_type}/{scope_key} reason={reason}")


# 全局单例
action_budget = ActionBudgetManager()


class CanaryExecutor:
    """金丝雀执行器 — 批量动作先试一个再分批"""

    async def execute_with_canary(
        self,
        targets: list,
        execute_fn,  # async (target) -> dict
        verify_fn=None,  # async (target, result) -> bool
        batch_size: int = 5,
    ) -> dict:
        """金丝雀执行

        1. 先处理一个目标
        2. 验证业务和安全效果
        3. 成功后再分批执行
        4. 任一批次异常立即停止
        """
        if len(targets) <= 1:
            results = []
            for t in targets:
                r = await execute_fn(t)
                results.append({"target": t, "result": r})
            return {"completed": True, "results": results, "canary": False}

        # 步骤 1: 金丝雀执行
        canary_target = targets[0]
        canary_result = await execute_fn(canary_target)

        if not canary_result.get("success", False):
            return {
                "completed": False,
                "aborted": True,
                "abort_reason": "canary_failed",
                "canary_target": canary_target,
                "canary_result": canary_result,
                "results": [{"target": canary_target, "result": canary_result}],
            }

        # 步骤 2: 验证
        if verify_fn:
            verified = await verify_fn(canary_target, canary_result)
            if not verified:
                return {
                    "completed": False,
                    "aborted": True,
                    "abort_reason": "canary_verification_failed",
                    "canary_target": canary_target,
                    "results": [{"target": canary_target, "result": canary_result}],
                }

        # 步骤 3: 分批执行剩余目标
        remaining = targets[1:]
        results = [{"target": canary_target, "result": canary_result, "canary": True}]

        for i in range(0, len(remaining), batch_size):
            batch = remaining[i:i + batch_size]
            for target in batch:
                try:
                    r = await execute_fn(target)
                    results.append({"target": target, "result": r})
                    if not r.get("success", False):
                        return {
                            "completed": False,
                            "aborted": True,
                            "abort_reason": f"batch_failure: {target}",
                            "results": results,
                        }
                except Exception as e:
                    return {
                        "completed": False,
                        "aborted": True,
                        "abort_reason": f"batch_exception: {e}",
                        "results": results,
                    }

        return {"completed": True, "results": results, "canary": True}


# 全局单例
canary_executor = CanaryExecutor()
