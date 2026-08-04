"""
分步提权授权管理器 — ActionGrant 生命周期管理

授权约束:
  1. 绑定具体 Agent
  2. 绑定具体事件
  3. 绑定具体工具
  4. 绑定具体目标（不允许通配符）
  5. 绑定参数范围
  6. 有较短有效期
  7. 有最大执行次数
  8. 可撤销
  9. 不允许通配符目标
  10. 不允许跨事件复用
  11. 不可通过分步提权绕过 A4 禁止策略

风险等级授权方式:
  低风险: 基础权限
  可逆低风险: 策略引擎自动签发
  中风险: CAD 审核后签发
  高风险: CAD + 人工审批
  极高风险: 拒绝签发
"""
import uuid
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ActionGrant
from .state_machine import AutomationLevel

logger = logging.getLogger(__name__)

# 默认有效期（秒）
DEFAULT_TTL = {
    AutomationLevel.A0: 3600,      # 1 小时
    AutomationLevel.A1: 1800,      # 30 分钟
    AutomationLevel.A2: 900,       # 15 分钟
    AutomationLevel.A3: 600,       # 10 分钟
    AutomationLevel.A4: 0,         # 拒绝
}

# 默认最大执行次数
DEFAULT_MAX_EXEC = {
    AutomationLevel.A0: 100,
    AutomationLevel.A1: 50,
    AutomationLevel.A2: 10,
    AutomationLevel.A3: 1,
    AutomationLevel.A4: 0,
}

# Agent 基础权限（最小化）
BASE_CAPABILITIES = {"logs:read", "assets:read", "alerts:create", "action:request"}


class GrantValidationError(Exception):
    pass


class GrantManager:
    """分步提权授权管理器"""

    async def issue_grant(
        self,
        session: AsyncSession,
        subject: str,
        incident_id: str,
        tool_name: str,
        target_scope: dict,
        parameter_constraints: dict = None,
        evidence_ids: list = None,
        approval_level: str = "basic",
        approval_record: dict = None,
        automation_level: AutomationLevel = AutomationLevel.A1,
        created_by: str = "",
        ttl_seconds: int = None,
        max_executions: int = None,
    ) -> ActionGrant:
        """签发授权"""
        # A4 不可绕过检查 — 即使通过分步提权, A4 工具也不能签发授权
        if automation_level == AutomationLevel.A4:
            raise GrantValidationError(
                f"A4 危险动作不可签发授权: tool={tool_name} "
                "(A4 不可通过分步提权绕过)"
            )

        # A4 永久禁止工具二次防线 — 直接调 DbSafetyPolicy
        try:
            from response_engine.db_safety import db_safety_policy
            if db_safety_policy is not None:
                a4_check = db_safety_policy.check_action(
                    tool_name=tool_name,
                    parameters=parameter_constraints or {},
                    target="",
                    asset_type="",
                )
                if a4_check.should_block:
                    raise GrantValidationError(
                        f"A4 工具禁止签发授权: {a4_check.reason}"
                    )
        except ImportError:
            pass

        # 验证：不允许通配符目标
        self._validate_target_scope(target_scope)

        # 验证：不允许跨事件复用（检查是否已存在同 subject+incident+tool 的 active grant）
        existing = await self._find_active_grant(session, subject, incident_id, tool_name)
        if existing:
            logger.info(f"复用已有授权: {existing.id}")
            return existing

        grant_id = f"GRANT-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(timezone.utc)

        if ttl_seconds is None:
            ttl_seconds = DEFAULT_TTL.get(automation_level, 600)
        if max_executions is None:
            max_executions = DEFAULT_MAX_EXEC.get(automation_level, 1)

        if ttl_seconds == 0 or max_executions == 0:
            raise GrantValidationError(f"自动化等级 {automation_level} 不允许签发授权")

        expires_at = now + timedelta(seconds=ttl_seconds)

        grant = ActionGrant(
            id=grant_id,
            subject=subject,
            incident_id=incident_id,
            tool_name=tool_name,
            target_scope=target_scope,
            parameter_constraints=parameter_constraints or {},
            max_executions=max_executions,
            expires_at=expires_at,
            evidence_ids=evidence_ids or [],
            approval_level=approval_level,
            approval_record=approval_record or {},
            revocable=True,
            used_count=0,
            status="active",
            created_at=now,
            created_by=created_by,
        )

        session.add(grant)
        await session.flush()
        logger.info(f"签发授权: {grant_id} subject={subject} tool={tool_name} "
                     f"target={target_scope} expires={expires_at} max_exec={max_executions}")
        return grant

    async def validate_grant(
        self,
        session: AsyncSession,
        grant_id: str,
        subject: str,
        incident_id: str,
        tool_name: str,
        target: str,
        parameters: dict,
    ) -> tuple[bool, str, Optional[ActionGrant]]:
        """验证授权 — 执行器必须验证，不能只由上层 Guard 验证"""
        grant = await session.get(ActionGrant, grant_id)
        if not grant:
            return False, "授权不存在", None

        # 1. 绑定具体 Agent
        if grant.subject != subject:
            return False, f"授权主体不匹配 (expected={grant.subject}, actual={subject})", None

        # 2. 绑定具体事件 — 不允许跨事件复用
        if grant.incident_id != incident_id:
            return False, f"跨事件复用授权被禁止 (grant_incident={grant.incident_id}, request_incident={incident_id})", None

        # 3. 绑定具体工具
        if grant.tool_name != tool_name:
            return False, f"工具不匹配 (expected={grant.tool_name}, actual={tool_name})", None

        # 4. 绑定具体目标
        if not self._target_in_scope(target, grant.target_scope):
            return False, f"目标不在授权范围内 (target={target}, scope={grant.target_scope})", None

        # 5. 绑定参数范围
        param_ok, param_msg = self._validate_parameters(parameters, grant.parameter_constraints)
        if not param_ok:
            return False, f"参数超出授权范围: {param_msg}", None

        # 6. 有效期检查
        now = datetime.now(timezone.utc)
        if now > grant.expires_at:
            await self._update_status(session, grant_id, "expired")
            return False, "授权已过期", None

        # 7. 最大执行次数
        if grant.used_count >= grant.max_executions:
            await self._update_status(session, grant_id, "used_up")
            return False, f"授权使用次数已耗尽 ({grant.used_count}/{grant.max_executions})", None

        # 8. 可撤销检查
        if grant.status == "revoked":
            return False, "授权已被撤销", None

        if grant.status != "active":
            return False, f"授权状态非 active ({grant.status})", None

        return True, "授权有效", grant

    async def consume_grant(
        self,
        session: AsyncSession,
        grant_id: str,
    ) -> bool:
        """消费一次授权（执行成功后调用）"""
        grant = await session.get(ActionGrant, grant_id)
        if not grant:
            return False

        grant.used_count += 1
        if grant.used_count >= grant.max_executions:
            grant.status = "used_up"

        await session.flush()
        return True

    async def revoke_grant(
        self,
        session: AsyncSession,
        grant_id: str,
        revoked_by: str = "admin",
    ) -> bool:
        """撤销授权"""
        grant = await session.get(ActionGrant, grant_id)
        if not grant:
            return False

        if not grant.revocable:
            return False

        grant.status = "revoked"
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revoked_by = revoked_by
        await session.flush()
        logger.info(f"撤销授权: {grant_id} by={revoked_by}")
        return True

    async def get_grant(self, session: AsyncSession, grant_id: str) -> Optional[ActionGrant]:
        return await session.get(ActionGrant, grant_id)

    async def list_active_grants(
        self, session: AsyncSession, subject: str = "", incident_id: str = "",
    ) -> list[ActionGrant]:
        """列出活跃授权"""
        conditions = [ActionGrant.status == "active"]
        if subject:
            conditions.append(ActionGrant.subject == subject)
        if incident_id:
            conditions.append(ActionGrant.incident_id == incident_id)

        result = await session.execute(
            select(ActionGrant).where(and_(*conditions)).order_by(ActionGrant.created_at.desc())
        )
        return list(result.scalars().all())

    def _validate_target_scope(self, target_scope: dict):
        """验证目标范围 — 不允许通配符"""
        for key, values in target_scope.items():
            if not isinstance(values, list):
                raise GrantValidationError(f"目标范围 {key} 必须是列表")
            for v in values:
                if v in ("*", "0.0.0.0/0", "::/0", "any", "ALL", ""):
                    raise GrantValidationError(f"目标范围 {key} 包含通配符: {v}")

    def _target_in_scope(self, target: str, target_scope: dict) -> bool:
        """检查目标是否在授权范围内"""
        for key, values in target_scope.items():
            if target in values:
                return True
            # 支持 CIDR 匹配
            if key in ("ips", "cidrs"):
                import ipaddress
                try:
                    ip = ipaddress.ip_address(target)
                    for cidr in values:
                        try:
                            if ip in ipaddress.ip_network(cidr, strict=False):
                                return True
                        except ValueError:
                            pass
                except ValueError:
                    pass
        return False

    def _validate_parameters(self, params: dict, constraints: dict) -> tuple[bool, str]:
        """验证参数是否在约束范围内"""
        for key, constraint in constraints.items():
            if key not in params:
                continue
            val = params[key]
            if isinstance(constraint, dict):
                if "min" in constraint and isinstance(val, (int, float)):
                    if val < constraint["min"]:
                        return False, f"{key}={val} < min={constraint['min']}"
                if "max" in constraint and isinstance(val, (int, float)):
                    if val > constraint["max"]:
                        return False, f"{key}={val} > max={constraint['max']}"
                if "allowed" in constraint and val not in constraint["allowed"]:
                    return False, f"{key}={val} not in allowed={constraint['allowed']}"
            elif isinstance(constraint, (list, set)):
                if val not in constraint:
                    return False, f"{key}={val} not in allowed={constraint}"
        return True, ""

    async def _find_active_grant(
        self, session: AsyncSession, subject: str, incident_id: str, tool_name: str,
    ) -> Optional[ActionGrant]:
        result = await session.execute(
            select(ActionGrant).where(and_(
                ActionGrant.subject == subject,
                ActionGrant.incident_id == incident_id,
                ActionGrant.tool_name == tool_name,
                ActionGrant.status == "active",
            )).limit(1)
        )
        return result.scalar_one_or_none()

    async def _update_status(self, session: AsyncSession, grant_id: str, status: str):
        await session.execute(
            update(ActionGrant).where(ActionGrant.id == grant_id).values(status=status)
        )


# 全局单例
grant_manager = GrantManager()
