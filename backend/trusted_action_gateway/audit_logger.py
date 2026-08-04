"""
统一审计日志 — 每个动作的完整生命周期记录

不记录明文 Token、密码和私钥。
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import TagAuditTrail

logger = logging.getLogger(__name__)


class TagAuditLogger:
    """统一审计日志记录器"""

    async def log_event(
        self,
        session: AsyncSession,
        trace_id: str,
        incident_id: str = "",
        action_id: str = "",
        idempotency_key: str = "",
        grant_id: str = "",
        agent_identity: str = "",
        tool_name: str = "",
        server_id: str = "",
        transport_type: str = "",
        server_identity: str = "",
        tool_schema_hash: str = "",
        target: str = "",
        normalized_parameters: dict = None,
        evidence_ids: list = None,
        risk_score: float = 0.0,
        risk_level: str = "",
        policy_decision: str = "",
        approval_record: dict = None,
        request_id: str = "",
        token_jti: str = "",
        execution_result: dict = None,
        verification_result: dict = None,
        rollback_result: dict = None,
        timestamps: dict = None,
        action_state: str = "proposed",
        blocked_by: str = "",
        block_reason: str = "",
    ) -> TagAuditTrail:
        """写入审计日志"""
        # 清理敏感参数 — 不记录明文 Token/密码/私钥
        safe_params = self._sanitize_params(normalized_parameters or {})

        entry = TagAuditTrail(
            trace_id=trace_id,
            incident_id=incident_id,
            action_id=action_id,
            idempotency_key=idempotency_key,
            grant_id=grant_id,
            agent_identity=agent_identity,
            tool_name=tool_name,
            server_id=server_id,
            transport_type=transport_type,
            server_identity=self._hash_identity(server_identity),
            tool_schema_hash=tool_schema_hash,
            target=target,
            normalized_parameters=safe_params,
            evidence_ids=evidence_ids or [],
            risk_score=risk_score,
            risk_level=risk_level,
            policy_decision=policy_decision,
            approval_record=approval_record or {},
            request_id=request_id,
            token_jti=token_jti,  # 只记录 JTI，不记录 Token 本身
            execution_result=execution_result or {},
            verification_result=verification_result or {},
            rollback_result=rollback_result or {},
            timestamps=timestamps or {},
            action_state=action_state,
            blocked_by=blocked_by,
            block_reason=block_reason,
        )

        session.add(entry)
        await session.flush()
        return entry

    async def update_state(
        self, session: AsyncSession, trace_id: str, action_state: str,
        execution_result: dict = None, verification_result: dict = None,
        rollback_result: dict = None, timestamps: dict = None,
    ):
        """更新审计记录状态"""
        from sqlalchemy import update
        values = {"action_state": action_state}
        if execution_result is not None:
            values["execution_result"] = execution_result
        if verification_result is not None:
            values["verification_result"] = verification_result
        if rollback_result is not None:
            values["rollback_result"] = rollback_result
        if timestamps is not None:
            values["timestamps"] = timestamps

        await session.execute(
            update(TagAuditTrail)
            .where(TagAuditTrail.trace_id == trace_id)
            .values(**values)
        )

    async def get_audit_trail(
        self, session: AsyncSession, trace_id: str = "",
        incident_id: str = "", action_id: str = "",
        limit: int = 100, offset: int = 0,
    ) -> list[TagAuditTrail]:
        """查询审计轨迹"""
        conditions = []
        if trace_id:
            conditions.append(TagAuditTrail.trace_id == trace_id)
        if incident_id:
            conditions.append(TagAuditTrail.incident_id == incident_id)
        if action_id:
            conditions.append(TagAuditTrail.action_id == action_id)

        result = await session.execute(
            select(TagAuditTrail)
            .where(and_(*conditions) if conditions else True)
            .order_by(TagAuditTrail.created_at.desc())
            .limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def get_blocked_actions(
        self, session: AsyncSession, limit: int = 50,
    ) -> list[TagAuditTrail]:
        """查询被阻止的动作"""
        result = await session.execute(
            select(TagAuditTrail)
            .where(TagAuditTrail.action_state == "blocked")
            .order_by(TagAuditTrail.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    def _sanitize_params(self, params: dict) -> dict:
        """清理敏感参数"""
        sensitive_keys = {"password", "secret", "token", "key", "api_key", "private_key"}
        safe = {}
        for k, v in params.items():
            if any(s in k.lower() for s in sensitive_keys):
                safe[k] = "***REDACTED***"
            else:
                safe[k] = v
        return safe

    def _hash_identity(self, identity: str) -> str:
        """哈希服务端身份（不记录明文）"""
        if not identity:
            return ""
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


# 全局单例
tag_audit_logger = TagAuditLogger()
