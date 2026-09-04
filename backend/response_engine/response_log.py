"""
响应日志 (Response Log)

记录所有威胁检测、响应执行、审批操作的全量审计日志。
支持按时间/IP/威胁类型/动作类型查询。

存储:
  - PostgreSQL (ResponseLog 表) — 持久化审计
  - Redis 缓存 — 近期日志快速查询
"""
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


@dataclass
class ResponseLogEntry:
    """响应日志条目"""
    id: int = 0
    session_id: str = ""
    event_id: int = 0
    threat_type: str = ""
    threat_confidence: float = 0.0
    threat_severity: str = ""
    src_ip: str = ""
    policy_name: str = ""
    action_name: str = ""
    action_params: dict = field(default_factory=dict)
    action_success: bool = False
    action_result: dict = field(default_factory=dict)
    rollback_token: str = ""
    auto_execute: bool = False
    approval_id: str = ""
    approval_status: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        result = self.action_result or {}
        params = self.action_params or {}
        mode = result.get("mode") or params.get("execution_mode") or ""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "event_id": self.event_id,
            "threat_type": self.threat_type,
            "threat_confidence": self.threat_confidence,
            "threat_severity": self.threat_severity,
            "src_ip": self.src_ip,
            "policy_name": self.policy_name,
            "action_name": self.action_name,
            "action_success": self.action_success,
            "action_params": params,
            "action_result": result,
            "execution_mode": mode,
            "verified": result.get("verified"),
            "rollback_token": self.rollback_token,
            "auto_execute": self.auto_execute,
            "approval_id": self.approval_id,
            "approval_status": self.approval_status,
            "created_at": self.created_at,
        }


class ResponseLogger:
    """响应日志记录器"""

    def __init__(self):
        self._redis = None
        self._cache_prefix = "response_log:"

    def set_redis(self, redis_client):
        self._redis = redis_client

    async def log_threat(
        self,
        session: AsyncSession,
        threat_info: dict,
        policy_name: str,
        actions: list[dict],
        auto_execute: bool,
        needs_approval: bool,
        match_status: str = "",
        skip_reason: str = "",
        category: str = "",
    ):
        """记录威胁检测事件到日志"""
        try:
            from models import ResponseLog

            log_entry = ResponseLog(
                session_id=threat_info.get("session_id", ""),
                event_id=threat_info.get("event_id", 0),
                threat_type=threat_info.get("threat_type", "UNKNOWN"),
                threat_confidence=threat_info.get("confidence", 0.0),
                threat_severity=threat_info.get("severity", "info"),
                src_ip=threat_info.get("src_ip", ""),
                policy_name=policy_name,
                action_name="policy_match",
                # v5 修复(C1/A):记录响应触发来源(fastpath_strong/fastpath_severity/
                # audit_llm)与是否允许封禁，便于追溯"封禁是谁决定的"
                # L1: match_status / skip_reason / category 可观测，禁止静默放过
                action_params={
                    "actions": actions,
                    "auto_execute": auto_execute,
                    "needs_approval": needs_approval,
                    "source": threat_info.get("response_source", ""),
                    "allow_blocking": bool(threat_info.get("allow_blocking", True)),
                    "match_status": match_status or threat_info.get("match_status", ""),
                    "skip_reason": skip_reason or threat_info.get("skip_reason", ""),
                    "category": category or threat_info.get("category", ""),
                },
                action_success=True,
                auto_execute=auto_execute,
                approval_status="approved" if auto_execute else "pending",
            )
            session.add(log_entry)
            await session.commit()
        except Exception as e:
            logger.warning(f"Failed to log threat: {e}")

    async def log_action(
        self,
        session: AsyncSession,
        session_id: str,
        event_id: int,
        threat_info: dict,
        action_name: str,
        action_params: dict,
        success: bool,
        result: dict,
        rollback_token: str,
        auto_execute: bool,
        approval_id: str = "",
        approval_status: str = "",
    ):
        """记录单次动作执行到日志"""
        try:
            from models import ResponseLog

            log_entry = ResponseLog(
                session_id=session_id,
                event_id=event_id,
                threat_type=threat_info.get("threat_type", "UNKNOWN"),
                threat_confidence=threat_info.get("confidence", 0.0),
                threat_severity=threat_info.get("severity", "info"),
                src_ip=threat_info.get("src_ip", ""),
                policy_name=threat_info.get("policy_name", ""),
                action_name=action_name,
                action_params=action_params,
                action_success=success,
                action_result=result,
                rollback_token=rollback_token,
                auto_execute=auto_execute,
                approval_id=approval_id,
                approval_status=approval_status,
            )
            session.add(log_entry)
            await session.commit()
        except Exception as e:
            logger.warning(f"Failed to log action: {e}")

    async def query_logs(
        self,
        session: AsyncSession,
        session_id: str = "",
        threat_type: str = "",
        src_ip: str = "",
        action_name: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[ResponseLogEntry]:
        """查询响应日志"""
        try:
            from models import ResponseLog

            conditions = []
            if session_id:
                conditions.append(ResponseLog.session_id == session_id)
            if threat_type:
                conditions.append(ResponseLog.threat_type == threat_type)
            if src_ip:
                conditions.append(ResponseLog.src_ip == src_ip)
            if action_name:
                conditions.append(ResponseLog.action_name == action_name)

            stmt = select(ResponseLog)
            if conditions:
                stmt = stmt.where(and_(*conditions))
            stmt = stmt.order_by(desc(ResponseLog.created_at)).limit(limit).offset(offset)

            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                ResponseLogEntry(
                    id=r.id,
                    session_id=r.session_id,
                    event_id=r.event_id,
                    threat_type=r.threat_type,
                    threat_confidence=r.threat_confidence,
                    threat_severity=r.threat_severity,
                    src_ip=r.src_ip,
                    policy_name=r.policy_name,
                    action_name=r.action_name,
                    action_params=r.action_params or {},
                    action_success=r.action_success,
                    action_result=r.action_result or {},
                    rollback_token=r.rollback_token or "",
                    auto_execute=r.auto_execute,
                    approval_id=r.approval_id or "",
                    approval_status=r.approval_status or "",
                    created_at=r.created_at.isoformat() if r.created_at else "",
                )
                for r in rows
            ]
        except Exception as e:
            logger.warning(f"Failed to query response logs: {e}")
            return []


response_logger = ResponseLogger()
