"""
Trusted Action Gateway 数据模型

新增 4 张表:
  - action_grants:      分步提权授权（ActionGrant）
  - action_ledger:       动作幂等账本（ActionLedger）
  - tag_audit_trail:     统一审计日志
  - action_budget_state: 预算与熔断状态
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey,
    Index, UniqueConstraint,
)
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy import JSON
from models import Base

MutableJSON = MutableDict.as_mutable(JSON)
MutableListJSON = MutableList.as_mutable(JSON)


def _utcnow():
    return datetime.now(timezone.utc)


class ActionGrant(Base):
    """分步提权授权 — 短期、单事件、单工具、单目标的临时权限"""
    __tablename__ = "action_grants"

    id = Column(String(64), primary_key=True)
    subject = Column(String(100), nullable=False, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    target_scope = Column(MutableJSON, nullable=False)
    parameter_constraints = Column(MutableJSON, nullable=False, default=dict)
    max_executions = Column(Integer, nullable=False, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    evidence_ids = Column(MutableListJSON, default=list)
    approval_level = Column(String(20), nullable=False, default="basic")
    approval_record = Column(MutableJSON, default=dict)
    revocable = Column(Boolean, default=True, nullable=False)
    used_count = Column(Integer, default=0, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(100), default="")
    status = Column(String(20), default="active", nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    created_by = Column(String(100), default="")

    __table_args__ = (
        Index("ix_grants_incident_tool", "incident_id", "tool_name"),
        Index("ix_grants_subject_status", "subject", "status"),
    )


class ActionLedger(Base):
    """动作幂等账本 — idempotency_key 唯一约束防并发竞争"""
    __tablename__ = "action_ledger"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(String(64), nullable=False, unique=True, index=True)
    idempotency_key = Column(String(128), nullable=False, unique=True)
    incident_id = Column(String(100), nullable=False, index=True)
    plan_version = Column(String(64), nullable=False, default="v1")
    tool_name = Column(String(100), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    normalized_parameters = Column(MutableJSON, nullable=False, default=dict)
    parameter_hash = Column(String(64), nullable=False)
    status = Column(String(30), default="proposed", nullable=False, index=True)
    request_count = Column(Integer, default=0, nullable=False)
    execution_started_at = Column(DateTime(timezone=True), nullable=True)
    execution_finished_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(MutableJSON, default=dict)
    error = Column(Text, default="")
    rollback_action_id = Column(String(64), nullable=True, index=True)
    rollback_idempotency_key = Column(String(128), nullable=True)
    rollback_result = Column(MutableJSON, default=dict)
    verification_result = Column(MutableJSON, default=dict)
    verification_passed = Column(Boolean, nullable=True)
    grant_id = Column(String(64), ForeignKey("action_grants.id"), nullable=True, index=True)
    trace_id = Column(String(64), default="", index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_ledger_incident_tool_target", "incident_id", "tool_name", "target"),
    )


class TagAuditTrail(Base):
    """统一审计日志 — 不记录明文 Token/密码/私钥"""
    __tablename__ = "tag_audit_trail"

    id = Column(Integer, primary_key=True, autoincrement=True)
    trace_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(100), default="", index=True)
    action_id = Column(String(64), default="", index=True)
    idempotency_key = Column(String(128), default="", index=True)
    grant_id = Column(String(64), default="", index=True)
    agent_identity = Column(String(100), default="")
    tool_name = Column(String(100), default="", index=True)
    server_id = Column(String(100), default="")
    transport_type = Column(String(20), default="")
    server_identity = Column(String(255), default="")
    tool_schema_hash = Column(String(64), default="")
    target = Column(String(255), default="")
    normalized_parameters = Column(MutableJSON, default=dict)
    evidence_ids = Column(MutableListJSON, default=list)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="")
    policy_decision = Column(String(30), default="")
    approval_record = Column(MutableJSON, default=dict)
    request_id = Column(String(64), default="")
    token_jti = Column(String(64), default="")
    execution_result = Column(MutableJSON, default=dict)
    verification_result = Column(MutableJSON, default=dict)
    rollback_result = Column(MutableJSON, default=dict)
    timestamps = Column(MutableJSON, default=dict)
    action_state = Column(String(30), default="proposed", index=True)
    blocked_by = Column(String(50), default="")
    block_reason = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)

    __table_args__ = (
        Index("ix_audit_trace_incident", "trace_id", "incident_id"),
        Index("ix_audit_tool_state", "tool_name", "action_state"),
    )


class ActionBudgetState(Base):
    """动作预算与熔断状态 — closed→open→half_open→closed"""
    __tablename__ = "action_budget_state"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scope_type = Column(String(20), nullable=False, index=True)
    scope_key = Column(String(200), nullable=False, index=True)
    action_count = Column(Integer, default=0, nullable=False)
    target_count = Column(Integer, default=0, nullable=False)
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)
    window_start = Column(DateTime(timezone=True), default=_utcnow)
    window_end = Column(DateTime(timezone=True), nullable=True)
    circuit_state = Column(String(20), default="closed", nullable=False, index=True)
    tripped_reason = Column(String(200), default="")
    tripped_at = Column(DateTime(timezone=True), nullable=True)
    tripped_count = Column(Integer, default=0)
    reset_by = Column(String(100), default="")
    reset_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        UniqueConstraint("scope_type", "scope_key", name="uq_budget_scope"),
    )
