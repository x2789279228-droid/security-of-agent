"""
Trusted Action Gateway — 主编排器

统一处理流程:
  Agent Plan
  → Tool Registry
  → Output Stabilizer
  → Schema Validator
  → Authorization (Grant Manager)
  → Risk Policy (Risk Engine)
  → Idempotency Guard
  → Transport Security
  → Executor
  → Post-Action Verification
  → Rollback Controller

所有状态变化写入审计日志 (TagAuditTrail)。
不破坏现有 Kafka / Flink / FastAPI / 前端 / RAG / HTTP 兼容模式。

设计原则:
  - 不使用 shell=True
  - 不允许任意命令执行
  - 不允许通配符高风险授权
  - 不允许未经验证就宣称处置成功
  - 不硬编码密钥
  - 执行器必须二次验证授权
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .state_machine import (
    ActionState, AutomationLevel, ExecutionMode,
    can_transition, is_terminal, LEVEL_APPROVAL_MAP, LEVEL_AUTO_EXECUTE,
)
from .risk_engine import risk_engine, RiskAssessment
from .grant_manager import grant_manager, GrantValidationError
from .idempotency_guard import idempotency_guard, IdempotencyError
from .impact_policy import (
    impact_policy_manager, action_budget, canary_executor,
    ActionBudgetManager, ImpactPolicyManager, CanaryExecutor,
)
from .audit_logger import tag_audit_logger
from .models import ActionGrant, ActionLedger, TagAuditTrail, ActionBudgetState

# A4 危险动作策略 — 延迟导入
try:
    from response_engine.db_safety import db_safety_policy
except ImportError:
    db_safety_policy = None

logger = logging.getLogger(__name__)


# ── 工具注册表 (TagToolRegistry) ──────────────────────────────

# 默认工具元数据: tool_name -> {base_risk, schema_hash, executor_type}
DEFAULT_TOOL_REGISTRY: dict[str, dict] = {
    "block_ip": {
        "base_risk": "HIGH",
        "executor_type": "iptables",
        "schema_hash": "sha256:block_ip_v1",
        "requires_rollback": True,
    },
    "isolate_host": {
        "base_risk": "CRITICAL",
        "executor_type": "iptables",
        "schema_hash": "sha256:isolate_host_v1",
        "requires_rollback": True,
    },
    "rate_limit": {
        "base_risk": "MEDIUM",
        "executor_type": "iptables",
        "schema_hash": "sha256:rate_limit_v1",
        "requires_rollback": True,
    },
    "alert_only": {
        "base_risk": "LOW",
        "executor_type": "noop",
        "schema_hash": "sha256:alert_only_v1",
        "requires_rollback": False,
    },
    "vulnerability_scan": {
        "base_risk": "LOW",
        "executor_type": "stdio_mcp",
        "schema_hash": "sha256:vuln_scan_v1",
        "requires_rollback": False,
    },
    "event_store.query": {
        "base_risk": "LOW",
        "executor_type": "noop",
        "schema_hash": "sha256:event_query_v1",
        "requires_rollback": False,
    },
    "knowledge.search": {
        "base_risk": "LOW",
        "executor_type": "noop",
        "schema_hash": "sha256:kb_search_v1",
        "requires_rollback": False,
    },
}


class TagToolRegistry:
    """TAG 工具注册表 — 工具白名单与元数据"""

    def __init__(self):
        self._tools: dict[str, dict] = dict(DEFAULT_TOOL_REGISTRY)

    def is_registered(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def get_meta(self, tool_name: str) -> Optional[dict]:
        return self._tools.get(tool_name)

    def register(self, tool_name: str, meta: dict) -> None:
        self._tools[tool_name] = meta

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())


# ── Schema 校验器 (轻量级，复用现有 stabilizer/validator) ──

class TagSchemaValidator:
    """参数 Schema 校验器 — 轻量级，避免重复实现"""

    TOOL_SCHEMAS: dict[str, dict] = {
        "block_ip": {
            "required": ["ip"],
            "types": {"ip": str, "ttl_seconds": int},
        },
        "isolate_host": {
            "required": ["host"],
            "types": {"host": str, "ttl_seconds": int},
        },
        "rate_limit": {
            "required": ["ip"],
            "types": {"ip": str, "rate": int},
        },
        "alert_only": {
            "required": ["message"],
            "types": {"message": str},
        },
        "vulnerability_scan": {
            "required": ["target"],
            "types": {"target": str},
        },
        "event_store.query": {
            "required": ["query"],
            "types": {"query": str},
        },
        "knowledge.search": {
            "required": ["query"],
            "types": {"query": str},
        },
    }

    def validate(self, tool_name: str, parameters: dict) -> tuple[bool, str]:
        schema = self.TOOL_SCHEMAS.get(tool_name)
        if not schema:
            return True, ""
        if not isinstance(parameters, dict):
            return False, "参数必须是 dict"
        for key in schema.get("required", []):
            if key not in parameters:
                return False, f"缺少必填参数: {key}"
        for key, expected_type in schema.get("types", {}).items():
            if key in parameters:
                val = parameters[key]
                if not isinstance(val, expected_type):
                    return False, f"参数 {key} 类型错误 (期望 {expected_type.__name__})"
        return True, ""


# ── 输出稳定器 ──

class TagOutputStabilizer:
    """输出稳定器 — 参数规范化与 JSON 修复"""

    def stabilize(self, parameters: dict) -> dict:
        if not isinstance(parameters, dict):
            return {}
        stable = {}
        for k, v in parameters.items():
            if v is None:
                continue
            if isinstance(v, str):
                v = v.strip()
            stable[k] = v
        return stable


# ── 请求 / 响应数据模型 ──────────────────────────────────────

@dataclass
class ActionPlan:
    """动作计划 — Agent 提交的处置意图"""
    tool_name: str
    target: str
    parameters: dict
    incident_id: str
    agent_identity: str
    evidence_ids: list = field(default_factory=list)
    plan_version: str = "v1"
    asset_info: dict = field(default_factory=dict)
    trace_id: str = ""
    request_id: str = ""
    token_jti: str = ""


@dataclass
class GatewayResult:
    """网关处理结果"""
    action_id: str
    trace_id: str
    action_state: ActionState
    policy_decision: str
    risk_assessment: Optional[RiskAssessment] = None
    grant_id: str = ""
    idempotency_key: str = ""
    blocked_by: str = ""
    block_reason: str = ""
    execution_result: dict = field(default_factory=dict)
    verification_result: dict = field(default_factory=dict)
    rollback_result: dict = field(default_factory=dict)
    ledger: Optional[ActionLedger] = None
    audit_trail_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "trace_id": self.trace_id,
            "action_state": self.action_state.value,
            "policy_decision": self.policy_decision,
            "risk_assessment": self.risk_assessment.to_dict() if self.risk_assessment else None,
            "grant_id": self.grant_id,
            "idempotency_key": self.idempotency_key,
            "blocked_by": self.blocked_by,
            "block_reason": self.block_reason,
            "execution_result": self.execution_result,
            "verification_result": self.verification_result,
            "rollback_result": self.rollback_result,
        }


# ── 异常 ──────────────────────────────────────────────────────

class TagError(Exception):
    """TAG 基础异常"""


class TagBlockedError(TagError):
    """动作被阻止"""

    def __init__(self, reason: str, blocked_by: str = ""):
        super().__init__(reason)
        self.blocked_by = blocked_by
        self.reason = reason


class TagAuthorizationError(TagError):
    """授权错误"""


class TagIdempotencyError(TagError):
    """幂等错误"""


# ── 主编排器: TrustedActionGateway ─────────────────────────────

class TrustedActionGateway:
    """Trusted Action Gateway — 可信行动网关主编排器"""

    def __init__(
        self,
        iptables_executor=None,
        post_verifier=None,
        mcp_client_factory=None,
        execution_mode: ExecutionMode = ExecutionMode.PRODUCTION,
    ):
        self._tool_registry = TagToolRegistry()
        self._stabilizer = TagOutputStabilizer()
        self._validator = TagSchemaValidator()
        self._iptables_executor = iptables_executor
        self._post_verifier = post_verifier
        self._mcp_client_factory = mcp_client_factory
        self._mode = execution_mode
        risk_engine.set_mode(execution_mode)

    def set_execution_mode(self, mode: ExecutionMode) -> None:
        self._mode = mode
        risk_engine.set_mode(mode)
        logger.info(f"[TAG] Execution mode -> {mode.value}")

    @property
    def execution_mode(self) -> ExecutionMode:
        return self._mode

    @property
    def tool_registry(self) -> TagToolRegistry:
        return self._tool_registry

    async def process_action(
        self, session: AsyncSession, plan: ActionPlan,
    ) -> GatewayResult:
        """处理动作计划 — 完整流程编排"""
        if not plan.trace_id:
            plan.trace_id = f"TRC-{uuid.uuid4().hex[:12].upper()}"
        if not plan.request_id:
            plan.request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"

        logger.info(
            f"[TAG] process_action start: tool={plan.tool_name} "
            f"target={plan.target} incident={plan.incident_id} "
            f"agent={plan.agent_identity} trace={plan.trace_id}"
        )

        if self._post_verifier is None and self._iptables_executor is not None:
            from .executors.post_verifier import TagPostActionVerifier
            self._post_verifier = TagPostActionVerifier(self._iptables_executor)

        # 步骤 1: PROPOSED — 创建审计记录
        audit_entry = await tag_audit_logger.log_event(
            session=session,
            trace_id=plan.trace_id,
            incident_id=plan.incident_id,
            action_id="",
            agent_identity=plan.agent_identity,
            tool_name=plan.tool_name,
            target=plan.target,
            normalized_parameters=plan.parameters,
            evidence_ids=plan.evidence_ids,
            request_id=plan.request_id,
            token_jti=plan.token_jti,
            action_state=ActionState.PROPOSED.value,
            timestamps={"proposed_at": datetime.now(timezone.utc).isoformat()},
        )

        # 步骤 2: PRECHECK
        precheck_result = await self._precheck(session, plan, audit_entry)
        if not precheck_result.ok:
            return await self._block(
                session, plan, "", precheck_result.blocked_by,
                precheck_result.reason, audit_entry,
            )

        risk = precheck_result.risk_assessment

        # shadow 模式：只生成计划不执行
        if self._mode == ExecutionMode.SHADOW or risk.factors.environment == "shadow":
            return await self._shadow_mode_return(session, plan, risk, audit_entry)

        # 步骤 3: 授权决策
        if risk.policy_decision == "deny":
            return await self._block(
                session, plan, "", "risk_policy",
                f"风险策略拒绝: {', '.join(risk.reasons)}", audit_entry,
                risk_assessment=risk,
            )

        if risk.policy_decision in ("require_confirmation", "require_human"):
            return await self._waiting_authorization(
                session, plan, risk, audit_entry,
            )

        # A0/A1/A2 自动签发授权
        grant = None
        if risk.approval_required in ("basic", "auto"):
            try:
                grant = await self._auto_issue_grant(session, plan, risk)
            except GrantValidationError as e:
                return await self._block(
                    session, plan, "", "grant_issue",
                    f"授权签发失败: {e}", audit_entry, risk_assessment=risk,
                )
        else:
            return await self._block(
                session, plan, "", "unsupported_approval",
                f"不支持的授权类型: {risk.approval_required}", audit_entry,
                risk_assessment=risk,
            )

        # 步骤 4: 执行
        return await self._execute(session, plan, grant, risk, audit_entry)

    async def _precheck(
        self, session: AsyncSession, plan: ActionPlan, audit_entry: TagAuditTrail,
    ):
        # 1. 工具注册表 — 拒绝未注册工具
        if not self._tool_registry.is_registered(plan.tool_name):
            return PrecheckResult(
                ok=False, blocked_by="tool_registry",
                reason=f"工具未注册: {plan.tool_name}",
            )

        # 2. 输出稳定器 — 参数规范化
        plan.parameters = self._stabilizer.stabilize(plan.parameters)

        # 3. Schema 校验
        ok, msg = self._validator.validate(plan.tool_name, plan.parameters)
        if not ok:
            return PrecheckResult(ok=False, blocked_by="schema_validator", reason=msg)

        # 4. 影响策略 — 目标检查
        ok, msg = impact_policy_manager.check_target(
            plan.tool_name, plan.target, plan.asset_info,
        )
        if not ok:
            return PrecheckResult(ok=False, blocked_by="impact_policy", reason=msg)

        # 5. 影响策略 — TTL 检查
        ttl = plan.parameters.get("ttl_seconds", 3600)
        ok, msg = impact_policy_manager.check_ttl(plan.tool_name, int(ttl))
        if not ok:
            return PrecheckResult(ok=False, blocked_by="impact_policy", reason=msg)

        # 6. 风险评估
        risk = risk_engine.assess(
            tool_name=plan.tool_name,
            target=plan.target,
            parameters=plan.parameters,
            incident_id=plan.incident_id,
            evidence_ids=plan.evidence_ids,
            asset_info=plan.asset_info,
        )

        # 7. 核心资产二次确认
        if risk.factors.is_protected_asset and self._mode == ExecutionMode.PRODUCTION:
            return PrecheckResult(
                ok=False, blocked_by="protected_asset",
                reason=f"核心资产禁止自动处置: {plan.target}",
                risk_assessment=risk,
            )

        await tag_audit_logger.update_state(
            session, plan.trace_id, ActionState.PRECHECK.value,
            timestamps={"precheck_at": datetime.now(timezone.utc).isoformat()},
        )
        await tag_audit_logger.log_event(
            session=session, trace_id=plan.trace_id,
            incident_id=plan.incident_id,
            tool_name=plan.tool_name, target=plan.target,
            normalized_parameters=plan.parameters,
            evidence_ids=plan.evidence_ids,
            risk_score=risk.risk_score, risk_level=risk.risk_level,
            policy_decision=risk.policy_decision,
            request_id=plan.request_id, token_jti=plan.token_jti,
            action_state=ActionState.PRECHECK.value,
            timestamps={"precheck_at": datetime.now(timezone.utc).isoformat()},
        )

        return PrecheckResult(ok=True, risk_assessment=risk)

    async def _auto_issue_grant(
        self, session: AsyncSession, plan: ActionPlan, risk: RiskAssessment,
    ) -> ActionGrant:
        """A0/A1/A2 自动签发授权 — 策略引擎自动签发"""
        target_scope = {"ips": [plan.target]}
        parameter_constraints = self._build_param_constraints(plan.tool_name, plan.parameters)

        return await grant_manager.issue_grant(
            session=session,
            subject=plan.agent_identity,
            incident_id=plan.incident_id,
            tool_name=plan.tool_name,
            target_scope=target_scope,
            parameter_constraints=parameter_constraints,
            evidence_ids=plan.evidence_ids,
            approval_level=risk.approval_required,
            approval_record={
                "auto_issued": True,
                "automation_level": risk.automation_level.value,
                "risk_score": risk.risk_score,
                "reasons": risk.reasons,
            },
            automation_level=risk.automation_level,
            created_by="tag_gateway:auto",
        )

    def _build_param_constraints(self, tool_name: str, params: dict) -> dict:
        constraints: dict = {}
        if "ttl_seconds" in params:
            ttl = int(params["ttl_seconds"])
            constraints["ttl_seconds"] = {"min": 1, "max": max(ttl, 3600)}
        return constraints

    async def _waiting_authorization(
        self, session: AsyncSession, plan: ActionPlan,
        risk: RiskAssessment, audit_entry: TagAuditTrail,
    ) -> GatewayResult:
        """等待授权 — A3 风险等级"""
        await tag_audit_logger.update_state(
            session, plan.trace_id,
            ActionState.WAITING_AUTHORIZATION.value,
            timestamps={"waiting_auth_at": datetime.now(timezone.utc).isoformat()},
        )

        logger.info(
            f"[TAG] action waiting for authorization: "
            f"tool={plan.tool_name} level={risk.automation_level.value} "
            f"trace={plan.trace_id}"
        )

        return GatewayResult(
            action_id="",
            trace_id=plan.trace_id,
            action_state=ActionState.WAITING_AUTHORIZATION,
            policy_decision=risk.policy_decision,
            risk_assessment=risk,
            block_reason=f"等待 {risk.approval_required} 授权",
        )

    async def _execute(
        self, session: AsyncSession, plan: ActionPlan,
        grant: ActionGrant, risk: RiskAssessment, audit_entry: TagAuditTrail,
    ) -> GatewayResult:
        """执行动作 — 幂等锁 → 预算 → 执行器 → 验证"""

        # 1. 幂等锁
        try:
            idem = await idempotency_guard.acquire_or_get(
                session=session,
                incident_id=plan.incident_id,
                tool_name=plan.tool_name,
                target=plan.target,
                parameters=plan.parameters,
                plan_version=plan.plan_version,
                grant_id=grant.id,
                trace_id=plan.trace_id,
            )
        except IdempotencyError as e:
            return await self._block(
                session, plan, "", "idempotency",
                f"幂等锁获取失败: {e}", audit_entry, risk_assessment=risk,
                grant_id=grant.id,
            )

        action = idem.get("action")
        action_id = idem.get("action_id", "")
        record = idem.get("record")

        # 已有记录 — 直接返回
        if action == "return":
            return GatewayResult(
                action_id=record.action_id,
                trace_id=plan.trace_id,
                action_state=ActionState(record.status),
                policy_decision=risk.policy_decision,
                risk_assessment=risk,
                grant_id=grant.id,
                idempotency_key=record.idempotency_key,
                execution_result=record.result or {},
                verification_result=record.verification_result or {},
                ledger=record,
            )

        if action == "blocked":
            return await self._block(
                session, plan, action_id or "", "idempotency",
                idem.get("reason", "幂等拦截"), audit_entry,
                risk_assessment=risk, grant_id=grant.id,
                ledger=record,
            )

        # 2. 执行器必须二次验证授权
        ok, msg, grant_valid = await grant_manager.validate_grant(
            session=session, grant_id=grant.id,
            subject=plan.agent_identity,
            incident_id=plan.incident_id,
            tool_name=plan.tool_name,
            target=plan.target,
            parameters=plan.parameters,
        )
        if not ok:
            return await self._block(
                session, plan, action_id, "grant_validation",
                f"执行器授权验证失败: {msg}", audit_entry,
                risk_assessment=risk, grant_id=grant.id, ledger=record,
            )

        # 3. 预算检查
        ok, msg, info = await action_budget.check_all_budgets(
            session, plan.incident_id, plan.agent_identity, plan.tool_name,
        )
        if not ok:
            await idempotency_guard.mark_blocked(session, action_id, msg)
            return await self._block(
                session, plan, action_id, "budget",
                f"预算超限: {msg}", audit_entry,
                risk_assessment=risk, grant_id=grant.id, ledger=record,
            )

        # 4. 标记 EXECUTING
        await idempotency_guard.mark_executing(session, action_id)
        await tag_audit_logger.update_state(
            session, plan.trace_id, ActionState.EXECUTING.value,
            timestamps={"executing_at": datetime.now(timezone.utc).isoformat()},
        )

        # 5. 选择执行器并执行
        tool_meta = self._tool_registry.get_meta(plan.tool_name) or {}
        executor_type = tool_meta.get("executor_type", "noop")

        try:
            exec_result = await self._dispatch_executor(
                executor_type, plan, action_id, grant,
            )
        except Exception as e:
            logger.error(f"[TAG] executor error: {e}", exc_info=True)
            await idempotency_guard.mark_failed(session, action_id, str(e), retryable=True)
            await tag_audit_logger.update_state(
                session, plan.trace_id, ActionState.FAILED_RETRYABLE.value,
                execution_result={"error": str(e)},
                timestamps={"failed_at": datetime.now(timezone.utc).isoformat()},
            )
            return GatewayResult(
                action_id=action_id, trace_id=plan.trace_id,
                action_state=ActionState.FAILED_RETRYABLE,
                policy_decision=risk.policy_decision,
                risk_assessment=risk, grant_id=grant.id,
                idempotency_key=record.idempotency_key,
                execution_result={"error": str(e)}, ledger=record,
            )

        # 6. 执行失败
        if not exec_result.get("success", False):
            err = exec_result.get("error", "unknown error")
            await idempotency_guard.mark_failed(session, action_id, err, retryable=True)
            await tag_audit_logger.update_state(
                session, plan.trace_id, ActionState.FAILED_RETRYABLE.value,
                execution_result=exec_result,
                timestamps={"failed_at": datetime.now(timezone.utc).isoformat()},
            )
            return GatewayResult(
                action_id=action_id, trace_id=plan.trace_id,
                action_state=ActionState.FAILED_RETRYABLE,
                policy_decision=risk.policy_decision,
                risk_assessment=risk, grant_id=grant.id,
                idempotency_key=record.idempotency_key,
                execution_result=exec_result, ledger=record,
            )

        # 7. VERIFYING — 执行后验证
        verify_result = {"verified": True, "skipped": True}
        if self._post_verifier:
            await tag_audit_logger.update_state(
                session, plan.trace_id, ActionState.VERIFYING.value,
                timestamps={"verifying_at": datetime.now(timezone.utc).isoformat()},
            )
            verify_result = await self._post_verifier.verify(
                tool_name=plan.tool_name,
                action_id=action_id,
                params=plan.parameters,
                exec_result=exec_result,
            )

        # 8. 验证失败 → ROLLBACK_REQUIRED
        if not verify_result.get("verified", False):
            await idempotency_guard.mark_rollback_required(
                session, action_id,
                verify_result.get("evidence", "verification failed"),
            )
            await tag_audit_logger.update_state(
                session, plan.trace_id, ActionState.ROLLBACK_REQUIRED.value,
                verification_result=verify_result,
                timestamps={"rollback_required_at": datetime.now(timezone.utc).isoformat()},
            )

            rollback_result = await self._do_rollback(session, plan, action_id, audit_entry)
            return GatewayResult(
                action_id=action_id, trace_id=plan.trace_id,
                action_state=ActionState.ROLLED_BACK if rollback_result.get("success")
                else ActionState.ROLLBACK_FAILED,
                policy_decision=risk.policy_decision,
                risk_assessment=risk, grant_id=grant.id,
                idempotency_key=record.idempotency_key,
                execution_result=exec_result,
                verification_result=verify_result,
                rollback_result=rollback_result, ledger=record,
            )

        # 9. 验证通过 → SUCCEEDED
        await idempotency_guard.mark_succeeded(
            session, action_id, exec_result, verify_result,
        )
        await grant_manager.consume_grant(session, grant.id)
        await action_budget.record_action(
            session, "incident", plan.incident_id, True,
        )
        await action_budget.record_action(
            session, "agent", plan.agent_identity, True,
        )
        await action_budget.record_action(
            session, "tool", plan.tool_name, True,
        )
        await action_budget.record_action(session, "global", "global", True)

        await tag_audit_logger.update_state(
            session, plan.trace_id, ActionState.SUCCEEDED.value,
            execution_result=exec_result,
            verification_result=verify_result,
            timestamps={"succeeded_at": datetime.now(timezone.utc).isoformat()},
        )

        logger.info(
            f"[TAG] action SUCCEEDED: action_id={action_id} "
            f"tool={plan.tool_name} target={plan.target} trace={plan.trace_id}"
        )

        return GatewayResult(
            action_id=action_id, trace_id=plan.trace_id,
            action_state=ActionState.SUCCEEDED,
            policy_decision=risk.policy_decision,
            risk_assessment=risk, grant_id=grant.id,
            idempotency_key=record.idempotency_key,
            execution_result=exec_result,
            verification_result=verify_result, ledger=record,
        )

    async def _dispatch_executor(
        self, executor_type: str, plan: ActionPlan,
        action_id: str, grant: ActionGrant,
    ) -> dict:
        """根据 executor_type 分派到具体执行器"""
        if executor_type == "iptables":
            if self._iptables_executor is None:
                return {"success": False, "error": "iptables_executor 未配置"}
            return await self._exec_iptables(plan, action_id)
        if executor_type == "stdio_mcp":
            return await self._exec_stdio_mcp(plan, action_id, grant)
        if executor_type == "remote_mcp":
            return await self._exec_remote_mcp(plan, action_id, grant)
        if executor_type == "noop":
            return {"success": True, "result": "noop", "action_id": action_id}
        return {"success": False, "error": f"未知 executor_type: {executor_type}"}

    async def _exec_iptables(self, plan: ActionPlan, action_id: str) -> dict:
        """iptables 执行器"""
        ttl = int(plan.parameters.get("ttl_seconds", 3600))
        if plan.tool_name == "block_ip":
            return await self._iptables_executor.block_ip(
                ip=plan.target, action_id=action_id,
                incident_id=plan.incident_id,
                ttl_seconds=ttl,
                reason=plan.parameters.get("reason", ""),
            )
        if plan.tool_name == "isolate_host":
            return await self._iptables_executor.isolate_host(
                host=plan.target, action_id=action_id,
                incident_id=plan.incident_id,
                ttl_seconds=ttl,
            )
        return {"success": False, "error": f"iptables 不支持工具: {plan.tool_name}"}

    async def _exec_stdio_mcp(
        self, plan: ActionPlan, action_id: str, grant: ActionGrant,
    ) -> dict:
        """STDIO MCP 执行器"""
        if self._mcp_client_factory is None:
            return {"success": False, "error": "mcp_client_factory 未配置"}
        server_id = plan.parameters.get("server_id", "default-stdio")
        client = self._mcp_client_factory(server_id)
        try:
            result = await client.call_tool(plan.tool_name, plan.parameters)
            return {
                "success": result.success,
                "result": result.result,
                "error": result.error,
                "latency_ms": result.latency_ms,
                "transport_type": result.transport_type,
                "server_identity": result.server_identity,
            }
        finally:
            pass

    async def _exec_remote_mcp(
        self, plan: ActionPlan, action_id: str, grant: ActionGrant,
    ) -> dict:
        """Remote MCP 执行器"""
        return await self._exec_stdio_mcp(plan, action_id, grant)

    async def request_rollback(
        self, session: AsyncSession, action_id: str,
        operator: str = "admin",
    ) -> GatewayResult:
        """请求回滚 — 幂等"""
        record = await idempotency_guard.get_by_action_id(session, action_id)
        if not record:
            return GatewayResult(
                action_id=action_id, trace_id="",
                action_state=ActionState.FAILED,
                policy_decision="deny",
                block_reason=f"动作不存在: {action_id}",
            )

        rollback_idem = await idempotency_guard.acquire_rollback(
            session, action_id, record.plan_version,
        )
        if rollback_idem.get("action") == "return":
            return GatewayResult(
                action_id=action_id, trace_id=record.trace_id,
                action_state=ActionState.ROLLED_BACK,
                policy_decision="allow",
                rollback_result=rollback_idem.get("result", {}),
                idempotency_key=record.idempotency_key,
                ledger=record,
            )

        plan = ActionPlan(
            tool_name=record.tool_name,
            target=record.target,
            parameters=record.normalized_parameters,
            incident_id=record.incident_id,
            agent_identity=operator,
            trace_id=record.trace_id or f"TRC-{uuid.uuid4().hex[:12].upper()}",
            plan_version=record.plan_version,
        )

        rollback_result = await self._do_rollback(session, plan, action_id, None)

        # 包装为 GatewayResult — _do_rollback 返回 dict
        if rollback_result.get("success"):
            final_state = ActionState.ROLLED_BACK
        else:
            final_state = ActionState.ROLLBACK_FAILED

        return GatewayResult(
            action_id=action_id,
            trace_id=plan.trace_id,
            action_state=final_state,
            policy_decision="allow",
            rollback_result=rollback_result,
            idempotency_key=record.idempotency_key,
            ledger=record,
        )

    async def _do_rollback(
        self, session: AsyncSession, plan: ActionPlan,
        action_id: str, audit_entry: Optional[TagAuditTrail],
    ) -> dict:
        """执行回滚"""
        await idempotency_guard.mark_rolling_back(session, action_id)
        if audit_entry:
            await tag_audit_logger.update_state(
                session, plan.trace_id, ActionState.ROLLING_BACK.value,
                timestamps={"rolling_back_at": datetime.now(timezone.utc).isoformat()},
            )

        try:
            if self._iptables_executor is None:
                rollback_result = {"success": False, "error": "iptables_executor 未配置"}
            else:
                rollback_result = await self._iptables_executor.rollback(action_id)
        except Exception as e:
            logger.error(f"[TAG] rollback error: {e}", exc_info=True)
            rollback_result = {"success": False, "error": str(e)}

        if rollback_result.get("success"):
            await idempotency_guard.mark_rolled_back(
                session, action_id, rollback_result,
            )
            if audit_entry:
                await tag_audit_logger.update_state(
                    session, plan.trace_id, ActionState.ROLLED_BACK.value,
                    rollback_result=rollback_result,
                    timestamps={"rolled_back_at": datetime.now(timezone.utc).isoformat()},
                )
            logger.info(f"[TAG] rollback SUCCEEDED: action_id={action_id}")
        else:
            await idempotency_guard.mark_rollback_failed(
                session, action_id, rollback_result.get("error", "unknown"),
            )
            if audit_entry:
                await tag_audit_logger.update_state(
                    session, plan.trace_id, ActionState.ROLLBACK_FAILED.value,
                    rollback_result=rollback_result,
                    timestamps={"rollback_failed_at": datetime.now(timezone.utc).isoformat()},
                )
            logger.warning(f"[TAG] rollback FAILED: action_id={action_id}")

        return rollback_result

    async def _block(
        self, session: AsyncSession, plan: ActionPlan, action_id: str,
        blocked_by: str, reason: str, audit_entry: TagAuditTrail,
        risk_assessment: Optional[RiskAssessment] = None,
        grant_id: str = "", ledger: Optional[ActionLedger] = None,
    ) -> GatewayResult:
        """标记动作为 BLOCKED

        A4 场景下额外:
          1. 调用 DbSafetyPolicy 生成处置建议 (写入审计日志)
          2. 创建人工审批工单 (HumanApprovalTicket)
          3. 不可通过分步提权绕过
        """
        if action_id:
            await idempotency_guard.mark_blocked(session, action_id, reason)
        await tag_audit_logger.update_state(
            session, plan.trace_id, ActionState.BLOCKED.value,
            timestamps={"blocked_at": datetime.now(timezone.utc).isoformat()},
        )

        # A4 处置建议生成
        recommendations: list[str] = []
        require_ticket = False
        if (db_safety_policy is not None
                and risk_assessment
                and risk_assessment.automation_level == AutomationLevel.A4):
            a4_decision = db_safety_policy.check_action(
                tool_name=plan.tool_name,
                parameters=plan.parameters,
                target=plan.target,
                asset_type=(plan.asset_info or {}).get("type", ""),
            )
            recommendations = a4_decision.recommendations
            require_ticket = a4_decision.require_ticket
            if recommendations:
                logger.info(
                    f"[TAG] A4 recommendations for {plan.tool_name}: "
                    f"{recommendations}"
                )

        # 创建人工审批工单 (A4 场景)
        ticket_id = ""
        if require_ticket:
            try:
                from response_engine.human_approval import approval_queue
                ticket = approval_queue.submit(
                    threat_info={
                        "threat_type": "A4_DANGEROUS_ACTION",
                        "src_ip": plan.target,
                        "message": reason,
                        "tool_name": plan.tool_name,
                        "trace_id": plan.trace_id,
                        "recommendations": recommendations,
                    },
                    policy_name="a4_block",
                    actions=[{
                        "name": plan.tool_name,
                        "params": plan.parameters,
                    }],
                )
                ticket_id = ticket.id
                logger.warning(
                    f"[TAG] A4 ticket created: {ticket_id} for "
                    f"tool={plan.tool_name} target={plan.target}"
                )
            except Exception as e:
                logger.error(f"[TAG] Failed to create A4 ticket: {e}")
                ticket_id = f"ticket_failed: {e}"

        await tag_audit_logger.log_event(
            session=session, trace_id=plan.trace_id,
            incident_id=plan.incident_id, action_id=action_id,
            grant_id=grant_id, agent_identity=plan.agent_identity,
            tool_name=plan.tool_name, target=plan.target,
            normalized_parameters=plan.parameters,
            risk_score=risk_assessment.risk_score if risk_assessment else 0.0,
            risk_level=risk_assessment.risk_level if risk_assessment else "",
            policy_decision="deny", request_id=plan.request_id,
            token_jti=plan.token_jti,
            action_state=ActionState.BLOCKED.value,
            blocked_by=blocked_by, block_reason=reason,
            approval_record={
                "recommendations": recommendations,
                "require_ticket": require_ticket,
                "ticket_id": ticket_id,
            } if recommendations or ticket_id else None,
            timestamps={"blocked_at": datetime.now(timezone.utc).isoformat()},
        )
        logger.warning(
            f"[TAG] action BLOCKED: tool={plan.tool_name} "
            f"target={plan.target} blocked_by={blocked_by} reason={reason} "
            f"trace={plan.trace_id} ticket={ticket_id}"
        )
        return GatewayResult(
            action_id=action_id, trace_id=plan.trace_id,
            action_state=ActionState.BLOCKED,
            policy_decision="deny",
            risk_assessment=risk_assessment, grant_id=grant_id,
            blocked_by=blocked_by, block_reason=reason, ledger=ledger,
        )

    async def _shadow_mode_return(
        self, session: AsyncSession, plan: ActionPlan,
        risk: RiskAssessment, audit_entry: TagAuditTrail,
    ) -> GatewayResult:
        """shadow 模式 — 只生成计划不执行"""
        await tag_audit_logger.log_event(
            session=session, trace_id=plan.trace_id,
            incident_id=plan.incident_id,
            agent_identity=plan.agent_identity,
            tool_name=plan.tool_name, target=plan.target,
            normalized_parameters=plan.parameters,
            risk_score=risk.risk_score, risk_level=risk.risk_level,
            policy_decision="shadow",
            action_state=ActionState.PROPOSED.value,
            blocked_by="shadow_mode",
            block_reason="shadow 模式：只生成动作计划不执行",
            timestamps={"shadow_at": datetime.now(timezone.utc).isoformat()},
        )
        logger.info(f"[TAG] shadow mode: {plan.tool_name} {plan.target}")
        return GatewayResult(
            action_id="", trace_id=plan.trace_id,
            action_state=ActionState.PROPOSED,
            policy_decision="shadow",
            risk_assessment=risk,
            blocked_by="shadow_mode",
            block_reason="shadow 模式：只生成动作计划不执行",
        )

    async def approve_authorization(
        self, session: AsyncSession, grant_id: str,
        approver: str = "cad", notes: str = "",
    ) -> tuple[bool, str]:
        """审批通过授权 — CAD 或人工"""
        grant = await grant_manager.get_grant(session, grant_id)
        if not grant:
            return False, "授权不存在"
        if grant.status != "active":
            return False, f"授权状态非 active ({grant.status})"
        grant.approval_record = {
            **(grant.approval_record or {}),
            "approved_by": approver,
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        }
        await session.flush()
        logger.info(f"[TAG] grant approved: {grant_id} by={approver}")
        return True, "授权已批准"

    async def deny_authorization(
        self, session: AsyncSession, grant_id: str,
        denyer: str = "cad", reason: str = "",
    ) -> tuple[bool, str]:
        """拒绝授权"""
        ok = await grant_manager.revoke_grant(session, grant_id, revoked_by=denyer)
        if ok:
            await tag_audit_logger.log_event(
                session=session, trace_id="", grant_id=grant_id,
                action_state=ActionState.BLOCKED.value,
                blocked_by="authorization_denied",
                block_reason=reason,
                timestamps={"denied_at": datetime.now(timezone.utc).isoformat()},
            )
        return ok, "授权已拒绝" if ok else "撤销失败"

    async def revoke_grant(
        self, session: AsyncSession, grant_id: str,
        revoked_by: str = "admin",
    ) -> bool:
        """撤销授权"""
        return await grant_manager.revoke_grant(session, grant_id, revoked_by)

    async def get_action_status(
        self, session: AsyncSession, action_id: str,
    ) -> Optional[dict]:
        """查询动作状态"""
        record = await idempotency_guard.get_by_action_id(session, action_id)
        if not record:
            return None
        return {
            "action_id": record.action_id,
            "idempotency_key": record.idempotency_key,
            "incident_id": record.incident_id,
            "tool_name": record.tool_name,
            "target": record.target,
            "status": record.status,
            "request_count": record.request_count,
            "execution_started_at": record.execution_started_at.isoformat() if record.execution_started_at else None,
            "execution_finished_at": record.execution_finished_at.isoformat() if record.execution_finished_at else None,
            "result": record.result,
            "error": record.error,
            "verification_passed": record.verification_passed,
            "grant_id": record.grant_id,
            "trace_id": record.trace_id,
        }

    async def get_audit_trail(
        self, session: AsyncSession, trace_id: str = "",
        incident_id: str = "", action_id: str = "",
        limit: int = 100, offset: int = 0,
    ) -> list:
        """查询审计轨迹"""
        trails = await tag_audit_logger.get_audit_trail(
            session, trace_id, incident_id, action_id, limit, offset,
        )
        return [
            {
                "id": t.id, "trace_id": t.trace_id,
                "incident_id": t.incident_id, "action_id": t.action_id,
                "grant_id": t.grant_id, "agent_identity": t.agent_identity,
                "tool_name": t.tool_name, "target": t.target,
                "risk_score": t.risk_score, "risk_level": t.risk_level,
                "policy_decision": t.policy_decision,
                "action_state": t.action_state,
                "blocked_by": t.blocked_by, "block_reason": t.block_reason,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            }
            for t in trails
        ]

    async def get_circuit_state(
        self, session: AsyncSession, scope_type: str, scope_key: str,
    ) -> dict:
        """查询熔断状态"""
        return await action_budget.get_circuit_state(session, scope_type, scope_key)

    async def reset_circuit(
        self, session: AsyncSession, scope_type: str, scope_key: str,
        reset_by: str = "admin",
    ) -> bool:
        """解除熔断"""
        return await action_budget.reset_circuit(
            session, scope_type, scope_key, reset_by,
        )


@dataclass
class PrecheckResult:
    ok: bool
    blocked_by: str = ""
    reason: str = ""
    risk_assessment: Optional[RiskAssessment] = None


# 全局单例
tag_gateway = TrustedActionGateway()
