"""
Trusted Action Gateway (TAG) — 可信行动网关

统一处理流程:
  Agent Plan -> Tool Registry -> Output Stabilizer -> Schema Validator
  -> Authorization -> Risk Policy -> Idempotency Guard -> Transport Security
  -> Executor -> Post-Action Verification -> Rollback Controller

模块组成:
  - models: 数据模型 (ActionGrant / ActionLedger / TagAuditTrail / ActionBudgetState)
  - state_machine: 动作状态机 + 自治等级 + 运行模式
  - risk_engine: 风险自适应自治引擎
  - grant_manager: 分步提权授权管理器
  - idempotency_guard: 动作幂等守卫
  - impact_policy: 影响范围控制 + 预算 + 金丝雀
  - audit_logger: 统一审计日志
  - transport: MCP 传输安全抽象 (STDIO + Remote)
  - executors: iptables 专用链 + 执行后验证
  - gateway: 主编排器
"""
from .state_machine import (
    ActionState, AutomationLevel, ExecutionMode,
    can_transition, is_terminal, decide_automation_level,
    LEVEL_APPROVAL_MAP, LEVEL_AUTO_EXECUTE,
)
from .risk_engine import risk_engine, RiskEngine, RiskAssessment, RiskFactors
from .grant_manager import grant_manager, GrantManager, GrantValidationError
from .idempotency_guard import (
    idempotency_guard, IdempotencyGuard, IdempotencyError,
)
from .impact_policy import (
    impact_policy_manager, action_budget, canary_executor,
    ImpactPolicyManager, ActionBudgetManager, CanaryExecutor,
    ToolImpactPolicy, PROTECTED_ASSET_TYPES,
)
from .audit_logger import tag_audit_logger, TagAuditLogger
from .gateway import (
    TrustedActionGateway, tag_gateway,
    ActionPlan, GatewayResult, TagToolRegistry,
    TagSchemaValidator, TagOutputStabilizer,
    TagError, TagBlockedError, TagAuthorizationError, TagIdempotencyError,
)
from .models import (
    ActionGrant, ActionLedger, TagAuditTrail, ActionBudgetState,
)

__all__ = [
    # 状态机
    "ActionState", "AutomationLevel", "ExecutionMode",
    "can_transition", "is_terminal", "decide_automation_level",
    "LEVEL_APPROVAL_MAP", "LEVEL_AUTO_EXECUTE",
    # 风险引擎
    "risk_engine", "RiskEngine", "RiskAssessment", "RiskFactors",
    # 授权管理
    "grant_manager", "GrantManager", "GrantValidationError",
    # 幂等
    "idempotency_guard", "IdempotencyGuard", "IdempotencyError",
    # 影响范围
    "impact_policy_manager", "action_budget", "canary_executor",
    "ImpactPolicyManager", "ActionBudgetManager", "CanaryExecutor",
    "ToolImpactPolicy", "PROTECTED_ASSET_TYPES",
    # 审计
    "tag_audit_logger", "TagAuditLogger",
    # 主编排器
    "TrustedActionGateway", "tag_gateway",
    "ActionPlan", "GatewayResult", "TagToolRegistry",
    "TagSchemaValidator", "TagOutputStabilizer",
    "TagError", "TagBlockedError", "TagAuthorizationError", "TagIdempotencyError",
    # 数据模型
    "ActionGrant", "ActionLedger", "TagAuditTrail", "ActionBudgetState",
]
