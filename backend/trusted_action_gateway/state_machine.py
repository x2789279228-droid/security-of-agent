"""
动作状态机 — 统一管理动作生命周期

正常流程: PROPOSED → PRECHECK → WAITING_AUTHORIZATION → AUTHORIZED → EXECUTING → VERIFYING → SUCCEEDED
异常状态: BLOCKED, FAILED, ROLLBACK_REQUIRED, ROLLING_BACK, ROLLED_BACK, ROLLBACK_FAILED
"""
from enum import Enum
from typing import Optional


class ActionState(str, Enum):
    PROPOSED = "proposed"
    PRECHECK = "precheck"
    WAITING_AUTHORIZATION = "waiting_authorization"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    # 异常状态
    BLOCKED = "blocked"
    FAILED = "failed"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_FINAL = "failed_final"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class AutomationLevel(str, Enum):
    """动作自治等级"""
    A0 = "A0"  # 只读操作，自动执行
    A1 = "A1"  # 无业务影响操作，自动执行
    A2 = "A2"  # 可逆、局部操作，满足证据和范围要求后自动执行
    A3 = "A3"  # 高风险操作，需要分步提权或人工审批
    A4 = "A4"  # 不可逆或大范围操作，禁止自动执行


class ExecutionMode(str, Enum):
    """运行模式"""
    SHADOW = "shadow"        # 只生成动作计划，不执行
    SANDBOX = "sandbox"      # 只允许操作测试资产和专用防火墙链
    PRODUCTION = "production"  # 启用完整授权、影响范围和审批控制


# 状态转换图
TRANSITIONS = {
    ActionState.PROPOSED: {ActionState.PRECHECK, ActionState.BLOCKED},
    ActionState.PRECHECK: {
        ActionState.WAITING_AUTHORIZATION,
        ActionState.AUTHORIZED,  # A0/A1 自动授权
        ActionState.BLOCKED,
    },
    ActionState.WAITING_AUTHORIZATION: {
        ActionState.AUTHORIZED,
        ActionState.BLOCKED,
        ActionState.FAILED,
    },
    ActionState.AUTHORIZED: {
        ActionState.EXECUTING,
        ActionState.BLOCKED,  # 授权过期或被撤销
    },
    ActionState.EXECUTING: {
        ActionState.VERIFYING,
        ActionState.FAILED_RETRYABLE,
        ActionState.FAILED_FINAL,
        ActionState.ROLLBACK_REQUIRED,
    },
    ActionState.VERIFYING: {
        ActionState.SUCCEEDED,
        ActionState.ROLLBACK_REQUIRED,
        ActionState.FAILED_RETRYABLE,
    },
    ActionState.SUCCEEDED: {
        ActionState.ROLLING_BACK,  # 可回滚
    },
    ActionState.FAILED_RETRYABLE: {
        ActionState.EXECUTING,  # 重试
        ActionState.FAILED_FINAL,
    },
    ActionState.ROLLBACK_REQUIRED: {
        ActionState.ROLLING_BACK,
    },
    ActionState.ROLLING_BACK: {
        ActionState.ROLLED_BACK,
        ActionState.ROLLBACK_FAILED,
    },
    # 终态
    ActionState.BLOCKED: set(),
    ActionState.FAILED: set(),
    ActionState.FAILED_FINAL: set(),
    ActionState.SUCCEEDED: set(),  # 但允许回滚（上面单独处理）
    ActionState.ROLLED_BACK: set(),
    ActionState.ROLLBACK_FAILED: {ActionState.ROLLING_BACK},  # 可重试回滚
}

TERMINAL_STATES = {
    ActionState.BLOCKED, ActionState.FAILED, ActionState.FAILED_FINAL,
    ActionState.SUCCEEDED, ActionState.ROLLED_BACK,
}


def can_transition(from_state: ActionState, to_state: ActionState) -> bool:
    return to_state in TRANSITIONS.get(from_state, set())


def is_terminal(state: ActionState) -> bool:
    return state in TERMINAL_STATES


def is_rollback_state(state: ActionState) -> bool:
    return state in {
        ActionState.ROLLBACK_REQUIRED,
        ActionState.ROLLING_BACK,
        ActionState.ROLLED_BACK,
        ActionState.ROLLBACK_FAILED,
    }


# 自动化等级决策矩阵
def decide_automation_level(
    action_base_risk: str,  # LOW/MEDIUM/HIGH/CRITICAL
    asset_criticality: str,  # low/medium/high/critical
    blast_radius: str,  # single/few/wide
    evidence_completeness: float,  # 0.0-1.0
    source_trust: float,  # 0.0-1.0
    reversibility: bool,
    environment: str,  # shadow/sandbox/production
    execution_mode: str,  # live/dry_run/mock
) -> AutomationLevel:
    """根据多维风险因子决定自动化等级"""
    # A4: 不可逆 + 大范围 或 CRITICAL 资产 + 不可逆
    if not reversibility and blast_radius == "wide":
        return AutomationLevel.A4
    if asset_criticality == "critical" and not reversibility:
        return AutomationLevel.A4

    # A3/A2: HIGH/CRITICAL 风险
    if action_base_risk == "CRITICAL":
        return AutomationLevel.A3
    if action_base_risk == "HIGH":
        if evidence_completeness < 0.5 or source_trust < 0.5:
            return AutomationLevel.A3
        if asset_criticality in ("high", "critical"):
            return AutomationLevel.A3
        # 可逆 + 单目标 + 证据充分 → A2 自动执行（策略引擎自动签发授权）
        if reversibility and blast_radius == "single":
            return AutomationLevel.A2
        return AutomationLevel.A3

    # A2: MEDIUM 风险 + 可逆
    if action_base_risk == "MEDIUM":
        if reversibility and evidence_completeness >= 0.4:
            return AutomationLevel.A2
        return AutomationLevel.A3

    # A1: LOW 风险 + 可逆 + 无业务影响
    if action_base_risk == "LOW":
        if reversibility:
            return AutomationLevel.A1
        return AutomationLevel.A2

    # A0: 只读
    return AutomationLevel.A0


# 自动化等级 → 授权要求
LEVEL_APPROVAL_MAP = {
    AutomationLevel.A0: "basic",       # 基础权限
    AutomationLevel.A1: "basic",       # 基础权限
    AutomationLevel.A2: "auto",        # 策略引擎自动签发
    AutomationLevel.A3: "cad",         # CAD 审核 + 人工审批
    AutomationLevel.A4: "denied",      # 拒绝签发
}

# 自动化等级 → 是否自动执行
LEVEL_AUTO_EXECUTE = {
    AutomationLevel.A0: True,
    AutomationLevel.A1: True,
    AutomationLevel.A2: True,   # 满足条件后自动
    AutomationLevel.A3: False,  # 需要审批
    AutomationLevel.A4: False,  # 禁止
}
