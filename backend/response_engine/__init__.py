"""
响应引擎 (Response Engine) — 安全审计的主动响应层

架构:
  Orchestrator (编排器) ← 监听威胁事件
      → Policy Engine (策略引擎) → 匹配威胁→动作映射
      → Human Approval Queue (审批队列) → 高危操作待审
      → Safe Executor (安全执行器) → 9 层安全检查 + 执行
      → Response Log (日志) → 全量审计记录

安全执行层 (SafeExecutor):
  ① CommandWhitelist   命令白名单（默认拒绝）
  ② ParamValidator     参数强校验
  ③ AssetWhitelist     核心资产保护
  ④ IdempotencyGuard   幂等检查（Redis）
  ⑤ ExecutionMode      dry_run / mock / live 路由
  ⑥ PrivilegeSelector  最小权限账号
  ⑦ PostValidator      执行后验证
  ⑧ TtlManager         TTL 自动解封（Redis）
  ⑨ AuditTrail         审计日志

与现有系统的集成:
  - log_ingestion.py: Audit-LLM 流水线完成后触发 Orchestrator
  - anomaly_detector.py: 高异常分事件直接触发快速响应
  - cad.py: 熔断器触发时暂停所有响应
"""
# 核心模块（无外部依赖）
from .response_registry import response_registry, ResponseActionDef
from .response_policies import policy_engine, ResponsePolicy, ThreatActionMap
from .response_executor import response_executor, ActionResult
from .human_approval import approval_queue, ApprovalTicket, ApprovalStatus
from .transport import ssh_transport

# 安全执行层
from .command_whitelist import command_whitelist
from .asset_whitelist import asset_whitelist
from .execution_modes import execution_router
from .post_validator import post_validator
from .ttl_manager import ttl_manager
from .safe_executor import safe_executor

# 延迟加载（依赖 sqlalchemy 的模块）
def get_orchestrator():
    from .response_orchestrator import response_orchestrator
    return response_orchestrator

def get_response_logger():
    from .response_log import response_logger
    return response_logger

__all__ = [
    "response_registry", "ResponseActionDef",
    "policy_engine", "ResponsePolicy", "ThreatActionMap",
    "response_executor", "ActionResult",
    "get_orchestrator", "get_response_logger",
    "approval_queue", "ApprovalTicket", "ApprovalStatus",
    "ssh_transport",
    # 安全执行层
    "command_whitelist", "asset_whitelist", "execution_router",
    "post_validator", "ttl_manager", "safe_executor",
]
