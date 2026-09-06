"""安全守卫编排器：串联四个安全检查模块，提供统一的安全审查入口。

在响应引擎执行安全动作（封禁IP、隔离主机等）之前，
SecurityGuard 对动作进行多维度安全审查：
  1. 意图审查：动作是否与威胁等级匹配
  2. 序列管控：动作序列是否存在危险模式
  3. 频率控制：动作频率是否超限
  4. 上下文感知：动作是否与历史上下文一致

调用链：
    响应引擎决策
        ↓
    SecurityGuard.inspect()  ← 本模块
        ↓ (allowed=True)
    执行安全动作
        ↓
    SecurityGuard.record()  ← 更新追踪器
"""
import logging

from .check_result import CheckResult
from .intent_checker import IntentChecker
from .sequence_guard import SequenceGuard
from .rate_limiter import RateLimiter
from .context_manager import ContextManager

logger = logging.getLogger(__name__)


class SecurityGuard:
    """安全守卫：在安全动作执行前进行多维度安全审查。"""

    def __init__(self):
        self.intent_checker = IntentChecker()
        self.sequence_guard = SequenceGuard()
        self.rate_limiter = RateLimiter()
        self.context_manager = ContextManager()

    def inspect(self, action_name: str, threat_info: dict) -> dict:
        """执行完整的安全审查。

        对即将执行的安全动作进行四项检查，任一失败即拦截。
        所有检查均会执行（不短路），以便收集完整的安全态势信息。

        Args:
            action_name: 要执行的安全动作名称（如 block_ip, isolate_host 等）
            threat_info: 威胁上下文信息，包含 threat_level, reason, src_ip 等

        Returns:
            dict: {
                "allowed": bool,           # 是否允许执行
                "reason": str,             # 决策原因
                "checks": [CheckResult],   # 各项检查的详细结果
                "requires_approval": bool, # 是否需要人工审批
            }
        """
        checks: list = []

        # 四项检查全部执行（不短路），收集完整安全态势
        check_specs = [
            ("调用意图审查", self.intent_checker),
            ("调用序列管控", self.sequence_guard),
            ("频率控制",     self.rate_limiter),
            ("上下文感知",   self.context_manager),
        ]

        for _label, checker in check_specs:
            result = checker.check(action_name, threat_info)
            checks.append(result)

        # 汇总决策：任一检查失败即拦截
        failed = [c for c in checks if not c.passed]

        if failed:
            # 取第一个失败项作为主原因
            first_fail = failed[0]
            reason = f"[{first_fail.check_name}] {first_fail.message}"
            self._emit_telemetry(
                action_name, threat_info, decision="deny",
                reason=reason, checks=checks, exec_status="blocked",
            )
            return {
                "allowed": False,
                "reason": reason,
                "checks": checks,
                "requires_approval": False,
            }

        # 全部通过：检查是否有需要人工审批的情况
        # 高危动作（isolate_host, terminate_process）在高级别威胁下需审批
        requires_approval = self._needs_approval(action_name, threat_info)

        return {
            "allowed": True,
            "reason": "安全检查全部通过",
            "checks": checks,
            "requires_approval": requires_approval,
        }

    def record(self, action_name: str, threat_info: dict, result: dict):
        """记录已执行的动作，更新所有追踪器。

        在安全动作实际执行后调用，用于更新序列历史、频率计数和上下文记录。
        频率名额已在 inspect()→rate_limiter.check() 通过时同步预留，
        这里只做结果确认：执行失败时释放预留，不重复计数。

        Args:
            action_name: 已执行的安全动作名称
            threat_info: 触发该动作的威胁信息
            result: 动作执行结果，含 success 字段（缺省按成功处理）
        """
        success = bool(result.get("success", True)) if isinstance(result, dict) else True
        self.sequence_guard.record(action_name)
        self.rate_limiter.record(action_name, success=success)
        self.context_manager.record(action_name, threat_info, result)
        self._emit_telemetry(
            action_name, threat_info,
            decision="allow",
            reason="response executed",
            exec_status="success" if success else "error",
            exec_result=result if isinstance(result, dict) else None,
        )

    def _emit_telemetry(
        self, action_name: str, threat_info: dict, *,
        decision: str, reason: str = "", checks: list = None,
        exec_status: str = None, exec_result: dict = None,
    ) -> None:
        """写入统一 tool telemetry。失败不影响护栏。"""
        try:
            from mcp_guard.telemetry import args_from_threat, ingest_tool_call
            ingest_tool_call(
                tool_name=action_name,
                arguments=args_from_threat(action_name, threat_info),
                caller="response_engine",
                source="response",
                caller_role="security_operator",
                decision=decision,
                reason=reason,
                checks=checks or [],
                exec_status=exec_status,
                exec_result=exec_result,
            )
        except Exception as e:
            logger.warning("security_guard telemetry failed: %s", e)

    def reset(self):
        """重置所有有状态的检查器（用于测试）。"""
        self.sequence_guard.reset()
        self.rate_limiter.reset()
        self.context_manager.reset()

    def _needs_approval(self, action_name: str, threat_info: dict) -> bool:
        """判断是否需要人工审批。

        规则：
        - isolate_host 和 terminate_process 始终需要审批
        - 其他动作在 critical 级别下不需要审批（紧急情况自动化处理）
        """
        high_risk_actions = {"isolate_host", "terminate_process"}
        return action_name in high_risk_actions


# 全局单例：供响应引擎直接引用
security_guard = SecurityGuard()
