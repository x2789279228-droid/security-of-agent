"""调用序列管控：检测危险的动作序列模式。

核心问题：单个动作可能合法，但连续执行某些组合可能构成攻击或误操作。
检查维度：
  1. 短时间内大量隔离操作 → 可能是自动化滥用
  2. 短时间内大量封禁操作 → 可能是批量误封
  3. 终止进程前未先告警 → 缺少必要的前置步骤
"""
import time
from collections import deque
from .check_result import CheckResult


class SequenceGuard:
    """调用序列管控器：基于滑动窗口检测危险序列。"""

    # 历史动作记录最大长度
    MAX_HISTORY = 50

    def __init__(self):
        # 记录最近的动作：deque of (action_name, timestamp)
        self._history: deque = deque(maxlen=self.MAX_HISTORY)

    def check(self, action_name: str, threat_info: dict) -> CheckResult:
        """检查当前动作是否构成危险序列。

        Args:
            action_name: 要执行的安全动作名称
            threat_info: 威胁上下文信息

        Returns:
            CheckResult: 检查结果
        """
        now = time.time()
        issues = []
        warnings = []

        # ---- 检查1：5分钟内 3+ 次 isolate_host → 阻断 ----
        # 短时间内大量隔离操作可能是自动化攻击或误操作
        if action_name == "isolate_host":
            isolate_count = self._count_in_window("isolate_host", window_sec=300, now=now)
            if isolate_count >= 3:
                issues.append(
                    f"5分钟内已执行 {isolate_count} 次 isolate_host，"
                    f"达到上限(3次)，疑似自动化滥用，阻断执行"
                )

        # ---- 检查2：1分钟内 5+ 次 block_ip → 阻断 ----
        # 短时间大量封禁可能是批量误封或攻击者利用自动化封禁合法IP
        if action_name == "block_ip":
            block_count = self._count_in_window("block_ip", window_sec=60, now=now)
            if block_count >= 5:
                issues.append(
                    f"1分钟内已执行 {block_count} 次 block_ip，"
                    f"达到上限(5次)，疑似自动化滥用，阻断执行"
                )

        # ---- 检查3：terminate_process 前未执行 alert_only → 警告 ----
        # 终止进程是高危操作，应先发出告警通知
        if action_name == "terminate_process":
            has_prior_alert = self._has_recent_action("alert_only", window_sec=300, now=now)
            if not has_prior_alert:
                warnings.append(
                    "执行 terminate_process 前未检测到近5分钟内的 alert_only 记录，"
                    "建议先发出告警通知再终止进程"
                )

        # 汇总结果
        if issues:
            return CheckResult(
                check_name="调用序列管控",
                passed=False,
                message="调用序列违规: " + "; ".join(issues),
                details={"issues": issues, "warnings": warnings, "action": action_name},
            )

        if warnings:
            # 警告不阻断，但记录在结果中
            return CheckResult(
                check_name="调用序列管控",
                passed=True,
                message="调用序列合法（有警告）: " + "; ".join(warnings),
                details={"warnings": warnings, "action": action_name},
            )

        return CheckResult(
            check_name="调用序列管控",
            passed=True,
            message=f"调用序列合法（动作: {action_name}）",
            details={"action": action_name},
        )

    def record(self, action_name: str):
        """记录一次已执行的动作到历史。

        Args:
            action_name: 已执行的安全动作名称
        """
        self._history.append((action_name, time.time()))

    def reset(self):
        """清空历史记录（用于测试）。"""
        self._history.clear()

    def _count_in_window(self, action_name: str, window_sec: int, now: float) -> int:
        """统计时间窗口内某动作的执行次数。"""
        return sum(
            1 for name, ts in self._history
            if name == action_name and (now - ts) <= window_sec
        )

    def _has_recent_action(self, action_name: str, window_sec: int, now: float) -> bool:
        """检查时间窗口内是否存在某动作的记录。"""
        return any(
            name == action_name and (now - ts) <= window_sec
            for name, ts in self._history
        )
