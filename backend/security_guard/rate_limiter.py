"""频率控制：防止安全动作执行失控。

核心问题：响应引擎可能在短时间内连续触发大量安全动作，导致业务中断或误操作。
检查维度：
  1. 单动作类型频率限制（滑动窗口）
  2. 全局总频率限制
"""
import time
from collections import defaultdict
from .check_result import CheckResult


class RateLimiter:
    """频率控制器：基于滑动窗口的动作频率限制。"""

    # 各动作类型的频率限制（每分钟最大次数）
    ACTION_LIMITS = {
        "block_ip": 10,        # 封禁IP：每分钟最多10次
        "isolate_host": 5,     # 隔离主机：每分钟最多5次
        "alert_only": 50,      # 告警：每分钟最多50次
    }

    # 全局频率限制（所有动作合计，每分钟最大次数）
    GLOBAL_LIMIT = 30

    # 滑动窗口大小（秒）
    WINDOW_SEC = 60

    def __init__(self):
        # 全局调用时间戳列表
        self._global_calls: list = []
        # 各动作类型的调用时间戳：{action_name: [timestamp, ...]}
        self._action_calls: dict = defaultdict(list)

    def check(self, action_name: str, threat_info: dict) -> CheckResult:
        """检查当前动作是否超过频率限制。

        Args:
            action_name: 要执行的安全动作名称
            threat_info: 威胁上下文信息

        Returns:
            CheckResult: 检查结果
        """
        now = time.time()
        issues = []

        # ---- 检查1：全局频率限制 ----
        global_count = self._count_in_window(self._global_calls, now)
        if global_count >= self.GLOBAL_LIMIT:
            issues.append(
                f"全局动作频率超限：每分钟最多 {self.GLOBAL_LIMIT} 次，"
                f"当前已达 {global_count} 次"
            )

        # ---- 检查2：单动作类型频率限制 ----
        action_limit = self.ACTION_LIMITS.get(action_name)
        if action_limit is not None:
            action_count = self._count_in_window(self._action_calls[action_name], now)
            if action_count >= action_limit:
                issues.append(
                    f"动作 '{action_name}' 频率超限：每分钟最多 {action_limit} 次，"
                    f"当前已达 {action_count} 次"
                )

        if issues:
            return CheckResult(
                check_name="频率控制",
                passed=False,
                message="频率超限: " + "; ".join(issues),
                details={
                    "issues": issues,
                    "action": action_name,
                    "global_count": global_count,
                    "global_limit": self.GLOBAL_LIMIT,
                },
            )

        return CheckResult(
            check_name="频率控制",
            passed=True,
            message=f"频率正常（动作: {action_name}）",
            details={"action": action_name, "global_count": global_count},
        )

    def record(self, action_name: str):
        """记录一次已执行的动作（用于频率统计）。

        Args:
            action_name: 已执行的安全动作名称
        """
        now = time.time()
        self._global_calls.append(now)
        self._action_calls[action_name].append(now)
        # 清理过期记录，避免内存无限增长
        self._cleanup(now)

    def reset(self):
        """清空所有频率记录（用于测试）。"""
        self._global_calls.clear()
        self._action_calls.clear()

    def _count_in_window(self, timestamps: list, now: float) -> int:
        """统计滑动窗口内的调用次数。"""
        return sum(1 for t in timestamps if (now - t) < self.WINDOW_SEC)

    def _cleanup(self, now: float):
        """清理超出窗口的过期记录。"""
        self._global_calls = [t for t in self._global_calls if (now - t) < self.WINDOW_SEC]
        for action in list(self._action_calls.keys()):
            self._action_calls[action] = [
                t for t in self._action_calls[action] if (now - t) < self.WINDOW_SEC
            ]
