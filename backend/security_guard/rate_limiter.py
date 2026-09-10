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
        "kill_process": 5,
        "quarantine_file": 10,
        "disable_account": 3,
        "dns_sinkhole": 10,
        "recall_email": 5,
        "forensic_snapshot": 20,
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

        # 通过检查：立即同步预留名额（占坑），而不是等动作执行后再 record。
        # 本方法全程无 await，在单事件循环内执行是原子的：即使多个协程并发
        # 通过 inspect，也不会同时看到同一个计数快照，窗口内实际放行数
        # 不会超过上限，消除了 check 与执行动作（跨越 await）之间的
        # check-then-act 竞态。
        # 注：该方案适用于单实例进程；多实例部署需改用 Redis INCR+EXPIRE。
        self._global_calls.append(now)
        self._action_calls[action_name].append(now)
        # 清理过期记录，避免内存无限增长
        self._cleanup(now)

        return CheckResult(
            check_name="频率控制",
            passed=True,
            message=f"频率正常（动作: {action_name}）",
            details={"action": action_name, "global_count": global_count + 1},
        )

    def record(self, action_name: str, success: bool = True):
        """确认或补偿 check() 预留的频率名额。

        check() 通过时已同步占坑，本方法不再重复计数：
          - success=True：动作执行成功（或无法区分结果），保留占坑；
          - success=False：动作执行失败，释放占坑，
            避免失败动作挤占窗口内的频率额度。

        Args:
            action_name: 已执行的安全动作名称
            success: 动作是否执行成功
        """
        if success:
            return
        self.release(action_name)

    def release(self, action_name: str):
        """释放最近一次预留（动作执行失败时的补偿）。

        从全局与该动作的窗口列表各移除一个时间戳，保证计数精确减一。
        """
        if self._global_calls:
            self._global_calls.pop()
        action_window = self._action_calls.get(action_name)
        if action_window:
            action_window.pop()

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
