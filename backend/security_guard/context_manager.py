"""上下文感知：追踪动作上下文并检查一致性。

核心问题：响应引擎执行动作时缺乏对历史上下文的感知，
可能重复封禁同一IP、或对同一威胁做出矛盾响应。
检查维度：
  1. 同一 src_ip 被重复封禁 → 可能是无效操作或误报
  2. 动作与威胁来源的一致性
"""
import time
from collections import defaultdict
from .check_result import CheckResult


class ContextManager:
    """上下文感知校验器：追踪动作历史并检查一致性。"""

    # 重复封禁检测窗口（秒）：同一IP在此时间内被重复封禁则告警
    DUPLICATE_WINDOW_SEC = 300

    # 同一IP最大封禁次数（窗口内）
    MAX_BLOCK_PER_IP = 3

    def __init__(self):
        # 动作历史记录：[(action_name, threat_info, result, timestamp), ...]
        self._action_history: list = []
        # 按 src_ip 索引的封禁记录：{ip: [timestamp, ...]}
        self._block_by_ip: dict = defaultdict(list)

    def check(self, action_name: str, threat_info: dict) -> CheckResult:
        """检查动作的上下文一致性。

        Args:
            action_name: 要执行的安全动作名称
            threat_info: 威胁上下文信息，可能包含 src_ip, dst_ip 等字段

        Returns:
            CheckResult: 检查结果
        """
        now = time.time()
        issues = []
        warnings = []
        context_info = {}

        src_ip = threat_info.get("src_ip", "")
        context_info["src_ip"] = src_ip
        context_info["action"] = action_name

        # ---- 检查1：同一 src_ip 重复封禁 ----
        if action_name == "block_ip" and src_ip:
            recent_blocks = [
                t for t in self._block_by_ip.get(src_ip, [])
                if (now - t) < self.DUPLICATE_WINDOW_SEC
            ]
            block_count = len(recent_blocks)
            context_info["recent_block_count"] = block_count

            if block_count >= self.MAX_BLOCK_PER_IP:
                issues.append(
                    f"IP {src_ip} 在 {self.DUPLICATE_WINDOW_SEC}秒 内已被封禁 {block_count} 次，"
                    f"重复封禁无意义，请检查是否存在误报或封禁未生效"
                )
            elif block_count >= 1:
                warnings.append(
                    f"IP {src_ip} 在 {self.DUPLICATE_WINDOW_SEC}秒 内已被封禁 {block_count} 次，"
                    f"本次为第 {block_count + 1} 次封禁"
                )

        # ---- 检查2：动作与威胁信息一致性 ----
        # 封禁操作应提供 src_ip
        if action_name == "block_ip" and not src_ip:
            warnings.append("block_ip 操作未提供 src_ip，无法追踪封禁上下文")

        # 隔离操作应提供目标主机信息
        if action_name == "isolate_host":
            hostname = threat_info.get("hostname", "")
            if not hostname:
                warnings.append("isolate_host 操作未提供 hostname，无法追踪隔离上下文")
            context_info["hostname"] = hostname

        # 汇总结果
        if issues:
            return CheckResult(
                check_name="上下文感知",
                passed=False,
                message="上下文校验失败: " + "; ".join(issues),
                details={"issues": issues, "warnings": warnings, **context_info},
            )

        if warnings:
            return CheckResult(
                check_name="上下文感知",
                passed=True,
                message="上下文校验通过（有警告）: " + "; ".join(warnings),
                details={"warnings": warnings, **context_info},
            )

        return CheckResult(
            check_name="上下文感知",
            passed=True,
            message="上下文校验通过",
            details=context_info,
        )

    def record(self, action_name: str, threat_info: dict, result: dict):
        """记录一次已执行的动作及其上下文。

        Args:
            action_name: 已执行的安全动作名称
            threat_info: 触发该动作的威胁信息
            result: 动作执行结果
        """
        now = time.time()
        self._action_history.append((action_name, threat_info, result, now))

        # 更新 IP 封禁索引
        if action_name == "block_ip":
            src_ip = threat_info.get("src_ip", "")
            if src_ip:
                self._block_by_ip[src_ip].append(now)

        # 清理过期记录
        self._cleanup(now)

    def reset(self):
        """清空所有上下文记录（用于测试）。"""
        self._action_history.clear()
        self._block_by_ip.clear()

    def _cleanup(self, now: float):
        """清理过期的上下文记录。"""
        # 清理动作历史（保留最近1小时）
        self._action_history = [
            entry for entry in self._action_history
            if (now - entry[3]) < 3600
        ]
        # 清理 IP 封禁索引（保留窗口内的记录）
        for ip in list(self._block_by_ip.keys()):
            self._block_by_ip[ip] = [
                t for t in self._block_by_ip[ip]
                if (now - t) < self.DUPLICATE_WINDOW_SEC
            ]
            if not self._block_by_ip[ip]:
                del self._block_by_ip[ip]
