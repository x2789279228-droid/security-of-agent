"""MCP Guard 调用日志记录模块。

职责：记录每次工具调用的完整审计信息。
- 使用 Python logging 输出结构化日志
- 维护内存中的最近调用记录（最多500条），供 API 查询

日志格式：timestamp | user_role | tool_name | decision | reason | exec_status
"""

import json
import logging
import threading
from collections import deque
from datetime import datetime
from typing import Optional

# 模块级 logger
logger = logging.getLogger("mcp_guard.call_logger")

# 内存中保留的最大记录数
_MAX_RECENT = 500


class CallLogger:
    """调用日志记录器。

    - 通过 Python logging 输出审计日志
    - 内存中保留最近 500 条记录，供 API 查询
    - 线程安全（使用锁保护 deque）
    """

    def __init__(self, max_recent: int = _MAX_RECENT):
        self._recent: deque = deque(maxlen=max_recent)
        self._lock = threading.Lock()
        self._counter = 0  # 自增ID

    def log(self, user_role: str, tool_name: str, arguments: dict,
            decision: str, reason: str, checks: list,
            exec_status: Optional[str] = None, exec_result: Optional[dict] = None):
        """记录一次工具调用。

        Args:
            user_role: 调用者角色
            tool_name: 工具名称
            arguments: 调用参数
            decision: Guard 决策 (allow/deny/require_confirmation)
            reason: 决策原因
            checks: 各层检查明细
            exec_status: 执行状态
            exec_result: 执行结果
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 构建记录
        with self._lock:
            self._counter += 1
            record = {
                "id": self._counter,
                "time": timestamp,
                "user_role": user_role,
                "tool_name": tool_name,
                "arguments": arguments,
                "decision": decision,
                "reason": reason,
                "checks": checks,
                "exec_status": exec_status,
                "exec_result": exec_result,
            }
            self._recent.append(record)

        # 通过 Python logging 输出结构化审计日志
        logger.info(
            "%s | %s | %s | %s | %s | %s",
            timestamp, user_role, tool_name, decision, reason, exec_status or "N/A",
        )

    def recent(self, limit: int = 10) -> list:
        """查询最近的调用记录。

        Args:
            limit: 返回条数，默认10

        Returns:
            最近调用记录列表（按时间倒序）
        """
        with self._lock:
            records = list(self._recent)
        # 倒序返回（最新的在前）
        return records[-limit:][::-1]

    def stats(self) -> dict:
        """统计调用情况。"""
        with self._lock:
            records = list(self._recent)

        total = len(records)
        allowed = sum(1 for r in records if r["decision"] == "allow")
        denied = sum(1 for r in records if r["decision"] == "deny")
        confirmed = sum(1 for r in records if r["decision"] == "require_confirmation")

        return {
            "total": total,
            "allow": allowed,
            "deny": denied,
            "require_confirmation": confirmed,
        }
