"""MCP Guard 审批工单队列。

职责：管理需人工确认的工具调用工单。
当 Guard 决策为 require_confirmation 时，生成工单存入队列。

工单生命周期：
- pending → approved（审批通过，执行工具）
- pending → denied（审批拒绝，不执行）

存储方式：内存存储（线程安全），无外部文件依赖。
"""

import threading
import uuid
from datetime import datetime
from typing import Optional


class ApprovalQueue:
    """审批工单队列（内存存储，线程安全）。"""

    def __init__(self):
        self._queue: list = []
        self._lock = threading.Lock()

    def create_ticket(
        self,
        tool_name: str,
        arguments: dict,
        user_role: str,
        reason: str,
        decision_reason: str,
        trigger: str = "policy",
        signature_score=None,
        signature_reasons=None,
    ) -> dict:
        """创建待审批工单。

        Args:
            tool_name: 工具名称
            arguments: 调用参数
            user_role: 请求者角色
            reason: 请求原因
            decision_reason: Guard 决策原因

        Returns:
            创建的工单字典
        """
        ticket = {
            "ticket_id": f"TK-{uuid.uuid4().hex[:8].upper()}",
            "tool_name": tool_name,
            "arguments": arguments,
            "user_role": user_role,
            "request_reason": reason,
            "decision_reason": decision_reason,
            "trigger": trigger or "policy",
            "signature_score": signature_score,
            "signature_reasons": list(signature_reasons or []),
            "status": "pending",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decided_at": None,
            "decided_by": None,
            "execution_result": None,
        }
        with self._lock:
            self._queue.append(ticket)
        return ticket

    def list_pending(self) -> list:
        """列出所有 pending 状态的工单。"""
        with self._lock:
            return [t for t in self._queue if t["status"] == "pending"]

    def list_all(self, page: int = 1, page_size: int = 20) -> dict:
        """列出所有工单（分页）。

        Args:
            page: 页码，从1开始
            page_size: 每页条数，默认20

        Returns:
            {
                "items": [...],
                "total": int,
                "page": int,
                "page_size": int,
                "total_pages": int,
            }
        """
        with self._lock:
            total = len(self._queue)
            # 按创建时间倒序
            sorted_queue = list(reversed(self._queue))

        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        end = start + page_size
        items = sorted_queue[start:end]

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    def get_ticket(self, ticket_id: str) -> Optional[dict]:
        """根据工单ID查询工单。"""
        with self._lock:
            for t in self._queue:
                if t["ticket_id"] == ticket_id:
                    return dict(t)
        return None

    def approve(self, ticket_id: str, decided_by: str = "admin",
                execution_result: Optional[dict] = None) -> Optional[dict]:
        """审批通过工单。

        Args:
            ticket_id: 工单ID
            decided_by: 审批人
            execution_result: 执行结果（审批通过后执行工具的结果）

        Returns:
            更新后的工单，若工单不存在或非 pending 状态则返回 None
        """
        with self._lock:
            for t in self._queue:
                if t["ticket_id"] == ticket_id and t["status"] == "pending":
                    t["status"] = "approved"
                    t["decided_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    t["decided_by"] = decided_by
                    t["execution_result"] = execution_result
                    return dict(t)
        return None

    def deny(self, ticket_id: str, decided_by: str = "admin",
             reason: str = "") -> Optional[dict]:
        """审批拒绝工单。

        Args:
            ticket_id: 工单ID
            decided_by: 审批人
            reason: 拒绝原因

        Returns:
            更新后的工单，若工单不存在或非 pending 状态则返回 None
        """
        with self._lock:
            for t in self._queue:
                if t["ticket_id"] == ticket_id and t["status"] == "pending":
                    t["status"] = "denied"
                    t["decided_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    t["decided_by"] = decided_by
                    t["deny_reason"] = reason
                    return dict(t)
        return None

    def clear(self):
        """清空工单队列（测试用）。"""
        with self._lock:
            self._queue.clear()
