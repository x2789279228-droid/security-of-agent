"""
人工审批队列 (Human Approval Queue)

管理需要人工确认才能执行的高危响应动作。

流程:
  1. Orchestrator 提交审批工单 → PENDING
  2. 审批人审批 (APPROVED/REJECTED)
  3. 自动执行或回滚

审批条件配置:
  - 动作危险等级为 high / critical
  - 策略明确 require_approval = true
  - 熔断器处于 tripped 状态
"""
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    """审批状态"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"  # 超时自动批准
    # 系统按策略自动执行（仅 HIGH 动作且策略显式 auto_execute 豁免），
    # 供事后审查/回滚，不是审批结果，审批人不可再批/拒
    AUTO_EXECUTED = "auto_executed"


@dataclass
class ApprovalTicket:
    """审批工单"""
    id: str
    threat_info: dict                  # 威胁上下文
    policy_name: str
    actions: list[dict]                # 待审批的动作
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = 0.0
    expires_at: float = 0.0            # 超时时间（默认30分钟）
    approved_by: str = ""
    approved_at: float = 0.0
    reject_reason: str = ""
    result: Optional[dict] = None      # 执行结果
    priority: str = "p2"               # p1=高优（Uncertain 等）/ p2=普通
    match_status: str = ""             # matched / uncertain / ...

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def summary(self) -> str:
        return (
            f"[{self.status.value}/{self.priority}] {self.policy_name} → "
            f"{len(self.actions)} actions, "
            f"threat={self.threat_info.get('threat_type', '?')}"
            f"{f' status={self.match_status}' if self.match_status else ''}"
        )

    @property
    def priority_rank(self) -> int:
        """数值越小越优先（list_pending 排序用）。"""
        order = {"p0": 0, "p1": 1, "p2": 2, "p3": 3}
        return order.get(str(self.priority or "p2").lower(), 9)


class ApprovalQueue:
    """审批队列"""

    def __init__(self, default_timeout_minutes: int = 30):
        self._tickets: dict[str, ApprovalTicket] = {}
        self._default_timeout = default_timeout_minutes
        self._auto_approve_timeout_minutes = 10  # 超时自动批准（高危不自动）

    def submit(
        self,
        threat_info: dict,
        policy_name: str,
        actions: list[dict],
        timeout_minutes: Optional[int] = None,
        priority: str = "p2",
        match_status: str = "",
    ) -> ApprovalTicket:
        """提交审批工单"""
        import uuid

        ticket = ApprovalTicket(
            id=str(uuid.uuid4()),
            threat_info=threat_info,
            policy_name=policy_name,
            actions=actions,
            status=ApprovalStatus.PENDING,
            created_at=time.time(),
            expires_at=time.time() + (timeout_minutes or self._default_timeout) * 60,
            priority=priority or "p2",
            match_status=match_status or "",
        )
        self._tickets[ticket.id] = ticket

        logger.warning(
            f"[APPROVAL] Ticket #{ticket.id[:8]} submitted: "
            f"{policy_name} ({len(actions)} actions) "
            f"threat={threat_info.get('threat_type','?')} "
            f"priority={ticket.priority} match_status={ticket.match_status or '-'} "
            f"expires={ticket.expires_at}"
        )

        return ticket

    def approve(self, ticket_id: str, approved_by: str = "admin") -> Optional[ApprovalTicket]:
        """批准工单"""
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            logger.warning(f"Approval ticket {ticket_id} not found")
            return None
        if ticket.status != ApprovalStatus.PENDING:
            logger.warning(f"Ticket {ticket_id} already {ticket.status.value}")
            return None

        ticket.status = ApprovalStatus.APPROVED
        ticket.approved_by = approved_by
        ticket.approved_at = time.time()
        logger.warning(f"[APPROVAL] Ticket #{ticket_id[:8]} APPROVED by {approved_by}")
        return ticket

    def reject(self, ticket_id: str, reason: str = "", rejected_by: str = "admin") -> Optional[ApprovalTicket]:
        """拒绝工单"""
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            return None
        if ticket.status != ApprovalStatus.PENDING:
            return None

        ticket.status = ApprovalStatus.REJECTED
        ticket.reject_reason = reason
        ticket.approved_by = rejected_by  # reuse field
        logger.warning(f"[APPROVAL] Ticket #{ticket_id[:8]} REJECTED by {rejected_by}: {reason}")
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[ApprovalTicket]:
        return self._tickets.get(ticket_id)

    def list_pending(self) -> list[ApprovalTicket]:
        """获取所有待审批工单（p1 置顶，其次按创建时间倒序）。"""
        pending = []
        for ticket in self._tickets.values():
            if ticket.status == ApprovalStatus.PENDING:
                if ticket.is_expired:
                    ticket.status = ApprovalStatus.EXPIRED
                else:
                    pending.append(ticket)
        pending.sort(key=lambda t: (t.priority_rank, -t.created_at))
        return pending

    def list_all(self, limit: int = 50) -> list[ApprovalTicket]:
        tickets = sorted(
            self._tickets.values(),
            key=lambda t: (t.priority_rank, -t.created_at),
        )
        return tickets[:limit]

    def cleanup(self, max_age_hours: int = 72):
        """清理过期工单"""
        cutoff = time.time() - max_age_hours * 3600
        expired = [tid for tid, t in self._tickets.items() if t.created_at < cutoff]
        for tid in expired:
            del self._tickets[tid]
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired approval tickets")


approval_queue = ApprovalQueue()
