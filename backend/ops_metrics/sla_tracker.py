"""
SLA 跟踪器 (SLA Tracker) — P0.B

取代 work_order_service.check_sla_breaches 的单点 SSE 推送：
  - 记录 breach 趋势到内存环形缓冲
  - 供 P1.C 升级引擎订阅
  - 提供查询接口（按时间 / priority 切分）

集成方式:
  - work_order_service.check_sla_breaches() 在打 SSE 后调 sla_tracker.record_breach()
  - scheduler._sla_check_loop 周期触发
"""
import logging
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models import WorkOrder, SecurityCase

logger = logging.getLogger(__name__)


class SlaTracker:
    """SLA 违约跟踪器"""

    def __init__(self, buffer_size: int = 1000):
        self._breaches: deque[dict] = deque(maxlen=buffer_size)
        self._subscribers: list = []  # P1.C 升级引擎的回调

    def subscribe(self, callback):
        """订阅 breach 事件 (P1.C escalator 使用)"""
        self._subscribers.append(callback)

    async def record_breach(self, order: dict) -> None:
        """
        记录一次 SLA breach
        - order: work_order_service._order_to_dict 返回结构
        """
        entry = {
            "order_id": order.get("id"),
            "order_number": order.get("order_number", ""),
            "case_id": order.get("case_id"),
            "priority": order.get("priority", "medium"),
            "sla_deadline": order.get("sla_deadline"),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._breaches.append(entry)
        logger.warning(
            f"[SLA] breach recorded: {entry['order_number']} "
            f"priority={entry['priority']}"
        )
        # 通知订阅者 (P1.C 升级引擎)
        for cb in self._subscribers:
            try:
                await cb(entry)
            except Exception as e:
                logger.warning(f"[SLA] subscriber notify failed: {e}")

    def recent_breaches(self, hours: int = 24) -> list[dict]:
        """最近 N 小时的 breach 记录 (内存)"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_iso = cutoff.isoformat()
        return [b for b in self._breaches if b["recorded_at"] >= cutoff_iso]

    async def breach_rate(
        self, session: AsyncSession, *,
        hours: int = 24, priority: str = "",
    ) -> dict:
        """
        最近 N 小时的 SLA 违约率 (DB 实时查询,不依赖快照)
        Returns: {total, breached, rate, by_priority: {...}}
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        conditions = [WorkOrder.created_at >= cutoff]
        if priority:
            conditions.append(WorkOrder.priority == priority)

        total_stmt = select(func.count(WorkOrder.id)).where(and_(*conditions))
        breached_stmt = (
            select(func.count(WorkOrder.id))
            .where(and_(*conditions, WorkOrder.sla_breached == True))
        )
        total = (await session.execute(total_stmt)).scalar() or 0
        breached = (await session.execute(breached_stmt)).scalar() or 0
        rate = round(breached / total, 4) if total > 0 else 0.0

        # 按 priority 切分
        by_priority: dict[str, dict] = {}
        for prio in ("critical", "high", "medium", "low"):
            t_stmt = select(func.count(WorkOrder.id)).where(
                WorkOrder.created_at >= cutoff, WorkOrder.priority == prio
            )
            b_stmt = select(func.count(WorkOrder.id)).where(
                WorkOrder.created_at >= cutoff,
                WorkOrder.priority == prio,
                WorkOrder.sla_breached == True,
            )
            t = (await session.execute(t_stmt)).scalar() or 0
            b = (await session.execute(b_stmt)).scalar() or 0
            by_priority[prio] = {
                "total": t, "breached": b,
                "rate": round(b / t, 4) if t > 0 else 0.0,
            }

        return {
            "hours": hours, "total": total, "breached": breached,
            "rate": rate, "by_priority": by_priority,
        }


sla_tracker = SlaTracker()