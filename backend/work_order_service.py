"""
工单服务 (Work Order Service)

持久化工单管理，支持处置/审批/复盘/回滚四种工单类型。
替代原有内存态 ApprovalQueue，提供 SLA 超时检测。

工单状态: pending → assigned → in_progress → completed → cancelled
审批状态: pending → approved | rejected

调用方式:
    from work_order_service import work_order_service
    order = await work_order_service.create_order(session, case_id=1, ...)
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import WorkOrder, SecurityCase

logger = logging.getLogger(__name__)

ORDER_TYPES = ["disposition", "approval", "review", "rollback"]
ORDER_STATUSES = ["pending", "assigned", "in_progress", "completed", "cancelled"]

# SLA 时限（小时），按优先级
SLA_HOURS = {"critical": 2, "high": 8, "medium": 24, "low": 72}


class WorkOrderService:
    """工单服务"""

    async def create_order(
        self,
        session: AsyncSession,
        case_id: Optional[int] = None,
        order_type: str = "disposition",
        title: str = "",
        description: str = "",
        priority: str = "medium",
        assignee: str = "",
        created_by: str = "system",
    ) -> WorkOrder:
        """创建工单"""
        order = WorkOrder(
            order_number=self._gen_order_number(),
            case_id=case_id,
            order_type=order_type,
            title=title,
            description=description,
            status="assigned" if assignee else "pending",
            priority=priority,
            assignee=assignee,
            created_by=created_by,
            approval_status="pending" if order_type == "approval" else "",
            sla_deadline=datetime.now(timezone.utc) + timedelta(hours=SLA_HOURS.get(priority, 24)),
        )
        session.add(order)
        await session.commit()
        logger.info(f"[WorkOrder] Created: {order.order_number} type={order_type} case={case_id}")
        return order

    async def update_status(
        self, session: AsyncSession, order_id: int, new_status: str
    ) -> dict:
        """更新工单状态"""
        order = await session.get(WorkOrder, order_id)
        if not order:
            return {"success": False, "error": "工单不存在"}
        if new_status not in ORDER_STATUSES:
            return {"success": False, "error": f"非法状态: {new_status}"}

        order.status = new_status
        order.updated_at = datetime.now(timezone.utc)
        if new_status == "completed":
            order.completed_at = datetime.now(timezone.utc)
            # 处置类工单完成 → 联动关联 case 推进到 resolved (依 VALID_TRANSITIONS 合法迁移)
            await self._maybe_resolve_case(session, order)
        await session.commit()
        return {"success": True, "status": new_status}

    async def _maybe_resolve_case(self, session: AsyncSession, order: WorkOrder) -> None:
        """仅 disposition 工单 completed 时, 把关联 case 从 responding 推到 resolved。

        失败仅警告, 不阻断工单状态更新。
        """
        try:
            if order.order_type != "disposition" or not order.case_id:
                return
            from case_manager import case_manager
            result = await case_manager.update_status(
                session, order.case_id, "resolved", by="system"
            )
            if result and not result.get("success"):
                logger.warning(f"[WorkOrder] case {order.case_id} 未推进 resolved: {result.get('error')}")
        except Exception as e:
            logger.warning(f"[WorkOrder] case resolve 联动失败: {e}")

    async def assign(
        self, session: AsyncSession, order_id: int, assignee: str
    ) -> dict:
        order = await session.get(WorkOrder, order_id)
        if not order:
            return {"success": False, "error": "工单不存在"}
        order.assignee = assignee
        if order.status == "pending":
            order.status = "assigned"
        order.updated_at = datetime.now(timezone.utc)
        await session.commit()
        return {"success": True, "assignee": assignee}

    async def approve(
        self, session: AsyncSession, order_id: int, approved_by: str = "admin"
    ) -> dict:
        """审批通过"""
        order = await session.get(WorkOrder, order_id)
        if not order:
            return {"success": False, "error": "工单不存在"}
        if order.approval_status != "pending":
            return {"success": False, "error": f"工单已审批: {order.approval_status}"}

        before_snapshot = {
            "approval_status": order.approval_status,
            "status": order.status,
        }
        order.approval_status = "approved"
        order.approved_by = approved_by
        order.approved_at = datetime.now(timezone.utc)
        order.status = "in_progress"
        order.updated_at = datetime.now(timezone.utc)
        await session.commit()

        # 审批通过后自动执行关联的响应动作
        if order.case_id:
            await self._execute_approved_actions(session, order)

        # P0.H 操作审计
        try:
            from audit_trail import log_action
            await log_action(
                session, actor=approved_by, action="order.approve",
                target_type="work_order", target_id=str(order_id),
                before=before_snapshot,
                after={"approval_status": "approved", "status": "in_progress"},
                reason=f"审批工单 {order.order_number}",
            )
        except Exception as e:
            logger.warning(f"[WorkOrder] audit_trail log failed: {e}")

        logger.info(f"[WorkOrder] {order.order_number} APPROVED by {approved_by}")
        return {"success": True, "approved_by": approved_by}

    async def reject(
        self, session: AsyncSession, order_id: int,
        reason: str = "", rejected_by: str = "admin"
    ) -> dict:
        """审批拒绝"""
        order = await session.get(WorkOrder, order_id)
        if not order:
            return {"success": False, "error": "工单不存在"}
        if order.approval_status != "pending":
            return {"success": False, "error": f"工单已审批: {order.approval_status}"}

        before_snapshot = {
            "approval_status": order.approval_status,
            "status": order.status,
        }
        order.approval_status = "rejected"
        order.approved_by = rejected_by
        order.reject_reason = reason
        order.status = "cancelled"
        order.updated_at = datetime.now(timezone.utc)
        await session.commit()

        try:
            from audit_trail import log_action
            await log_action(
                session, actor=rejected_by, action="order.reject",
                target_type="work_order", target_id=str(order_id),
                before=before_snapshot,
                after={"approval_status": "rejected", "status": "cancelled"},
                reason=reason or f"拒绝工单 {order.order_number}",
            )
        except Exception as e:
            logger.warning(f"[WorkOrder] audit_trail log failed: {e}")

        logger.info(f"[WorkOrder] {order.order_number} REJECTED by {rejected_by}: {reason}")
        return {"success": True}

    async def list_orders(
        self, session: AsyncSession,
        case_id: int = 0, order_type: str = "", status: str = "",
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        conditions = []
        if case_id:
            conditions.append(WorkOrder.case_id == case_id)
        if order_type:
            conditions.append(WorkOrder.order_type == order_type)
        if status:
            conditions.append(WorkOrder.status == status)

        stmt = select(WorkOrder)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(WorkOrder.created_at)).limit(limit).offset(offset)

        result = await session.execute(stmt)
        return [self._order_to_dict(o) for o in result.scalars().all()]

    async def check_sla_breaches(self, session: AsyncSession) -> list[dict]:
        """扫描超时工单"""
        now = datetime.now(timezone.utc)
        stmt = (
            select(WorkOrder)
            .where(
                WorkOrder.status.in_(["pending", "assigned", "in_progress"]),
                WorkOrder.sla_deadline <= now,
                WorkOrder.sla_breached == False,
            )
        )
        result = await session.execute(stmt)
        breached = []
        for order in result.scalars().all():
            order.sla_breached = True
            order.updated_at = now
            breached.append(self._order_to_dict(order))
            logger.warning(f"[WorkOrder] SLA BREACHED: {order.order_number}")

        if breached:
            await session.commit()
            # SSE 推送
            try:
                from event_bus import event_bus
                for b in breached:
                    event_bus.publish("pipeline_health", {
                        "type": "sla_breach",
                        "order_number": b["order_number"],
                        "case_id": b["case_id"],
                        "priority": b["priority"],
                    })
            except Exception:
                pass

            # P0.B: 上报 SLA tracker (供 P1.C 升级引擎订阅)
            try:
                from ops_metrics.sla_tracker import sla_tracker
                for b in breached:
                    await sla_tracker.record_breach(b)
            except Exception as e:
                logger.warning(f"[WorkOrder] sla_tracker record failed: {e}")

        return breached

    async def _execute_approved_actions(self, session: AsyncSession, order: WorkOrder):
        """审批通过后执行响应动作"""
        try:
            from response_engine import get_orchestrator
            orch = get_orchestrator()
            case = await session.get(SecurityCase, order.case_id)
            if case and case.event_ids:
                # 更新案例状态
                case.status = "responding"
                case.updated_at = datetime.now(timezone.utc)
                await session.commit()
        except Exception as e:
            logger.warning(f"[WorkOrder] Auto-execute failed: {e}")

    @staticmethod
    def _gen_order_number() -> str:
        import uuid
        now = datetime.now()
        return f"WO-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    @staticmethod
    def _order_to_dict(o: WorkOrder) -> dict:
        return {
            "id": o.id,
            "order_number": o.order_number,
            "case_id": o.case_id,
            "order_type": o.order_type,
            "title": o.title,
            "description": o.description,
            "status": o.status,
            "priority": o.priority,
            "assignee": o.assignee,
            "created_by": o.created_by,
            "approval_status": o.approval_status,
            "approved_by": o.approved_by,
            "reject_reason": o.reject_reason,
            "sla_deadline": o.sla_deadline.isoformat() if o.sla_deadline else None,
            "sla_breached": o.sla_breached,
            "result": o.result or {},
            "created_at": o.created_at.isoformat() if o.created_at else "",
            "completed_at": o.completed_at.isoformat() if o.completed_at else None,
        }


work_order_service = WorkOrderService()
