"""
案例生命周期管理 (Case Manager)

将多条关联告警事件聚合为安全案例，管理案例从创建到关闭的完整生命周期。

自动聚合规则:
  1. 同一 src_ip + 30 分钟窗口 → 同一案例
  2. 攻击链检测命中的事件 → 同一案例
  3. 同 threat_type + 同 dst_ip → 同一案例

状态机:
  open → investigating → pending_approval → responding → resolved → closed
                                                              ↘ false_positive

调用方式:
    from case_manager import case_manager
    case = await case_manager.auto_create_case(session, event)
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import SecurityEvent, SecurityCase

logger = logging.getLogger(__name__)

# 案例状态流转规则
VALID_TRANSITIONS = {
    "open": ["investigating", "closed", "false_positive"],
    "investigating": ["pending_approval", "responding", "resolved", "closed", "false_positive"],
    "pending_approval": ["responding", "investigating", "closed"],
    "responding": ["resolved", "investigating", "closed"],
    "resolved": ["closed", "investigating"],
    "closed": [],
    "false_positive": ["closed", "investigating"],
}

# 聚合时间窗口
AGGREGATION_WINDOW_MINUTES = 30

# SLA 时限（小时），按优先级
SLA_HOURS = {
    "critical": 1,
    "high": 4,
    "medium": 24,
    "low": 72,
}


class CaseManager:
    """案例生命周期管理器"""

    async def auto_create_case(
        self, session: AsyncSession, event: SecurityEvent
    ) -> Optional[SecurityCase]:
        """
        尝试将新事件聚合到已有案例，或创建新案例

        聚合策略:
          1. 查找同 src_ip + 时间窗口内的 open/investigating 案例
          2. 查找同 threat_type + 同 dst_ip 的活跃案例
          3. 都不匹配 → 创建新案例
        """
        if not event.src_ip and not event.event_type:
            return None

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=AGGREGATION_WINDOW_MINUTES)

        # 策略 1: 同 src_ip + 时间窗口
        if event.src_ip:
            existing = await self._find_active_case_by_ip(
                session, event.src_ip, window_start
            )
            if existing:
                await self._add_event_to_case(session, existing, event)
                return existing

        # 策略 2: 同 threat_type + 同 dst_ip
        if event.event_type and event.dst_ip:
            existing = await self._find_active_case_by_type_target(
                session, event.event_type, event.dst_ip
            )
            if existing:
                await self._add_event_to_case(session, existing, event)
                return existing

        # 创建新案例
        return await self._create_case_from_event(session, event)

    async def create_case(
        self,
        session: AsyncSession,
        title: str,
        event_ids: list[int] = None,
        priority: str = "medium",
        threat_type: str = "",
        assignee: str = "",
        tags: list[str] = None,
    ) -> SecurityCase:
        """手动创建案例"""
        case = SecurityCase(
            case_number=self._gen_case_number(),
            title=title,
            status="open",
            priority=priority,
            threat_type=threat_type,
            assignee=assignee,
            tags=tags or [],
            event_ids=event_ids or [],
            event_count=len(event_ids) if event_ids else 0,
            sla_deadline=datetime.now(timezone.utc) + timedelta(hours=SLA_HOURS.get(priority, 24)),
        )
        session.add(case)
        await session.flush()

        # 关联事件
        if event_ids:
            for eid in event_ids:
                evt = await session.get(SecurityEvent, eid)
                if evt:
                    evt.case_id = case.id
                    evt.status = "acknowledged"
                    if evt.src_ip and evt.src_ip not in (case.src_ips or []):
                        case.src_ips = [*(case.src_ips or []), evt.src_ip]
                    if evt.dst_ip and evt.dst_ip not in (case.dst_ips or []):
                        case.dst_ips = [*(case.dst_ips or []), evt.dst_ip]

        await session.commit()
        logger.info(f"[Case] Created: {case.case_number} '{title}' (events={len(event_ids or [])})")
        return case

    async def update_status(
        self, session: AsyncSession, case_id: int, new_status: str, by: str = ""
    ) -> dict:
        """状态流转（含合法性检查）"""
        case = await session.get(SecurityCase, case_id)
        if not case:
            return {"success": False, "error": "案例不存在"}

        allowed = VALID_TRANSITIONS.get(case.status, [])
        if new_status not in allowed:
            return {
                "success": False,
                "error": f"非法状态流转: {case.status} → {new_status}，允许: {allowed}",
            }

        old_status = case.status
        before_snapshot = {"status": old_status, "assignee": case.assignee}
        case.status = new_status
        case.updated_at = datetime.now(timezone.utc)

        if new_status == "closed":
            case.closed_at = datetime.now(timezone.utc)
        if new_status == "false_positive":
            # 同步更新关联事件状态
            for eid in (case.event_ids or []):
                evt = await session.get(SecurityEvent, eid)
                if evt:
                    evt.status = "false_positive"

        await session.commit()

        # P0.H 操作审计 trail
        try:
            from audit_trail import log_action
            await log_action(
                session, actor=by or "anonymous", action="case.transition",
                target_type="case", target_id=str(case_id),
                before=before_snapshot,
                after={"status": new_status, "assignee": case.assignee},
                reason=f"{old_status} → {new_status}",
            )
        except Exception as e:
            logger.warning(f"[Case] audit_trail log failed: {e}")

        logger.info(f"[Case] {case.case_number}: {old_status} → {new_status} (by={by})")
        return {"success": True, "old_status": old_status, "new_status": new_status}

    async def assign(
        self, session: AsyncSession, case_id: int, assignee: str
    ) -> dict:
        """指派案例"""
        case = await session.get(SecurityCase, case_id)
        if not case:
            return {"success": False, "error": "案例不存在"}
        old_assignee = case.assignee
        before_snapshot = {"assignee": old_assignee, "status": case.status}
        case.assignee = assignee
        case.updated_at = datetime.now(timezone.utc)
        new_status = case.status
        if case.status == "open":
            case.status = "investigating"
            new_status = "investigating"
        await session.commit()

        try:
            from audit_trail import log_action
            await log_action(
                session, actor=assignee or "anonymous", action="case.assign",
                target_type="case", target_id=str(case_id),
                before=before_snapshot,
                after={"assignee": assignee, "status": new_status},
                reason=f"指派 {assignee}",
            )
        except Exception as e:
            logger.warning(f"[Case] audit_trail log failed: {e}")

        return {"success": True, "assignee": assignee}

    async def set_disposition(
        self, session: AsyncSession, case_id: int,
        disposition: str, by: str = ""
    ) -> dict:
        """写入最终处置结论"""
        case = await session.get(SecurityCase, case_id)
        if not case:
            return {"success": False, "error": "案例不存在"}
        before_snapshot = {"disposition": case.disposition or ""}
        case.disposition = disposition
        case.disposition_by = by
        case.disposition_at = datetime.now(timezone.utc)
        case.updated_at = datetime.now(timezone.utc)
        await session.commit()

        try:
            from audit_trail import log_action
            await log_action(
                session, actor=by or "anonymous", action="case.disposition",
                target_type="case", target_id=str(case_id),
                before=before_snapshot, after={"disposition": disposition},
                reason="写入处置结论",
            )
        except Exception as e:
            logger.warning(f"[Case] audit_trail log failed: {e}")

        logger.info(f"[Case] {case.case_number}: disposition set by {by}")
        return {"success": True}

    async def get_case(self, session: AsyncSession, case_id: int) -> Optional[dict]:
        """获取案例详情"""
        case = await session.get(SecurityCase, case_id)
        if not case:
            return None
        return self._case_to_dict(case)

    async def list_cases(
        self, session: AsyncSession,
        status: str = "", priority: str = "",
        assignee: str = "", limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        """列表查询"""
        conditions = []
        if status:
            conditions.append(SecurityCase.status == status)
        if priority:
            conditions.append(SecurityCase.priority == priority)
        if assignee:
            conditions.append(SecurityCase.assignee == assignee)

        stmt = select(SecurityCase)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(SecurityCase.created_at)).limit(limit).offset(offset)

        result = await session.execute(stmt)
        return [self._case_to_dict(c) for c in result.scalars().all()]

    async def get_case_timeline(
        self, session: AsyncSession, case_id: int
    ) -> list[dict]:
        """获取案例时间线（事件 + 响应日志）"""
        case = await session.get(SecurityCase, case_id)
        if not case:
            return []

        timeline = []

        # 事件（批量查询，避免 N+1）
        if case.event_ids:
            stmt = (
                select(SecurityEvent)
                .where(SecurityEvent.id.in_(case.event_ids))
                .order_by(SecurityEvent.created_at)
            )
            result = await session.execute(stmt)
            for evt in result.scalars().all():
                timeline.append({
                    "time": evt.created_at.isoformat() if evt.created_at else "",
                    "type": "event",
                    "detail": f"[{evt.severity}] {evt.event_type}: {(evt.message or '')[:100]}",
                    "event_id": evt.id,
                    "status": evt.status,
                })

        # 响应日志
        try:
            from models import ResponseLog
            stmt = (
                select(ResponseLog)
                .where(ResponseLog.event_id.in_(case.event_ids or []))
                .order_by(ResponseLog.created_at)
            )
            result = await session.execute(stmt)
            for log in result.scalars().all():
                timeline.append({
                    "time": log.created_at.isoformat() if log.created_at else "",
                    "type": "response",
                    "detail": f"{log.action_name} ({'成功' if log.action_success else '失败'})",
                    "action": log.action_name,
                })
        except Exception:
            pass

        timeline.sort(key=lambda x: x.get("time", ""))
        return timeline

    # ── 内部方法 ──

    async def _find_active_case_by_ip(
        self, session: AsyncSession, src_ip: str, window_start: datetime
    ) -> Optional[SecurityCase]:
        stmt = (
            select(SecurityCase)
            .where(
                SecurityCase.status.in_(["open", "investigating", "responding"]),
                SecurityCase.created_at >= window_start,
            )
            .order_by(desc(SecurityCase.created_at))
            .limit(10)
        )
        result = await session.execute(stmt)
        for case in result.scalars().all():
            if src_ip in (case.src_ips or []):
                return case
        return None

    async def _find_active_case_by_type_target(
        self, session: AsyncSession, threat_type: str, dst_ip: str
    ) -> Optional[SecurityCase]:
        stmt = (
            select(SecurityCase)
            .where(
                SecurityCase.status.in_(["open", "investigating"]),
                SecurityCase.threat_type == threat_type,
            )
            .order_by(desc(SecurityCase.created_at))
            .limit(10)
        )
        result = await session.execute(stmt)
        for case in result.scalars().all():
            if dst_ip in (case.dst_ips or []):
                return case
        return None

    async def _create_case_from_event(
        self, session: AsyncSession, event: SecurityEvent
    ) -> SecurityCase:
        severity = event.severity or "medium"
        # P0.A: 根据目标资产关键性自动提升案例优先级
        priority = {"critical": "critical", "high": "high"}.get(severity, "medium")
        try:
            from asset import asset_correlator
            recommended = await asset_correlator.recommend_case_priority(
                session, event.dst_ip or "", priority
            )
            if recommended:
                priority = recommended
        except Exception as e:
            logger.debug(f"[Case] asset correlation skipped: {e}")

        raw = event.raw_data or {}
        threat_type = event.event_type or raw.get("event", "UNKNOWN")

        # P0.A: 富化资产元数据写入案例
        asset_snapshot = None
        try:
            from asset import asset_correlator
            asset_snapshot = await asset_correlator.enrich_case_target(
                session, event.dst_ip or ""
            )
        except Exception:
            pass

        case_meta = {}
        if asset_snapshot:
            case_meta["dst_asset"] = asset_snapshot

        case = SecurityCase(
            case_number=self._gen_case_number(),
            title=f"[{severity.upper()}] {threat_type} - {event.src_ip or 'unknown'}",
            status="open",
            priority=priority,
            threat_type=threat_type,
            severity=severity,
            confidence=raw.get("_anomaly", {}).get("score", 0.0),
            src_ips=[event.src_ip] if event.src_ip else [],
            dst_ips=[event.dst_ip] if event.dst_ip else [],
            event_ids=[event.id],
            event_count=1,
            sla_deadline=datetime.now(timezone.utc) + timedelta(hours=SLA_HOURS.get(priority, 24)),
            metadata_=case_meta,
        )
        session.add(case)
        await session.flush()

        event.case_id = case.id
        event.status = "acknowledged"
        await session.commit()

        logger.info(
            f"[Case] Auto-created: {case.case_number} "
            f"type={threat_type} src={event.src_ip} sev={severity}"
        )
        return case

    async def _add_event_to_case(
        self, session: AsyncSession, case: SecurityCase, event: SecurityEvent
    ):
        event_ids = list(case.event_ids or [])
        if event.id not in event_ids:
            event_ids.append(event.id)
            case.event_ids = event_ids
            case.event_count = len(event_ids)

        if event.src_ip and event.src_ip not in (case.src_ips or []):
            case.src_ips = [*(case.src_ips or []), event.src_ip]
        if event.dst_ip and event.dst_ip not in (case.dst_ips or []):
            case.dst_ips = [*(case.dst_ips or []), event.dst_ip]

        # 升级严重度/优先级
        sev_order = ["info", "low", "medium", "high", "critical"]
        if sev_order.index(event.severity or "info") > sev_order.index(case.severity or "info"):
            case.severity = event.severity
            case.priority = {"critical": "critical", "high": "high"}.get(event.severity, case.priority)

        event.case_id = case.id
        event.status = "acknowledged"
        case.updated_at = datetime.now(timezone.utc)
        await session.commit()

        logger.debug(f"[Case] Event #{event.id} added to {case.case_number}")

    @staticmethod
    def _gen_case_number() -> str:
        import uuid
        now = datetime.now()
        return f"CASE-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    @staticmethod
    def _case_to_dict(case: SecurityCase) -> dict:
        return {
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "status": case.status,
            "priority": case.priority,
            "threat_type": case.threat_type,
            "severity": case.severity,
            "confidence": case.confidence,
            "src_ips": case.src_ips or [],
            "dst_ips": case.dst_ips or [],
            "event_ids": case.event_ids or [],
            "event_count": case.event_count,
            "assignee": case.assignee,
            "sla_deadline": case.sla_deadline.isoformat() if case.sla_deadline else None,
            "disposition": case.disposition,
            "disposition_by": case.disposition_by,
            "tags": case.tags or [],
            "created_at": case.created_at.isoformat() if case.created_at else "",
            "updated_at": case.updated_at.isoformat() if case.updated_at else "",
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        }


case_manager = CaseManager()
