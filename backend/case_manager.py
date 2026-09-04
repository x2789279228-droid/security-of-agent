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
    "responding": ["resolved", "investigating", "closed", "pending_approval"],
    "resolved": ["closed", "investigating"],
    "closed": [],
    "false_positive": ["closed", "investigating"],
}

# 聚合时间窗口
AGGREGATION_WINDOW_MINUTES = 30
# 同 threat_type + dst_ip 的吸收窗口（防止跨日旧案吞噬新攻击）
TYPE_TARGET_WINDOW_HOURS = 6

# 杀伤链阶段：用于升级案例标题 / threat_type（数值越大越靠后）
KILLCHAIN_RANK = {
    "PORT_SCAN": 10,
    "XSS_ATTACK": 15,
    "BRUTE_FORCE": 20,
    "SSH_BRUTE": 20,
    "SQL_INJECTION": 25,
    "LATERAL_MOVE": 30,
    "LATERAL_MOVEMENT": 30,
    "PRIVILEGE_ESCALATION": 35,
    "C2_BEACON": 40,
    "MALWARE_DETECT": 40,
    "DATA_EXFIL": 50,
    "RANSOMWARE": 60,
}

# SLA 时限（小时），按优先级
# critical 从 1h 调至 4h：告警自动创建的案例在 1h 内几乎不可能走完
# 分析→响应闭环，导致历史上 100% 超时、徽标失去区分度
SLA_HOURS = {
    "critical": 4,
    "high": 8,
    "medium": 24,
    "low": 72,
}

# 自动响应落地后，案例空闲超过该分钟再收口（避免杀伤链后半段被拆案）
DEFAULT_AUTO_RESOLVE_IDLE_MINUTES = 10
AUTO_RESPONSE_ACTIONS = frozenset({
    "block_ip", "rate_limit", "send_alert", "isolate_host",
    "kill_session", "unblock_ip", "restore_host",
})
ACTIVE_CASE_STATUSES = ("open", "investigating", "responding")


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class CaseManager:
    """案例生命周期管理器"""

    async def auto_create_case(
        self, session: AsyncSession, event: SecurityEvent
    ) -> Optional[SecurityCase]:
        """
        尝试将新事件聚合到已有案例，或创建新案例

        聚合策略:
          0. 同 session_id 的活跃案例（杀伤链同源优先）
             有 session_id 时不再回落到跨 session 的 IP/类型匹配，避免演示轮次并案
          1. 无 session_id：查找同 src_ip + 时间窗口内的 open/investigating 案例
          2. 无 session_id：查找同 threat_type + 同 dst_ip 的活跃案例（带时间窗）
          3. 都不匹配 → 创建新案例
        """
        if not event.src_ip and not event.event_type:
            return None

        # 事件已挂案例：幂等复用，避免 ingest + audit/Kafka 双路径并开两案
        if event.case_id:
            existing = await session.get(SecurityCase, event.case_id)
            if existing and existing.status in (
                "open", "investigating", "responding", "pending_approval"
            ):
                await self._add_event_to_case(session, existing, event)
                return existing

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=AGGREGATION_WINDOW_MINUTES)
        type_window_start = now - timedelta(hours=TYPE_TARGET_WINDOW_HOURS)

        await self._lock_session_case(session, event.session_id)

        # 策略 0: 同 session 聚合（演示/同源攻击链）
        if event.session_id:
            existing = await self._find_active_case_by_session(
                session, event.session_id
            )
            if existing:
                await self._add_event_to_case(session, existing, event)
                return existing
            # 新 session 必须新开案例，禁止被同 IP 的旧 demo 吸走
            return await self._create_case_from_event(session, event)

        # 策略 1: 同 src_ip + 时间窗口（仅无 session 的真实采集流）
        if event.src_ip:
            existing = await self._find_active_case_by_ip(
                session, event.src_ip, window_start
            )
            if existing:
                await self._add_event_to_case(session, existing, event)
                return existing

        # 策略 2: 同 threat_type + 同 dst_ip（限时间窗，避免吸进多日前旧案）
        if event.event_type and event.dst_ip:
            existing = await self._find_active_case_by_type_target(
                session, event.event_type, event.dst_ip, type_window_start
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
                mode = ""
                if isinstance(log.action_result, dict):
                    mode = log.action_result.get("mode") or ""
                suffix = f" [{mode}]" if mode else ""
                timeline.append({
                    "time": log.created_at.isoformat() if log.created_at else "",
                    "type": "response",
                    "detail": f"{log.action_name} ({'成功' if log.action_success else '失败'}){suffix}",
                    "action": log.action_name,
                    "execution_mode": mode,
                })
        except Exception:
            pass

        timeline.sort(key=lambda x: x.get("time", ""))
        return timeline

    # ── 内部方法 ──

    async def _lock_session_case(self, session: AsyncSession, session_id: str) -> None:
        """Postgres 事务锁，防止同 session 并发创建两个案例。SQLite 单测忽略。"""
        if not session_id:
            return
        try:
            from sqlalchemy import text
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:sid))"),
                {"sid": session_id},
            )
        except Exception as e:
            # 非 Postgres 后端（如 SQLite 测试/本地模式）没有咨询锁，
            # 此时并发保护静默失效，必须留痕便于排查，不能完全吞掉
            logger.warning(f"advisory lock unavailable for {session_id[:8]}...: {e}")

    async def _find_active_case_by_session(
        self, session: AsyncSession, session_id: str
    ) -> Optional[SecurityCase]:
        """同源 session 下已有活跃案例则并入（跨事件类型杀伤链）。"""
        if not session_id:
            return None
        # 通过事件反查：同 session 的事件已挂 case_id
        stmt = (
            select(SecurityEvent.case_id)
            .where(
                SecurityEvent.session_id == session_id,
                SecurityEvent.case_id.isnot(None),
            )
            .order_by(desc(SecurityEvent.created_at))
            .limit(5)
        )
        result = await session.execute(stmt)
        case_ids = [row[0] for row in result.all() if row[0]]
        if not case_ids:
            return None
        for cid in case_ids:
            case = await session.get(SecurityCase, cid)
            if case and case.status in (
                "open", "investigating", "responding", "pending_approval"
            ):
                return case
        return None

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
        self,
        session: AsyncSession,
        threat_type: str,
        dst_ip: str,
        window_start: Optional[datetime] = None,
    ) -> Optional[SecurityCase]:
        filters = [
            SecurityCase.status.in_(["open", "investigating"]),
            SecurityCase.threat_type == threat_type,
        ]
        if window_start is not None:
            filters.append(SecurityCase.created_at >= window_start)
        stmt = (
            select(SecurityCase)
            .where(*filters)
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
        if event.session_id:
            case_meta["session_id"] = event.session_id

        case = SecurityCase(
            case_number=self._gen_case_number(),
            title=self._compose_title(severity, threat_type, event.src_ip or "unknown"),
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
        # 高/严重告警自动派生工单 (仅新建 case 路径; 聚合复用不重复派单)
        await self._maybe_auto_dispatch(session, case)
        return case

    async def _maybe_auto_dispatch(self, session: AsyncSession, case: SecurityCase) -> bool:
        """自动派单：命中阈值优先级的案例 → 派生工单并推进到 responding。

        按 VALID_TRANSITIONS 合法迁移: open→investigating→responding。
        已有未完成 disposition 工单则不重复派单，仅补齐状态。
        未命中阈值返回 False。
        """
        if case is None:
            return False
        try:
            from config import settings
            from work_order_service import work_order_service
            from models import WorkOrder
            prios = [p.strip().lower() for p in (settings.case_auto_order_priorities or "").split(",") if p.strip()]
            if (case.priority or "").lower() not in (prios or ["high", "critical"]):
                return False

            existing = (await session.execute(
                select(WorkOrder.id).where(
                    WorkOrder.case_id == case.id,
                    WorkOrder.order_type == "disposition",
                    WorkOrder.status.in_(["pending", "assigned", "in_progress"]),
                ).limit(1)
            )).scalar_one_or_none()

            async def _advance(from_status: str, to_status: str):
                if case.status != from_status:
                    return
                result = await self.update_status(session, case.id, to_status, by="system")
                if result.get("success"):
                    case.status = result["new_status"]

            if existing:
                await _advance("open", "investigating")
                await _advance("investigating", "responding")
                return True

            await _advance("open", "investigating")
            order = await work_order_service.create_order(
                session, case_id=case.id,
                order_type="disposition",
                title=f"[自动派单] {case.title}",
                priority=case.priority,
                created_by="system",
                assignee=(settings.case_default_assignee or "").strip(),
            )
            await _advance("investigating", "responding")
            logger.info(f"[Case] Auto-dispatched work_order {order.order_number} for {case.case_number}")
            return True
        except Exception as e:
            logger.warning(f"[Case] auto-dispatch failed: {e}")
            return False

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
        upgraded = False
        if sev_order.index(event.severity or "info") > sev_order.index(case.severity or "info"):
            case.severity = event.severity
            new_prio = {"critical": "critical", "high": "high"}.get(event.severity, case.priority)
            if new_prio != case.priority:
                upgraded = True
            case.priority = new_prio
            new_deadline = datetime.now(timezone.utc) + timedelta(
                hours=SLA_HOURS.get(case.priority, 24)
            )
            current_deadline = case.sla_deadline
            if current_deadline is not None and current_deadline.tzinfo is None:
                current_deadline = current_deadline.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            # 只收紧不放宽；但已超期（breach 粘滞）的案例在升级时必须重新计时，
            # 否则 deadline 永不刷新、sla_breached 永久为 True，污染 breach rate KPI
            if current_deadline is None or current_deadline > new_deadline or current_deadline < now:
                case.sla_deadline = new_deadline
                if case.sla_breached and current_deadline is not None and current_deadline < now:
                    case.sla_breached = False
                    logger.info(
                        f"[Case] {case.case_number} severity upgraded on breached case: "
                        f"SLA re-armed with new deadline {new_deadline.isoformat()}"
                    )

        self._refresh_case_narrative(case, event)

        event.case_id = case.id
        event.status = "acknowledged"
        case.updated_at = datetime.now(timezone.utc)
        await session.commit()

        if upgraded or (case.priority or "").lower() in ("high", "critical"):
            await self._maybe_auto_dispatch(session, case)

        logger.debug(f"[Case] Event #{event.id} added to {case.case_number}")

    @staticmethod
    def _killchain_rank(threat_type: str) -> int:
        return KILLCHAIN_RANK.get((threat_type or "").upper().replace("-", "_"), 0)

    @staticmethod
    def _compose_title(severity: str, threat_type: str, src_ip: str) -> str:
        return f"[{(severity or 'medium').upper()}] {threat_type or 'UNKNOWN'} - {src_ip or 'unknown'}"

    def _refresh_case_narrative(self, case: SecurityCase, event: SecurityEvent) -> None:
        """随杀伤链推进改写标题、threat_type、tags。"""
        et = (event.event_type or "").strip()
        tags = list(case.tags or [])
        if et and et not in tags:
            tags.append(et)
            case.tags = tags
        if et and self._killchain_rank(et) >= self._killchain_rank(case.threat_type):
            case.threat_type = et
            title_src = event.src_ip or ((case.src_ips or [None])[0]) or "unknown"
        else:
            title_src = ((case.src_ips or [None])[0]) or event.src_ip or "unknown"
        meta = dict(case.metadata_ or {})
        if event.session_id:
            meta["session_id"] = event.session_id
        case.metadata_ = meta
        case.title = self._compose_title(case.severity, case.threat_type, title_src)

    async def _case_log_scope(self, session: AsyncSession, case: SecurityCase):
        """ResponseLog 过滤：案例事件 ID + 同源 session。"""
        from models import ResponseLog
        ids = [i for i in (case.event_ids or []) if i]
        clauses = []
        if ids:
            clauses.append(ResponseLog.event_id.in_(ids))
        session_ids = set()
        meta_sid = (case.metadata_ or {}).get("session_id")
        if meta_sid:
            session_ids.add(meta_sid)
        if ids:
            rows = (await session.execute(
                select(SecurityEvent.session_id).where(SecurityEvent.id.in_(ids))
            )).all()
            session_ids.update(r[0] for r in rows if r[0])
        if session_ids:
            clauses.append(ResponseLog.session_id.in_(list(session_ids)))
        if not clauses:
            return None
        from sqlalchemy import or_
        return or_(*clauses)

    async def has_pending_approval(self, session: AsyncSession, case: SecurityCase) -> bool:
        from models import ResponseLog
        scope = await self._case_log_scope(session, case)
        if scope is None:
            return False
        row = (await session.execute(
            select(ResponseLog.id).where(
                scope,
                ResponseLog.approval_status == "pending",
            ).limit(1)
        )).scalar_one_or_none()
        return row is not None

    async def has_auto_response(self, session: AsyncSession, case: SecurityCase) -> bool:
        from models import ResponseLog
        from sqlalchemy import or_, and_
        scope = await self._case_log_scope(session, case)
        if scope is None:
            return False
        named = and_(
            scope,
            ResponseLog.action_name.in_(list(AUTO_RESPONSE_ACTIONS)),
            ResponseLog.action_success == True,  # noqa: E712
        )
        matched = and_(
            scope,
            ResponseLog.action_name == "policy_match",
            ResponseLog.auto_execute == True,  # noqa: E712
            ResponseLog.approval_status.in_(["approved", "auto_approved", "auto_executed", ""]),
        )
        row = (await session.execute(
            select(ResponseLog.id).where(or_(named, matched)).limit(1)
        )).scalar_one_or_none()
        return row is not None

    async def try_auto_resolve(
        self,
        session: AsyncSession,
        case: SecurityCase,
        *,
        now: Optional[datetime] = None,
        idle_minutes: Optional[int] = None,
    ) -> dict:
        """自动响应已落地、无待审批、空闲超过阈值 → 完成工单并 resolved。"""
        now = now or datetime.now(timezone.utc)
        if idle_minutes is None:
            try:
                from config import settings
                idle_minutes = int(getattr(settings, "case_auto_resolve_idle_minutes", DEFAULT_AUTO_RESOLVE_IDLE_MINUTES))
            except Exception:
                idle_minutes = DEFAULT_AUTO_RESOLVE_IDLE_MINUTES
        if idle_minutes < 0:
            return {"resolved": False, "reason": "disabled"}
        if case.status not in ACTIVE_CASE_STATUSES:
            return {"resolved": False, "reason": f"status={case.status}"}
        has_resp = await self.has_auto_response(session, case)
        has_pend = await self.has_pending_approval(session, case)
        deadline = _aware(case.sla_deadline)
        stale = bool(deadline and deadline < now)
        if has_pend and not has_resp and not stale:
            return {"resolved": False, "reason": "pending_approval"}
        if not has_resp and not stale:
            return {"resolved": False, "reason": "no_auto_response"}
        updated = _aware(case.updated_at) or _aware(case.created_at)
        if has_resp and not stale:
            if idle_minutes > 0 and updated and updated > now - timedelta(minutes=idle_minutes):
                return {"resolved": False, "reason": "not_idle"}

        from models import WorkOrder
        from work_order_service import work_order_service
        orders = (await session.execute(
            select(WorkOrder).where(
                WorkOrder.case_id == case.id,
                WorkOrder.order_type == "disposition",
                WorkOrder.status.in_(["pending", "assigned", "in_progress"]),
            )
        )).scalars().all()
        for order in orders:
            await work_order_service.update_status(session, order.id, "completed")

        case = await session.get(SecurityCase, case.id)
        if case and case.status != "resolved":
            if case.status == "open":
                await self.update_status(session, case.id, "investigating", by="system")
            case = await session.get(SecurityCase, case.id)
            if case and case.status in ("investigating", "responding"):
                result = await self.update_status(session, case.id, "resolved", by="system")
                if not result.get("success"):
                    return {"resolved": False, "reason": result.get("error", "transition_failed")}
        logger.info(f"[Case] Auto-resolved {case.case_number if case else '?'} after auto-response")
        return {"resolved": True, "case_id": case.id if case else 0}

    async def auto_resolve_idle_cases(
        self, session: AsyncSession, *, now: Optional[datetime] = None
    ) -> int:
        """扫描可收口的活跃案例，返回成功 resolved 数量。"""
        now = now or datetime.now(timezone.utc)
        rows = (await session.execute(
            select(SecurityCase).where(SecurityCase.status.in_(list(ACTIVE_CASE_STATUSES)))
        )).scalars().all()
        n = 0
        for case in rows:
            try:
                result = await self.try_auto_resolve(session, case, now=now)
                if result.get("resolved"):
                    n += 1
            except Exception as e:
                logger.warning(f"[Case] auto-resolve {getattr(case, 'case_number', '?')} failed: {e}")
        if n:
            logger.info(f"[Case] Auto-resolved {n} idle responded cases")
        return n

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
            "sla_breached": bool(case.sla_breached),
            "disposition": case.disposition,
            "disposition_by": case.disposition_by,
            "tags": case.tags or [],
            "created_at": case.created_at.isoformat() if case.created_at else "",
            "updated_at": case.updated_at.isoformat() if case.updated_at else "",
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        }


case_manager = CaseManager()
