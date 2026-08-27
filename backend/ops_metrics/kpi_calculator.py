"""
KPI 计算器 (KPI Calculator) — P0.B 核心

从 security_cases / work_orders / feedback_records 聚合：
  - MTTD: case.created_at → status 首次进入 investigating 的 updated_at
  - MTTR: case.created_at → closed_at
  - case_count: 案例计数 (按 priority / threat_type 切分)
  - sla_breach_rate: 工单 SLA breach 比例
  - fp_rate: feedback_records 中 false_positive 占比 (平台级聚合)
  - case_cycle: 各状态停留时长分布 (近似: created→closed 平均)

快照粒度: daily | weekly
存储: kpi_snapshots 表 (UNIQUE on (date, period, metric_key, dimensions))
"""
import json
import logging
from datetime import date, datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    SecurityCase, WorkOrder, FeedbackRecord, KpiSnapshot,
)

logger = logging.getLogger(__name__)


METRIC_KEYS = [
    "mttd",               # 平均检测时间（小时）
    "mttr",               # 平均响应/恢复时间（小时）
    "case_count",         # 案例总数
    "case_cycle_hours",   # 案例 created→closed 平均时长
    "sla_breach_rate",    # 工单 SLA 违约率
    "case_sla_breach_rate", # 案例 SLA 违约率
    "fp_rate",            # 误报率（平台级）
    "feedback_count",     # 反馈总数
    "order_count",        # 工单总数
    "automation_rate",    # 自动化处置率（无需人工干预的处置比例）
    "grounding_pass_rate", # Grounding 验证通过率
]


class KpiCalculator:
    """KPI 聚合计算 + 快照写入"""

    # ── 指标计算 ──

    async def compute_mttr(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
        priority: str = "",
    ) -> Optional[float]:
        """
        平均响应时间（小时）= avg(closed_at - created_at)
        跨方言实现：先在 ORM 取出 closed/created，再在 Python 端聚合，
        避免依赖 PG 专属的 EXTRACT(EPOCH FROM ...) 语法。
        """
        conditions = [
            SecurityCase.created_at >= start,
            SecurityCase.created_at < end,
            SecurityCase.closed_at.is_not(None),
            SecurityCase.status == "closed",
        ]
        if priority:
            conditions.append(SecurityCase.priority == priority)
        stmt = select(SecurityCase.created_at, SecurityCase.closed_at).where(and_(*conditions))
        result = await session.execute(stmt)
        rows = result.all()
        if not rows:
            return 0.0
        total_hours = 0.0
        for created_at, closed_at in rows:
            if created_at and closed_at:
                delta = (closed_at - created_at).total_seconds() / 3600.0
                if delta >= 0:
                    total_hours += delta
        return round(total_hours / len(rows), 4) if rows else 0.0

    async def compute_mttd(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
        priority: str = "",
    ) -> Optional[float]:
        """
        平均检测时间（小时）= avg(first investigating - created_at)
        近似实现：用 updated_at - created_at 作为首次进入 investigating 的时间代理
        （audit_trail 已有精确版本，可后续升级为读 audit_trail.case.transition）
        跨方言实现：取出后 Python 端聚合。
        """
        conditions = [
            SecurityCase.created_at >= start,
            SecurityCase.created_at < end,
            SecurityCase.status.in_(
                ["investigating", "responding", "resolved", "closed",
                 "pending_approval", "false_positive"]
            ),
        ]
        if priority:
            conditions.append(SecurityCase.priority == priority)
        stmt = select(SecurityCase.created_at, SecurityCase.updated_at).where(and_(*conditions))
        result = await session.execute(stmt)
        rows = result.all()
        if not rows:
            return 0.0
        total_hours = 0.0
        for created_at, updated_at in rows:
            if created_at and updated_at:
                delta = (updated_at - created_at).total_seconds() / 3600.0
                if delta >= 0:
                    total_hours += delta
        return round(total_hours / len(rows), 4) if rows else 0.0

    async def compute_case_count(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
        priority: str = "", threat_type: str = "",
    ) -> int:
        conditions = [
            SecurityCase.created_at >= start,
            SecurityCase.created_at < end,
        ]
        if priority:
            conditions.append(SecurityCase.priority == priority)
        if threat_type:
            conditions.append(SecurityCase.threat_type == threat_type)
        stmt = select(func.count(SecurityCase.id)).where(and_(*conditions))
        result = await session.execute(stmt)
        return int(result.scalar() or 0)

    async def compute_case_cycle_hours(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
    ) -> Optional[float]:
        """case created→closed 平均时长（小时），仅看已关闭案例。跨方言实现。"""
        conditions = [
            SecurityCase.created_at >= start,
            SecurityCase.created_at < end,
            SecurityCase.closed_at.is_not(None),
        ]
        stmt = select(SecurityCase.created_at, SecurityCase.closed_at).where(and_(*conditions))
        result = await session.execute(stmt)
        rows = result.all()
        if not rows:
            return 0.0
        total_hours = 0.0
        for created_at, closed_at in rows:
            if created_at and closed_at:
                delta = (closed_at - created_at).total_seconds() / 3600.0
                if delta >= 0:
                    total_hours += delta
        return round(total_hours / len(rows), 4) if rows else 0.0

    async def compute_sla_breach_rate(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
        priority: str = "",
    ) -> float:
        """工单 SLA 违约率 = breached / (breached + completed_in_time)"""
        conditions = [
            WorkOrder.created_at >= start,
            WorkOrder.created_at < end,
        ]
        if priority:
            conditions.append(WorkOrder.priority == priority)
        total_stmt = select(func.count(WorkOrder.id)).where(and_(*conditions))
        breached_stmt = (
            select(func.count(WorkOrder.id))
            .where(and_(*conditions, WorkOrder.sla_breached == True))
        )
        total = (await session.execute(total_stmt)).scalar() or 0
        breached = (await session.execute(breached_stmt)).scalar() or 0
        if total == 0:
            return 0.0
        return round(breached / total, 4)

    async def compute_case_sla_breach_rate(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
        priority: str = "",
    ) -> float:
        """案例 SLA 违约率 = case.sla_breached / 期间新建 case"""
        conditions = [
            SecurityCase.created_at >= start,
            SecurityCase.created_at < end,
        ]
        if priority:
            conditions.append(SecurityCase.priority == priority)
        total_stmt = select(func.count(SecurityCase.id)).where(and_(*conditions))
        breached_stmt = (
            select(func.count(SecurityCase.id))
            .where(and_(*conditions, SecurityCase.sla_breached == True))
        )
        total = (await session.execute(total_stmt)).scalar() or 0
        breached = (await session.execute(breached_stmt)).scalar() or 0
        if total == 0:
            return 0.0
        return round(breached / total, 4)

    async def compute_fp_rate(
        self, session: AsyncSession, *,
        start: datetime, end: datetime,
    ) -> float:
        """平台级误报率 = false_positive / (false_positive + true_positive)"""
        conditions = [FeedbackRecord.created_at >= start, FeedbackRecord.created_at < end]
        total_stmt = (
            select(func.count(FeedbackRecord.id))
            .where(and_(*conditions, FeedbackRecord.feedback_type.in_(
                ["false_positive", "true_positive"]
            )))
        )
        fp_stmt = (
            select(func.count(FeedbackRecord.id))
            .where(and_(*conditions, FeedbackRecord.feedback_type == "false_positive"))
        )
        total = (await session.execute(total_stmt)).scalar() or 0
        fp = (await session.execute(fp_stmt)).scalar() or 0
        if total == 0:
            return 0.0
        return round(fp / total, 4)

    async def compute_feedback_count(
        self, session: AsyncSession, *, start: datetime, end: datetime,
    ) -> int:
        stmt = (
            select(func.count(FeedbackRecord.id))
            .where(FeedbackRecord.created_at >= start, FeedbackRecord.created_at < end)
        )
        return int((await session.execute(stmt)).scalar() or 0)

    async def compute_order_count(
        self, session: AsyncSession, *, start: datetime, end: datetime,
    ) -> int:
        stmt = (
            select(func.count(WorkOrder.id))
            .where(WorkOrder.created_at >= start, WorkOrder.created_at < end)
        )
        return int((await session.execute(stmt)).scalar() or 0)

    async def compute_automation_rate(
        self, session: AsyncSession, *, start: datetime, end: datetime,
    ) -> float:
        """
        自动化处置率 = 无需人工审批的响应动作数 / 总响应动作数
        从 response_logs 表统计 auto_execute=True 且 action_success=True 的比例
        """
        from models import ResponseLog
        total_stmt = select(func.count(ResponseLog.id)).where(
            ResponseLog.created_at >= start, ResponseLog.created_at < end
        )
        auto_stmt = select(func.count(ResponseLog.id)).where(
            ResponseLog.created_at >= start, ResponseLog.created_at < end,
            ResponseLog.auto_execute == True,
            ResponseLog.action_success == True,
        )
        total = (await session.execute(total_stmt)).scalar() or 0
        auto = (await session.execute(auto_stmt)).scalar() or 0
        if total == 0:
            return 0.0
        return round(auto / total, 4)

    async def compute_grounding_pass_rate(
        self, session: AsyncSession, *, start: datetime, end: datetime,
    ) -> float:
        """
        Grounding 验证通过率 = grounding_score >= 0.6 的事件数 / 已审计事件数
        从 security_events 的 raw_data._audit_llm.grounding_score 统计
        """
        from models import SecurityEvent
        analyzed_stmt = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.created_at >= start, SecurityEvent.created_at < end,
            SecurityEvent.analyzed == True,
        )
        total_analyzed = (await session.execute(analyzed_stmt)).scalar() or 0
        if total_analyzed == 0:
            return 0.0
        # 取 raw_data 中 grounding_score >= 0.6 的事件
        events_stmt = select(SecurityEvent.raw_data).where(
            SecurityEvent.created_at >= start, SecurityEvent.created_at < end,
            SecurityEvent.analyzed == True,
        )
        events = (await session.execute(events_stmt)).scalars().all()
        passed = 0
        for raw in events:
            if not raw:
                continue
            score = raw.get("_audit_llm", {}).get("grounding_score", 0)
            if isinstance(score, (int, float)) and score >= 0.6:
                passed += 1
        return round(passed / total_analyzed, 4)

    # ── 快照写入 ──

    async def snapshot_daily(
        self, session: AsyncSession, snapshot_date: Optional[date] = None,
    ) -> dict:
        """
        生成日快照（覆盖前一天的数据）
        - snapshot_date=None → 用 yesterday
        """
        if snapshot_date is None:
            snapshot_date = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        start = datetime.combine(snapshot_date, datetime.min.time(), tzinfo=timezone.utc)
        end = start + timedelta(days=1)

        return await self._snapshot(session, snapshot_date, "daily", start, end)

    async def snapshot_weekly(
        self, session: AsyncSession, snapshot_date: Optional[date] = None,
    ) -> dict:
        """生成周快照（snapshot_date 所在周的前 7 天数据）"""
        if snapshot_date is None:
            snapshot_date = (datetime.now(timezone.utc) - timedelta(days=7)).date()
        end = datetime.combine(snapshot_date + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
        start = end - timedelta(days=7)
        return await self._snapshot(session, snapshot_date, "weekly", start, end)

    async def _snapshot(
        self, session: AsyncSession, snapshot_date: date, period: str,
        start: datetime, end: datetime,
    ) -> dict:
        """计算全套指标 + 写入 kpi_snapshots 表（upsert）"""
        # 平台级聚合（无切分）
        mttr = await self.compute_mttr(session, start=start, end=end)
        mttd = await self.compute_mttd(session, start=start, end=end)
        case_count = await self.compute_case_count(session, start=start, end=end)
        case_cycle = await self.compute_case_cycle_hours(session, start=start, end=end)
        sla_breach_rate = await self.compute_sla_breach_rate(session, start=start, end=end)
        case_sla_breach_rate = await self.compute_case_sla_breach_rate(session, start=start, end=end)
        fp_rate = await self.compute_fp_rate(session, start=start, end=end)
        feedback_count = await self.compute_feedback_count(session, start=start, end=end)
        order_count = await self.compute_order_count(session, start=start, end=end)
        automation_rate = await self.compute_automation_rate(session, start=start, end=end)
        grounding_pass_rate = await self.compute_grounding_pass_rate(session, start=start, end=end)

        agg_metrics: list[tuple[str, float, dict]] = [
            ("mttd", float(mttd or 0), {}),
            ("mttr", float(mttr or 0), {}),
            ("case_count", float(case_count), {}),
            ("case_cycle_hours", float(case_cycle or 0), {}),
            ("sla_breach_rate", float(sla_breach_rate), {}),
            ("case_sla_breach_rate", float(case_sla_breach_rate), {}),
            ("fp_rate", float(fp_rate), {}),
            ("feedback_count", float(feedback_count), {}),
            ("order_count", float(order_count), {}),
            ("automation_rate", float(automation_rate), {}),
            ("grounding_pass_rate", float(grounding_pass_rate), {}),
        ]

        # 按 priority 切分（critical / high / medium / low）
        for prio in ("critical", "high", "medium", "low"):
            agg_metrics.append((
                "case_count",
                float(await self.compute_case_count(
                    session, start=start, end=end, priority=prio
                )),
                {"priority": prio},
            ))
            mttr_p = await self.compute_mttr(
                session, start=start, end=end, priority=prio
            )
            agg_metrics.append((
                "mttr", float(mttr_p or 0), {"priority": prio}
            ))
            sla_p = await self.compute_sla_breach_rate(
                session, start=start, end=end, priority=prio
            )
            agg_metrics.append((
                "sla_breach_rate", float(sla_p), {"priority": prio}
            ))

        # 写入 kpi_snapshots (UNIQUE upsert)
        written = 0
        for metric_key, value, dims in agg_metrics:
            try:
                await self._upsert_snapshot(
                    session, snapshot_date, period, metric_key, value, dims
                )
                written += 1
            except Exception as e:
                logger.warning(
                    f"[KPI] upsert failed: {metric_key}/{dims}: {e}"
                )

        await session.commit()
        logger.info(f"[KPI] snapshot {snapshot_date} ({period}): {written} metrics written")
        return {
            "date": snapshot_date.isoformat(), "period": period,
            "metrics_written": written,
            "summary": {
                "mttd_hours": float(mttd or 0),
                "mttr_hours": float(mttr or 0),
                "case_count": case_count,
                "sla_breach_rate": sla_breach_rate,
                "fp_rate": fp_rate,
                "automation_rate": automation_rate,
                "grounding_pass_rate": grounding_pass_rate,
            },
        }

    async def _upsert_snapshot(
        self, session: AsyncSession, snapshot_date: date, period: str,
        metric_key: str, value: float, dims: dict,
    ):
        """
        upsert 到 kpi_snapshots (替 PG ON CONFLICT 通用为 ORM 先查后插/更新)
        UNIQUE on (snapshot_date, period, metric_key, dimensions)
        """
        existing_stmt = (
            select(KpiSnapshot)
            .where(
                KpiSnapshot.snapshot_date == snapshot_date,
                KpiSnapshot.period == period,
                KpiSnapshot.metric_key == metric_key,
            )
        )
        result = await session.execute(existing_stmt)
        # 进一步按 dimensions 字段精确匹配（JSON 列等值比较方言差异大，先过滤后 Python 判定）
        target = None
        for r in result.scalars().all():
            if (r.dimensions or {}) == (dims or {}):
                target = r
                break

        if target:
            target.metric_value = float(value)
            from datetime import datetime, timezone
            target.created_at = datetime.now(timezone.utc)
        else:
            session.add(KpiSnapshot(
                snapshot_date=snapshot_date, period=period, metric_key=metric_key,
                metric_value=float(value), dimensions=dims or {},
            ))

    # ── 查询 ──

    async def get_kpi(
        self, session: AsyncSession, *,
        metric_key: str, period: str = "daily",
        days: int = 30,
        dimensions: Optional[dict] = None,
    ) -> list[dict]:
        """按指标 key 查询最近 N 天快照"""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()
        stmt = (
            select(KpiSnapshot)
            .where(
                KpiSnapshot.metric_key == metric_key,
                KpiSnapshot.period == period,
                KpiSnapshot.snapshot_date >= cutoff,
            )
            .order_by(KpiSnapshot.snapshot_date)
            .limit(days + 5)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

        # 可选: 按 dimensions 过滤
        out = []
        for r in rows:
            if dimensions and (r.dimensions or {}) != dimensions:
                continue
            out.append({
                "date": r.snapshot_date.isoformat() if r.snapshot_date else "",
                "metric_key": r.metric_key,
                "metric_value": r.metric_value,
                "dimensions": r.dimensions or {},
                "created_at": r.created_at.isoformat() if r.created_at else "",
            })
        return out

    async def dashboard(
        self, session: AsyncSession, days: int = 30,
    ) -> dict:
        """
        返回运营仪表盘数据 (供前端 KPI tab 直接消费)
        - 各指标 30 天时间序列 (按天聚合)
        - 关键指标优先级切分
        """
        out: dict = {}
        for key in METRIC_KEYS:
            out[key] = await self.get_kpi(
                session, metric_key=key, period="daily", days=days
            )
        # priority 切分聚合放在 case_count_priority 字段
        out["case_count_priority"] = {}
        for prio in ("critical", "high", "medium", "low"):
            out["case_count_priority"][prio] = await self.get_kpi(
                session, metric_key="case_count", period="daily", days=days,
                dimensions={"priority": prio},
            )
        out["mttr_priority"] = {}
        for prio in ("critical", "high", "medium", "low"):
            out["mttr_priority"][prio] = await self.get_kpi(
                session, metric_key="mttr", period="daily", days=days,
                dimensions={"priority": prio},
            )
        out["sla_breach_rate_priority"] = {}
        for prio in ("critical", "high", "medium", "low"):
            out["sla_breach_rate_priority"][prio] = await self.get_kpi(
                session, metric_key="sla_breach_rate", period="daily", days=days,
                dimensions={"priority": prio},
            )
        return out


kpi_calculator = KpiCalculator()