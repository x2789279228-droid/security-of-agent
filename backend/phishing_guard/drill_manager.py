"""钓鱼演练管理器 — 演练活动全生命周期管理

功能:
  - 创建 / 列表 / 详情 / 删除演练
  - 发起演练（批量生成目标记录）
  - 记录目标事件（sent / opened / clicked / reported）
  - 演练统计（点击率 / 上报率 / 完成率）
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from models import PhishingDrill, PhishingDrillRecord

logger = logging.getLogger(__name__)


class DrillManager:
    """钓鱼演练管理器"""

    async def create_drill(
        self, session: AsyncSession,
        name: str, drill_type: str = "email",
        template_subject: str = "", template_body: str = "",
    ) -> dict:
        drill = PhishingDrill(
            name=name,
            drill_type=drill_type,
            template_subject=template_subject,
            template_body=template_body,
            status="draft",
        )
        session.add(drill)
        await session.commit()
        await session.refresh(drill)
        return self._drill_dict(drill)

    async def list_drills(
        self, session: AsyncSession,
        status: str = "", limit: int = 50,
    ) -> list[dict]:
        stmt = select(PhishingDrill).order_by(PhishingDrill.created_at.desc())
        if status:
            stmt = stmt.where(PhishingDrill.status == status)
        stmt = stmt.limit(limit)
        result = await session.execute(stmt)
        return [self._drill_dict(d) for d in result.scalars().all()]

    async def get_drill(self, session: AsyncSession, drill_id: int) -> dict | None:
        drill = await session.get(PhishingDrill, drill_id)
        if not drill:
            return None
        d = self._drill_dict(drill)
        d["stats"] = await self.drill_stats(session, drill_id)
        return d

    async def delete_drill(self, session: AsyncSession, drill_id: int) -> bool:
        drill = await session.get(PhishingDrill, drill_id)
        if not drill:
            return False
        await session.execute(
            delete(PhishingDrillRecord).where(PhishingDrillRecord.drill_id == drill_id)
        )
        await session.delete(drill)
        await session.commit()
        return True

    async def launch_drill(
        self, session: AsyncSession,
        drill_id: int, targets: list[str],
    ) -> dict | None:
        drill = await session.get(PhishingDrill, drill_id)
        if not drill:
            return None
        if drill.status == "running":
            return {"error": "演练已在运行中"}

        now = datetime.now(timezone.utc)
        for t in targets:
            record = PhishingDrillRecord(
                drill_id=drill_id,
                target_identifier=t.strip(),
                sent_at=now,
                verdict="sent",
            )
            session.add(record)

        drill.status = "running"
        drill.target_count = len(targets)
        drill.sent_count = len(targets)
        drill.start_time = now
        await session.commit()
        await session.refresh(drill)
        return self._drill_dict(drill)

    async def record_event(
        self, session: AsyncSession,
        drill_id: int, target_identifier: str, event_type: str,
    ) -> dict | None:
        """记录目标事件: opened / clicked / reported"""
        stmt = (
            select(PhishingDrillRecord)
            .where(
                PhishingDrillRecord.drill_id == drill_id,
                PhishingDrillRecord.target_identifier == target_identifier,
            )
            .order_by(PhishingDrillRecord.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        record = result.scalars().first()
        if not record:
            return None

        now = datetime.now(timezone.utc)
        if event_type == "opened":
            record.opened_at = now
            if record.verdict == "sent":
                record.verdict = "opened"
        elif event_type == "clicked":
            record.clicked_at = now
            record.verdict = "clicked"
        elif event_type == "reported":
            record.reported_at = now
            record.verdict = "reported"

        # 更新演练聚合计数
        drill = await session.get(PhishingDrill, drill_id)
        if drill:
            drill.opened_count = (await session.execute(
                select(func.count(PhishingDrillRecord.id)).where(
                    PhishingDrillRecord.drill_id == drill_id,
                    PhishingDrillRecord.opened_at.isnot(None),
                )
            )).scalar() or 0
            drill.clicked_count = (await session.execute(
                select(func.count(PhishingDrillRecord.id)).where(
                    PhishingDrillRecord.drill_id == drill_id,
                    PhishingDrillRecord.clicked_at.isnot(None),
                )
            )).scalar() or 0
            drill.reported_count = (await session.execute(
                select(func.count(PhishingDrillRecord.id)).where(
                    PhishingDrillRecord.drill_id == drill_id,
                    PhishingDrillRecord.reported_at.isnot(None),
                )
            )).scalar() or 0

        await session.commit()
        return {
            "drill_id": drill_id,
            "target": target_identifier,
            "event": event_type,
            "verdict": record.verdict,
        }

    async def drill_stats(self, session: AsyncSession, drill_id: int) -> dict:
        total = (await session.execute(
            select(func.count(PhishingDrillRecord.id)).where(
                PhishingDrillRecord.drill_id == drill_id
            )
        )).scalar() or 0
        sent = (await session.execute(
            select(func.count(PhishingDrillRecord.id)).where(
                PhishingDrillRecord.drill_id == drill_id,
                PhishingDrillRecord.sent_at.isnot(None),
            )
        )).scalar() or 0
        opened = (await session.execute(
            select(func.count(PhishingDrillRecord.id)).where(
                PhishingDrillRecord.drill_id == drill_id,
                PhishingDrillRecord.opened_at.isnot(None),
            )
        )).scalar() or 0
        clicked = (await session.execute(
            select(func.count(PhishingDrillRecord.id)).where(
                PhishingDrillRecord.drill_id == drill_id,
                PhishingDrillRecord.clicked_at.isnot(None),
            )
        )).scalar() or 0
        reported = (await session.execute(
            select(func.count(PhishingDrillRecord.id)).where(
                PhishingDrillRecord.drill_id == drill_id,
                PhishingDrillRecord.reported_at.isnot(None),
            )
        )).scalar() or 0

        open_rate = round(opened / sent * 100, 1) if sent else 0
        click_rate = round(clicked / sent * 100, 1) if sent else 0
        report_rate = round(reported / sent * 100, 1) if sent else 0

        return {
            "total": total,
            "sent": sent,
            "opened": opened,
            "clicked": clicked,
            "reported": reported,
            "open_rate": open_rate,
            "click_rate": click_rate,
            "report_rate": report_rate,
        }

    @staticmethod
    def _drill_dict(d: PhishingDrill) -> dict:
        return {
            "id": d.id,
            "name": d.name,
            "drill_type": d.drill_type,
            "template_subject": d.template_subject,
            "template_body": d.template_body[:200] if d.template_body else "",
            "target_count": d.target_count,
            "status": d.status,
            "sent_count": d.sent_count,
            "opened_count": d.opened_count,
            "clicked_count": d.clicked_count,
            "reported_count": d.reported_count,
            "start_time": d.start_time.isoformat() if d.start_time else None,
            "end_time": d.end_time.isoformat() if d.end_time else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        }


drill_manager = DrillManager()
