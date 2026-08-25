"""
复盘服务 (Post-Mortem Service)

案例关闭后的结构化复盘流程。
支持从案例数据自动生成复盘草稿（timeline + 误报统计 + LLM 根因分析）。

状态: draft → reviewed → published

调用方式:
    from post_mortem_service import post_mortem_service
    pm = await post_mortem_service.create_post_mortem(session, case_id=1)
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    PostMortem, SecurityCase, SecurityEvent, ResponseLog, FeedbackRecord,
)

logger = logging.getLogger(__name__)


class PostMortemService:
    """复盘服务"""

    async def create_post_mortem(
        self, session: AsyncSession, case_id: int, author: str = ""
    ) -> dict:
        """
        创建复盘报告（自动生成草稿）

        自动填充:
          - timeline: 从事件 + 响应日志提取
          - false_positive_count: 从反馈记录统计
          - root_cause + lessons_learned: LLM 生成（可选）
        """
        # 检查是否已存在
        existing = await session.execute(
            select(PostMortem).where(PostMortem.case_id == case_id)
        )
        if existing.scalars().first():
            return {"success": False, "error": "该案例已有复盘报告"}

        case = await session.get(SecurityCase, case_id)
        if not case:
            return {"success": False, "error": "案例不存在"}

        # 构建 timeline
        timeline = await self._build_timeline(session, case)

        # 统计误报
        fp_count = await self._count_false_positives(session, case)

        pm = PostMortem(
            case_id=case_id,
            title=f"复盘: {case.title}",
            summary=f"案例 {case.case_number} 复盘报告（自动生成草稿）",
            timeline=timeline,
            false_positive_count=fp_count,
            author=author,
            status="draft",
        )
        session.add(pm)
        await session.commit()

        # 尝试 LLM 生成根因分析
        try:
            analysis = await self._llm_analyze(case, timeline, fp_count)
            pm.root_cause = analysis.get("root_cause", "")
            pm.impact_assessment = analysis.get("impact", "")
            pm.lessons_learned = analysis.get("lessons", [])
            pm.detection_gaps = analysis.get("gaps", "")
            pm.rule_improvements = analysis.get("rule_improvements", [])
            await session.commit()
        except Exception as e:
            logger.warning(f"[PostMortem] LLM analysis failed: {e}")

        logger.info(f"[PostMortem] Created for case {case.case_number}")
        return {"success": True, "id": pm.id, "case_number": case.case_number}

    async def get_post_mortem(
        self, session: AsyncSession, case_id: int
    ) -> Optional[dict]:
        result = await session.execute(
            select(PostMortem).where(PostMortem.case_id == case_id)
        )
        pm = result.scalars().first()
        if not pm:
            return None
        return self._pm_to_dict(pm)

    async def update_post_mortem(
        self, session: AsyncSession, case_id: int, updates: dict
    ) -> dict:
        result = await session.execute(
            select(PostMortem).where(PostMortem.case_id == case_id)
        )
        pm = result.scalars().first()
        if not pm:
            return {"success": False, "error": "复盘报告不存在"}

        allowed_fields = [
            "title", "summary", "root_cause", "impact_assessment",
            "lessons_learned", "action_items", "detection_gaps",
            "rule_improvements", "reviewer",
        ]
        for field_name in allowed_fields:
            if field_name in updates:
                setattr(pm, field_name, updates[field_name])

        pm.updated_at = datetime.now(timezone.utc)
        await session.commit()
        return {"success": True}

    async def publish(
        self, session: AsyncSession, case_id: int, reviewer: str = ""
    ) -> dict:
        result = await session.execute(
            select(PostMortem).where(PostMortem.case_id == case_id)
        )
        pm = result.scalars().first()
        if not pm:
            return {"success": False, "error": "复盘报告不存在"}

        pm.status = "published"
        pm.reviewer = reviewer
        pm.updated_at = datetime.now(timezone.utc)
        await session.commit()

        # 将规则改进建议写入反馈系统
        if pm.rule_improvements:
            try:
                from feedback_loop import feedback_loop
                for imp in pm.rule_improvements:
                    if isinstance(imp, dict):
                        await feedback_loop.submit_feedback(
                            session,
                            case_id=case_id,
                            feedback_type="rule_suggestion",
                            rule_id=imp.get("rule_id", ""),
                            rule_suggestion=imp.get("suggestion", str(imp)),
                            submitted_by=reviewer or pm.author,
                        )
            except Exception as e:
                logger.warning(f"[PostMortem] Failed to export rule improvements: {e}")

        logger.info(f"[PostMortem] Published for case_id={case_id}")
        return {"success": True, "status": "published"}

    # ── 内部方法 ──

    async def _build_timeline(
        self, session: AsyncSession, case: SecurityCase
    ) -> list[dict]:
        timeline = []
        for eid in (case.event_ids or []):
            evt = await session.get(SecurityEvent, eid)
            if evt:
                timeline.append({
                    "time": evt.created_at.isoformat() if evt.created_at else "",
                    "event": f"告警: {evt.event_type}",
                    "detail": f"[{evt.severity}] {evt.src_ip} → {evt.dst_ip}: {(evt.message or '')[:100]}",
                })

        try:
            stmt = (
                select(ResponseLog)
                .where(ResponseLog.event_id.in_(case.event_ids or []))
                .order_by(ResponseLog.created_at)
            )
            result = await session.execute(stmt)
            for log in result.scalars().all():
                timeline.append({
                    "time": log.created_at.isoformat() if log.created_at else "",
                    "event": f"响应: {log.action_name}",
                    "detail": f"策略={log.policy_name} 成功={log.action_success}",
                })
        except Exception:
            pass

        timeline.sort(key=lambda x: x.get("time", ""))
        return timeline

    async def _count_false_positives(
        self, session: AsyncSession, case: SecurityCase
    ) -> int:
        try:
            from sqlalchemy import func
            stmt = (
                select(func.count(FeedbackRecord.id))
                .where(
                    FeedbackRecord.case_id == case.id,
                    FeedbackRecord.feedback_type == "false_positive",
                )
            )
            result = await session.execute(stmt)
            return result.scalar() or 0
        except Exception:
            return 0

    async def _llm_analyze(
        self, case: SecurityCase, timeline: list[dict], fp_count: int
    ) -> dict:
        from summary_compression import summary
        from trace_hook import set_trace_context

        timeline_text = "\n".join(
            f"  {t['time'][:19]} | {t['event']} | {t['detail'][:80]}"
            for t in timeline[:20]
        )

        from prompts import render
        prompt = render("tooling/post_mortem_review",
                        case_number=case.case_number,
                        title=case.title,
                        threat_type=case.threat_type,
                        severity=case.severity,
                        event_count=case.event_count,
                        src_ips=case.src_ips,
                        disposition=case.disposition,
                        fp_count=fp_count,
                        timeline_text=timeline_text)

        set_trace_context(operation="post_mortem", caller="post_mortem_service")
        result = await summary.llm.chat([
            {"role": "system", "content": render("tooling/post_mortem_review_system")},
            {"role": "user", "content": prompt},
        ])

        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"root_cause": result[:300], "impact": "", "lessons": [], "gaps": "", "rule_improvements": []}

    @staticmethod
    def _pm_to_dict(pm: PostMortem) -> dict:
        return {
            "id": pm.id,
            "case_id": pm.case_id,
            "title": pm.title,
            "summary": pm.summary,
            "timeline": pm.timeline or [],
            "root_cause": pm.root_cause,
            "impact_assessment": pm.impact_assessment,
            "lessons_learned": pm.lessons_learned or [],
            "action_items": pm.action_items or [],
            "false_positive_count": pm.false_positive_count,
            "detection_gaps": pm.detection_gaps,
            "rule_improvements": pm.rule_improvements or [],
            "author": pm.author,
            "reviewer": pm.reviewer,
            "status": pm.status,
            "created_at": pm.created_at.isoformat() if pm.created_at else "",
            "updated_at": pm.updated_at.isoformat() if pm.updated_at else "",
        }


post_mortem_service = PostMortemService()
