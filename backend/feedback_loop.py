"""
误报反馈 + 调优闭环 (Feedback Loop)

运营人员对检测结论的纠正 → 误报率统计 → 规则调优建议。

闭环:
  提交反馈 → 统计 FP 率 → 生成调优建议 → 应用到规则 → 验证效果

调用方式:
    from feedback_loop import feedback_loop
    await feedback_loop.submit_feedback(session, event_id=1, ...)
    stats = await feedback_loop.get_fp_statistics(session)
    suggestions = await feedback_loop.generate_tuning_suggestions(session)
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import FeedbackRecord, SecurityEvent, SecurityCase

logger = logging.getLogger(__name__)

FEEDBACK_TYPES = ["false_positive", "true_positive", "missed_threat", "rule_suggestion"]
FEEDBACK_STATUSES = ["submitted", "reviewed", "applied", "dismissed"]

# 调优阈值（PR4: 15% 即降级，禁止自动封禁）
FP_RATE_ALERT_THRESHOLD = 0.15
MISSED_THREAT_THRESHOLD = 3       # 漏报 > 3 次 → 建议新增规则
AUTO_DOWNGRADE_WINDOW_DAYS = 7
AUTO_DOWNGRADE_MIN_SAMPLES = 5


class FeedbackLoop:
    """误报反馈 + 调优闭环"""

    async def submit_feedback(
        self,
        session: AsyncSession,
        event_id: Optional[int] = None,
        case_id: Optional[int] = None,
        feedback_type: str = "false_positive",
        original_conclusion: str = "",
        operator_conclusion: str = "",
        reason: str = "",
        rule_id: str = "",
        rule_suggestion: str = "",
        submitted_by: str = "",
    ) -> FeedbackRecord:
        """提交反馈"""
        record = FeedbackRecord(
            event_id=event_id,
            case_id=case_id,
            feedback_type=feedback_type,
            original_conclusion=original_conclusion,
            operator_conclusion=operator_conclusion,
            reason=reason,
            rule_id=rule_id,
            rule_suggestion=rule_suggestion,
            submitted_by=submitted_by,
            status="submitted",
        )
        session.add(record)

        # 如果是误报，同步更新事件状态
        if feedback_type == "false_positive" and event_id:
            evt = await session.get(SecurityEvent, event_id)
            if evt:
                evt.status = "false_positive"

        await session.commit()
        logger.info(
            f"[Feedback] Submitted: type={feedback_type} event={event_id} "
            f"rule={rule_id} by={submitted_by}"
        )
        if feedback_type == "false_positive" and rule_id:
            try:
                await self.maybe_auto_downgrade(session, rule_id)
            except Exception as e:
                logger.warning(f"[Feedback] auto-downgrade failed for {rule_id}: {e}")
        return record

    async def maybe_auto_downgrade(
        self, session: AsyncSession, rule_id: str, days: int = AUTO_DOWNGRADE_WINDOW_DAYS,
    ) -> dict:
        """同一规则 7 天 FP>15% 且样本足够 → 降级为 alert_only。"""
        if not rule_id:
            return {"downgraded": False, "reason": "empty_rule_id"}
        stats = await self.get_fp_statistics(session, rule_id=rule_id, days=days)
        by_rule = (stats.get("by_rule") or {}).get(rule_id) or {}
        total = int(by_rule.get("total") or 0)
        fp_rate = float(by_rule.get("fp_rate") or 0.0)
        if total < AUTO_DOWNGRADE_MIN_SAMPLES:
            return {"downgraded": False, "reason": "insufficient_samples", "total": total}
        if fp_rate <= FP_RATE_ALERT_THRESHOLD:
            return {"downgraded": False, "reason": "fp_rate_ok", "fp_rate": fp_rate}
        from ops_loop import apply_rule_downgrade
        applied = apply_rule_downgrade(rule_id)
        logger.warning(
            f"[Feedback] AUTO-DOWNGRADE rule={rule_id} fp_rate={fp_rate:.0%} "
            f"n={total} → alert_only {applied}"
        )
        return {"downgraded": True, "fp_rate": fp_rate, "total": total, "applied": applied}

    async def review_feedback(
        self, session: AsyncSession, feedback_id: int,
        new_status: str = "reviewed"
    ) -> dict:
        """审核反馈"""
        record = await session.get(FeedbackRecord, feedback_id)
        if not record:
            return {"success": False, "error": "反馈不存在"}
        # LLM 结论不得自动写回检测规则；applied 必须是运营显式选择
        if new_status == "applied" and (record.original_conclusion or "").startswith("llm:"):
            return {"success": False, "error": "LLM 结论须人工确认后才能写回规则"}
        record.status = new_status
        record.reviewed_at = datetime.now(timezone.utc)
        await session.commit()
        return {"success": True, "status": new_status}

    async def get_fp_statistics(
        self, session: AsyncSession,
        rule_id: str = "", days: int = 30
    ) -> dict:
        """误报率统计"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        conditions = [FeedbackRecord.created_at >= cutoff]
        if rule_id:
            conditions.append(FeedbackRecord.rule_id == rule_id)

        # 按类型统计
        stmt = (
            select(
                FeedbackRecord.feedback_type,
                func.count(FeedbackRecord.id),
            )
            .where(and_(*conditions))
            .group_by(FeedbackRecord.feedback_type)
        )
        result = await session.execute(stmt)
        type_counts = {row[0]: row[1] for row in result.all()}

        total = sum(type_counts.values())
        fp_count = type_counts.get("false_positive", 0)
        tp_count = type_counts.get("true_positive", 0)
        missed_count = type_counts.get("missed_threat", 0)

        # 按规则统计 FP 率
        rule_fp_stmt = (
            select(
                FeedbackRecord.rule_id,
                FeedbackRecord.feedback_type,
                func.count(FeedbackRecord.id),
            )
            .where(and_(*conditions, FeedbackRecord.rule_id != ""))
            .group_by(FeedbackRecord.rule_id, FeedbackRecord.feedback_type)
        )
        rule_result = await session.execute(rule_fp_stmt)
        rule_stats: dict[str, dict] = {}
        for rid, ftype, count in rule_result.all():
            if rid not in rule_stats:
                rule_stats[rid] = {"total": 0, "false_positive": 0, "true_positive": 0}
            rule_stats[rid]["total"] += count
            if ftype in ("false_positive", "true_positive"):
                rule_stats[rid][ftype] += count

        for rid, stats in rule_stats.items():
            stats["fp_rate"] = round(
                stats["false_positive"] / max(stats["total"], 1), 4
            )

        return {
            "period_days": days,
            "total_feedback": total,
            "false_positive": fp_count,
            "true_positive": tp_count,
            "missed_threat": missed_count,
            "rule_suggestion": type_counts.get("rule_suggestion", 0),
            "overall_fp_rate": round(fp_count / max(fp_count + tp_count, 1), 4),
            "by_rule": rule_stats,
        }

    async def generate_tuning_suggestions(
        self, session: AsyncSession, days: int = 30
    ) -> list[dict]:
        """生成规则调优建议"""
        stats = await self.get_fp_statistics(session, days=days)
        suggestions = []

        # 建议 1: FP 率过高的规则
        for rule_id, rule_stats in stats.get("by_rule", {}).items():
            if rule_stats["fp_rate"] > FP_RATE_ALERT_THRESHOLD and rule_stats["total"] >= 3:
                suggestions.append({
                    "type": "high_fp_rate",
                    "rule_id": rule_id,
                    "severity": "high",
                    "fp_rate": rule_stats["fp_rate"],
                    "total_feedback": rule_stats["total"],
                    "suggestion": (
                        f"规则 {rule_id} 误报率 {rule_stats['fp_rate']:.0%} "
                        f"({rule_stats['false_positive']}/{rule_stats['total']})，"
                        f"已触发/应触发 alert_only 降级（禁止自动封禁）"
                    ),
                    "actions": ["alert_only 降级", "提高阈值", "添加白名单排除"],
                })

        # 建议 2: 漏报
        missed = stats.get("missed_threat", 0)
        if missed >= MISSED_THREAT_THRESHOLD:
            # 查询漏报反馈的详情
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            stmt = (
                select(FeedbackRecord)
                .where(
                    FeedbackRecord.feedback_type == "missed_threat",
                    FeedbackRecord.created_at >= cutoff,
                )
                .limit(10)
            )
            result = await session.execute(stmt)
            missed_records = result.scalars().all()

            suggestions.append({
                "type": "missed_threats",
                "severity": "critical",
                "count": missed,
                "suggestion": f"近 {days} 天有 {missed} 次漏报反馈，建议新增或增强检测规则",
                "details": [
                    {"reason": r.reason[:100], "rule_suggestion": r.rule_suggestion[:200]}
                    for r in missed_records if r.reason
                ],
                "actions": ["新增 Sigma 规则", "降低现有规则阈值", "增加异常检测维度"],
            })

        # 建议 3: 用户提交的规则建议
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = (
            select(FeedbackRecord)
            .where(
                FeedbackRecord.feedback_type == "rule_suggestion",
                FeedbackRecord.status == "submitted",
                FeedbackRecord.created_at >= cutoff,
            )
            .limit(5)
        )
        result = await session.execute(stmt)
        for record in result.scalars().all():
            suggestions.append({
                "type": "user_suggestion",
                "severity": "medium",
                "feedback_id": record.id,
                "rule_id": record.rule_id,
                "suggestion": record.rule_suggestion[:300] or record.reason[:300],
                "submitted_by": record.submitted_by,
            })

        # 建议 4: CEP 攻击链模式调优
        cep_suggestions = await self._cep_pattern_suggestions(session, days)
        suggestions.extend(cep_suggestions)

        # 建议 5: 异常检测阈值调优
        threshold_suggestions = await self._anomaly_threshold_suggestions(session, days)
        suggestions.extend(threshold_suggestions)

        logger.info(f"[FeedbackLoop] Generated {len(suggestions)} tuning suggestions")
        return suggestions

    async def _cep_pattern_suggestions(
        self, session: AsyncSession, days: int = 30
    ) -> list[dict]:
        """CEP 攻击链模式调优建议（误报反馈→CEP 闭环）"""
        suggestions = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # 查询针对 CEP 模式的误报反馈 (rule_id 含 flink_ 或攻击链名称)
        cep_keywords = ["flink_", "port_scan_to_c2", "lateral_movement", "data_exfil",
                        "attack_chain", "ATTACK_CHAIN"]
        for keyword in cep_keywords:
            stmt = (
                select(
                    FeedbackRecord.rule_id,
                    FeedbackRecord.feedback_type,
                    func.count(FeedbackRecord.id),
                )
                .where(
                    FeedbackRecord.created_at >= cutoff,
                    FeedbackRecord.rule_id.like(f"%{keyword}%"),
                )
                .group_by(FeedbackRecord.rule_id, FeedbackRecord.feedback_type)
            )
            result = await session.execute(stmt)
            for rule_id, ftype, count in result.all():
                if ftype == "false_positive" and count >= 2:
                    suggestions.append({
                        "type": "cep_high_fp",
                        "severity": "high",
                        "rule_id": rule_id,
                        "fp_count": count,
                        "suggestion": (
                            f"CEP 模式 {rule_id} 近 {days} 天有 {count} 次误报，"
                            f"建议切换为灰度模式 (shadow mode) 或调整时间窗口"
                        ),
                        "actions": ["切换灰度模式", "缩短时间窗口", "禁用模式", "增加过滤条件"],
                        "api": f"POST /api/cep/patterns/{rule_id}/shadow",
                    })
        return suggestions

    async def _anomaly_threshold_suggestions(
        self, session: AsyncSession, days: int = 30
    ) -> list[dict]:
        """异常检测阈值调优建议（误报反馈→动态基线闭环）"""
        suggestions = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # 统计异常检测相关的误报（rule_id 含 anomaly/flink_anomaly）
        stmt = (
            select(
                FeedbackRecord.feedback_type,
                func.count(FeedbackRecord.id),
            )
            .where(
                FeedbackRecord.created_at >= cutoff,
                FeedbackRecord.rule_id.like("%anomal%"),
            )
            .group_by(FeedbackRecord.feedback_type)
        )
        result = await session.execute(stmt)
        type_counts = {row[0]: row[1] for row in result.all()}

        fp = type_counts.get("false_positive", 0)
        tp = type_counts.get("true_positive", 0)
        total = fp + tp

        if total >= 5:
            fp_rate = fp / total
            if fp_rate > 0.4:
                suggestions.append({
                    "type": "anomaly_threshold_high_fp",
                    "severity": "high",
                    "fp_rate": round(fp_rate, 4),
                    "total_feedback": total,
                    "suggestion": (
                        f"异常检测误报率 {fp_rate:.0%} ({fp}/{total})，"
                        f"建议提高频率异常 σ 倍数（当前 2.0σ → 建议 2.5σ）"
                        f"或提高告警路由阈值（当前 0.6 → 建议 0.7）"
                    ),
                    "actions": [
                        "提高 σ 倍数 (FREQ_SIGMA_FACTOR: 2.0→2.5)",
                        "提高告警阈值 (0.6→0.7)",
                        "延长冷启动期 (10→20 事件)",
                        "增加凌晨时段例外白名单",
                    ],
                })
            elif fp_rate < 0.1 and tp >= 3:
                suggestions.append({
                    "type": "anomaly_threshold_conservative",
                    "severity": "medium",
                    "fp_rate": round(fp_rate, 4),
                    "suggestion": (
                        f"异常检测误报率极低 ({fp_rate:.0%})，"
                        f"模型偏保守，可适当降低阈值以捕获更多威胁"
                    ),
                    "actions": ["降低 σ 倍数 (2.0→1.5)", "降低告警阈值 (0.6→0.5)"],
                })

        # 漏报反馈中是否有异常检测相关
        missed = type_counts.get("missed_threat", 0)
        if missed >= 2:
            suggestions.append({
                "type": "anomaly_missed_threats",
                "severity": "critical",
                "count": missed,
                "suggestion": f"异常检测有 {missed} 次漏报，建议降低阈值或增加检测维度",
                "actions": ["降低 σ 倍数", "增加资产重要性权重", "扩展凌晨时段范围"],
            })

        return suggestions

    async def list_feedback(
        self, session: AsyncSession,
        feedback_type: str = "", status: str = "",
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        conditions = []
        if feedback_type:
            conditions.append(FeedbackRecord.feedback_type == feedback_type)
        if status:
            conditions.append(FeedbackRecord.status == status)

        stmt = select(FeedbackRecord)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(FeedbackRecord.created_at)).limit(limit).offset(offset)

        result = await session.execute(stmt)
        return [
            {
                "id": r.id,
                "event_id": r.event_id,
                "case_id": r.case_id,
                "feedback_type": r.feedback_type,
                "original_conclusion": r.original_conclusion,
                "operator_conclusion": r.operator_conclusion,
                "reason": r.reason,
                "rule_id": r.rule_id,
                "rule_suggestion": r.rule_suggestion,
                "submitted_by": r.submitted_by,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in result.scalars().all()
        ]


feedback_loop = FeedbackLoop()
