"""
定时调度器 — 后台周期性任务

职责:
  1. 异常基线定时快照到 PostgreSQL（每5分钟）
  2. 长周期关联扫描（每30分钟）
  3. 基线从 Redis 重建（启动时，若 Redis 为空则从 DB 重建）

所有任务作为 asyncio 后台任务运行，不阻塞主服务。
"""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from anomaly_detector import anomaly_detector, EntityBaseline
from event_store import event_store, EventFilter

logger = logging.getLogger(__name__)

SNAPSHOT_INTERVAL = 300        # 基线快照间隔（5分钟）
LONG_CHAIN_INTERVAL = 1800     # 长周期关联间隔（30分钟）
WATCHDOG_INTERVAL = 600        # 看门狗巡检间隔（10分钟）
SLA_CHECK_INTERVAL = 300       # SLA 超时扫描间隔（5分钟）
FP_ANALYTICS_INTERVAL = 3600   # 误报统计间隔（1小时）
KPI_DAILY_INTERVAL = 86400    # KPI 日快照间隔（24小时,默认凌晨触发）


class Scheduler:
    """
    定时调度器 — 后台周期任务

    用法:
        scheduler = Scheduler()
        await scheduler.start(db_session_factory)  # 在 app 启动时调用
        # 自动运行后台循环
    """

    def __init__(self):
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def start(self, db_session_factory):
        """启动所有后台定时任务"""
        if self._running:
            return
        self._running = True
        self._tasks = [
            asyncio.create_task(self._baseline_snapshot_loop(db_session_factory)),
            asyncio.create_task(self._long_chain_scan_loop(db_session_factory)),
            asyncio.create_task(self._cad_context_audit_loop()),
            asyncio.create_task(self._watchdog_patrol_loop()),
            asyncio.create_task(self._sla_check_loop(db_session_factory)),
            asyncio.create_task(self._case_sla_loop(db_session_factory)),
            asyncio.create_task(self._fp_analytics_loop(db_session_factory)),
            asyncio.create_task(self._kpi_daily_loop(db_session_factory)),
            asyncio.create_task(self._llm_budget_reset_loop()),
        ]
        logger.info("Scheduler started: snapshot=%ds, long_chain=%ds, cad_ctx=%ds, watchdog=%ds, sla=%ds, fp=%ds, kpi=%ds",
                     SNAPSHOT_INTERVAL, LONG_CHAIN_INTERVAL, 3600, WATCHDOG_INTERVAL,
                     SLA_CHECK_INTERVAL, FP_ANALYTICS_INTERVAL, KPI_DAILY_INTERVAL)

    async def stop(self):
        """停止所有后台任务"""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Scheduler stopped")

    # ── 1. 基线快照 ──

    async def _baseline_snapshot_loop(self, db_factory):
        """定时快照异常检测基线到 PostgreSQL"""
        while self._running:
            try:
                await asyncio.sleep(SNAPSHOT_INTERVAL)
                async with db_factory() as session:
                    await self._snapshot_baselines(session)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Baseline snapshot failed: {e}")

    async def _snapshot_baselines(self, session: AsyncSession):
        """快照当前内存基线到 baseline_snapshots 表"""
        now = datetime.now(timezone.utc)

        # 创建表（如果不存在）
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id SERIAL PRIMARY KEY,
                entity_type VARCHAR(50) NOT NULL,
                entity_key VARCHAR(255) NOT NULL,
                snapshot JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        # 创建索引
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_type_key
            ON baseline_snapshots (entity_type, entity_key)
        """))

        # 写入当前基线
        inserted = 0
        for entity_type in ("src_ip", "dst_ip", "event_type"):
            for key, bl in list(anomaly_detector.baselines[entity_type].items()):
                if bl.total_count < 3:
                    continue  # 数据太少，不保存
                await session.execute(
                    text("""
                        INSERT INTO baseline_snapshots (entity_type, entity_key, snapshot, created_at)
                        VALUES (:type, :key, :snapshot, :now)
                    """),
                    {
                        "type": entity_type,
                        "key": key,
                        "snapshot": json.dumps({
                            "hourly_counts": bl.hourly_counts,
                            "daily_count": bl.daily_count,
                            "total_count": bl.total_count,
                            "last_seen": bl.last_seen,
                            "event_types": list(bl.event_types),
                            "first_seen": bl.first_seen,
                        }),
                        "now": now,
                    }
                )
                inserted += 1

        # 保留最近 10080 条（7天 × 288次/天 ÷ 5分钟 ≈ 2016次，留余量）
        await session.execute(text("""
            DELETE FROM baseline_snapshots
            WHERE id IN (
                SELECT id FROM baseline_snapshots
                ORDER BY id DESC OFFSET 10080
            )
        """))

        await session.commit()
        logger.debug(f"Baseline snapshot: {inserted} entities saved")

    async def rebuild_baselines_from_db(self, db_factory):
        """
        从 DB 重建基线（Redis 为空时调用）
        
        扫描过去 7 天的 SecurityEvent，重建统计基线。
        """
        async with db_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            from sqlalchemy import select
            from models import SecurityEvent

            stmt = (
                select(SecurityEvent)
                .where(SecurityEvent.created_at >= cutoff)
                .order_by(SecurityEvent.created_at)
            )
            result = await session.execute(stmt)
            events = result.scalars().all()

            if not events:
                logger.info("No events found for baseline rebuild")
                return

            # 重建基线
            anomaly_detector.baselines = {
                "src_ip": defaultdict(EntityBaseline),
                "event_type": defaultdict(EntityBaseline),
                "dst_ip": defaultdict(EntityBaseline),
            }
            anomaly_detector.global_hourly_counts = [0] * 24
            anomaly_detector.global_event_types.clear()

            for evt in events:
                hour = evt.created_at.hour
                raw = evt.raw_data or {}
                event_type = evt.event_type
                src_ip = evt.src_ip or ""
                dst_ip = evt.dst_ip or ""

                anomaly_detector.global_hourly_counts[hour] += 1
                anomaly_detector.global_event_types[event_type] += 1

                if src_ip:
                    anomaly_detector._update_baseline("src_ip", src_ip, event_type, hour)
                if dst_ip:
                    anomaly_detector._update_baseline("dst_ip", dst_ip, event_type, hour)
                anomaly_detector._update_baseline("event_type", event_type, event_type, hour)

            await anomaly_detector._save_baselines_to_redis()
            logger.info(
                f"Rebuilt baselines from DB: {len(events)} events, "
                f"{len(anomaly_detector.baselines['src_ip'])} src_ips"
            )

    # ── 2. 长周期关联 ──

    async def _long_chain_scan_loop(self, db_factory):
        """定时扫描长周期攻击链"""
        while self._running:
            try:
                await asyncio.sleep(LONG_CHAIN_INTERVAL)
                async with db_factory() as session:
                    await self._scan_long_chains(session)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Long chain scan failed: {e}")

    async def _scan_long_chains(self, session: AsyncSession):
        """
        扫描 30 天内未闭合的攻击链

        方法：按天分批查询，每天内独立匹配，跨天合并。
        """
        from correlation_engine import correlation_engine

        now = datetime.now(timezone.utc)
        results = []

        # 获取所有有事件的 session_id
        from models import SecurityEvent
        sessions_q = await session.execute(
            select(SecurityEvent.session_id)
            .where(SecurityEvent.created_at >= now - timedelta(days=30))
            .distinct()
        )
        all_session_ids = [row[0] for row in sessions_q.all()]

        for sid in all_session_ids:
            try:
                # 按天分批
                for day_offset in range(30):
                    day_start = now - timedelta(days=day_offset + 1)
                    day_end = now - timedelta(days=day_offset)

                    stmt = (
                        select(SecurityEvent)
                        .where(
                            SecurityEvent.session_id == sid,
                            SecurityEvent.created_at >= day_start,
                            SecurityEvent.created_at < day_end,
                        )
                        .order_by(SecurityEvent.created_at)
                    )
                    result = await session.execute(stmt)
                    day_events = result.scalars().all()

                    if len(day_events) < 2:
                        continue

                    # 对每天运行关联引擎（使用当天的数据）
                    result = await correlation_engine.analyze(
                        session, sid, time_window_minutes=1440
                    )
                    if result.chains:
                        results.extend(result.chains)

                if results:
                    logger.info(
                        f"Long-chain scan for {sid}: {len(results)} chains found "
                        f"in 30-day window"
                    )
            except Exception as e:
                logger.warning(f"Long-chain scan failed for {sid}: {e}")

        return results

    # ── 3. CAD 上下文审计 ──

    async def _cad_context_audit_loop(self):
        """定时运行 CAD 上下文审计"""
        while self._running:
            try:
                await asyncio.sleep(3600)  # 每小时
                from agents.agent_cad import cad_agent
                report = await cad_agent.audit_context()
                if report["critical_count"] > 0:
                    logger.warning(
                        f"CAD context audit: {report['critical_count']} critical risks"
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"CAD context audit failed: {e}")

    # ── 4. 看门狗巡检 ──

    async def _watchdog_patrol_loop(self):
        """定时运行全链路健康巡检"""
        while self._running:
            try:
                await asyncio.sleep(WATCHDOG_INTERVAL)
                from observability.watchdog import watchdog
                result = await watchdog.patrol()
                status = result.get("status", result.get("severity", "unknown"))
                if status != "healthy":
                    logger.warning(f"[Watchdog] Patrol result: {status}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[Watchdog] Patrol failed: {e}")

    # ── 5. SLA 超时扫描 ──

    async def _sla_check_loop(self, db_factory):
        """定时扫描超时工单"""
        while self._running:
            try:
                await asyncio.sleep(SLA_CHECK_INTERVAL)
                from work_order_service import work_order_service
                async with db_factory() as session:
                    breached = await work_order_service.check_sla_breaches(session)
                    if breached:
                        logger.warning(f"[SLA] {len(breached)} work orders breached SLA")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[SLA] Check failed: {e}")

    async def _case_sla_loop(self, db_factory):
        """定时扫描超期案例: 标记 sla_breached + 自动推进 open→investigating

        与 _sla_check_loop(工单维度) 并行的案例维度 SLA 监测。
        """
        from datetime import datetime, timezone
        from sqlalchemy import select
        from models import SecurityCase
        while self._running:
            try:
                await asyncio.sleep(SLA_CHECK_INTERVAL)
                now = datetime.now(timezone.utc)
                async with db_factory() as session:
                    rows = (await session.execute(
                        select(SecurityCase).where(
                            SecurityCase.status.in_(["open", "investigating"]),
                            SecurityCase.sla_deadline.is_not(None),
                            SecurityCase.sla_deadline < now,
                            SecurityCase.sla_breached == False,
                        )
                    )).scalars().all()
                    if rows:
                        from case_manager import case_manager
                        for case in rows:
                            case.sla_breached = True
                            if case.status == "open":
                                await case_manager.update_status(
                                    session, case.id, "investigating", by="system"
                                )
                        try:
                            await session.commit()
                        except Exception:
                            pass
                        logger.warning(f"[case-sla] {len(rows)} cases breached SLA")

                    # resolved 超阈值(默认24h)未人工 closed → 自动 closed
                    await self._close_stale_resolved(session, now)
            except ImportError:
                break  # 环境无 SQLAlchemy/model 依赖(只读工具)则跳过
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[case-sla] Check failed: {e}")

    async def _close_stale_resolved(self, session, now) -> int:
        """resolved 且超 case_auto_close_hours 未人工 closed 的案例 → 自动 closed。

        返回自动关闭数量。case_auto_close_hours <= 0 时不处理(不自动关闭)。
        """
        from datetime import timedelta
        from sqlalchemy import select
        from models import SecurityCase
        try:
            from config import settings
            auto_close_hours = getattr(settings, "case_auto_close_hours", 24) or 0
            if auto_close_hours <= 0:
                return 0
            close_cutoff = now - timedelta(hours=auto_close_hours)
            to_close = (await session.execute(
                select(SecurityCase).where(
                    SecurityCase.status == "resolved",
                    SecurityCase.closed_at.is_(None),
                    SecurityCase.updated_at < close_cutoff,
                )
            )).scalars().all()
            if not to_close:
                return 0
            from case_manager import case_manager
            for c in to_close:
                await case_manager.update_status(session, c.id, "closed", by="system")
            try:
                await session.commit()
            except Exception:
                pass
            logger.warning(
                f"[case-sla] auto-closed {len(to_close)} resolved cases (> {auto_close_hours}h)"
            )
            return len(to_close)
        except Exception as e:
            logger.warning(f"[case-sla] auto-close failed: {e}")
            return 0

    # ── 6. 误报统计 ──

    async def _fp_analytics_loop(self, db_factory):
        """定时生成误报统计 + 调优建议"""
        while self._running:
            try:
                await asyncio.sleep(FP_ANALYTICS_INTERVAL)
                from feedback_loop import feedback_loop
                async with db_factory() as session:
                    suggestions = await feedback_loop.generate_tuning_suggestions(session)
                    if suggestions:
                        logger.info(f"[FP Analytics] {len(suggestions)} tuning suggestions generated")
                        from event_bus import event_bus
                        event_bus.publish("pipeline_health", {
                            "type": "tuning_suggestions",
                            "count": len(suggestions),
                            "suggestions": [s.get("suggestion", "")[:100] for s in suggestions[:3]],
                        })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[FP Analytics] Failed: {e}")

    # ── 7. KPI 日快照 ──

    async def _kpi_daily_loop(self, db_factory):
        """每日生成 KPI 快照（默认凌晨 02:00 触发前一天聚合）"""
        while self._running:
            try:
                # 计算到下一个 02:00 的等待时间
                now = datetime.now(timezone.utc)
                next_run = now.replace(hour=2, minute=5, second=0, microsecond=0)
                if next_run <= now:
                    next_run = next_run + timedelta(days=1)
                wait_seconds = (next_run - now).total_seconds()
                await asyncio.sleep(min(wait_seconds, KPI_DAILY_INTERVAL))

                from ops_metrics.kpi_calculator import kpi_calculator
                async with db_factory() as session:
                    result = await kpi_calculator.snapshot_daily(session)
                    logger.info(f"[KPI] daily snapshot: {result.get('metrics_written')} metrics")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[KPI] daily snapshot failed: {e}")

    # ── 8. LLM 增强器预算日重置 ──

    async def _llm_budget_reset_loop(self):
        """每日凌晨重置 LLM 增强器各模块预算计数 (UTC 00:00 触发)"""
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                next_run = now.replace(hour=0, minute=0, second=10, microsecond=0)
                if next_run <= now:
                    next_run = next_run + timedelta(days=1)
                wait_seconds = (next_run - now).total_seconds()
                await asyncio.sleep(wait_seconds)

                from llm_enhancer import reset_daily_budgets
                reset_daily_budgets()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[LLM] budget reset failed: {e}")


scheduler = Scheduler()
