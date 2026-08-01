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
        ]
        logger.info("Scheduler started: snapshot=%ds, long_chain=%ds, cad_ctx=%ds",
                     SNAPSHOT_INTERVAL, LONG_CHAIN_INTERVAL, 3600)

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


scheduler = Scheduler()
