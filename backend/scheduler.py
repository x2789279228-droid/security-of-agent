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
EMBED_BACKFILL_INTERVAL = 300  # embedding 回填巡检间隔（5分钟; 漏跑自愈）
STUCK_AUDIT_REAP_INTERVAL = 120  # r6: 卡住未分析事件收口间隔（2分钟）
# PQ drain 间隔由 settings.audit_pq_drain_interval_s 控制


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
        self._embed_patrol_task = None

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
            asyncio.create_task(self._stuck_audit_reap_loop(db_session_factory)),
            asyncio.create_task(self._audit_pq_drain_loop()),
        ]
        # embedding 回填巡检(延迟到启动自检之后再进入周期, 避免与启动回填抢占)
        self._embed_patrol_task = asyncio.create_task(self._embedding_backfill_patrol())
        self._tasks.append(self._embed_patrol_task)
        logger.info("Scheduler started: snapshot=%ds, long_chain=%ds, cad_ctx=%ds, watchdog=%ds, sla=%ds, fp=%ds, kpi=%ds, embed_backfill=%ds",
                     SNAPSHOT_INTERVAL, LONG_CHAIN_INTERVAL, 3600, WATCHDOG_INTERVAL,
                     SLA_CHECK_INTERVAL, FP_ANALYTICS_INTERVAL, KPI_DAILY_INTERVAL,
                     EMBED_BACKFILL_INTERVAL)

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

        每个 session 用一个 30 天滑动窗口做一次关联分析。
        （旧实现按天切片循环 30 次，但 day_start/day_end 从未传入 analyze，
        每次 analyze 实际都是"最近 24h"窗口，30 次结果完全相同，纯属重复计算。）
        """
        from correlation_engine import correlation_engine

        now = datetime.now(timezone.utc)

        # 获取所有有事件的 session_id
        from models import SecurityEvent
        sessions_q = await session.execute(
            select(SecurityEvent.session_id)
            .where(SecurityEvent.created_at >= now - timedelta(days=30))
            .distinct()
        )
        all_session_ids = [row[0] for row in sessions_q.all()]

        results = []
        for sid in all_session_ids:
            try:
                result = await correlation_engine.analyze(
                    session, sid, time_window_minutes=30 * 1440
                )
                if result.chains:
                    logger.info(
                        f"Long-chain scan for {sid}: {len(result.chains)} chains found "
                        f"in 30-day window"
                    )
                    results.extend(result.chains)
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
        """定时扫描超期案例: 自动收口已处置案、标记 sla_breached、关闭陈旧 resolved。"""
        first = True
        while self._running:
            try:
                if not first:
                    await asyncio.sleep(SLA_CHECK_INTERVAL)
                first = False
                now = datetime.now(timezone.utc)
                async with db_factory() as session:
                    await self._run_case_sla_once(session, now)
            except ImportError:
                break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[case-sla] Check failed: {e}")

    async def _run_case_sla_once(self, session, now) -> None:
        from sqlalchemy import select
        from models import SecurityCase
        from case_manager import case_manager

        try:
            resolved_n = await case_manager.auto_resolve_idle_cases(session, now=now)
            if resolved_n:
                logger.info(f"[case-sla] auto-resolved {resolved_n} responded cases")
        except Exception as e:
            logger.warning(f"[case-sla] auto-resolve failed: {e}")

        rows = (await session.execute(
            select(SecurityCase).where(
                SecurityCase.status.in_(["open", "investigating", "responding"]),
                SecurityCase.sla_deadline.is_not(None),
                SecurityCase.sla_deadline < now,
                SecurityCase.sla_breached == False,
            )
        )).scalars().all()
        marked = 0
        for case in rows:
            if await case_manager.has_pending_approval(session, case):
                continue
            case.sla_breached = True
            marked += 1
            if case.status == "open":
                await case_manager.update_status(
                    session, case.id, "investigating", by="system"
                )
        if marked:
            try:
                await session.commit()
            except Exception:
                pass
            logger.warning(f"[case-sla] {marked} cases breached SLA")

        await self._close_stale_resolved(session, now)

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

    async def _embedding_backfill_patrol(self):
        """周期巡检 embedding 缺失; 有缺失则启动受管回填(自身幂等防重入)。"""
        # 首轮等一个周期, 让启动时触发的回填优先跑完/跑动, 避免重复触发
        await asyncio.sleep(EMBED_BACKFILL_INTERVAL)
        while self._running:
            try:
                from rag.seeder import has_missing_embeddings, launch_embedding_backfill
                if await has_missing_embeddings(scope="chunks"):
                    launch_embedding_backfill(scope="chunks")
                if await has_missing_embeddings(scope="memories"):
                    launch_embedding_backfill(scope="memories")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[EmbedBackfill] patrol failed: {e}")
            await asyncio.sleep(EMBED_BACKFILL_INTERVAL)

    # ── 9b. 审计优先级队列拉取 (Phase C) ──

    async def _audit_pq_drain_loop(self):
        """从 Redis ZSET 弹出最高优任务并 start Temporal workflow。

        inflight 仍满则把任务重新入队(短暂退避),避免忙等。
        """
        from config import settings as _cfg
        interval = float(getattr(_cfg, "audit_pq_drain_interval_s", 1.0) or 1.0)
        while self._running:
            try:
                await asyncio.sleep(max(0.2, interval))
                drained = await self._drain_audit_pq_once()
                if drained:
                    logger.info(f"[AuditPQ] drained {drained} job(s)")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[AuditPQ] drain failed: {e}")

    async def _drain_audit_pq_once(self) -> int:
        from audit_pq import audit_pq
        from temporal.client import start_audit_workflow, inflight_stats
        from config import settings as _cfg

        if not audit_pq.available:
            return 0
        # 每次最多拉一批,避免一次占满
        batch = 5
        n = 0
        for _ in range(batch):
            stats = await inflight_stats()
            limit = int(stats.get("limit") or 0)
            total = int(stats.get("total") or 0)
            if limit > 0 and total >= limit:
                break
            job = await audit_pq.pop_highest()
            if not job:
                break
            eid = int(job.get("event_id") or 0)
            if not eid:
                continue
            started = await start_audit_workflow(
                session_id=str(job.get("session_id") or ""),
                event_id=eid,
                log_data=job.get("log_data") or {},
                anomaly_score=float(job.get("anomaly_score") or 0),
                anomaly_reasons=list(job.get("anomaly_reasons") or []),
                max_rounds=int(job.get("max_rounds") or 3),
                tier=str(job.get("tier") or "P1"),
            )
            if started is True:
                n += 1
                continue
            if started == "shed":
                # 槽又满了 — 重新入队
                ttl = int(getattr(_cfg, "audit_pq_ttl_s", 900) or 900)
                await audit_pq.enqueue(
                    event_id=eid,
                    session_id=str(job.get("session_id") or ""),
                    log_data=job.get("log_data") or {},
                    anomaly_score=float(job.get("anomaly_score") or 0),
                    anomaly_reasons=list(job.get("anomaly_reasons") or []),
                    max_rounds=int(job.get("max_rounds") or 3),
                    priority=int(job.get("priority") or 50),
                    tier=str(job.get("tier") or "P1"),
                    ttl_s=ttl,
                )
                break
            # Temporal 不可用: 标记 fallback,避免永远挂在 PQ
            try:
                from log_ingestion import log_ingestor
                _score = float(job.get("anomaly_score") or 0)

                class _AR:
                    anomaly_score = _score
                    reasons = list(job.get("anomaly_reasons") or [])
                    is_anomaly = _score >= 0.6
                    deviation_sigma = 0.0

                await log_ingestor._fallback_analysis(
                    eid, job.get("log_data") or {}, _AR(), "pq_temporal_unavailable"
                )
                await log_ingestor._mark_analyzed(
                    eid, error="pq_temporal_unavailable", status="fallback"
                )
            except Exception as fe:
                logger.warning(f"[AuditPQ] fallback for #{eid} failed: {fe}")
        # 偶尔清理幽灵成员
        if n == 0:
            await audit_pq.purge_stale()
        return n

    # ── 9. 卡住未分析事件运行时收口 (r6) ──

    async def _stuck_audit_reap_loop(self, db_factory):
        """analyzed=false 超过阈值 → fallback 落库 + 尝试取消 Temporal workflow。

        启动时清理不够: r6 测试窗口内 1100 事件长期 pending,需运行中收口。
        """
        while self._running:
            try:
                await asyncio.sleep(STUCK_AUDIT_REAP_INTERVAL)
                async with db_factory() as session:
                    n = await self._reap_stuck_audits(session)
                    if n:
                        logger.warning(f"[StuckAudit] reaped {n} stuck unanalyzed events")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[StuckAudit] reap failed: {e}")

    async def _reap_stuck_audits(self, session: AsyncSession) -> int:
        from config import settings
        from models import SecurityEvent

        minutes = int(getattr(settings, "stuck_audit_reap_minutes", 0) or 0)
        if minutes <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        rows = (await session.execute(
            select(SecurityEvent).where(
                SecurityEvent.analyzed == False,
                SecurityEvent.created_at < cutoff,
            ).limit(200)
        )).scalars().all()
        if not rows:
            return 0

        # 尝试取消仍在跑的 Temporal workflow(忽略不存在)
        try:
            from temporal.client import get_client
            client = await get_client()
        except Exception:
            client = None

        n = 0
        for e in rows:
            if client is not None:
                try:
                    handle = client.get_workflow_handle(f"audit-{e.id}")
                    await handle.terminate(reason="stuck_audit_reap")
                except Exception:
                    pass
            e.analyzed = True
            raw = dict(e.raw_data or {})
            raw["_audit_llm_error"] = "stuck_audit_reap"
            audit = dict(raw.get("_audit_llm") or {})
            audit.update({
                "status": "failed",
                "fallback": True,
                "fallback_reason": "stuck_audit_reap",
                "error": "stuck_audit_reap",
                "note": f"reaped after {minutes}m unanalyzed",
            })
            raw["_audit_llm"] = audit
            e.raw_data = raw
            n += 1
            try:
                event_store.invalidate(e.id, broadcast=True)
            except Exception:
                pass
        if n:
            await session.commit()
            # 归还可能泄漏的 in-flight 计数(粗略校正)
            try:
                from temporal.client import inflight_release
                for _ in range(min(n, 30)):
                    await inflight_release()
            except Exception:
                pass
        return n


scheduler = Scheduler()
