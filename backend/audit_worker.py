"""有界 Audit worker 池 — 取代每事件 asyncio.create_task(_audit_pipeline)。

内存里永远只有 N 个审计协程。队列满时 P0/P1 进 Redis PQ, P2/P3 返回 overflow
让调用方规则收口。cancel(event_id) 供 stuck reaper 回收 slot。

P0/P1 never-drop (audit_p0/p1_never_drop=True): 内存队列满时按
Redis PQ → Kafka overflow topic → 进程内 _p0_overflow deque 兜底,
永不返回 overflow。worker 在内存队列空时 drain 兜底 deque。
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any, Optional

from config import settings

logger = logging.getLogger(__name__)

# 进程内 P0/P1 兜底 deque 容量上限(仅 Redis PQ 与 Kafka overflow 均失败时使用)
P0_OVERFLOW_MAX = 10000


class AuditWorkerPool:
    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._tasks: list[asyncio.Task] = []
        self._inflight: dict[int, asyncio.Task] = {}
        self._busy = 0
        self._seq = 0
        self._started = False
        self._start_lock: Optional[asyncio.Lock] = None
        self._p0_overflow: deque = deque()

    @property
    def started(self) -> bool:
        return self._started

    @property
    def busy(self) -> int:
        return self._busy

    def queue_depth(self) -> int:
        try:
            return int(self._queue.qsize())
        except Exception:
            return 0

    def inflight_ids(self) -> list[int]:
        return list(self._inflight.keys())

    def _n_workers(self) -> int:
        return max(1, int(getattr(settings, "audit_workers", 12) or 12))

    def _queue_max(self) -> int:
        return max(1, int(getattr(settings, "audit_queue_max", 2000) or 2000))

    async def start(self) -> None:
        if self._started:
            return
        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        async with self._start_lock:
            if self._started:
                return
            n = self._n_workers()
            self._tasks = [
                asyncio.create_task(self._loop(i), name=f"audit-worker-{i}")
                for i in range(n)
            ]
            self._started = True
            logger.info("AuditWorkerPool started workers=%d queue_max=%d", n, self._queue_max())
            self._publish_gauges()

    async def stop(self) -> None:
        self._started = False
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for t in list(self._inflight.values()):
            t.cancel()
        self._inflight.clear()
        self._busy = 0
        logger.info("AuditWorkerPool stopped")

    def cancel(self, event_id: int) -> bool:
        t = self._inflight.get(int(event_id))
        if t is None:
            return False
        t.cancel()
        return True

    def _publish_gauges(self) -> None:
        try:
            from metrics import set_audit_runtime
            set_audit_runtime(inflight=self._busy, queue_depth=self.queue_depth(), workers=self._n_workers())
        except Exception:
            pass

    async def submit(
        self,
        *,
        session_id: str,
        event_id: int,
        log_data: dict,
        anomaly_report: Any,
        from_overflow: bool = False,
    ) -> str:
        """投递审计任务。

        Returns:
          queued    — 进内存堆
          shed      — 队列满, 已持久化到 Redis PQ
          deferred  — 队列满, PQ 失败但已进 Kafka overflow topic 或进程内 deque
          overflow  — P2/P3 (或 never_drop 关闭时 P0/P1) 队列满, 调用方规则收口
          direct    — worker 未启动(测试), 直接 create_task
        """
        if not self._started:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return "direct"
            # 测试/延迟启动: 懒启动,避免无界 create_task
            await self.start()

        from audit_triage import score_event
        score = float(getattr(anomaly_report, "anomaly_score", 0) or 0)
        triage = score_event(log_data or {}, score)
        if self.queue_depth() >= self._queue_max():
            tier = triage.tier
            never_drop = (
                (tier == "P0" and bool(getattr(settings, "audit_p0_never_drop", True)))
                or (tier == "P1" and bool(getattr(settings, "audit_p1_never_drop", True)))
            )
            if never_drop:
                # P0/P1 永不丢: Redis PQ → Kafka overflow → 进程内 deque
                # from_overflow=True: 已从 Kafka overflow 回灌, 禁止再 produce 以免环路
                job = {
                    "session_id": session_id,
                    "event_id": int(event_id),
                    "log_data": log_data,
                    "anomaly_report": anomaly_report,
                    "tier": tier,
                    "priority": int(triage.priority),
                }
                if await self._enqueue_pq(
                    session_id=session_id,
                    event_id=event_id,
                    log_data=log_data,
                    anomaly_report=anomaly_report,
                    triage=triage,
                ):
                    self._shed(tier, "pq_ok")
                    return "shed"
                self._shed(tier, "pq_fail")
                if not from_overflow and await self._enqueue_kafka_overflow(job):
                    self._shed(tier, "kafka_overflow")
                    return "deferred"
                self._p0_overflow.append(job)
                while len(self._p0_overflow) > P0_OVERFLOW_MAX:
                    dropped = self._p0_overflow.popleft()
                    logger.error(
                        "AuditWorker P0/P1 local deque evicted event_id=%s (cap=%s)",
                        dropped.get("event_id"), P0_OVERFLOW_MAX,
                    )
                    self._shed(str(dropped.get("tier") or tier), "local_deque_evicted")
                self._shed(tier, "local_deque")
                return "deferred"
            self._shed(tier, "memory_full")
            return "overflow"

        self._seq += 1
        job = {
            "session_id": session_id,
            "event_id": int(event_id),
            "log_data": log_data,
            "anomaly_report": anomaly_report,
            "tier": triage.tier,
            "priority": int(triage.priority),
        }
        await self._queue.put((-int(triage.priority), self._seq, job))
        self._publish_gauges()
        return "queued"

    async def _enqueue_pq(self, *, session_id, event_id, log_data, anomaly_report, triage) -> bool:
        try:
            from audit_pq import audit_pq, pq_ttl_for_tier
            from audit_triage import lane_max_rounds
            ttl = pq_ttl_for_tier(triage.tier)
            return await audit_pq.enqueue(
                event_id=int(event_id),
                session_id=session_id,
                log_data=log_data or {},
                anomaly_score=float(getattr(anomaly_report, "anomaly_score", 0) or 0),
                anomaly_reasons=list(getattr(anomaly_report, "reasons", []) or []),
                max_rounds=lane_max_rounds(triage.lane, 3),
                priority=int(triage.priority),
                tier=triage.tier,
                ttl_s=ttl,
            )
        except Exception as e:
            logger.warning("AuditWorker PQ enqueue failed: %s", e)
            return False

    def _shed(self, tier: str, reason: str) -> None:
        try:
            from metrics import inc_audit_shed
            inc_audit_shed(tier, reason)
        except Exception:
            pass

    async def _enqueue_kafka_overflow(self, job: dict) -> bool:
        """内存队列满且 Redis PQ 失败时, 把审计任务持久化到 Kafka overflow topic。

        producer 未启动或投递失败 → False, 调用方走进程内 deque 兜底。
        """
        try:
            from kafka_producer import kafka_producer as kp
            if not bool(getattr(kp, "is_active", False)):
                return False
            ar = job.get("anomaly_report")
            payload = {
                "event_id": int(job.get("event_id") or 0),
                "session_id": job.get("session_id") or "",
                "log_data": job.get("log_data") or {},
                "anomaly_score": float(getattr(ar, "anomaly_score", 0) or 0),
                "reasons": list(getattr(ar, "reasons", []) or [])[:20],
                "tier": job.get("tier") or "",
                "priority": int(job.get("priority") or 0),
            }
            return await kp.produce_raw(
                payload,
                topic=settings.kafka_topic_audit_overflow,
                key_field="event_id",
            )
        except Exception as e:
            logger.warning("AuditWorker Kafka overflow enqueue failed: %s", e)
            return False

    async def _loop(self, idx: int) -> None:
        overflow_streak = 0
        while True:
            job = None
            from_mem = True
            try:
                if self._p0_overflow:
                    # 本地兜底 FIFO; 每 2 个 overflow 穿插 1 个普通队列, 穿插后重置 streak,
                    # 避免 streak 停在阈值导致普通队列把 deque 饿死。
                    take_mem = overflow_streak >= 2 and not self._queue.empty()
                    if take_mem:
                        try:
                            _prio, _seq, job = self._queue.get_nowait()
                            overflow_streak = 0
                        except asyncio.QueueEmpty:
                            job = self._p0_overflow.popleft()
                            from_mem = False
                            overflow_streak += 1
                    else:
                        job = self._p0_overflow.popleft()
                        from_mem = False
                        overflow_streak += 1
                else:
                    overflow_streak = 0
                    _prio, _seq, job = await self._queue.get()
            except asyncio.CancelledError:
                break
            try:
                await self._run_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("AuditWorker[%s] job failed: %s", idx, e, exc_info=True)
            finally:
                if from_mem:
                    try:
                        self._queue.task_done()
                    except Exception:
                        pass
                self._publish_gauges()

    async def _run_job(self, job: dict) -> None:
        from log_ingestion import log_ingestor

        eid = int(job.get("event_id") or 0)
        self._busy += 1
        t = asyncio.create_task(
            log_ingestor._audit_pipeline(
                job.get("session_id") or "",
                eid,
                job.get("log_data") or {},
                job.get("anomaly_report"),
            ),
            name=f"audit-job-{eid}",
        )
        t.add_done_callback(log_ingestor._audit_task_done)
        self._inflight[eid] = t
        try:
            await t
        finally:
            self._inflight.pop(eid, None)
            self._busy = max(0, self._busy - 1)


audit_worker = AuditWorkerPool()
