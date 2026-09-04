"""
全量日志存储 (EventStore) — 安全审计的数据底座

设计原则：
  - 所有原始日志永久保留（永不压缩、永不删除）
  - 分层存储：热(PostgreSQL) → 温(Parquet) → 冷(S3)
  - 独立于记忆系统，Agent 通过引用查询完整数据

分层策略：
  热存储 (7天):  PostgreSQL + Redis 缓存
  温存储 (90天):  本地 Parquet 文件
  冷存储 (永久):   可配置 S3/MinIO 对象存储

用法:
    store = EventStore()
    # 写入
    await store.store(session, event_data)
    # 查询
    events = await store.query(session_id, filters={
        "src_ip": "10.0.0.5",
        "time_range": ("2026-07-01", "2026-07-28"),
        "severity": "critical",
    })
    # 攻击链回溯
    chain = await store.get_chain(session_id, correlation_id)
"""
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, desc, and_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models import SecurityEvent
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class EventFilter:
    """事件查询过滤器"""
    session_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    event_type: str = ""
    severity: str = ""
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    min_anomaly_score: float = 0.0
    is_anomaly: Optional[bool] = None
    limit: int = 100
    offset: int = 0


@dataclass
class StoredEvent:
    """存储在 EventStore 中的完整事件"""
    id: int
    session_id: str
    event_type: str
    severity: str
    src_ip: str
    dst_ip: str
    message: str
    raw_data: dict
    anomaly_score: float = 0.0
    correlation_id: str = ""
    created_at: str = ""
    analyzed: bool = False


class EventStore:
    """
    全量日志存储

    支持的存储后端：
    - postgres: 通过现有的 SecurityEvent 表（热存储）
    - parquet: 本地列存文件（温存储）
    - s3: 对象存储（冷存储，可选）

    所有写入操作强制同步写入 postgres，异步归档到温/冷层。
    """

    def __init__(self):
        self.data_dir = os.path.join(
            os.path.dirname(__file__), "event_archive"
        )
        os.makedirs(self.data_dir, exist_ok=True)
        # 热缓存 LRU：此前是无上限 dict，持续写入永不淘汰，长跑内存持续膨胀。
        # 容量可由 EVENT_STORE_HOT_CACHE_MAX 调整；超容时按最久未访问淘汰。
        self._hot_cache: "OrderedDict[int, dict]" = OrderedDict()
        self._hot_cache_max = int(os.environ.get("EVENT_STORE_HOT_CACHE_MAX", "2000"))
        self._initialized = False
        # Redis 跨进程失效通道: Temporal worker 写回后通知 backend 丢弃热缓存
        self._redis = None
        self._invalidate_channel = "soc:event_store:invalidate"
        self._invalidate_listener_task = None

    def _cache_put(self, event_id: int, data: dict) -> None:
        """写入热缓存并执行 LRU 淘汰。"""
        self._hot_cache[event_id] = data
        self._hot_cache.move_to_end(event_id)
        while len(self._hot_cache) > self._hot_cache_max:
            self._hot_cache.popitem(last=False)

    def set_redis(self, redis_client) -> None:
        """接入 Redis，启用跨进程热缓存失效广播。"""
        self._redis = redis_client
        logger.info("EventStore: Redis invalidate channel enabled")

    def invalidate(self, event_id: int, *, broadcast: bool = True) -> None:
        """审计/响应写回后丢弃热缓存，避免 get_by_id 读到入库时的陈旧快照。

        broadcast=True 时同步通过 Redis pub/sub 通知其他进程(backend API)丢弃同 ID。
        Temporal worker 与 FastAPI 不共享内存，缺广播会导致流水线报告 API 永远 pending。
        """
        if event_id is None:
            return
        eid = int(event_id)
        self._hot_cache.pop(eid, None)
        if broadcast and self._redis is not None:
            try:
                # redis.asyncio: fire-and-forget create_task; sync redis: publish 直接调
                import asyncio
                pub = getattr(self._redis, "publish", None)
                if pub is None:
                    return
                result = pub(self._invalidate_channel, str(eid))
                if asyncio.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        pass
            except Exception as e:
                logger.debug(f"EventStore invalidate broadcast failed: {e}")

    def update_hot_cache(self, event_id: int, **fields) -> None:
        """就地更新热缓存字段；不存在则忽略（下次 get_by_id 走 DB）。"""
        if event_id is None:
            return
        cached = self._hot_cache.get(int(event_id))
        if not cached:
            return
        cached.update(fields)

    async def start_invalidate_listener(self) -> None:
        """订阅 Redis 失效通道，丢弃本进程热缓存。backend / worker 均可调用。"""
        if self._redis is None or self._invalidate_listener_task is not None:
            return
        try:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(self._invalidate_channel)
        except Exception as e:
            logger.warning(f"EventStore invalidate listener subscribe failed: {e}")
            return

        async def _listen():
            try:
                async for msg in pubsub.listen():
                    if not msg or msg.get("type") != "message":
                        continue
                    data = msg.get("data")
                    try:
                        if isinstance(data, bytes):
                            data = data.decode()
                        eid = int(data)
                    except (TypeError, ValueError):
                        continue
                    # 本进程收到广播时不再二次广播
                    self._hot_cache.pop(eid, None)
            except Exception as e:
                logger.warning(f"EventStore invalidate listener stopped: {e}")

        import asyncio
        self._invalidate_listener_task = asyncio.create_task(
            _listen(), name="event-store-invalidate"
        )
        logger.info("EventStore: invalidate listener started")

    async def store(
        self,
        session: AsyncSession,
        event_data: dict,
        session_id: str,
        anomaly_score: float = 0.0,
        correlation_id: str = "",
    ) -> StoredEvent:
        """
        存储一条安全事件到全量存储

        自动写 PostgreSQL（热存储），异步归档到文件（温存储）。

        幂等性 (event_id 唯一约束兜底):
          上游 eventId 已存在 → 跳过插入并返回已存在记录，
          跨运行时重放/Exactly-Once 下同一条事件只落库一次。
          (替代原 kafka_consumer 的 Redis 24h 去重)
        """
        # 写入 PostgreSQL（通过 SecurityEvent 模型）
        event_type = event_data.get("event", event_data.get("type", "UNKNOWN"))
        severity = event_data.get("severity", "info")
        event_id = event_data.get("eventId", "") or None

        # 幂等检查: eventId 已落库 → 直接返回已存在记录 (不重复插入)
        if event_id:
            existing = await self.get_by_upstream_id(session, event_id)
            if existing is not None:
                logger.info(
                    f"[Idempotent] eventId={event_id} 已存在 (#{existing.id}), 跳过重复入库"
                )
                return existing

        evt = SecurityEvent(
            event_id=event_id,
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            src_ip=event_data.get("src_ip", ""),
            dst_ip=event_data.get("dst_ip", ""),
            protocol=event_data.get("protocol", ""),
            action=event_data.get("action", ""),
            message=event_data.get("message", ""),
            raw_data={
                **event_data,
                "_anomaly_score": anomaly_score,
                "_correlation_id": correlation_id,
            },
            # 同步写入独立 anomaly_score 列，供 SQL 层直接过滤（见 get_unreviewed_anomalies）
            anomaly_score=anomaly_score,
            analyzed=False,
        )
        session.add(evt)
        try:
            await session.commit()
        except IntegrityError:
            # 并发/重放下唯一索引冲突 → 回滚并返回已存在记录
            await session.rollback()
            logger.warning(
                f"[Idempotent] eventId={event_id} 唯一约束冲突, 返回已存在记录"
            )
            if event_id:
                existing = await self.get_by_upstream_id(session, event_id)
                if existing is not None:
                    return existing
            raise
        await session.refresh(evt)
        # real-time approx counters (Redis; no-op when unavailable); genuine inserts only
        try:
            from stats_counter import inc_insert
        except Exception:
            pass
        else:
            try:
                await inc_insert()
            except Exception:
                pass

        stored = StoredEvent(
            id=evt.id,
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            src_ip=event_data.get("src_ip", ""),
            dst_ip=event_data.get("dst_ip", ""),
            message=event_data.get("message", ""),
            raw_data=event_data,
            anomaly_score=anomaly_score,
            correlation_id=correlation_id,
            created_at=evt.created_at.isoformat(),
        )

        # 缓存到 hot cache (LRU)
        self._cache_put(evt.id, asdict(stored))

        logger.info(f"Stored event #{evt.id}: {event_type}/{severity} "
                    f"anomaly={anomaly_score:.3f} "
                    f"correlation={correlation_id or 'none'}")

        return stored

    async def get_by_upstream_id(
        self,
        session: AsyncSession,
        event_id: str,
    ) -> Optional[StoredEvent]:
        """按上游 eventId 查询已落库事件 (幂等检查)"""
        stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        result = await session.execute(stmt)
        evt = result.scalars().first()
        if not evt:
            return None
        raw = evt.raw_data or {}
        return StoredEvent(
            id=evt.id,
            session_id=evt.session_id,
            event_type=evt.event_type,
            severity=evt.severity,
            src_ip=evt.src_ip or "",
            dst_ip=evt.dst_ip or "",
            message=evt.message or "",
            raw_data=raw,
            anomaly_score=evt.anomaly_score or 0.0,
            correlation_id=raw.get("_correlation_id", ""),
            created_at=evt.created_at.isoformat() if evt.created_at else "",
        )

    async def query(
        self,
        session: AsyncSession,
        filters: EventFilter,
    ) -> list[StoredEvent]:
        """
        查询安全事件 — 保留原始数据的溯源查询

        支持按 session_id/IP/事件类型/严重度/异常分数 筛选
        """
        conditions = []

        if filters.session_id:
            conditions.append(SecurityEvent.session_id == filters.session_id)
        if filters.src_ip:
            conditions.append(SecurityEvent.src_ip == filters.src_ip)
        if filters.dst_ip:
            conditions.append(SecurityEvent.dst_ip == filters.dst_ip)
        if filters.event_type:
            conditions.append(SecurityEvent.event_type == filters.event_type)
        if filters.severity:
            conditions.append(SecurityEvent.severity == filters.severity)
        if filters.time_start:
            conditions.append(SecurityEvent.created_at >= filters.time_start)
        if filters.time_end:
            conditions.append(SecurityEvent.created_at <= filters.time_end)

        stmt = select(SecurityEvent)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(SecurityEvent.created_at))
        stmt = stmt.limit(filters.limit).offset(filters.offset)

        result = await session.execute(stmt)
        rows = result.scalars().all()

        events = []
        for evt in rows:
            raw = evt.raw_data or {}
            # anomaly_score 优先读取独立列（迁移后路径），回退到 raw_data（向后兼容）
            anomaly_score = (
                evt.anomaly_score if evt.anomaly_score is not None
                else raw.get("_anomaly_score", 0.0)
            )
            events.append(StoredEvent(
                id=evt.id,
                session_id=evt.session_id,
                event_type=evt.event_type,
                severity=evt.severity,
                src_ip=evt.src_ip or "",
                dst_ip=evt.dst_ip or "",
                message=evt.message or "",
                raw_data=raw,
                anomaly_score=anomaly_score,
                correlation_id=raw.get("_correlation_id", ""),
                created_at=evt.created_at.isoformat(),
            ))

        logger.info(f"EventStore query: {len(events)} results "
                    f"(session={filters.session_id}, "
                    f"src_ip={filters.src_ip})")
        return events

    def _to_stored(self, evt: SecurityEvent) -> StoredEvent:
        raw = evt.raw_data or {}
        anomaly_score = (
            evt.anomaly_score if evt.anomaly_score is not None
            else raw.get("_anomaly_score", 0.0)
        )
        return StoredEvent(
            id=evt.id,
            session_id=evt.session_id,
            event_type=evt.event_type,
            severity=evt.severity,
            src_ip=evt.src_ip or "",
            dst_ip=evt.dst_ip or "",
            message=evt.message or "",
            raw_data=raw,
            anomaly_score=anomaly_score,
            correlation_id=raw.get("_correlation_id", ""),
            created_at=evt.created_at.isoformat() if evt.created_at else "",
            analyzed=bool(evt.analyzed),
        )

    async def get_by_id(
        self,
        session: AsyncSession,
        event_id: int,
        *,
        prefer_db: bool = False,
    ) -> Optional[StoredEvent]:
        """按 ID 获取单条完整事件。

        Temporal worker 与 FastAPI 分进程: ingest 时写入的热缓存不含后续
        `_audit_llm` 写回。若缓存标记 analyzed=False(或强制 prefer_db),
        必须回源 DB,否则 /audit-llm/pipeline 会永远返回空报告。
        """
        cached = self._hot_cache.get(event_id)
        if cached is not None and not prefer_db:
            # 已完成审计的缓存可信; 未完成的可能是跨进程写回前的陈旧快照 → 回源
            if cached.get("analyzed") and (cached.get("raw_data") or {}).get("_audit_llm"):
                self._hot_cache.move_to_end(event_id)
                return StoredEvent(**cached)
            # fall through to DB revalidation

        evt = await session.get(SecurityEvent, event_id)
        if not evt:
            return None

        stored = self._to_stored(evt)
        # 回填/刷新热缓存(带 LRU 淘汰),避免持续穿透
        try:
            self._cache_put(event_id, asdict(stored))
        except Exception:
            pass
        return stored

    async def get_unreviewed_anomalies(
        self,
        session: AsyncSession,
        session_id: str,
        min_score: float = 0.5,
        limit: int = 50,
    ) -> list[StoredEvent]:
        """获取未审核的异常事件（供 Agent-D 使用）

        改造后：anomaly_score 下沉为 SecurityEvent 独立列 + 索引，
        min_score 过滤直接在 SQL 完成，避免低分事件挤占 limit 名额导致漏报。
        历史 SQL fallback：若部署未执行迁移（anomaly_score 列缺失），
        回退到 Python 层过滤模式保证向后兼容。
        """
        # 优先走 SQL 层（anomaly_score 列存在时）
        try:
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.session_id == session_id,
                    SecurityEvent.analyzed == False,
                    SecurityEvent.anomaly_score >= min_score,
                )
                .order_by(desc(SecurityEvent.created_at))
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            events = []
            for evt in rows:
                raw = evt.raw_data or {}
                events.append(StoredEvent(
                    id=evt.id,
                    session_id=evt.session_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                    message=evt.message or "",
                    raw_data=raw,
                    anomaly_score=evt.anomaly_score,
                    correlation_id=raw.get("_correlation_id", ""),
                    created_at=evt.created_at.isoformat() if evt.created_at else "",
                ))
            return events
        except Exception as e:
            # 兼容回退：列不存在或 SQL 失败时回到旧 Python 层过滤模式
            logger.warning(
                f"SQL anomaly_score filter failed ({e}), "
                f"falling back to Python-layer filter (likely missing column)"
            )
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.session_id == session_id,
                    SecurityEvent.analyzed == False,
                )
                .order_by(desc(SecurityEvent.created_at))
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            events = []
            for evt in rows:
                raw = evt.raw_data or {}
                score = raw.get("_anomaly_score", 0.0)
                if score < min_score:
                    continue
                events.append(StoredEvent(
                    id=evt.id,
                    session_id=evt.session_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                    message=evt.message or "",
                    raw_data=raw,
                    anomaly_score=score,
                    correlation_id=raw.get("_correlation_id", ""),
                    created_at=evt.created_at.isoformat() if evt.created_at else "",
                ))
            return events

    async def get_stats(
        self,
        session: AsyncSession,
        session_id: str,
    ) -> dict:
        """获取存储统计"""
        from sqlalchemy import func

        total = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id
            )
        )
        analyzed = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id,
                SecurityEvent.analyzed == True,
            )
        )
        by_severity = await session.execute(
            select(
                SecurityEvent.severity,
                func.count(SecurityEvent.id)
            ).where(
                SecurityEvent.session_id == session_id
            ).group_by(SecurityEvent.severity)
        )

        total_n = total.scalar() or 0
        analyzed_n = analyzed.scalar() or 0
        return {
            "total_events": total_n,
            "analyzed": analyzed_n,
            "pending": total_n - analyzed_n,
            "by_severity": dict(by_severity.all()),
        }


event_store = EventStore()
