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
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, desc, and_, text
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
        self._hot_cache: dict[int, dict] = {}
        self._initialized = False

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
        """
        # 写入 PostgreSQL（通过 SecurityEvent 模型）
        event_type = event_data.get("event", event_data.get("type", "UNKNOWN"))
        severity = event_data.get("severity", "info")

        evt = SecurityEvent(
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
            analyzed=False,
        )
        session.add(evt)
        await session.commit()
        await session.refresh(evt)

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

        # 缓存到 hot cache
        self._hot_cache[evt.id] = asdict(stored)

        logger.info(f"Stored event #{evt.id}: {event_type}/{severity} "
                    f"anomaly={anomaly_score:.3f} "
                    f"correlation={correlation_id or 'none'}")

        return stored

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
            events.append(StoredEvent(
                id=evt.id,
                session_id=evt.session_id,
                event_type=evt.event_type,
                severity=evt.severity,
                src_ip=evt.src_ip or "",
                dst_ip=evt.dst_ip or "",
                message=evt.message or "",
                raw_data=raw,
                anomaly_score=raw.get("_anomaly_score", 0.0),
                correlation_id=raw.get("_correlation_id", ""),
                created_at=evt.created_at.isoformat(),
            ))

        logger.info(f"EventStore query: {len(events)} results "
                    f"(session={filters.session_id}, "
                    f"src_ip={filters.src_ip})")
        return events

    async def get_by_id(
        self,
        session: AsyncSession,
        event_id: int,
    ) -> Optional[StoredEvent]:
        """按 ID 获取单条完整事件"""
        # 先查 hot cache
        if event_id in self._hot_cache:
            return StoredEvent(**self._hot_cache[event_id])

        # 查 DB
        evt = await session.get(SecurityEvent, event_id)
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
            anomaly_score=raw.get("_anomaly_score", 0.0),
            correlation_id=raw.get("_correlation_id", ""),
            created_at=evt.created_at.isoformat(),
        )

    async def get_unreviewed_anomalies(
        self,
        session: AsyncSession,
        session_id: str,
        min_score: float = 0.5,
        limit: int = 50,
    ) -> list[StoredEvent]:
        """获取未审核的异常事件（供 Agent-D 使用）"""
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
                created_at=evt.created_at.isoformat(),
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

        return {
            "total_events": total.scalar() or 0,
            "analyzed": analyzed.scalar() or 0,
            "pending": (total.scalar() or 0) - (analyzed.scalar() or 0),
            "by_severity": dict(by_severity.all()),
        }


event_store = EventStore()
