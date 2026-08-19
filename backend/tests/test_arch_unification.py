"""
架构改造单元测试 — Phase 1/2 (Flink 唯一流处理事实源, Python 薄消费者)

覆盖:
  - event_store.store 幂等: 同一 eventId 重复落库只产生一行
  - schema_registry.validate: 跨运行时 Schema 契约 (Flink↔Python)
  - kafka_consumer 常量: 已移除 Redis 去重 (无 DEDUP_PREFIX)

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")
os.environ.setdefault("SHARED_MEMORY_KAFKA_ENABLED", "false")
os.environ.setdefault("SHARED_MEMORY_SCHEMA_REGISTRY_URL", "")

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine
def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)
_sa_async.create_async_engine = _patched_create_async_engine


async def _reset_db():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        # 应用增量迁移 (event_id 唯一索引)
        from models import _migrate_existing_tables
        await _migrate_existing_tables(conn)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── event_store 幂等 ──

def test_event_store_idempotent_same_event_id():
    """同一 eventId 重复落库 → 只产生一行, 返回已存在记录"""
    from event_store import event_store

    async def _case():
        await _reset_db()
        from models import async_session
        from sqlalchemy import select, func
        from models import SecurityEvent

        event = {
            "eventId": "uuid-1234",
            "event": "BRUTE_FORCE",
            "severity": "high",
            "src_ip": "10.0.0.1",
            "message": "brute force attempt",
            "_anomaly": {"score": 0.8, "is_anomaly": True},
        }
        async with async_session() as s:
            first = await event_store.store(s, event, "sess-a", anomaly_score=0.8)
            second = await event_store.store(s, event, "sess-b", anomaly_score=0.8)
            total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
            # 幂等: 同一 eventId 只落库一次
            assert total == 1, f"expected 1 row, got {total}"
            # 返回的应是已存在记录
            assert first.id == second.id
        return first

    evt = _run(_case())
    assert evt.event_type == "BRUTE_FORCE"


def test_event_store_distinct_event_ids():
    """不同 eventId 正常各自落库"""
    from event_store import event_store

    async def _case():
        await _reset_db()
        from models import async_session
        from sqlalchemy import select, func
        from models import SecurityEvent

        async with async_session() as s:
            await event_store.store(
                s, {"eventId": "a-1", "event": "LOGIN", "severity": "info", "message": "m"}, "s")
            await event_store.store(
                s, {"eventId": "a-2", "event": "LOGIN", "severity": "info", "message": "m"}, "s")
            total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
            assert total == 2
        return total

    assert _run(_case()) == 2


def test_security_event_model_has_event_id_column():
    """模型含 event_id 列 + 唯一约束 (幂等兜底)"""
    from models import SecurityEvent

    assert any(c.name == "event_id" for c in SecurityEvent.__table__.columns)
    uniques = [uc.name for uc in SecurityEvent.__table__.constraints if uc.name]
    assert any("uq_security_events_event_id" in (u or "") for u in uniques) or \
           any(uc.unique for uc in SecurityEvent.__table__.columns if uc.name == "event_id")


# ── 跨运行时 Schema 契约 ──

def test_schema_registry_validates_security_event():
    from schema_registry import schema_registry

    ok = {
        "eventId": "uuid-1", "eventType": "BRUTE_FORCE",
        "severity": "high", "message": "x", "timestamp": 1750000000000,
    }
    bad_severity = {**ok, "severity": "critical2"}
    missing_ts = {k: v for k, v in ok.items() if k != "timestamp"}

    assert schema_registry.validate("security-events-enriched", ok) == []
    assert schema_registry.validate("security-audit-queue", ok) == []
    assert len(schema_registry.validate("security-events-enriched", bad_severity)) > 0
    assert len(schema_registry.validate("security-audit-queue", missing_ts)) > 0
    # 未映射 topic 跳过校验
    assert schema_registry.validate("security-logs-rejected", {"x": 1}) == []


def test_schema_registry_validates_alert():
    from schema_registry import schema_registry

    ok_alert = {
        "alertId": "CHAIN-x", "eventType": "port_scan_to_c2", "severity": "critical",
        "srcIp": "1.2.3.4", "message": "chain", "anomalyScore": 1.0,
        "alertType": "ATTACK_CHAIN", "reasons": ["r"], "timestamp": 1750000000000,
    }
    bad_alert = {**ok_alert, "alertType": "UNKNOWN_TYPE"}

    assert schema_registry.validate("security-alerts", ok_alert) == []
    assert len(schema_registry.validate("security-alerts", bad_alert)) > 0


# ── kafka_consumer 去重移除 ──

def test_kafka_consumer_redis_dedup_removed():
    """Redis 24h 去重已移除, 改为 PG event_id 唯一索引兜底"""
    import kafka_consumer as kc

    assert not hasattr(kc, "DEDUP_PREFIX"), "Redis 去重常量应已移除"
    assert not hasattr(kc, "DEDUP_TTL"), "Redis 去重常量应已移除"
    manager = kc.kafka_consumer_manager
    assert not hasattr(manager, "_is_duplicate"), "Redis 去重方法应已移除"
    assert "dedup_skipped" not in manager._stats
    assert "idempotent_skipped" in manager._stats
    assert "dlq_sent" in manager._stats