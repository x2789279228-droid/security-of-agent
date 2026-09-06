"""
P0 安全运营基础模块单元测试

覆盖:
  - P0.A AssetManager: 注册/查找/权重查询/资产关联
  - P0.G SourceRegistry: 注册/认证/吊销 持久化
  - P0.H audit_trail: log_action 写入与查询
  - P0.B KpiCalculator: 指标计算/快照写入/dashboard

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta, date as date_cls

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── 测试环境前置 (在 import models 之前注入) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

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


def _run(coro):
    """统一 async 驱动 (每个测试用独立 event loop)"""
    return asyncio.new_event_loop().run_until_complete(coro)


# ════════════════════════════════════════════
# 1. 资产管理 (P0.A)
# ════════════════════════════════════════════

class TestAssetManager:

    def test_register_and_find(self):
        async def t():
            from asset.asset_manager import asset_manager, ASSET_LEVELS
            from models import async_session
            await _reset_db()

            async with async_session() as s:
                r = await asset_manager.register(
                    s, ip="10.0.0.5", hostname="db-primary", asset_type="server",
                    criticality="critical", business_owner="finance",
                    business_unit="db", source="test", changed_by="tester",
                )
                assert r["success"]
                assert r["asset"]["criticality"] == "critical"
                assert r["asset"]["weight"] == 1.5

            async with async_session() as s:
                found = await asset_manager.find_by_ip(s, "10.0.0.5")
                assert found is not None
                assert found["business_owner"] == "finance"

            async with async_session() as s:
                assert await asset_manager.get_asset_weight(s, "10.0.0.5") == 1.5
                assert await asset_manager.get_asset_weight(s, "192.168.99.99") == 1.0
        _run(t())

    def test_update_via_re_register_creates_diff(self):
        async def t():
            from asset.asset_manager import asset_manager
            from models import async_session
            await _reset_db()

            async with async_session() as s:
                await asset_manager.register(
                    s, ip="10.0.0.6", criticality="medium",
                    source="test", changed_by="tester",
                )
            async with async_session() as s:
                r = await asset_manager.register(
                    s, ip="10.0.0.6", criticality="critical",
                    source="test", changed_by="tester2",
                )
                assert r["success"]
                assert "criticality" in (r.get("diff") or {})
        _run(t())

    def test_remove_soft_deletes(self):
        async def t():
            from asset.asset_manager import asset_manager
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                r = await asset_manager.register(
                    s, ip="10.0.0.7", criticality="medium", source="test",
                    changed_by="tester",
                )
                asset_id = r["asset"]["id"]
            async with async_session() as s:
                r2 = await asset_manager.remove(s, asset_id, by="tester")
                assert r2["success"]
            async with async_session() as s:
                asset = await asset_manager.get_asset(s, asset_id)
                assert asset["is_active"] is False
        _run(t())

    def test_correlator_enrich_and_priority(self):
        async def t():
            from asset.asset_manager import asset_manager
            from asset.asset_correlator import asset_correlator
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await asset_manager.register(
                    s, ip="10.0.0.8", criticality="critical",
                    source="test", changed_by="tester",
                )
            async with async_session() as s:
                snap = await asset_correlator.enrich_case_target(s, "10.0.0.8")
                assert snap is not None
                assert snap["criticality"] == "critical"
            async with async_session() as s:
                rec = await asset_correlator.recommend_case_priority(
                    s, "10.0.0.8", "medium"
                )
                assert rec == "critical"  # 资产 critical → medium 案例升级
            async with async_session() as s:
                miss = await asset_correlator.enrich_case_target(s, "8.8.8.8")
                assert miss is None
        _run(t())


# ════════════════════════════════════════════
# 2. 数据源持久化 (P0.G)
# ════════════════════════════════════════════

class TestSourceRegistryPersistence:

    def test_register_persists_to_db(self):
        async def t():
            from source_registry import source_registry, _hash_key
            from models import async_session, DataSource as DSM
            from sqlalchemy import select
            await _reset_db()
            async with async_session() as s:
                ds = await source_registry.register(
                    s, api_key="sk-test-123", name="test-syslog",
                    source_type="syslog", changed_by="tester",
                )
                assert ds.api_key_hash == _hash_key("sk-test-123")
                assert ds.db_id > 0

            async with async_session() as s:
                stmt = select(DSM).where(DSM.api_key_hash == _hash_key("sk-test-123"))
                row = (await s.execute(stmt)).scalars().first()
                assert row is not None
                assert row.name == "test-syslog"
                assert row.source_type == "syslog"
        _run(t())

    def test_authenticate_uses_cache(self):
        async def t():
            from source_registry import source_registry
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await source_registry.register(
                    s, api_key="sk-auth", name="auth-test", changed_by="tester",
                )
            hit = source_registry.authenticate("sk-auth")
            assert hit is not None
            assert hit.name == "auth-test"

            miss = source_registry.authenticate("sk-unknown")
            assert miss is None
        _run(t())

    def test_revoke_blocks_authenticate(self):
        async def t():
            from source_registry import source_registry
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await source_registry.register(
                    s, api_key="sk-rev", name="rev-test", changed_by="tester",
                )
            async with async_session() as s:
                ok = await source_registry.revoke(s, "sk-rev", by="tester")
                assert ok
            ds = source_registry.authenticate("sk-rev")
            assert ds is None
        _run(t())

    def test_load_from_db_rebuilds_cache(self):
        async def t():
            from source_registry import source_registry
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await source_registry.register(
                    s, api_key="sk-loadtest", name="load-test", changed_by="tester",
                )
            # 清空内存缓存
            source_registry._sources.clear()
            if hasattr(source_registry, "_sources_by_hash"):
                source_registry._sources_by_hash.clear()
            # 重新加载
            await source_registry.load_from_db(async_session)
            # DB-only 来源(无明文)的 authenticate 应走 hash 比对
            ds = source_registry.authenticate("sk-loadtest")
            assert ds is not None
            assert ds.name == "load-test"
        _run(t())


# ════════════════════════════════════════════
# 3. 操作审计 trail (P0.H)
# ════════════════════════════════════════════

class TestAuditTrail:

    def test_log_and_list(self):
        async def t():
            from audit_trail import log_action, list_trail
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await log_action(
                    s, actor="alice", action="case.transition",
                    target_type="case", target_id="1",
                    before={"status": "open"}, after={"status": "investigating"},
                    reason="测试流转", actor_role="analyst",
                )
            async with async_session() as s:
                rows = await list_trail(s, actor="alice")
                assert len(rows) == 1
                assert rows[0]["action"] == "case.transition"
                assert rows[0]["after"]["status"] == "investigating"
        _run(t())

    def test_query_by_target(self):
        async def t():
            from audit_trail import log_action, list_trail
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                await log_action(s, actor="bob", action="asset.create",
                                 target_type="asset", target_id="42",
                                 after={"asset_key": "ip:1.2.3.4"})
            async with async_session() as s:
                await log_action(s, actor="bob", action="asset.update",
                                 target_type="asset", target_id="42",
                                 before={"criticality": "medium"},
                                 after={"criticality": "critical"})
            async with async_session() as s:
                rows = await list_trail(s, target_type="asset", target_id="42")
                assert len(rows) == 2
                actions = {r["action"] for r in rows}
                assert actions == {"asset.create", "asset.update"}
        _run(t())

    def test_none_session_persists_when_db_available(self):
        async def t():
            from audit_trail import log_action, list_trail, _fallback_buffer
            from models import async_session
            await _reset_db()
            _fallback_buffer.clear()
            await log_action(
                None, actor="blue_reviewer", action="selfplay.rule_dismissed",
                target_type="selfplay_rule", target_id="SP-X",
                before={"status": "candidate"}, after={"status": "dismissed"},
            )
            assert _fallback_buffer == []
            async with async_session() as s:
                rows = await list_trail(s, actor="blue_reviewer")
                assert len(rows) == 1
                assert rows[0]["action"] == "selfplay.rule_dismissed"
        _run(t())

    def test_fallback_buffer_then_flush(self):
        async def t():
            from audit_trail import log_action, flush_fallback, list_trail, _fallback_buffer
            from models import async_session
            await _reset_db()
            _fallback_buffer.clear()

            class Boom:
                def add(self, *_a, **_k):
                    raise RuntimeError("db down")

                async def commit(self):
                    return None

            await log_action(
                Boom(), actor="system", action="source.register",
                target_type="source", target_id="99",
                before={}, after={"name": "x"},
            )
            assert len(_fallback_buffer) == 1
            async with async_session() as s:
                n = await flush_fallback(s)
                assert n == 1
            async with async_session() as s:
                rows = await list_trail(s, action="source.register")
                assert len(rows) == 1
        _run(t())

    def test_flush_commit_failure_keeps_buffer(self):
        async def t():
            from audit_trail import log_action, flush_fallback, _fallback_buffer
            await _reset_db()
            _fallback_buffer.clear()

            class BoomAdd:
                def add(self, *_a, **_k):
                    raise RuntimeError("db down")

                async def commit(self):
                    return None

            await log_action(
                BoomAdd(), actor="system", action="source.register",
                target_type="source", target_id="99",
                before={}, after={"name": "x"},
            )
            assert len(_fallback_buffer) == 1

            class BoomCommit:
                def add(self, *_a, **_k):
                    return None

                async def commit(self):
                    raise RuntimeError("commit fail")

                async def rollback(self):
                    return None

            n = await flush_fallback(BoomCommit())
            assert n == 0
            assert len(_fallback_buffer) == 1
        _run(t())

    def test_scheduler_flush_loop_is_wired(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / "scheduler.py").read_text(encoding="utf-8")
        assert "_audit_trail_flush_loop" in text
        assert "flush_fallback" in text
        assert "create_task(self._audit_trail_flush_loop" in text

    def test_reviewer_audit_does_not_pass_none_session(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parents[1] / "self_play" / "reviewer.py").read_text(encoding="utf-8")
        assert "log_action(None" not in text.replace(" ", "")
        assert "async_session()" in text


# ════════════════════════════════════════════
# 4. KPI 计算 (P0.B)
# ════════════════════════════════════════════

class TestKpiCalculator:

    def test_empty_db_returns_zeroes(self):
        async def t():
            from ops_metrics.kpi_calculator import kpi_calculator
            from models import async_session
            await _reset_db()
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=1)
            async with async_session() as s:
                assert (await kpi_calculator.compute_mttr(s, start=start, end=now)) == 0.0
                assert (await kpi_calculator.compute_mttd(s, start=start, end=now)) == 0.0
                assert (await kpi_calculator.compute_case_count(s, start=start, end=now)) == 0
                assert (await kpi_calculator.compute_sla_breach_rate(s, start=start, end=now)) == 0.0
                assert (await kpi_calculator.compute_fp_rate(s, start=start, end=now)) == 0.0
        _run(t())

    def test_mttr_with_closed_case(self):
        async def t():
            from ops_metrics.kpi_calculator import kpi_calculator
            from models import async_session, SecurityCase
            await _reset_db()
            now = datetime.now(timezone.utc)
            created = now - timedelta(hours=20)
            closed = now - timedelta(hours=10)
            async with async_session() as s:
                s.add(SecurityCase(
                    case_number="CASE-MTTR-001", title="t", status="closed",
                    priority="critical", threat_type="x", severity="critical",
                    src_ips=[], dst_ips=[], event_ids=[], event_count=0,
                    created_at=created, updated_at=closed, closed_at=closed,
                ))
                await s.commit()

            async with async_session() as s:
                mttr = await kpi_calculator.compute_mttr(
                    s, start=now - timedelta(days=1), end=now
                )
            # 期望 10 小时左右 (允许 ±1 小时 窗口边界误差)
            assert 9.0 <= mttr <= 11.0, f"MTTR out of range: {mttr}"
        _run(t())

    def test_snapshot_daily_writes_rows(self):
        async def t():
            from ops_metrics.kpi_calculator import kpi_calculator, METRIC_KEYS
            from models import async_session, KpiSnapshot
            from sqlalchemy import select
            await _reset_db()
            snap_date = (datetime.now(timezone.utc) - timedelta(days=1)).date()
            async with async_session() as s:
                r = await kpi_calculator.snapshot_daily(s, snapshot_date=snap_date)
                assert r["metrics_written"] >= 8  # 至少 8 个 METRIC_KEYS
            async with async_session() as s:
                stmt = select(KpiSnapshot).where(KpiSnapshot.snapshot_date == snap_date)
                rows = (await s.execute(stmt)).scalars().all()
                assert len(rows) >= 8
                keys = {r.metric_key for r in rows}
                assert keys == set(METRIC_KEYS)
        _run(t())

    def test_dashboard_returns_all_metrics(self):
        async def t():
            from ops_metrics.kpi_calculator import kpi_calculator, METRIC_KEYS
            from models import async_session
            await _reset_db()
            async with async_session() as s:
                d = await kpi_calculator.dashboard(s, days=30)
                for k in METRIC_KEYS:
                    assert k in d, f"missing metric in dashboard: {k}"
                assert "case_count_priority" in d
                assert "critical" in d["case_count_priority"]
        _run(t())

    def test_sla_tracker_records_and_subscribes(self):
        async def t():
            from ops_metrics.sla_tracker import sla_tracker
            await _reset_db()
            sla_tracker._breaches.clear()
            sla_tracker._subscribers.clear()
            received = []
            async def cb(entry):
                received.append(entry)
            sla_tracker.subscribe(cb)
            await sla_tracker.record_breach({
                "order_number": "WO-TEST-001", "case_id": 1,
                "priority": "critical", "sla_deadline": "2026-08-01T00:00:00Z",
            })
            assert len(received) == 1
            assert received[0]["order_number"] == "WO-TEST-001"
            assert len(sla_tracker.recent_breaches(hours=24)) == 1
        _run(t())


# ── 运行入口 ──

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])