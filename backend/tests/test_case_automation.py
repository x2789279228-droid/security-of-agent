"""
案例自动派单/状态推进单测 — 修复"运营中心案例全部失败"根因

覆盖:
  - case_manager.auto_create_case: 高/严重告警自动派生工单并把 case 推进到 responding
  - 阈值过滤: medium 不自动建单
  - kpi_calculator.compute_case_sla_breach_rate: case 维度 SLA 违约率

无需 pytest-asyncio: 显式 asyncio.run() 驱动。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async
_orig = _sa_async.create_async_engine
def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)
_sa_async.create_async_engine = _patched
import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def _mk_event(severity: str, src_ip="10.0.0.9"):
    from models import SecurityEvent, async_session
    async with async_session() as s:
        evt = SecurityEvent(
            session_id="sess-t", event_type="PORT_SCAN", severity=severity,
            src_ip=src_ip, dst_ip="172.16.0.5", message="scan",
            raw_data={}, analyzed=False,
        )
        s.add(evt)
        await s.commit()
        await s.refresh(evt)
        return evt


class TestAutoDispatch:
    def test_high_event_creates_case_and_order(self):
        async def t():
            from models import SecurityCase, WorkOrder
            from sqlalchemy import select
            from models import async_session
            from case_manager import case_manager
            await _reset()
            evt = await _mk_event("high")
            from models import SecurityEvent
            async with async_session() as s:
                db_evt = await s.get(SecurityEvent, evt.id)
                case = await case_manager.auto_create_case(s, db_evt)
            assert case is not None
            async with async_session() as s:
                orders = (await s.execute(
                    select(WorkOrder).where(WorkOrder.case_id == case.id)
                )).scalars().all()
                dbc = await s.get(SecurityCase, case.id)
            assert len(orders) >= 1, "high 告警应自动建工单"
            assert dbc.status == "responding", f"预期 responding, 实得 {dbc.status}"
        _run(t())

    def test_medium_event_no_auto_order(self):
        async def t():
            from sqlalchemy import select
            from models import async_session, WorkOrder, SecurityCase
            from case_manager import case_manager
            await _reset()
            evt = await _mk_event("medium")
            from models import SecurityEvent
            async with async_session() as s:
                db_evt = await s.get(SecurityEvent, evt.id)
                case = await case_manager.auto_create_case(s, db_evt)
            assert case is not None
            async with async_session() as s:
                orders = (await s.execute(
                    select(WorkOrder).where(WorkOrder.case_id == case.id)
                )).scalars().all()
            assert len(orders) == 0, "medium 不应自动建工单"
        _run(t())

    def test_sla_breach_marked_by_kpi_and_state(self):
        async def t():
            from models import SecurityCase, async_session
            from ops_metrics import kpi_calculator
            kc = kpi_calculator  # 单例实例
            await _reset()
            # 造一个 high case + 一个过期(breached) case
            from case_manager import case_manager
            evt = await _mk_event("high")
            from models import SecurityEvent
            async with async_session() as s:
                db_evt = await s.get(SecurityEvent, evt.id)
                await case_manager.auto_create_case(s, db_evt)
                # 直接标一个 case breached
                stmt = ("SELECT id FROM security_cases")
                from sqlalchemy import text
                case_id = (await s.execute(text(stmt))).scalars().first()
                c = await s.get(SecurityCase, case_id)
                c.sla_breached = True
                await s.commit()
            start = datetime.now(timezone.utc) - timedelta(days=1)
            end = datetime.now(timezone.utc) + timedelta(hours=1)
            async with async_session() as s:
                rate = await kc.compute_case_sla_breach_rate(
                    s, start=start, end=end
                )
            assert rate > 0, "存在 breached case 时 case_sla_breach_rate 应 > 0"
            assert rate <= 1.0
        _run(t())

    def test_audit_pipeline_path_creates_case(self):
        """Kafka 审计入口(_audit_pipeline)现会触发 auto_create_case(此前从不)。"""
        async def t():
            import log_ingestion
            from sqlalchemy import select
            from models import async_session, SecurityCase, WorkOrder
            from anomaly_detector import AnomalyReport
            await _reset()
            evt = await _mk_event("high")
            # 让流水线主体尽早返回, 只测开头 case 创建
            real_inner = log_ingestion.log_ingestor._audit_pipeline_inner
            log_ingestion.log_ingestor._audit_pipeline_inner = lambda *a, **k: None
            try:
                report = AnomalyReport(event_id=evt.id, anomaly_score=0.9,
                                       is_anomaly=True, deviation_sigma=0.1, reasons=[])
                await log_ingestion.log_ingestor._audit_pipeline(
                    "sess-kafka", evt.id, {"event": "PORT_SCAN"}, report, max_rounds=1
                )
            finally:
                log_ingestion.log_ingestor._audit_pipeline_inner = real_inner
            async with async_session() as s:
                cases = (await s.execute(select(SecurityCase))).scalars().all()
                orders = (await s.execute(select(WorkOrder))).scalars().all()
            assert len(cases) >= 1, "_audit_pipeline(Kafka 入口)应自动建 case"
            assert len(orders) >= 1, "high case 应自动派单建工单"
        _run(t())


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])