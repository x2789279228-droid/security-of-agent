"""learn_loop 事件边测试: 案例 close/FP → 复盘草稿(幂等), disposition → 反馈。

不重写 test_learn_loop.py / test_case_lifecycle.py 的既有用例;
沿用 test_ops_loop.py 的 env-var bootstrap (SHARED_MEMORY_DATABASE_URL
必须在 import models 之前注入)。
"""
import asyncio
import contextlib
import os
import sys
from pathlib import Path

# ── 测试环境前置(必须在 import models 之前注入) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine


def _run(coro):
    """显式 asyncio 驱动(每个测试独立 event loop, 跑完即关)。"""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


@contextlib.asynccontextmanager
async def _db():
    """每个测试一个独立内存库引擎(StaticPool 单连接, 跨读写一致)。"""
    from sqlalchemy.pool import StaticPool
    from models import Base

    eng = _sa_async.create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from sqlalchemy.ext.asyncio import async_sessionmaker
    sm = async_sessionmaker(eng, expire_on_commit=False)
    try:
        yield sm
    finally:
        await eng.dispose()


class _SpawnRecorder:
    """捕获 fire-and-forget 协程, 由测试显式驱动(替代后台调度)。"""

    def __init__(self):
        self.coros = []

    def __call__(self, coro):
        self.coros.append(coro)

    async def drain(self):
        coros, self.coros = self.coros, []
        for c in coros:
            await c


def _case_manager_mod():
    import case_manager as cm
    return cm


def _stub_llm_analyze():
    """测试环境禁走真实 LLM(复盘 LLM 分析可选且 fail-open)。

    赋在实例上, 调用形态是 self._llm_analyze(case, timeline, fp_count),
    不会再注入 self, 因此 fake 不能带 self 参数; 必须是 async(被 await)。
    """
    from post_mortem_service import post_mortem_service
    original = post_mortem_service._llm_analyze

    async def fake(case, timeline, fp_count=0):
        return {}

    post_mortem_service._llm_analyze = fake
    return original


def _restore_llm_analyze(original):
    from post_mortem_service import post_mortem_service
    if original is not None:
        post_mortem_service._llm_analyze = original


class TestCloseToPostMortemEdge:

    def _make_case_row(self, number: str):
        from models import SecurityCase
        return SecurityCase(
            case_number=number, title="学习闭环边测试",
            status="open", priority="high", threat_type="PORT_SCAN",
            event_ids=[], event_count=0, src_ips=[], dst_ips=[],
        )

    def test_close_creates_post_mortem_draft(self):
        async def t():
            import models
            from sqlalchemy import select
            from models import PostMortem
            from unittest.mock import patch
            cm = _case_manager_mod()
            recorder = _SpawnRecorder()
            orig_async_session = models.async_session
            orig_llm = _stub_llm_analyze()

            async def _capture(case_id):
                recorder(cm.case_manager._draft_post_mortem_task(case_id))

            try:
                async with _db() as sm:
                    models.async_session = sm
                    async with sm() as s:
                        case = self._make_case_row("CASE-EDGE-PM-1")
                        s.add(case)
                        await s.commit()
                        case_id = case.id

                    with patch.object(
                        cm.case_manager, "schedule_draft_post_mortem",
                        side_effect=_capture,
                    ):
                        async with sm() as s:
                            result = await cm.case_manager.update_status(
                                s, case_id, "closed", by="tester"
                            )
                            assert result["success"] is True
                            assert result["new_status"] == "closed"

                    assert len(recorder.coros) == 1
                    await recorder.drain()

                    async with sm() as s:
                        pm = (await s.execute(
                            select(PostMortem).where(PostMortem.case_id == case_id)
                        )).scalars().first()
                        assert pm is not None
                        assert pm.status == "draft"
                        assert pm.author == "learn_loop"
            finally:
                models.async_session = orig_async_session
                _restore_llm_analyze(orig_llm)
        _run(t())

    def test_close_false_positive_also_drafts(self):
        async def t():
            import models
            from sqlalchemy import select
            from models import PostMortem
            from unittest.mock import patch
            cm = _case_manager_mod()
            recorder = _SpawnRecorder()
            orig_async_session = models.async_session
            orig_llm = _stub_llm_analyze()

            async def _capture(case_id):
                recorder(cm.case_manager._draft_post_mortem_task(case_id))

            try:
                async with _db() as sm:
                    models.async_session = sm
                    async with sm() as s:
                        case = self._make_case_row("CASE-EDGE-PM-2")
                        s.add(case)
                        await s.commit()
                        case_id = case.id

                    with patch.object(
                        cm.case_manager, "schedule_draft_post_mortem",
                        side_effect=_capture,
                    ):
                        async with sm() as s:
                            result = await cm.case_manager.update_status(
                                s, case_id, "false_positive", by="tester"
                            )
                            assert result["success"] is True
                    await recorder.drain()

                    async with sm() as s:
                        pm = (await s.execute(
                            select(PostMortem).where(PostMortem.case_id == case_id)
                        )).scalars().first()
                        assert pm is not None
            finally:
                models.async_session = orig_async_session
                _restore_llm_analyze(orig_llm)
        _run(t())

    def test_close_twice_still_one_post_mortem(self):
        """重复触发(定时任务 + 学习闭环动作并发) → 仅一行, 二次命中 existing=True。"""
        async def t():
            import models
            from sqlalchemy import select, func
            from models import PostMortem
            from post_mortem_service import post_mortem_service
            cm = _case_manager_mod()
            orig_async_session = models.async_session
            orig_llm = _stub_llm_analyze()
            try:
                async with _db() as sm:
                    async with sm() as s:
                        case = self._make_case_row("CASE-EDGE-PM-3")
                        s.add(case)
                        await s.commit()
                        case_id = case.id

                    async with sm() as s:
                        r1 = await post_mortem_service.create_post_mortem(
                            s, case_id, author="learn_loop"
                        )
                        assert r1["success"] is True
                        assert r1.get("existing") is None

                    async with sm() as s:
                        r2 = await post_mortem_service.create_post_mortem(
                            s, case_id, author="learn_loop"
                        )
                        assert r2["success"] is True
                        assert r2.get("existing") is True
                        assert r2["id"] == r1["id"]

                    async with sm() as s:
                        count = (await s.execute(
                            select(func.count(PostMortem.id)).where(
                                PostMortem.case_id == case_id)
                        )).scalar()
                        assert count == 1

                    # 走 case_manager 后台任务路径再补一次 → 依旧一行
                    models.async_session = sm
                    await cm.case_manager._draft_post_mortem_task(case_id)

                    async with sm() as s:
                        count = (await s.execute(
                            select(func.count(PostMortem.id)).where(
                                PostMortem.case_id == case_id)
                        )).scalar()
                        assert count == 1
            finally:
                models.async_session = orig_async_session
                _restore_llm_analyze(orig_llm)
        _run(t())


class TestDispositionFeedbackEdge:

    def _seed_case(self, s, number: str):
        from models import SecurityCase
        case = SecurityCase(
            case_number=number, title="反馈边测试", status="open",
            priority="medium", threat_type="PORT_SCAN",
            event_ids=[], event_count=0, src_ips=[], dst_ips=[],
        )
        s.add(case)
        return case

    def test_disposition_false_positive_creates_feedback(self):
        async def t():
            from sqlalchemy import select
            from models import FeedbackRecord
            from case_manager import case_manager
            async with _db() as sm:
                async with sm() as s:
                    case = self._seed_case(s, "CASE-EDGE-FB-1")
                    await s.commit()
                    case_id = case.id

                async with sm() as s:
                    result = await case_manager.set_disposition(
                        s, case_id, "误报，检测逻辑误判", by="op1"
                    )
                    assert result["success"] is True

                async with sm() as s:
                    rows = (await s.execute(
                        select(FeedbackRecord).where(
                            FeedbackRecord.case_id == case_id)
                    )).scalars().all()
                    assert len(rows) == 1
                    assert rows[0].feedback_type == "false_positive"
                    assert rows[0].submitted_by == "op1"
                    assert "误报" in (rows[0].reason or "")

                # 24h 内重复写入同类结论 → 去重仍只有一条
                async with sm() as s:
                    result2 = await case_manager.set_disposition(
                        s, case_id, "false_positive again", by="op2"
                    )
                    assert result2["success"] is True
                async with sm() as s:
                    count = (await s.execute(
                        select(FeedbackRecord.id).where(
                            FeedbackRecord.case_id == case_id)
                    )).scalars().all()
                    assert len(count) == 1
        _run(t())

    def test_disposition_unrelated_text_no_feedback(self):
        async def t():
            from sqlalchemy import select
            from models import FeedbackRecord
            from case_manager import case_manager
            async with _db() as sm:
                async with sm() as s:
                    case = self._seed_case(s, "CASE-EDGE-FB-2")
                    await s.commit()
                    case_id = case.id

                async with sm() as s:
                    result = await case_manager.set_disposition(
                        s, case_id, "已完成处置并归档", by="op1"
                    )
                    assert result["success"] is True

                async with sm() as s:
                    rows = (await s.execute(
                        select(FeedbackRecord)
                    )).scalars().all()
                    assert rows == []
        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
