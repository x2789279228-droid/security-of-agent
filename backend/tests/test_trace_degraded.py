"""
Agent trace 失败率诊断相关单测 — degraded 语义 + 兼容解析 + 原因分组

覆盖:
  - summary_compression._extract_text_content: OpenAI 标准 / ASTRON 扁平 / 嵌套 text 多格式提取
  - eval_repository.get_trace_stats: degraded 独立于 error, 提供 by_error_type / by_degraded_type 分组

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys
from datetime import datetime, timezone

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

import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestExtractTextContent:
    """_extract_text_content 多格式兼容解析"""

    def test_openai_standard(self):
        from summary_compression import _extract_text_content
        data = {"choices": [{"message": {"content": "标准结果"}}]}
        assert _extract_text_content(data) == "标准结果"

    def test_astron_flat_fields(self):
        from summary_compression import _extract_text_content
        for key in ("output_text", "text", "content", "response", "answer", "result"):
            assert _extract_text_content({key: "扁平结果"}) == "扁平结果"

    def test_nested_choices_text(self):
        from summary_compression import _extract_text_content
        data = {"choices": [{"text": "嵌套text"}]}
        assert _extract_text_content(data) == "嵌套text"

    def test_unparsable_raises(self):
        from summary_compression import _extract_text_content
        with pytest.raises(ValueError):
            _extract_text_content({"foo": "bar"})


class TestGetTraceStatsDegraded:
    """degraded 不计入 error_rate, 且提供原因分组"""

    async def _seed(self):
        from models import AgentTrace, async_session
        async with async_session() as s:
            s.add(AgentTrace(caller="p", operation="execute", model="m", status="success",
                             created_at=datetime.now(timezone.utc)))
            s.add(AgentTrace(caller="p", operation="review", model="m", status="error",
                             error_type="timeout", created_at=datetime.now(timezone.utc)))
            s.add(AgentTrace(caller="p", operation="decompose", model="m", status="degraded",
                             error_type="no_api_key", created_at=datetime.now(timezone.utc)))
            await s.commit()

    async def _reset(self):
        from models import Base, engine
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    def test_degraded_not_counted_as_error(self):
        async def t():
            from eval_repository import get_trace_stats
            await self._reset()
            await self._seed()
            stats = await get_trace_stats(caller="p")
            assert stats["total_calls"] == 3
            assert stats["error_count"] == 1
            assert stats["degraded_count"] == 1
            assert stats["error_rate"] == 0.3333  # round(1/3, 4)
            assert stats["by_error_type"] == {"timeout": 1}
            assert stats["by_degraded_type"] == {"no_api_key": 1}
        _run(t())


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
