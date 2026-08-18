"""
pytest 全局 conftest —— 仅做测试环境注入

职责:
  - 注入测试用 env(指向 sqlite 内存库),避免本地装 asyncpg/postgres
  - patch sqlalchemy.create_async_engine 去掉 PG 专属 pool 参数,使其能在 sqlite 上跑
  - 不定义任何 fixture(测试自带 _reset_db 与 asyncio.run 驱动)
"""
import os
import sys
from pathlib import Path

# 把 backend 目录加入 sys.path(放在 import models 前)
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── env 注入(必须在 import models 之前) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

# ── patch create_async_engine 去掉 PG 专属 pool 参数(sqlite 不支持) ──
import sqlalchemy.ext.asyncio as _sa_async

_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine

# 让旧测试模块(如 test_case_lifecycle)能 patch 后再 import models
import models  # noqa: F401  触发 create_async_engine 应用 patched 版本