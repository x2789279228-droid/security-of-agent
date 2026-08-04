"""pytest 全局配置 — 在收集测试前注入 mock Base，避免 pgvector / 数据库依赖。

当 pytest 收集 trusted_action_gateway/tests/test_tag.py 时，
会先导入 trusted_action_gateway 包 (__init__.py)，进而执行
`from models import Base`。真实 backend/models.py 在导入时创建数据库
引擎并依赖 pgvector + config.settings，会导致测试环境失败。

本 conftest.py 位于 rootdir，pytest 会优先加载它，在 TAG 包导入前
将 mock 的 `models` 模块注入 sys.modules，确保测试使用 SQLite 兼容
的 Base。
"""
import sys
import types

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs


class _TestBase(AsyncAttrs, DeclarativeBase):
    pass


# 注入 mock models 模块 — TAG models.py 执行 `from models import Base` 时拿到的是这个 mock
if "models" not in sys.modules or not hasattr(sys.modules["models"], "_is_test_mock"):
    _mock = types.ModuleType("models")
    _mock.Base = _TestBase
    _mock._is_test_mock = True
    sys.modules["models"] = _mock
