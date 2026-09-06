"""双池: sqlite 共用 engine; 别名兼容。"""
import models


def test_engine_alias_is_oltp():
    assert models.engine is models.engine_oltp


def test_sqlite_shares_bg_engine():
    url = str(models.settings.database_url or "")
    if url.startswith("sqlite"):
        assert models.engine_bg is models.engine_oltp
    assert models.async_session is not None
    assert models.async_session_bg is not None
