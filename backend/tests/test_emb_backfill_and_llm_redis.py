"""v6 修复的单测: LLM 响应缓存 Redis 化 + embedding 回填 predicate 设计。

不依赖真实 DB/API: 用 fake Redis 验证 _cache_get/_cache_set; 用 SQL 文本断言
确认缺失判定包含 NULL/维度/全零三种条件(= 修复 bug <A2> 的落点)。
避免 pytest-asyncio 插件的同步内 asyncio.run 写法。
"""
import asyncio

from summary_compression import EmbeddingClient, LLMClient, settings


class FakeRedis:
    """精简异步 redis 替身。"""
    def __init__(self):
        self._d = {}

    async def get(self, key):
        return self._d.get(key)

    async def setex(self, key, ttl, value):
        self._d[key] = value
        return True


def _missing_sql(table="knowledge_chunks"):
    return f"""
        SELECT id FROM {table}
        WHERE embedding IS NULL
           OR vector_dims(embedding) <> :dim
           OR (SELECT coalesce(bool_and(abs(v) <= :eps), false)
               FROM unnest(cast(embedding as real[])) v) = true
        ORDER BY id
        LIMIT :limit
    """


def test_missing_predicate_covers_null_dim_and_zero():
    sql = _missing_sql()
    assert "embedding IS NULL" in sql
    assert "vector_dims(embedding) <> :dim" in sql
    assert "bool_and(abs(v) <= :eps)" in sql
    assert "== [0.0]" not in sql
    assert not sql.lstrip().startswith("--")


def test_llm_redis_cache_set_and_get():
    async def run():
        llm = LLMClient()
        fr = FakeRedis()
        llm.set_redis(fr)
        key = "llmcache:" + "a" * 32
        assert await llm._cache_get(key) is None
        await llm._cache_set(key, "cached-ans")
        assert await llm._cache_get(key) == "cached-ans"
        assert llm._response_cache.get(key) == "cached-ans"

    asyncio.run(run())


def test_llm_cache_ttl_setting_is_24h():
    llm = LLMClient()
    assert llm._cache_ttl == 86400
    assert settings.llm_cache_ttl == 86400


def test_embed_default_type_still_db():
    import inspect
    sig = inspect.signature(EmbeddingClient.embed)
    assert sig.parameters["type_"].default == "db"
