"""
P0 修复回归: RollbackStore Redis 双写

修复前 record 只写内存、get() 留有 "# TODO: 从Redis读取"，
进程重启后所有已执行动作（封禁/隔离）的回滚令牌全部丢失。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response_engine.response_executor import RollbackStore


class FakeRedis:
    """最小 Redis stub：get / set(ex=...) / delete"""

    def __init__(self, fail: bool = False):
        self.data: dict = {}
        self.ttls: dict = {}
        self.fail = fail

    async def set(self, key, value, ex=None):
        if self.fail:
            raise RuntimeError("redis down")
        self.data[key] = value
        self.ttls[key] = ex

    async def get(self, key):
        return self.data.get(key)

    async def delete(self, key):
        self.data.pop(key, None)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


RECORDS = [{
    "action": "block_ip",
    "success": True,
    "rollback_token": "rb_1",
    "params": {"src_ip": "1.2.3.4"},
}]


class TestRollbackStoreRedis:
    def test_record_writes_redis_and_survives_memory_loss(self):
        async def t():
            store = RollbackStore()
            fake = FakeRedis()
            store.set_redis(fake)

            await store.record("tok1", RECORDS)
            assert "rollback:tok1" in fake.data
            assert fake.ttls["rollback:tok1"] == RollbackStore.REDIS_TTL_SEC

            # 模拟进程重启：内存清空
            store._store.clear()
            got = await store.get("tok1")
            assert got == RECORDS, "内存丢失后应能从 Redis 恢复回滚记录"
            assert store._store.get("tok1") == RECORDS, "Redis 读回应回填内存"
        _run(t())

    def test_get_prefers_memory(self):
        async def t():
            store = RollbackStore()
            fake = FakeRedis()
            store.set_redis(fake)
            await store.record("tok2", RECORDS)
            fake.data["rollback:tok2"] = "[]"  # 篡改 Redis 值
            got = await store.get("tok2")
            assert got == RECORDS, "内存命中时应优先读内存"
        _run(t())

    def test_no_redis_behaviour_unchanged(self):
        async def t():
            store = RollbackStore()
            await store.record("tok3", RECORDS)
            assert await store.get("tok3") == RECORDS
            assert await store.get("missing") is None
        _run(t())

    def test_redis_failure_degrades_to_memory(self):
        async def t():
            store = RollbackStore()
            store.set_redis(FakeRedis(fail=True))
            # Redis 写失败不应抛异常，动作执行不受影响
            await store.record("tok4", RECORDS)
            assert await store.get("tok4") == RECORDS
        _run(t())

    def test_remove_deletes_both(self):
        async def t():
            store = RollbackStore()
            fake = FakeRedis()
            store.set_redis(fake)
            await store.record("tok5", RECORDS)
            await store.remove("tok5")
            assert "tok5" not in store._store
            assert "rollback:tok5" not in fake.data
            assert await store.get("tok5") is None
        _run(t())
