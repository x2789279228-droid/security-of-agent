"""
P0 修复回归: Redis 基线加载 KEYS → SCAN (#14)

修复前: load_baselines_from_redis 用 KEYS 通配符拉取实体基线,
        键空间为每源 IP 一个 key，长期积累后每次重启都阻塞 Redis 单线程。
修复后: 改用 SCAN 分批迭代；本测试的 FakeRedis 故意不实现 keys()，
        若代码退回 KEYS 将直接报错。
"""
import asyncio
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import AnomalyDetector


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class FakeRedisScanOnly:
    """只实现 SCAN 路径所需方法；keys() 主动抛错以防退化"""

    def __init__(self):
        self.data = {
            "anomaly:baseline:global:hourly": json.dumps([5] * 24),
            "anomaly:baseline:global:event_types": json.dumps({"BRUTE_FORCE": 30}),
            "anomaly:baseline:src_ip:1.2.3.4": json.dumps({
                "hourly_counts": [1] * 24,
                "daily_count": 10, "weekly_count": 24,
                "last_seen": 1.0, "total_count": 24,
                "event_types": ["BRUTE_FORCE"], "first_seen": 0.5,
            }),
            "anomaly:baseline:event_type:BRUTE_FORCE": json.dumps({
                "hourly_counts": [2] * 24,
                "daily_count": 30, "weekly_count": 30,
                "last_seen": 1.0, "total_count": 30,
                "event_types": ["BRUTE_FORCE"], "first_seen": 0.5,
            }),
        }
        self.keys_called = False

    async def get(self, key):
        return self.data.get(key)

    def keys(self, pattern):
        # 修复退化的哨兵：任何 KEYS 调用都应视为缺陷
        self.keys_called = True
        raise RuntimeError("KEYS must not be used; use scan_iter")

    async def scan_iter(self, match=None, count=None):
        import fnmatch
        for key in list(self.data.keys()):
            if fnmatch.fnmatch(key, match):
                yield key


class TestBaselineLoadScan:
    def test_load_baselines_without_keys_command(self):
        async def t():
            fake = FakeRedisScanOnly()
            det = AnomalyDetector()
            det.set_redis(fake)

            await det.load_baselines_from_redis()

            assert fake.keys_called is False, "基线加载不得调用 KEYS"
            assert det.global_hourly_counts == [5] * 24
            assert det.global_event_types["BRUTE_FORCE"] == 30
            assert "1.2.3.4" in det.baselines["src_ip"]
            assert "BRUTE_FORCE" in det.baselines["event_type"]
        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
