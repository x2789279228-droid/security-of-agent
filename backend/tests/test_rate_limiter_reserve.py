"""
P0 修复回归: RateLimiter 预留式计数

修复前: check() 只读、record() 在动作执行后才计数，多协程并发下
        check→(await 执行动作)→record 之间可无限超发（TOCTOU 竞态）。
修复后: check() 通过时同步预留名额（单事件循环内原子），record()
        只做失败补偿，不再重复计数。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_guard.rate_limiter import RateLimiter


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestReserveOnCheck:
    def test_check_reserves_slot_immediately(self):
        rl = RateLimiter()
        results = [rl.check("block_ip", {}) for _ in range(12)]
        passed = sum(1 for r in results if r.passed)
        assert passed == 10, f"block_ip 限速 10/min，实际通过 {passed}"
        # 占坑数与通过数严格一致
        assert len(rl._action_calls["block_ip"]) == passed

    def test_global_limit_enforced(self):
        rl = RateLimiter()
        # alert_only 单动作上限 50，全局上限 30 先触顶
        passed = sum(1 for _ in range(40) if rl.check("alert_only", {}).passed)
        assert passed == RateLimiter.GLOBAL_LIMIT

    def test_concurrent_check_exec_record_never_exceeds_limit(self):
        """旧实现的核心缺陷场景：多协程 check 读到同一快照后各自执行。"""
        async def t():
            rl = RateLimiter()
            executed = []

            async def worker():
                if rl.check("block_ip", {}).passed:
                    await asyncio.sleep(0)  # 模拟动作执行的真实 await 挂起点
                    executed.append(1)
                    rl.record("block_ip", success=True)

            await asyncio.gather(*[worker() for _ in range(25)])
            return len(executed)

        executed = _run(t())
        assert executed == 10, f"窗口内实际执行 {executed} 次，应恰好为上限 10"

    def test_failed_action_releases_quota(self):
        rl = RateLimiter()
        for _ in range(10):
            assert rl.check("block_ip", {}).passed
        assert not rl.check("block_ip", {}).passed  # 已达上限

        # 动作执行失败 → 释放一个预留名额
        rl.record("block_ip", success=False)
        assert rl.check("block_ip", {}).passed

    def test_successful_record_does_not_double_count(self):
        rl = RateLimiter()
        assert rl.check("block_ip", {}).passed
        rl.record("block_ip", success=True)
        assert len(rl._action_calls["block_ip"]) == 1, "record 不应重复计数"
        for _ in range(9):
            assert rl.check("block_ip", {}).passed
        assert not rl.check("block_ip", {}).passed

    def test_release_removes_one_from_both_windows(self):
        rl = RateLimiter()
        assert rl.check("block_ip", {}).passed
        assert rl.check("isolate_host", {}).passed
        rl.release("block_ip")
        assert len(rl._global_calls) == 1
        assert len(rl._action_calls["block_ip"]) == 0
        assert len(rl._action_calls["isolate_host"]) == 1
