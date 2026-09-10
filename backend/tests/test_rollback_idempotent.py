"""
PR2 控制面: 回滚幂等 + dry-run 预览回归

覆盖:
  1. ssh_firewall.rollback 幂等: 规则不存在 → status=success(非 not_found 失败), idempotent=True
  2. ssh_firewall.rollback_all 幂等: 无规则 → status=ok + idempotent=True
  3. response_registry._restore_host: 无可恢复规则 → success=True + idempotent=True
  4. rollback_batch 幂等短路: 第二次回滚 is_rolled 命中 → 不再逐条删除, 全 succeeded + idempotent
  5. rollback_batch: not_found / idempotent 结果按成功计数
  6. preview: preview_mode ContextVar → _execution_mode()=dry_run（全局 mode 不变）
"""
import asyncio
import os
import sys

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

from response_engine.response_executor import ResponseExecutor, RollbackStore, rollback_store
from response_engine.response_registry import (
    _execution_mode, response_registry,
)
from response_engine.ssh_firewall import SshFirewallAdapter


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class FakeFirewall(SshFirewallAdapter):
    """假适配器: _exec 返回 iptables 列表/删除, 无需 SSH"""

    def __init__(self, rules: list[str]):
        super().__init__()
        self.rules = list(rules)   # 仍在 iptables 里的 rule_id 注释
        self.delete_calls = 0

    def _exec(self, cmd, timeout=None, skip_whitelist=False):
        if cmd.startswith("iptables -L") or cmd.startswith("ip6tables -L"):
            lines = ["Chain INPUT (policy ACCEPT)", "num  target     prot opt source"]
            for i, rid in enumerate(self.rules, start=1):
                lines.append(f"{i}    DROP  all  --  1.2.3.4        0.0.0.0/0  /* {rid} */")
            return "\n".join(lines) + "\n"
        if cmd.startswith("iptables -D") or cmd.startswith("ip6tables -D"):
            self.delete_calls += 1
            self.rules = []  # 删行号即删规则
            return ""
        raise RuntimeError(f"unexpected cmd: {cmd}")


class FakeRedis:
    """最小 Redis stub：get / set(ex=...) / delete（与 test_rollback_store_redis 同模式）"""

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


# ── 注册假动作（挂在全局注册表, 名称带 PR2 前缀防撞） ──

CALLS = {"rollback": 0}


async def _fake_exec(**kwargs):
    return {"action": "fake_pr2_block", "success": True, "mode": "stub"}


async def _fake_rollback(**kwargs):
    CALLS["rollback"] += 1
    return {"action": "fake_pr2_block", "success": True, "deleted": 1}


async def _fake_rollback_not_found(**kwargs):
    return {"action": "fake_pr2_gone", "success": False, "status": "not_found", "deleted": 0}


response_registry.register(
    "fake_pr2_block", _fake_exec, description="test only",
    severity="low", rollback_fn=_fake_rollback,
)
response_registry.register(
    "fake_pr2_gone", _fake_exec, description="test only",
    severity="low", rollback_fn=_fake_rollback_not_found,
)


def _reset_store(fake: FakeRedis):
    rollback_store._store.clear()
    rollback_store._rolled.clear()
    rollback_store.set_redis(fake)


class TestFirewallRollbackIdempotent:
    def test_rollback_twice_both_success(self):
        fw = FakeFirewall(rules=["FW-RULE-111"])
        r1 = fw.rollback("FW-RULE-111")
        assert r1["status"] == "success" and r1["deleted"] == 1
        assert r1.get("idempotent") is False
        # 第二次: 规则已不在 → 幂等成功(而不是 not_found 失败)
        r2 = fw.rollback("FW-RULE-111")
        assert r2["status"] == "success"
        assert r2["deleted"] == 0
        assert r2.get("idempotent") is True
        assert fw.delete_calls >= 1

    def test_rollback_missing_rule_is_success(self):
        fw = FakeFirewall(rules=[])
        r = fw.rollback("FW-RULE-404")
        assert r["status"] == "success", "规则不存在应视为已回滚(success)而非失败"
        assert r["deleted"] == 0
        assert r.get("idempotent") is True

    def test_rollback_all_idempotent_when_no_rules(self):
        fw = FakeFirewall(rules=[])
        r = fw.rollback_all()
        assert r["status"] == "ok"
        assert r["rolled_back"] == 0
        assert r.get("idempotent") is True

    def test_rollback_all_with_rules(self):
        fw = FakeFirewall(rules=["EDR-ISO-777"])
        r = fw.rollback_all()
        assert r["status"] == "ok"
        assert r["rolled_back"] >= 1
        assert r.get("idempotent") is None or r.get("idempotent") is False


class TestRestoreHostIdempotent:
    def test_restore_host_nothing_to_restore_is_success(self):
        async def t():
            import response_engine.ssh_firewall as fw_mod
            fw = FakeFirewall(rules=[])
            orig = fw_mod.ssh_firewall
            fw_mod.ssh_firewall = fw  # _restore_host 运行时 from .ssh_firewall import → 取模块属性
            try:
                r = await response_registry.rollback(
                    "isolate_host", host_ip="10.7.7.7")
            finally:
                fw_mod.ssh_firewall = orig
            assert r["success"] is True
            inner = r.get("result", {})
            assert inner.get("idempotent") is True
            assert inner.get("deleted_count") == 0
        _run(t())


class TestRollbackBatchIdempotent:
    def test_second_rollback_short_circuits(self):
        async def t():
            CALLS["rollback"] = 0
            _reset_store(FakeRedis())
            executor = ResponseExecutor()
            await rollback_store.record("tok-a", [{
                "action": "fake_pr2_block", "success": True,
                "rollback_token": "rb_1", "params": {"src_ip": "1.2.3.4"},
            }])
            r1 = await executor.rollback_batch("tok-a")
            assert r1.succeeded == 1 and r1.failed == 0
            assert CALLS["rollback"] == 1
            assert (await rollback_store.is_rolled("tok-a")) is True

            r2 = await executor.rollback_batch("tok-a")
            assert r2.failed == 0
            assert r2.succeeded == r2.total == 1
            assert all(getattr(x, "idempotent", False) for x in r2.results), \
                "重放结果必须带 idempotent 标记"
            assert CALLS["rollback"] == 1, "is_rolled 短路后不应再执行真实回滚"
        _run(t())

    def test_not_found_counts_as_success_and_marks_rolled(self):
        async def t():
            _reset_store(FakeRedis())
            executor = ResponseExecutor()
            await rollback_store.record("tok-b", [{
                "action": "fake_pr2_gone", "success": True,
                "rollback_token": "rb_2", "params": {"src_ip": "1.2.3.4"},
            }])
            r = await executor.rollback_batch("tok-b")
            assert r.failed == 0
            assert r.succeeded == 1
            assert r.results[0].idempotent is True
            assert (await rollback_store.is_rolled("tok-b")) is True

    def test_redis_persists_rolled_flag(self):
        async def t():
            fake = FakeRedis()
            _reset_store(fake)
            executor = ResponseExecutor()
            await rollback_store.record("tok-c", [{
                "action": "fake_pr2_block", "success": True,
                "rollback_token": "rb_3", "params": {"src_ip": "1.2.3.4"},
            }])
            await executor.rollback_batch("tok-c")
            assert "rollback:done:tok-c" in fake.data, "rolled 标记应双写 Redis"
            # 模拟重启: 内存清空后仍可从 Redis 恢复幂等标记
            rollback_store._rolled.clear()
            assert (await rollback_store.is_rolled("tok-c")) is True

    def test_real_error_not_marked_rolled(self):
        async def t():
            _reset_store(FakeRedis())
            executor = ResponseExecutor()
            await rollback_store.record("tok-d", [{
                "action": "fake_pr2_block", "success": True,
                "rollback_token": "rb_4", "params": {"boom": True},
            }])
            # 临时让回滚函数抛错
            from response_engine import response_registry as _rr
            orig = _rr.response_registry._rollback_fns.get("fake_pr2_block")

            async def _boom(**kwargs):
                raise RuntimeError("ssh down")

            _rr.response_registry._rollback_fns["fake_pr2_block"] = _boom
            try:
                r = await executor.rollback_batch("tok-d")
            finally:
                _rr.response_registry._rollback_fns["fake_pr2_block"] = orig
            assert r.failed == 1
            assert (await rollback_store.is_rolled("tok-d")) is False, \
                "真实失败不应标记已回滚(允许重试)"


class TestPreviewMode:
    def test_preview_mode_overrides_live(self):
        from config import settings
        from response_engine.preview import preview_mode
        saved = getattr(settings, "execution_mode", "live")
        try:
            settings.execution_mode = "live"
            assert _execution_mode() == "live"
            token = preview_mode.set(True)
            try:
                assert _execution_mode() == "dry_run"
            finally:
                preview_mode.reset(token)
            assert _execution_mode() == "live", "退出预览后必须恢复原模式"
        finally:
            settings.execution_mode = saved

    def test_preview_actions_dry_run_no_side_effect(self):
        async def t():
            from config import settings
            from response_engine.preview import preview_mode, preview_actions
            saved = getattr(settings, "execution_mode", "live")
            try:
                settings.execution_mode = "live"  # 执行配置为 live
                assert getattr(preview_mode, "get", lambda d=None: False)(False) is False
                results = await preview_actions([
                    {"name": "block_ip", "params": {"src_ip": "10.9.9.9", "duration_minutes": 5}},
                    {"name": "no_such_action", "params": {}},
                ])
                assert results[0]["success"] is True
                assert results[0]["mode"] == "dry_run"
                assert results[0]["preview"].get("mode") == "dry_run"
                assert results[0]["preview"].get("would_execute") is True
                # 未知动作: 预览不炸, 逐条报告错误
                assert results[1]["success"] is False
                assert "error" in results[1]
                # ContextVar 已复位, 不影响后续真实执行
                assert preview_mode.get() is False
            finally:
                settings.execution_mode = saved
        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
