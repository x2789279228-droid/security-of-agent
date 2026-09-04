"""
P0 修复回归: PolicyEngine._cooldowns / SigmaDetector._agg_windows 过期清理

修复前两处数据结构只增不删：每个出现过 src_ip 的条目永久滞留，
长期运行（大量不同攻击源 IP）必然内存无限增长。
修复后: match()/detect() 入口惰性限频触发全量过期清理。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response_engine.response_policies import PolicyEngine
from sigma_detector import SigmaDetector


def _engine_with_cooldowns() -> PolicyEngine:
    engine = PolicyEngine()
    engine.load_defaults()
    now = time.time()
    engine._cooldowns = {
        "C2通信自动封禁": {
            "10.0.0.1": now,               # 冷却中，应保留
            "10.0.0.2": now - 3600 * 24,   # 已过期（冷却 60min），应删除
        },
        "不存在的策略": {
            "10.0.0.3": now - 7200,        # 策略已下线的孤儿条目，超兜底 TTL，应删除
            "10.0.0.4": now - 60,          # 未超兜底 TTL，应保留
        },
    }
    return engine


class TestPolicyCooldownCleanup:
    def test_cleanup_expired_keeps_active_removes_stale(self):
        engine = _engine_with_cooldowns()
        engine.cleanup_expired()
        c2 = engine._cooldowns.get("C2通信自动封禁", {})
        assert "10.0.0.1" in c2, "冷却中的条目不应被清理"
        assert "10.0.0.2" not in c2, "已过期条目应被删除"
        orphan = engine._cooldowns.get("不存在的策略", {})
        assert "10.0.0.3" not in orphan, "孤儿条目应按兜底 TTL 过期"
        assert "10.0.0.4" in orphan

    def test_cleanup_removes_empty_policy_maps(self):
        engine = _engine_with_cooldowns()
        # 把仅剩的活跃条目也变成过期
        engine._cooldowns["C2通信自动封禁"]["10.0.0.1"] = time.time() - 10**7
        engine._cooldowns["不存在的策略"]["10.0.0.4"] = time.time() - 10**7
        engine.cleanup_expired()
        assert engine._cooldowns == {}, "清空后的 policy map 应整键删除"

    def test_match_triggers_lazy_cleanup(self):
        engine = _engine_with_cooldowns()
        engine._last_cleanup = time.time() - engine.CLEANUP_INTERVAL_SEC - 1
        engine.match(threat_type="C2_BEACON", confidence=0.9, severity="high",
                     src_ip="10.0.0.1")
        assert engine._last_cleanup > time.time() - 5, "match 应触发惰性清理"
        assert "10.0.0.2" not in engine._cooldowns.get("C2通信自动封禁", {})

    def test_lazy_cleanup_rate_limited(self):
        engine = _engine_with_cooldowns()
        engine._last_cleanup = time.time()  # 刚清理过
        before = engine._last_cleanup
        engine.match(threat_type="C2_BEACON", confidence=0.9, severity="high",
                     src_ip="10.0.0.2")
        # 距上次清理不足间隔，不应重新触发清理
        assert engine._last_cleanup == before


def _detector_with_stale_windows():
    from collections import deque
    det = SigmaDetector()
    now = time.time()
    det._agg_windows.clear()
    det._agg_windows["SIG-001"]["10.0.0.7"] = deque([(now - 3600, 1)])   # 过期数据
    det._agg_windows["SIG-001"]["10.0.0.8"] = deque([(now, 1)])          # 活跃
    det._agg_windows["SIG-001"]["10.0.0.9"] = deque()                    # 已空
    det._agg_windows["SIG-XXX"]["10.0.0.7"] = deque([(now - 3600, 1)])   # 未知规则
    return det, now


class TestSigmaWindowCleanup:
    def test_cleanup_removes_stale_group_keys(self):
        det, now = _detector_with_stale_windows()
        det.cleanup_windows(now=now)
        g = det._agg_windows.get("SIG-001", {})
        assert "10.0.0.7" not in g, "过期 group_key 应被删除"
        assert "10.0.0.9" not in g, "空 group_key 应被删除"
        assert list(g.get("10.0.0.8") or []) == [(now, 1)], "活跃窗口应保留"
        assert "SIG-XXX" not in det._agg_windows, "清空后的 rule map 应整键删除"

    def test_detect_triggers_lazy_cleanup(self):
        det, _ = _detector_with_stale_windows()
        det._last_cleanup = time.time() - det.CLEANUP_INTERVAL_SEC - 1
        det.detect({"eventType": "INFO", "message": "nothing suspicious"})
        assert "10.0.0.7" not in det._agg_windows.get("SIG-001", {})
        assert "10.0.0.9" not in det._agg_windows.get("SIG-001", {})
