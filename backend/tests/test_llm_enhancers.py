"""
P0.S LLM 增强器单元测试 — 性能门禁 + 降级链路

覆盖:
  - LlmEnhancer: 缓存命中 / 预算超限降级 / 模块开关 / JSON 解析
  - 流量大模型: 触发阈值 / 主路径同步 latency 红线 / 失败降级
  - 钓鱼大模型: should_trigger / aggregate_with_llm 降级 + 升格
  - 数据安全大模型: 分类 / 工单触发 (mock)
  - 性能门禁: 主路径 ≤ 5ms,LLM 异步派发不阻塞

本套测试严格在 sqlite + aiosqlite 内存库跑,无需 PostgreSQL.
"""
import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── 测试环境注入 ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine
def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)
_sa_async.create_async_engine = _patched_create_async_engine

from datetime import datetime, timezone, timedelta


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ════════════════════════════════════════════
# 1. LlmEnhancer 基础设施
# ════════════════════════════════════════════

class TestLlmEnhancer:
    """LLM 增强器通用基础设施"""

    def test_disabled_module_returns_none_without_calling_llm(self):
        """模块禁用时直接返 None,绝不调 LLM API"""
        async def t():
            import llm_enhancer
            # 重置 + 确保开关为 False
            llm_enhancer._MODULE_BUDGET.clear()
            r = await llm_enhancer.enhance(
                module="phishing", cache_key="t1",
                prompt_messages=[], budget_cost_yuan=0.1,
            )
            assert r is None
        _run(t())

    def test_budget_status_default_zero_usage(self):
        """初始预算状态应覆盖全部 7 个模块且 used=0"""
        import llm_enhancer
        s = llm_enhancer.get_module_budget_status()
        assert set(s.keys()) == {
            "traffic", "phishing", "data_security",
            "encrypted_traffic", "edr", "intel", "sandbox",
        }
        for m, info in s.items():
            assert info["used_jpy"] == 0.0
            assert info["usage_pct"] == 0.0

    def test_json_safe_parse_handles_code_fences(self):
        """LLM 输出裹 ```json ... ``` 的兼容性"""
        import llm_enhancer
        # 普通对象
        assert llm_enhancer._safe_parse_json('{"a":1}') == {"a": 1}
        # 代码块包裹
        assert llm_enhancer._safe_parse_json('```json\n{"a":2}\n```') == {"a": 2}
        # 前后带多余文字
        assert llm_enhancer._safe_parse_json('Here is your answer:\n{"x":99}\nDone.') == {"x": 99}
        # 非 JSON
        assert llm_enhancer._safe_parse_json("not json") is None
        assert llm_enhancer._safe_parse_json("") is None
        assert llm_enhancer._safe_parse_json(None) is None

    def test_budget_check_rejects_when_over_limit(self, monkeypatch):
        """in strict mode (llm_budget_unlimited=False) module budget over-limit rejects"""
        import llm_enhancer
        import config as _cfg
        monkeypatch.setattr(_cfg.settings, "llm_budget_unlimited", False)
        llm_enhancer._MODULE_BUDGET.clear()
        allowed = 0
        for _ in range(100):
            if llm_enhancer._check_and_consume_budget("traffic", 0.1):
                allowed += 1
        assert allowed < 100
        assert not llm_enhancer._check_and_consume_budget("traffic", 0.1)

    def test_budget_unlimited_allows_all_calls(self, monkeypatch):
        """unlimited(unlimited=True) : budget only records, never rejects LLM enhancer call"""
        import llm_enhancer
        import config as _cfg
        monkeypatch.setattr(_cfg.settings, "llm_budget_unlimited", True)
        llm_enhancer._MODULE_BUDGET.clear()
        allowed = 0
        for _ in range(200):
            if llm_enhancer._check_and_consume_budget("traffic", 0.1):
                allowed += 1
        assert allowed == 200
        assert llm_enhancer._check_and_consume_budget("traffic", 0.1)

    def test_budget_release_on_failure(self):
        """失败时退还预算"""
        import llm_enhancer
        llm_enhancer._MODULE_BUDGET.clear()
        assert llm_enhancer._check_and_consume_budget("phishing", 1.0)
        used_before = llm_enhancer._MODULE_BUDGET["phishing"]["used"]
        llm_enhancer._release_budget_on_failure("phishing", 1.0)
        used_after = llm_enhancer._MODULE_BUDGET["phishing"]["used"]
        assert used_after == used_before - 1.0

    def test_reset_daily_budgets_zero_all_modules(self):
        import llm_enhancer
        llm_enhancer._MODULE_BUDGET["phishing"]["used"] = 50
        llm_enhancer.reset_daily_budgets()
        for m in ("traffic", "phishing", "data_security"):
            assert llm_enhancer._MODULE_BUDGET[m]["used"] == 0.0

    def test_is_module_enabled_default_false(self):
        import llm_enhancer
        assert llm_enhancer.is_module_enabled("traffic") is False
        assert llm_enhancer.is_module_enabled("phishing") is False
        assert llm_enhancer.is_module_enabled("data_security") is False

    def test_safe_dispatch_does_not_throw_without_event_loop(self):
        """无 event loop 场景 safe_dispatch 不抛错"""
        import llm_enhancer
        async def noop():
            await asyncio.sleep(0.001)
        # 调用不抛
        llm_enhancer.safe_dispatch(noop(), log_label="test")


# ════════════════════════════════════════════
# 2. 流量大模型
# ════════════════════════════════════════════

class TestTrafficLlmAnomaly:

    def test_should_trigger_returns_false_when_disabled(self):
        """模块禁用时,3σ 异常也不触发 LLM"""
        from traffic_baseline import should_trigger_llm
        # 默认 settings.llm_traffic_enabled=False
        assert not should_trigger_llm({
            "is_anomaly": True, "z_score": 5.0,
        })

    def test_should_trigger_returns_false_when_not_anomaly(self):
        """非异常(verdict=False) 不触发"""
        from traffic_baseline import llm_anomaly
        # 临时打开开关
        from config import settings
        original = settings.llm_traffic_enabled
        settings.llm_traffic_enabled = True
        try:
            assert not llm_anomaly.should_trigger_llm({"is_anomaly": False, "z_score": 0.5})
            assert not llm_anomaly.should_trigger_llm({"is_anomaly": True, "z_score": 2.5})
        finally:
            settings.llm_traffic_enabled = original

    def test_should_trigger_returns_true_on_3sigma_when_enabled(self):
        from traffic_baseline import llm_anomaly
        from config import settings
        original = settings.llm_traffic_enabled
        settings.llm_traffic_enabled = True
        try:
            assert llm_anomaly.should_trigger_llm({"is_anomaly": True, "z_score": 3.5})
            assert llm_anomaly.should_trigger_llm({"is_anomaly": True, "z_score": -3.5})
        finally:
            settings.llm_traffic_enabled = original

    def test_main_path_latency_under_5ms_when_disabled(self):
        """性能门禁:主路径(规则)延迟 < 5ms 无论 LLM 是否启用"""
        from traffic_baseline.seasonal import seasonal_detector
        seasonal_detector._series.clear()
        # 灌够 48 个观测以触发检测
        for i in range(60):
            seasonal_detector.add_observation("10.0.0.1", "bytes_out", 1000.0 + i * 10)
        # 触发 detect 100 次,延迟必须 < 5ms 平均
        t0 = time.perf_counter()
        for _ in range(100):
            seasonal_detector.detect("10.0.0.1", "bytes_out")
        elapsed_ms = (time.perf_counter() - t0) * 1000 / 100
        assert elapsed_ms < 5.0, f"Main path latency >= 5ms: {elapsed_ms:.3f}ms"

    def test_llm_analyze_returns_none_when_disabled(self):
        """模块禁用时 LLM 分析直接返 None (无副作用)"""
        async def t():
            from traffic_baseline import llm_anomaly
            r = await llm_anomaly.llm_analyze_anomaly(
                ip="10.0.0.1", metric="bytes_out",
                detect_result={"z_score": 4.0, "current_value": 8000, "expected": 100},
                flow_id=0,
            )
            assert r is None
        _run(t())


# ════════════════════════════════════════════
# 3. 钓鱼大模型
# ════════════════════════════════════════════

class TestPhishingLlmDimension:

    def test_should_trigger_returns_false_when_disabled(self):
        from phishing_guard.llm_dimension import should_trigger_llm
        from phishing_guard.models import PhishingVerdict
        v = PhishingVerdict(detection_type="email", target="t", risk_level="phishing", score=80)
        assert not should_trigger_llm(v)

    def test_should_trigger_returns_false_for_safe_verdict(self):
        """安全 verdict 不调 LLM (按方案:A 只在 suspicious+phishing 触发)"""
        from phishing_guard.llm_dimension import should_trigger_llm
        from phishing_guard.models import PhishingVerdict
        from config import settings
        original = settings.llm_phishing_enabled
        settings.llm_phishing_enabled = True
        try:
            safe_v = PhishingVerdict(detection_type="email", target="t", risk_level="safe", score=20)
            assert not should_trigger_llm(safe_v)
            susp_v = PhishingVerdict(detection_type="email", target="t", risk_level="suspicious", score=50)
            assert should_trigger_llm(susp_v)
            phish_v = PhishingVerdict(detection_type="email", target="t", risk_level="phishing", score=80)
            assert should_trigger_llm(phish_v)
        finally:
            settings.llm_phishing_enabled = original

    def test_aggregate_with_llm_degrade_returns_rule_verdict(self):
        """LLM 失败(llm_indicator=None) → 返回原 verdict 不变"""
        from phishing_guard.scoring import aggregate_with_llm
        from phishing_guard.models import PhishingVerdict
        rule_v = PhishingVerdict(
            detection_type="email", target="t", risk_level="suspicious",
            confidence=0.6, score=45, indicators=[], summary="x", suggested_actions=[],
        )
        out = aggregate_with_llm(rule_v, None)
        assert out.risk_level == "suspicious"
        assert out.score == 45
        assert out.confidence == 0.6

    def test_aggregate_with_llm_inject_indicator_includes_review_action(self):
        """注入 LLM indicator 后, suggested_actions 含复核提示"""
        from phishing_guard.scoring import aggregate_with_llm
        from phishing_guard.models import PhishingVerdict, PhishingIndicator
        rule_v = PhishingVerdict(
            detection_type="email", target="t", risk_level="suspicious",
            confidence=0.6, score=45, indicators=[], summary="x", suggested_actions=[],
        )
        llm_ind = PhishingIndicator(
            name="LLM 仿冒判定", category="llm_semantic",
            severity="high", detail="x", score=32.0,
        )
        out = aggregate_with_llm(rule_v, llm_ind)
        # suspicious 或 phishing 都应有 LLM 复核提示
        assert any("LLM 复核" in a for a in out.suggested_actions)
        # 指标列表含 LLM 维度
        assert any(i.category == "llm_semantic" for i in out.indicators)

    def test_phishing_detect_email_main_path_under_5ms(self):
        """性能门禁:detect_email 主路径 < 5ms (默认 llm_enrich=False)"""
        from phishing_guard import phishing_guard
        from phishing_guard.models import EmailPhishingRequest
        req = EmailPhishingRequest(
            sender="no-reply@amaz0n-secure.com",
            subject="[URGENT] Verify your password in 24 hours",
            body="Click here: http://amaz0n-verify.com/x?token=abc",
        )
        # 预热
        for _ in range(10):
            phishing_guard.detect_email(req)

        t0 = time.perf_counter()
        for _ in range(100):
            phishing_guard.detect_email(req)
        elapsed_ms = (time.perf_counter() - t0) * 1000 / 100
        assert elapsed_ms < 5.0, f"detect_email latency >= 5ms: {elapsed_ms:.3f}ms"

    def test_phishing_detect_email_with_llm_enrich_no_main_path_block(self):
        """即使 llm_enrich=True,模块禁用时主路径也 0 LLM 调用"""
        from phishing_guard import phishing_guard
        from phishing_guard.models import EmailPhishingRequest
        req = EmailPhishingRequest(
            sender="x@y.com", subject="test", body="normal content",
        )
        t0 = time.perf_counter()
        v = phishing_guard.detect_email(req, llm_enrich=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        # 模块禁用 → 主路径纯规则 < 5ms
        assert elapsed_ms < 5.0
        assert v.detection_type == "email"


# ════════════════════════════════════════════
# 4. 数据安全大模型
# ════════════════════════════════════════════

class TestDataSecurityLlmClassifier:

    def test_classify_returns_none_when_disabled(self):
        async def t():
            from data_security import classify_session
            v = await classify_session(http_summary={
                "url": "/api/export/users.csv", "method": "GET",
                "body_snippet": "name,email,phone\nAlice,alice@x.com,13800",
                "rule_hit": "sensitive_data_leak",
            })
            assert v is None
        _run(t())

    def test_classify_parses_valid_llm_json(self):
        """模拟 LLM 返回 → 解析正确,字段校验通过"""
        async def t():
            from data_security import llm_classifier
            # 临时启用模块 + monkeypatch enhance_data_security
            from config import settings
            settings.llm_data_security_enabled = True
            original_enhance = None
            try:
                import llm_enhancer
                async def fake_enhance(*, cache_key, prompt_messages, budget_cost_yuan):
                    return {
                        "is_sensitive": True, "category": "PII",
                        "confidence": 0.9, "false_positive_prob": 0.1,
                        "rationale": "包含 PII 列", "recommended_action": "audit",
                    }
                original_enhance = llm_enhancer.enhance_data_security
                llm_enhancer.enhance_data_security = fake_enhance

                v = await llm_classifier.classify_session(http_summary={
                    "url": "/api/users.csv", "method": "GET",
                    "body_snippet": "name,email",
                    "rule_hit": "sensitive_data_leak",
                })
                assert v is not None
                assert v["is_sensitive"] is True
                assert v["category"] == "PII"
                assert v["confidence"] == 0.9
            finally:
                if original_enhance is not None:
                    llm_enhancer.enhance_data_security = original_enhance
                settings.llm_data_security_enabled = False
        _run(t())

    def test_classify_invalid_fields_get_defaults(self):
        """LLM 返回非法字段 → 兜底默认值"""
        async def t():
            from data_security import llm_classifier
            from config import settings
            settings.llm_data_security_enabled = True
            try:
                import llm_enhancer
                async def fake_enhance(*, cache_key, prompt_messages, budget_cost_yuan):
                    return {
                        "is_sensitive": "yes",            # 非布尔
                        "category": "weird_category",     # 非法
                        "confidence": "high",             # 非数字
                        "recommended_action": "hack_it",  # 非法
                    }
                llm_enhancer.enhance_data_security = fake_enhance
                v = await llm_classifier.classify_session(http_summary={
                    "url": "/x", "method": "GET", "body_snippet": "", "rule_hit": "",
                })
                assert v is not None
                assert v["category"] == "none"
                assert v["recommended_action"] == "audit"
                assert 0.0 <= v["confidence"] <= 1.0
            finally:
                settings.llm_data_security_enabled = False
        _run(t())


# ════════════════════════════════════════════
# 5. 性能门禁综合
# ════════════════════════════════════════════

class TestPerformanceGates:

    def test_module_off_main_path_zero_llm_calls(self):
        """模块开关全关时,1000 次检测 0 次 LLM 调用 (防意外触发)"""
        import llm_enhancer
        llm_enhancer._MODULE_BUDGET.clear()
        from phishing_guard import phishing_guard
        from phishing_guard.models import EmailPhishingRequest
        req = EmailPhishingRequest(sender="x@y.com", subject="t", body="b")
        for _ in range(100):
            phishing_guard.detect_email(req, llm_enrich=True)
        for m in ("traffic", "phishing", "data_security"):
            used = llm_enhancer.get_module_budget_status().get(m, {}).get("used_jpy", 0)
            assert used == 0, f"意外消耗 {m} 预算: {used}"

    def test_concurrency_semaphore_capped_at_5(self):
        """5 并发上限:开 100 并发 enhance 任务,允许并行的最多 5"""
        async def t():
            import llm_enhancer
            from config import settings
            settings.llm_traffic_enabled = True
            try:
                current_parallel = 0
                max_parallel = 0

                async def slow_task():
                    nonlocal current_parallel, max_parallel
                    # _get_semaphore 内部已 limit 5
                    sem = llm_enhancer._get_semaphore()
                    async with sem:
                        current_parallel += 1
                        max_parallel = max(max_parallel, current_parallel)
                        await asyncio.sleep(0.1)
                        current_parallel -= 1

                await asyncio.gather(*[slow_task() for _ in range(20)])
                assert max_parallel <= 5, f"并发超 5 上限: {max_parallel}"
            finally:
                settings.llm_traffic_enabled = False
        _run(t())


# ── 运行入口 ──

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])