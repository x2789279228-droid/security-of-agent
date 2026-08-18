"""
可观测性模块单元测试

覆盖:
  - PipelineTracer: span 创建/结束/超时/环形缓冲/阶段统计/事件时间线
  - HealthMonitor: 错误率触发/延迟触发/卡死触发/健康快照
  - Watchdog: patrol 全绿不触发 / 规则降级诊断
"""
import asyncio
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from observability.pipeline_tracer import (
    PipelineTracer, Span, STAGES,
    STATUS_SUCCESS, STATUS_ERROR, STATUS_TIMEOUT, STATUS_RUNNING,
)
from observability.health_monitor import (
    HealthMonitor, HealthSnapshot, StageHealth,
    ERROR_RATE_THRESHOLD, STUCK_THRESHOLD_SECONDS,
)
from observability.watchdog import WatchdogAgent


# ════════════════════════════════════════════
# 1. PipelineTracer 测试
# ════════════════════════════════════════════

class TestPipelineTracer:
    """PipelineTracer 测试"""

    def setup_method(self):
        self.tracer = PipelineTracer(buffer_size=100)

    def test_start_and_end_span(self):
        sp = self.tracer.start_span("decomposer", event_id=42, session_id="s1")
        assert sp.status == STATUS_RUNNING
        assert sp.stage == "decomposer"
        assert sp.event_id == 42

        self.tracer.end_span(sp)
        assert sp.status == STATUS_SUCCESS
        assert sp.latency_ms >= 0
        assert sp.is_complete

    def test_end_span_with_error(self):
        sp = self.tracer.start_span("executor", event_id=1)
        self.tracer.end_span(sp, error="LLM timeout")
        assert sp.status == STATUS_ERROR
        assert "LLM timeout" in sp.error

    def test_mark_timeout(self):
        sp = self.tracer.start_span("reviewer", event_id=2)
        self.tracer.mark_timeout(sp)
        assert sp.status == STATUS_TIMEOUT
        assert "timed out" in sp.error

    def test_context_manager_success(self):
        with self.tracer.span("tool_builder", event_id=10) as sp:
            pass  # 正常执行
        assert sp.status == STATUS_SUCCESS

    def test_context_manager_error(self):
        with pytest.raises(ValueError):
            with self.tracer.span("executor", event_id=11) as sp:
                raise ValueError("test error")
        assert sp.status == STATUS_ERROR
        assert "test error" in sp.error

    def test_context_manager_timeout(self):
        with pytest.raises(asyncio.TimeoutError):
            with self.tracer.span("decomposer", event_id=12) as sp:
                raise asyncio.TimeoutError()
        assert sp.status == STATUS_TIMEOUT

    def test_ring_buffer_overflow(self):
        tracer = PipelineTracer(buffer_size=5)
        for i in range(10):
            sp = tracer.start_span("ingest", event_id=i)
            tracer.end_span(sp)
        # 只保留最近 5 条
        spans = tracer.get_recent_spans(limit=20)
        assert len(spans) == 5
        # event_id 0-4 应被淘汰
        event_ids = {s["event_id"] for s in spans}
        assert 0 not in event_ids
        assert 9 in event_ids

    def test_get_recent_spans_filter_by_event(self):
        for i in range(5):
            sp = self.tracer.start_span("executor", event_id=100)
            self.tracer.end_span(sp)
        sp = self.tracer.start_span("executor", event_id=200)
        self.tracer.end_span(sp)

        spans = self.tracer.get_recent_spans(event_id=100)
        assert len(spans) == 5
        assert all(s["event_id"] == 100 for s in spans)

    def test_get_recent_spans_filter_by_stage(self):
        for stage in ["decomposer", "executor", "reviewer"]:
            sp = self.tracer.start_span(stage, event_id=1)
            self.tracer.end_span(sp)

        spans = self.tracer.get_recent_spans(stage="executor")
        assert len(spans) == 1
        assert spans[0]["stage"] == "executor"

    def test_get_active_spans(self):
        sp1 = self.tracer.start_span("decomposer", event_id=1)
        sp2 = self.tracer.start_span("executor", event_id=2)
        active = self.tracer.get_active_spans()
        assert len(active) == 2
        # 结束后不再活跃
        self.tracer.end_span(sp1)
        active = self.tracer.get_active_spans()
        assert len(active) == 1

    def test_get_stage_stats(self):
        # 模拟 executor 阶段: 7 成功 + 3 失败
        for i in range(7):
            sp = self.tracer.start_span("executor", event_id=i)
            self.tracer.end_span(sp)
        for i in range(3):
            sp = self.tracer.start_span("executor", event_id=100 + i)
            self.tracer.end_span(sp, error="fail")

        stats = self.tracer.get_stage_stats()
        executor_stats = stats["executor"]
        assert executor_stats["total"] == 10
        assert executor_stats["success"] == 7
        assert executor_stats["error"] == 3
        assert abs(executor_stats["error_rate"] - 0.3) < 0.01

    def test_get_event_timeline(self):
        for stage in ["ingest", "decomposer", "executor", "reviewer"]:
            sp = self.tracer.start_span(stage, event_id=999)
            self.tracer.end_span(sp)

        timeline = self.tracer.get_event_timeline(999)
        assert len(timeline) == 4
        stages = [s["stage"] for s in timeline]
        assert stages == ["ingest", "decomposer", "executor", "reviewer"]

    def test_span_to_dict(self):
        sp = self.tracer.start_span("cad_verify", event_id=5, session_id="sess-1")
        self.tracer.end_span(sp, metadata={"claims_verified": 3})
        d = sp.to_dict()
        assert d["stage"] == "cad_verify"
        assert d["event_id"] == 5
        assert d["metadata"]["claims_verified"] == 3
        assert "latency_ms" in d


# ════════════════════════════════════════════
# 2. HealthMonitor 测试
# ════════════════════════════════════════════

class TestHealthMonitor:
    """HealthMonitor 测试"""

    def setup_method(self):
        self.tracer = PipelineTracer(buffer_size=200)
        self.monitor = HealthMonitor()
        # Patch: 直接操作 sys.modules 中的模块对象
        import sys
        hm_module = sys.modules["observability.health_monitor"]
        self._orig_tracer = hm_module.pipeline_tracer
        hm_module.pipeline_tracer = self.tracer

    def teardown_method(self):
        import sys
        hm_module = sys.modules["observability.health_monitor"]
        hm_module.pipeline_tracer = self._orig_tracer

    def test_all_green_when_healthy(self):
        for i in range(10):
            sp = self.tracer.start_span("executor", event_id=i)
            self.tracer.end_span(sp)

        snapshot = self.monitor.check()
        assert snapshot.overall_status == "green"
        assert len(snapshot.alerts) == 0

    def test_red_on_high_error_rate(self):
        # 10 次调用，4 次失败 (40% > 30%)
        for i in range(6):
            sp = self.tracer.start_span("executor", event_id=i)
            self.tracer.end_span(sp)
        for i in range(4):
            sp = self.tracer.start_span("executor", event_id=100 + i)
            self.tracer.end_span(sp, error="LLM error")

        snapshot = self.monitor.check()
        executor_health = snapshot.stages["executor"]
        assert executor_health.status == "red"
        assert executor_health.error_rate > ERROR_RATE_THRESHOLD
        assert snapshot.overall_status == "red"
        assert len(snapshot.alerts) >= 1

    def test_yellow_on_moderate_error_rate(self):
        # 10 次调用，2 次失败 (20%，在 10-30% 之间)
        for i in range(8):
            sp = self.tracer.start_span("decomposer", event_id=i)
            self.tracer.end_span(sp)
        for i in range(2):
            sp = self.tracer.start_span("decomposer", event_id=100 + i)
            self.tracer.end_span(sp, error="parse error")

        snapshot = self.monitor.check()
        decomp_health = snapshot.stages["decomposer"]
        assert decomp_health.status == "yellow"

    def test_red_on_stuck_span(self):
        # 模拟一个卡死的 span（开始时间很早）
        sp = self.tracer.start_span("executor", event_id=999)
        sp.start_time = time.time() - 200  # 200 秒前开始
        # 不结束它，让它留在 active 中

        snapshot = self.monitor.check()
        executor_health = snapshot.stages["executor"]
        assert executor_health.stuck_spans >= 1
        assert executor_health.status == "red"

    def test_no_alert_below_min_samples(self):
        # 只有 2 次调用（< MIN_SAMPLES_FOR_ALERT=5），即使全失败也不告警
        for i in range(2):
            sp = self.tracer.start_span("reviewer", event_id=i)
            self.tracer.end_span(sp, error="fail")

        snapshot = self.monitor.check()
        reviewer_health = snapshot.stages["reviewer"]
        # 错误率 100% 但样本不足，不应为 red
        assert reviewer_health.status != "red"

    def test_health_snapshot_to_dict(self):
        sp = self.tracer.start_span("ingest", event_id=1)
        self.tracer.end_span(sp)
        snapshot = self.monitor.check()
        d = snapshot.to_dict()
        assert "overall_status" in d
        assert "stages" in d
        assert "ingest" in d["stages"]

    def test_alert_cooldown(self):
        # 触发一次告警
        for i in range(10):
            sp = self.tracer.start_span("executor", event_id=i)
            self.tracer.end_span(sp, error="fail")

        snap1 = self.monitor.check()
        assert len(snap1.alerts) >= 1

        # 立即再次检查 — 冷却期内不应重复告警
        snap2 = self.monitor.check()
        assert len(snap2.alerts) == 0


# ════════════════════════════════════════════
# 3. Watchdog 测试
# ════════════════════════════════════════════

class TestWatchdog:
    """Watchdog 测试"""

    def test_rule_based_diagnosis(self):
        wd = WatchdogAgent()
        diag_data = {
            "stage_stats": {
                "executor": {
                    "status": "red",
                    "error_rate": 0.5,
                    "p95_latency_ms": 45000,
                    "last_error": "Connection refused",
                },
            },
            "active_spans": [
                {"stage": "executor", "event_id": 1, "running_seconds": 200},
            ],
            "recent_errors": [],
            "circuit_breaker": {"tripped": False},
            "affected_events": 3,
        }
        result = wd._rule_based_diagnosis("error_rate", "executor", diag_data)
        assert "executor" in result["root_cause"]
        assert len(result["recommendations"]) >= 1

    def test_assess_severity_critical_on_stuck(self):
        wd = WatchdogAgent()
        diag_data = {
            "active_spans": [
                {"stage": "executor", "running_seconds": 200},
            ],
            "stage_stats": {},
        }
        assert wd._assess_severity(diag_data) == "critical"

    def test_assess_severity_high_on_red(self):
        wd = WatchdogAgent()
        diag_data = {
            "active_spans": [],
            "stage_stats": {
                "decomposer": {"status": "red", "error_rate": 0.4},
            },
        }
        assert wd._assess_severity(diag_data) == "high"

    def test_assess_severity_medium_default(self):
        wd = WatchdogAgent()
        diag_data = {"active_spans": [], "stage_stats": {}}
        assert wd._assess_severity(diag_data) == "medium"

    def test_get_status(self):
        wd = WatchdogAgent()
        status = wd.get_status()
        assert "diagnose_count" in status
        assert status["diagnose_count"] == 0

    @pytest.mark.asyncio
    async def test_diagnose_cooldown(self):
        wd = WatchdogAgent()
        wd._diagnose_cooldown = 9999  # 长冷却
        wd._last_diagnose_time = time.time()  # 刚诊断过

        result = await wd.diagnose(trigger_reason="test")
        assert result.get("skipped") is True
        assert "cooldown" in result.get("reason", "")


# ════════════════════════════════════════════
# 运行入口
# ════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
