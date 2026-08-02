"""
流水线健康监控 (Health Monitor)

从 PipelineTracer 聚合各阶段指标，通过规则引擎检测异常，
触发 WatchdogAgent 进行自动诊断。

4 种触发条件:
  1. 错误率阈值: 某阶段最近 N 次调用错误率 > 30%
  2. 延迟飙升:   某阶段 p95 延迟 > 阈值
  3. 阶段卡死:   事件进入某阶段后 > 120s 无输出
  4. 定时巡检:   由 scheduler 每 10 分钟调用 patrol()

健康状态:
  - green:  正常
  - yellow: 有退化趋势（错误率 10-30% 或延迟接近阈值）
  - red:    触发告警（错误率 > 30% 或延迟超限或有卡死）
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Coroutine

from .pipeline_tracer import pipeline_tracer, STAGES

logger = logging.getLogger(__name__)

# ── 阈值配置 ──

ERROR_RATE_THRESHOLD = 0.30        # 错误率 > 30% → red
ERROR_RATE_WARNING = 0.10          # 错误率 10-30% → yellow
LATENCY_THRESHOLDS_MS = {          # 各阶段 p95 延迟阈值
    "ingest": 5000,
    "anomaly_detect": 3000,
    "sigma_detect": 1000,
    "store": 5000,
    "decomposer": 30000,            # LLM 调用
    "tool_builder": 2000,
    "executor": 60000,              # LLM + 并行工具
    "reviewer": 30000,              # LLM 调用
    "cad_verify": 15000,
    "response": 15000,
}
STUCK_THRESHOLD_SECONDS = 120      # 阶段卡死阈值
MIN_SAMPLES_FOR_ALERT = 5          # 至少 N 次调用才触发告警（避免冷启动误报）
COOLDOWN_SECONDS = 300             # 同一阶段告警冷却（避免重复触发）


@dataclass
class StageHealth:
    """单阶段健康状态"""
    stage: str
    status: str = "green"          # green | yellow | red
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total: int = 0
    error_count: int = 0
    timeout_count: int = 0
    last_error: str = ""
    stuck_spans: int = 0           # 当前卡死的 span 数
    message: str = ""


@dataclass
class HealthSnapshot:
    """全链路健康快照"""
    timestamp: float = 0.0
    overall_status: str = "green"
    stages: dict = field(default_factory=dict)  # stage → StageHealth
    alerts: list = field(default_factory=list)   # 当前活跃告警
    active_spans: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "overall_status": self.overall_status,
            "stages": {
                k: {
                    "status": v.status,
                    "error_rate": v.error_rate,
                    "avg_latency_ms": v.avg_latency_ms,
                    "p95_latency_ms": v.p95_latency_ms,
                    "total": v.total,
                    "error_count": v.error_count,
                    "timeout_count": v.timeout_count,
                    "last_error": v.last_error,
                    "stuck_spans": v.stuck_spans,
                    "message": v.message,
                }
                for k, v in self.stages.items()
            },
            "alerts": self.alerts,
            "active_spans": self.active_spans,
        }


class HealthMonitor:
    """流水线健康监控器"""

    def __init__(self):
        self._last_alert_time: dict[str, float] = {}  # stage → last alert timestamp
        self._diagnose_callback: Optional[Callable[..., Coroutine]] = None

    def set_diagnose_callback(self, fn: Callable[..., Coroutine]):
        """设置诊断回调（WatchdogAgent.diagnose）"""
        self._diagnose_callback = fn
        logger.info("[HealthMonitor] Diagnose callback registered")

    def check(self) -> HealthSnapshot:
        """
        执行一次健康检查

        Returns:
            HealthSnapshot 包含各阶段状态和告警
        """
        stats = pipeline_tracer.get_stage_stats()
        active = pipeline_tracer.get_active_spans()
        now = time.time()

        snapshot = HealthSnapshot(timestamp=now, active_spans=len(active))
        alerts = []
        worst_status = "green"

        # 按阶段统计卡死 span
        stuck_by_stage: dict[str, int] = {}
        for sp in active:
            if sp.get("running_seconds", 0) > STUCK_THRESHOLD_SECONDS:
                stage = sp.get("stage", "unknown")
                stuck_by_stage[stage] = stuck_by_stage.get(stage, 0) + 1

        for stage in STAGES:
            st = stats.get(stage, {})
            health = StageHealth(stage=stage)
            health.total = st.get("total", 0)
            health.error_count = st.get("error", 0)
            health.timeout_count = st.get("timeout", 0)
            health.error_rate = st.get("error_rate", 0.0)
            health.avg_latency_ms = st.get("avg_latency_ms", 0.0)
            health.p95_latency_ms = st.get("p95_latency_ms", 0.0)
            health.last_error = st.get("last_error", "")
            health.stuck_spans = stuck_by_stage.get(stage, 0)

            # ── 规则评估 ──
            reasons = []

            # 规则 1: 错误率
            if health.total >= MIN_SAMPLES_FOR_ALERT:
                if health.error_rate > ERROR_RATE_THRESHOLD:
                    reasons.append(
                        f"错误率 {health.error_rate:.0%} > {ERROR_RATE_THRESHOLD:.0%} "
                        f"({health.error_count}E+{health.timeout_count}T / {health.total})"
                    )
                    health.status = "red"
                elif health.error_rate > ERROR_RATE_WARNING:
                    reasons.append(f"错误率 {health.error_rate:.0%} 偏高")
                    if health.status != "red":
                        health.status = "yellow"

            # 规则 2: 延迟
            latency_limit = LATENCY_THRESHOLDS_MS.get(stage, 10000)
            if health.p95_latency_ms > latency_limit and health.total >= MIN_SAMPLES_FOR_ALERT:
                reasons.append(
                    f"P95 延迟 {health.p95_latency_ms:.0f}ms > {latency_limit}ms"
                )
                health.status = "red"
            elif health.p95_latency_ms > latency_limit * 0.7 and health.total >= MIN_SAMPLES_FOR_ALERT:
                if health.status == "green":
                    health.status = "yellow"
                reasons.append(f"P95 延迟 {health.p95_latency_ms:.0f}ms 接近阈值")

            # 规则 3: 卡死
            if health.stuck_spans > 0:
                reasons.append(f"{health.stuck_spans} 个 span 卡死 > {STUCK_THRESHOLD_SECONDS}s")
                health.status = "red"

            health.message = "; ".join(reasons) if reasons else "正常"
            snapshot.stages[stage] = health

            # 更新全局最差状态
            if health.status == "red":
                worst_status = "red"
            elif health.status == "yellow" and worst_status == "green":
                worst_status = "yellow"

            # 生成告警（red 且有冷却）
            if health.status == "red" and reasons:
                last_alert = self._last_alert_time.get(stage, 0)
                if now - last_alert > COOLDOWN_SECONDS:
                    alert = {
                        "stage": stage,
                        "reasons": reasons,
                        "error_rate": health.error_rate,
                        "p95_latency_ms": health.p95_latency_ms,
                        "stuck_spans": health.stuck_spans,
                        "last_error": health.last_error,
                        "timestamp": now,
                    }
                    alerts.append(alert)
                    self._last_alert_time[stage] = now

        snapshot.overall_status = worst_status
        snapshot.alerts = alerts

        # 发布 SSE 事件
        if alerts:
            self._publish_alerts(alerts)

        return snapshot

    async def check_and_diagnose(self) -> HealthSnapshot:
        """检查健康状态，如有 red 告警则自动触发诊断"""
        snapshot = self.check()

        if snapshot.alerts and self._diagnose_callback:
            # 取最严重的告警触发诊断
            worst_alert = snapshot.alerts[0]
            logger.warning(
                f"[HealthMonitor] RED alert on '{worst_alert['stage']}': "
                f"{worst_alert['reasons']}"
            )
            try:
                await self._diagnose_callback(
                    trigger_reason=f"health_monitor: {worst_alert['stage']} - {'; '.join(worst_alert['reasons'])}",
                    trigger_stage=worst_alert["stage"],
                    context=snapshot.to_dict(),
                )
            except Exception as e:
                logger.error(f"[HealthMonitor] Diagnose callback failed: {e}")

        return snapshot

    async def patrol(self) -> HealthSnapshot:
        """
        定时巡检（由 scheduler 调用）

        与 check_and_diagnose 相同，但语义上用于周期性巡检。
        """
        logger.info("[HealthMonitor] Running scheduled patrol...")
        snapshot = await self.check_and_diagnose()
        if snapshot.overall_status == "green":
            logger.info("[HealthMonitor] Patrol: all stages GREEN")
        else:
            logger.warning(
                f"[HealthMonitor] Patrol: overall={snapshot.overall_status}, "
                f"alerts={len(snapshot.alerts)}"
            )
        return snapshot

    def get_health_snapshot(self) -> HealthSnapshot:
        """获取当前健康快照（不触发诊断）"""
        return self.check()

    def _publish_alerts(self, alerts: list[dict]):
        """通过 EventBus 发布告警（SSE 推送）"""
        try:
            from event_bus import event_bus
            for alert in alerts:
                event_bus.publish("pipeline_health", {
                    "type": "alert",
                    "stage": alert["stage"],
                    "reasons": alert["reasons"],
                    "severity": "critical",
                    "timestamp": alert["timestamp"],
                })
        except Exception as e:
            logger.debug(f"[HealthMonitor] SSE publish failed: {e}")


health_monitor = HealthMonitor()
