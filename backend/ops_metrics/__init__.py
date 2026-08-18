"""
运营指标模块 (Ops Metrics) — P0.B

职责:
  1. 从 security_cases / work_orders / feedback_records / response_logs 聚合 KPI
  2. MTTD / MTTR / 案例周期 / SLA breach 率 / FP 率 / 案例计数
  3. 日/周快照写入 kpi_snapshots 表
  4. SLA breach 趋势跟踪 (供 P1.C 升级引擎消费)

调用方式:
    from ops_metrics import kpi_calculator, sla_tracker
    await kpi_calculator.snapshot_daily(session, date(2026, 8, 2))
    trend = sla_tracker.recent_breaches(session, hours=24)
"""
from .kpi_calculator import kpi_calculator, METRIC_KEYS
from .sla_tracker import sla_tracker

__all__ = ["kpi_calculator", "sla_tracker", "METRIC_KEYS"]