"""
全链路可观测性 (Observability)

提供流水线阶段追踪、健康监控、自动诊断能力。

模块:
  - pipeline_tracer: 轻量级 Span 追踪（环形缓冲 + 异步落库）
  - health_monitor:  阶段健康指标聚合 + 规则引擎（4 种触发条件）
  - watchdog:        看门狗诊断 Agent（LLM 根因分析 + 三通道输出）
"""
from .pipeline_tracer import pipeline_tracer
from .health_monitor import health_monitor
from .watchdog import watchdog

__all__ = ["pipeline_tracer", "health_monitor", "watchdog"]
