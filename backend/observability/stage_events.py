"""
Agent 阶段事件 — 将 pipeline_tracer Span 生命周期映射为 SSE 可读的 agent_stage

只推送审计接力主阶段（避免 ingest/anomaly 刷屏）。
过滤可通过环境变量 SHARED_MEMORY_SSE_STAGE_FILTER 覆盖（逗号分隔）。
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from observability.pipeline_tracer import Span

# 默认推送到 Monitor 接力条的主阶段
DEFAULT_SSE_STAGES = frozenset({
    "decomposer",
    "tool_builder",
    "executor",
    "reviewer",
    "cad_verify",
    "response",
})

STAGE_LABELS = {
    "ingest": "接入",
    "anomaly_detect": "异常检测",
    "sigma_detect": "Sigma 规则",
    "store": "存储",
    "decomposer": "分解者",
    "tool_builder": "工具构建",
    "executor": "执行者",
    "reviewer": "复核者",
    "cad_verify": "CAD 监督",
    "response": "响应引擎",
}


def _sse_stages() -> frozenset[str]:
    raw = os.environ.get("SHARED_MEMORY_SSE_STAGE_FILTER", "").strip()
    if not raw:
        return DEFAULT_SSE_STAGES
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def publish_agent_stage(span: "Span", phase: str) -> None:
    """向事件总线发布 agent_stage（phase=start|end）。失败静默，不影响主流程。"""
    try:
        if not span.event_id:
            return
        if span.stage not in _sse_stages():
            return

        from event_bus import event_bus

        payload = {
            "event_id": span.event_id,
            "session_id": span.session_id or "",
            "trace_id": span.trace_id or "",
            "span_id": span.span_id,
            "stage": span.stage,
            "agent_id": span.stage,
            "agent_label": STAGE_LABELS.get(span.stage, span.stage),
            "phase": phase,
            "status": span.status,
            "latency_ms": round(span.latency_ms, 1) if phase == "end" and span.latency_ms else None,
            "error": (span.error or "")[:300],
            "severity": "high" if span.status in ("error", "timeout") else "info",
        }
        round_num = span.metadata.get("round") if span.metadata else None
        if round_num is not None:
            payload["round"] = round_num

        event_bus.publish("agent_stage", payload)
    except Exception as e:
        logger.debug(f"[stage_events] publish failed: {e}")
