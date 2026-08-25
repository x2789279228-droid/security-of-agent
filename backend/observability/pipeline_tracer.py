"""
流水线 Span 追踪 (Pipeline Tracer) — OpenTelemetry 标准化

为 Audit-LLM 全链路提供阶段追踪。每个阶段产生一条 Span。
当 OTel 可用且启用时, span 与标准 OTel/Tempo 体系互通 (W3C 上下文父子关系,
trace_id 关联), 否则回退为纯内存/落库实现 (API 完全兼容)。

存储:
  - OTel: 导出到 otel-collector → Tempo (标准体系)
  - 内存环形缓冲（最近 500 条）— 快速查询
  - 异步落库 pipeline_spans 表 — 持久化历史 (含 trace_id 列)

埋点方式 (API 不变):
  with pipeline_tracer.span("decomposer", event_id=123):
      result = await decomposer.decompose(...)
"""
import asyncio
import logging
import time
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# 流水线阶段枚举
STAGES = [
    "ingest",
    "anomaly_detect",
    "sigma_detect",
    "store",
    "decomposer",
    "tool_builder",
    "executor",
    "reviewer",
    "cad_verify",
    "response",
]

# 阶段状态
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"

# 关键审计阶段 → soc.importance (Jaeger 按重要性过滤; 与 HttpTraceMiddleware 一致)
_CRITICAL_STAGES = {"executor", "reviewer", "cad_verify", "response"}
_NORMAL_STAGES = {"ingest", "anomaly_detect", "sigma_detect", "store", "tool_builder"}


def _stage_importance(stage: str) -> str:
    """返回阶段重要度: critical(关键裁决/产出) | important | normal"""
    if stage in _CRITICAL_STAGES:
        return "critical"
    if stage in _NORMAL_STAGES:
        return "normal"
    return "important"

# ── OpenTelemetry 可选集成 ──
try:
    from opentelemetry import trace as otel_trace
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


@dataclass
class Span:
    """单条流水线 Span"""
    span_id: str
    event_id: int
    session_id: str
    stage: str
    status: str = STATUS_RUNNING
    start_time: float = 0.0
    end_time: float = 0.0
    latency_ms: float = 0.0
    error: str = ""
    metadata: dict = field(default_factory=dict)
    created_at: str = ""
    trace_id: str = ""           # W3C trace-id (32 hex), 关联标准 trace 树
    _otel_span: object = None    # 内部: OTel span 句柄 (非 dataclass 字段输出)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def is_complete(self) -> bool:
        return self.status in (STATUS_SUCCESS, STATUS_ERROR, STATUS_TIMEOUT)

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "stage": self.stage,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "trace_id": self.trace_id,
        }


class PipelineTracer:
    """流水线 Span 追踪器"""

    def __init__(self, buffer_size: int = 500):
        self._buffer: deque[Span] = deque(maxlen=buffer_size)
        self._active: dict[str, Span] = {}  # span_id → Span (running)
        self._persist_enabled = False

    def enable_persist(self):
        """启用异步落库"""
        self._persist_enabled = True
        logger.info("[PipelineTracer] Persistence enabled")

    # ── Span 生命周期 ──

    def _otel_enabled(self) -> bool:
        return HAS_OTEL and settings.otel_enabled

    def start_span(
        self,
        stage: str,
        event_id: int = 0,
        session_id: str = "",
        metadata: Optional[dict] = None,
    ) -> Span:
        """开始一条 Span (OTel 可用时同步创建标准 span, 继承当前上下文父级)"""
        otel_span = None
        trace_id = ""
        if self._otel_enabled():
            try:
                tracer = otel_trace.get_tracer("soc-backend", "2.0.0")
                otel_span = tracer.start_span(
                    f"pipeline.{stage}",
                    attributes={
                        "soc.stage": stage,
                        "soc.event_id": event_id,
                        "soc.session_id": session_id or "",
                        "soc.importance": _stage_importance(stage),
                    },
                )
                sc = otel_span.get_span_context()
                if sc and sc.is_valid:
                    trace_id = format(sc.trace_id, "032x")
            except Exception as e:
                logger.debug(f"OTel start_span failed: {e}")
                otel_span = None
        span = Span(
            span_id=uuid.uuid4().hex[:12],
            event_id=event_id,
            session_id=session_id,
            stage=stage,
            status=STATUS_RUNNING,
            start_time=time.time(),
            metadata=metadata or {},
            trace_id=trace_id,
            _otel_span=otel_span,
        )
        self._active[span.span_id] = span
        logger.debug(f"[Span] START {stage} event=#{event_id} span={span.span_id} trace={trace_id[:8] or '-'}")
        return span

    def end_span(self, span: Span, error: str = "", metadata: Optional[dict] = None):
        """结束一条 Span (同步结束 OTel span)"""
        span.end_time = time.time()
        span.latency_ms = (span.end_time - span.start_time) * 1000
        span.status = STATUS_ERROR if error else STATUS_SUCCESS
        span.error = error[:500] if error else ""
        if metadata:
            span.metadata.update(metadata)
        self._finalize_otel(span, error)
        self._active.pop(span.span_id, None)
        self._buffer.append(span)

        level = logging.WARNING if error else logging.DEBUG
        logger.log(
            level,
            f"[Span] END {span.stage} event=#{span.event_id} "
            f"status={span.status} latency={span.latency_ms:.0f}ms"
            f"{' error=' + error[:100] if error else ''}"
        )

        # 异步落库
        if self._persist_enabled:
            self._persist_span(span)

    def mark_timeout(self, span: Span):
        """标记 Span 超时 (同步结束 OTel span)"""
        span.end_time = time.time()
        span.latency_ms = (span.end_time - span.start_time) * 1000
        span.status = STATUS_TIMEOUT
        span.error = f"Stage timed out after {span.latency_ms:.0f}ms"
        self._finalize_otel(span, span.error)
        self._active.pop(span.span_id, None)
        self._buffer.append(span)
        logger.warning(
            f"[Span] TIMEOUT {span.stage} event=#{span.event_id} "
            f"latency={span.latency_ms:.0f}ms"
        )

    def _finalize_otel(self, span: Span, error: str = ""):
        """结束 OTel span 并写状态/属性"""
        if not span._otel_span:
            return
        try:
            if error:
                span._otel_span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR, error[:500]))
                span._otel_span.record_exception(Exception(error[:500]) if error else None)
            else:
                span._otel_span.set_status(otel_trace.Status(otel_trace.StatusCode.OK))
            if span.metadata:
                for k, v in span.metadata.items():
                    if isinstance(v, (str, int, float, bool)):
                        span._otel_span.set_attribute(f"soc.{k}", v)
            span._otel_span.end()
        except Exception as e:
            logger.debug(f"OTel end_span failed: {e}")

    @contextmanager
    def span(
        self,
        stage: str,
        event_id: int = 0,
        session_id: str = "",
        metadata: Optional[dict] = None,
    ):
        """上下文管理器 — 自动 start/end span (OTel 时使 span 成为当前, 子调用挂其下)"""
        sp = self.start_span(stage, event_id, session_id, metadata)
        try:
            if sp._otel_span is not None:
                with otel_trace.use_span(sp._otel_span, end_on_exit=False):
                    yield sp
            else:
                yield sp
            self.end_span(sp)
        except asyncio.TimeoutError:
            self.mark_timeout(sp)
            raise
        except Exception as e:
            self.end_span(sp, error=str(e))
            raise

    def traced(self, stage: str):
        """装饰器 — 自动追踪异步函数"""
        def decorator(fn):
            async def wrapper(*args, **kwargs):
                event_id = kwargs.get("event_id", 0)
                session_id = kwargs.get("session_id", "")
                with self.span(stage, event_id=event_id, session_id=session_id):
                    return await fn(*args, **kwargs)
            wrapper.__name__ = fn.__name__
            wrapper.__qualname__ = fn.__qualname__
            return wrapper
        return decorator

    # ── 查询接口 ──

    def get_recent_spans(
        self,
        event_id: Optional[int] = None,
        stage: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """查询最近的 Span"""
        spans = list(self._buffer)
        if event_id is not None:
            spans = [s for s in spans if s.event_id == event_id]
        if stage:
            spans = [s for s in spans if s.stage == stage]
        spans.sort(key=lambda s: s.start_time, reverse=True)
        return [s.to_dict() for s in spans[:limit]]

    def get_active_spans(self) -> list[dict]:
        """获取正在运行的 Span（用于卡死检测）"""
        now = time.time()
        return [
            {**s.to_dict(), "running_seconds": round(now - s.start_time, 1)}
            for s in self._active.values()
        ]

    def get_stage_stats(self, window: int = 50) -> dict[str, dict]:
        """
        按阶段聚合最近 N 条 Span 的指标

        Returns:
            {stage: {success, error, timeout, error_rate, avg_latency_ms, p95_latency_ms, last_error}}
        """
        spans = list(self._buffer)[-window * len(STAGES):]  # 取足够多的 span
        stage_spans: dict[str, list[Span]] = {}
        for s in spans:
            stage_spans.setdefault(s.stage, []).append(s)

        stats = {}
        for stage in STAGES:
            ss = stage_spans.get(stage, [])
            if not ss:
                stats[stage] = {
                    "total": 0, "success": 0, "error": 0, "timeout": 0,
                    "error_rate": 0.0, "avg_latency_ms": 0.0, "p95_latency_ms": 0.0,
                    "last_error": "", "last_success_time": None,
                }
                continue

            recent = ss[-window:]
            success = sum(1 for s in recent if s.status == STATUS_SUCCESS)
            error = sum(1 for s in recent if s.status == STATUS_ERROR)
            timeout = sum(1 for s in recent if s.status == STATUS_TIMEOUT)
            total = len(recent)
            latencies = sorted(s.latency_ms for s in recent if s.is_complete)

            last_error = ""
            last_success_time = None
            for s in reversed(recent):
                if s.error and not last_error:
                    last_error = s.error
                if s.status == STATUS_SUCCESS and not last_success_time:
                    last_success_time = s.end_time
                if last_error and last_success_time:
                    break

            p95_idx = int(len(latencies) * 0.95) if latencies else 0
            stats[stage] = {
                "total": total,
                "success": success,
                "error": error,
                "timeout": timeout,
                "error_rate": round((error + timeout) / max(total, 1), 4),
                "avg_latency_ms": round(sum(latencies) / max(len(latencies), 1), 1),
                "p95_latency_ms": round(latencies[min(p95_idx, len(latencies) - 1)], 1) if latencies else 0.0,
                "last_error": last_error[:200],
                "last_success_time": last_success_time,
            }
        return stats

    def get_event_timeline(self, event_id: int) -> list[dict]:
        """获取单个事件的全链路时间线"""
        spans = [s for s in self._buffer if s.event_id == event_id]
        spans.sort(key=lambda s: s.start_time)
        return [s.to_dict() for s in spans]

    # ── 持久化 ──

    def _persist_span(self, span: Span):
        """异步落库（fire-and-forget）"""
        try:
            from models import async_session as db_session

            async def _write():
                try:
                    from models import PipelineSpan as PipelineSpanModel
                    async with db_session() as session:
                        session.add(PipelineSpanModel(
                            span_id=span.span_id,
                            event_id=span.event_id,
                            session_id=span.session_id,
                            stage=span.stage,
                            status=span.status,
                            start_time=span.start_time,
                            end_time=span.end_time,
                            latency_ms=span.latency_ms,
                            error=span.error,
                            trace_id=span.trace_id,
                            metadata_=span.metadata,
                        ))
                        await session.commit()
                except Exception as e:
                    logger.debug(f"[PipelineTracer] Persist failed: {e}")

            loop = asyncio.get_running_loop()
            loop.create_task(_write())
        except Exception:
            pass


pipeline_tracer = PipelineTracer()
