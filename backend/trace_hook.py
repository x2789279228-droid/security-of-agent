"""
Agent 轨迹钩子 — LLM 调用留痕（参考 studyagentplus 的 trace_hook 设计）

用法:
  set_trace_context(caller="audit_pipeline", event_id=123, session_id="...")
  ... 调用 summary.llm.chat() ...
  LLMClient 内部在调用完成后自动 emit_trace()

本模块保持轻量，不直接依赖存储；落库由异步 recorder 完成，
任何异常都不会影响主 LLM 调用链路。
"""
import asyncio
import logging
from contextvars import ContextVar
from typing import Any, Callable

logger = logging.getLogger(__name__)

_current_trace_context: ContextVar[dict[str, Any]] = ContextVar("llm_trace_context", default={})

# 模块末尾会将 _recorder 初始化为默认异步 recorder（延迟导入，避免循环依赖）


def _otel_trace_id() -> str:
    try:
        from opentelemetry import trace as otel_trace
        span = otel_trace.get_current_span()
        sc = span.get_span_context() if span else None
        if sc and getattr(sc, "is_valid", False) and sc.trace_id:
            return format(sc.trace_id, "032x")
    except Exception:
        pass
    return ""


def coerce_trace_id(value: Any) -> str:
    """规整为 32 hex; 空串保持空,不随机生成(避免每次调用拆成新树)。"""
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    try:
        from trace_context import parse_traceparent, normalize_trace_id
        parsed = parse_traceparent(s)
        if parsed:
            return parsed["trace_id"]
        cleaned = s.replace("-", "").lower()
        if len(cleaned) == 32 and all(c in "0123456789abcdef" for c in cleaned):
            return cleaned
        return normalize_trace_id(s)
    except Exception:
        return s.replace("-", "").lower()[:32]


def resolve_trace_id(*candidates: Any, event_id: int = 0) -> str:
    """候选 → OTel 当前 span → event:{id} 确定性兜底。"""
    for c in candidates:
        tid = coerce_trace_id(c)
        if tid:
            return tid
    tid = _otel_trace_id()
    if tid:
        return tid
    ctx = _current_trace_context.get() or {}
    tid = coerce_trace_id(ctx.get("trace_id"))
    if tid:
        return tid
    if event_id:
        from trace_context import normalize_trace_id
        return normalize_trace_id(f"event:{int(event_id)}")
    return ""


def set_trace_context(**kwargs: Any) -> None:
    """为当前上下文中的下一次 LLM 调用附加元数据。自动补 W3C trace_id。"""
    ctx = {**_current_trace_context.get(), **kwargs}
    log_data = ctx.get("log_data") if isinstance(ctx.get("log_data"), dict) else {}
    raw = log_data.get("rawData") if isinstance(log_data.get("rawData"), dict) else {}
    event_id = int(ctx.get("event_id") or 0)
    ctx["trace_id"] = resolve_trace_id(
        kwargs.get("trace_id"),
        ctx.get("trace_id"),
        log_data.get("_trace_id"),
        log_data.get("trace_id"),
        log_data.get("traceparent"),
        raw.get("_trace_id"),
        event_id=event_id,
    )
    ctx.pop("log_data", None)
    _current_trace_context.set(ctx)


def clear_trace_context() -> None:
    """清空当前上下文的轨迹元数据"""
    _current_trace_context.set({})


def get_trace_context() -> dict[str, Any]:
    """返回当前轨迹上下文副本"""
    return dict(_current_trace_context.get())


def register_trace_recorder(recorder: Callable[..., None]) -> None:
    global _recorder
    _recorder = recorder
    logger.info("trace recorder registered")


def emit_trace(**kwargs: Any) -> None:
    """发出一条轨迹记录（异步落库，失败不影响主流程）"""
    if _recorder is None:
        return
    try:
        ctx = get_trace_context()
        merged = {**ctx, **kwargs}
        _recorder(**merged)
    except Exception:
        logger.warning("trace recorder failed", exc_info=True)


def _lazy_recorder(**kwargs: Any) -> None:
    """默认 recorder — 异步插入 AgentTrace，绝不阻塞调用方"""
    try:
        from models import AgentTrace, async_session
        from datetime import datetime, timezone

        async def _persist():
            try:
                async with async_session() as session:
                    session.add(AgentTrace(
                        caller=str(kwargs.get("caller", "unknown"))[:50],
                        operation=str(kwargs.get("operation", "chat"))[:50],
                        model=str(kwargs.get("model", ""))[:100],
                        event_id=int(kwargs.get("event_id", 0) or 0),
                        session_id=str(kwargs.get("session_id", ""))[:100],
                        trace_id=str(kwargs.get("trace_id") or "")[:32],
                        prompt_tokens=int(kwargs.get("prompt_tokens", 0)),
                        completion_tokens=int(kwargs.get("completion_tokens", 0)),
                        total_tokens=int(kwargs.get("total_tokens", 0)),
                        latency_ms=float(kwargs.get("latency_ms", 0.0)),
                        cache_hit=bool(kwargs.get("cache_hit", False)),
                        status=str(kwargs.get("status", "success"))[:20],
                        error_type=str(kwargs.get("error_type", ""))[:50],
                        retry_count=int(kwargs.get("retry_count", 0)),
                        created_at=datetime.now(timezone.utc),
                    ))
                    await session.commit()
            except Exception as e:
                logger.warning(f"trace persist failed: {e}")

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_persist())
        except RuntimeError:
            asyncio.ensure_future(_persist())
    except Exception as e:
        logger.warning(f"trace recorder init failed: {e}")


# 默认使用异步落库 recorder（模块加载时即生效）
_recorder = _lazy_recorder
