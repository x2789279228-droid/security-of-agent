"""
otel_setup.py — OpenTelemetry SDK 初始化 (标准 trace 体系)

职责:
  - 初始化 TracerProvider + OTLP exporter → otel-collector (默认 :4317 gRPC)
  - 注册 FastAPI / httpx 自动 instrumentation (HTTP 头提取/注入, 响应头回传 traceparent)
  - 提供 get_tracer() / trace context 工具 (W3C traceparent 解析)

采集策略: SDK 侧 AlwaysOn 全量导出, 采样在 otel-collector 尾部采样完成
(告警/审计 100%, 普通事件按比率), 兼顾保真与存储成本。
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

try:
    from opentelemetry import trace as otel_trace
    from opentelemetry import propagate
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

# W3C traceparent 文本传播器 (供手动提取/注入)
TRACE_PROPAGATOR = TraceContextTextMapPropagator() if HAS_OTEL else None


def _tracer():
    return otel_trace.get_tracer("soc-backend", "2.0.0")


def setup_otel(app=None):
    """初始化 OTel SDK。OTel 未启用或 SDK 缺失时返回 None (应用照常运行)。"""
    if not HAS_OTEL:
        logger.warning("opentelemetry 未安装 — trace 导出禁用")
        return None
    if not settings.otel_enabled:
        logger.info("OTel 已配置但 otel_enabled=False, 跳过导出")
        return None

    resource = Resource.create({
        "service.name": "soc-backend",
        "service.version": "2.0.0",
        "deployment.environment": settings.env_name or "dev",
    })
    provider = TracerProvider(resource=resource)
    try:
        exporter = OTLPSpanExporter(
            endpoint=settings.otel_endpoint,
            insecure=True,
            timeout=5,
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
    except Exception as e:
        logger.warning(f"OTel OTLP exporter 初始化失败: {e}")
        return None

    otel_trace.set_tracer_provider(provider)
    propagate.set_global_textmap(TRACE_PROPAGATOR)

    if app is not None:
        try:
            # 自定义 ASGI trace 中间件 (替代 FastAPIInstrumentor, 规避
            # _IncludedRouter 路由内省兼容问题, 保证 API 不被破坏)
            app.add_middleware(HttpTraceMiddleware)
            logger.info("OTel HTTP trace middleware enabled")
        except Exception as e:
            logger.warning(f"HTTP trace middleware 注册失败: {e}")
    try:
        HTTPXClientInstrumentor().instrument()
        logger.info("OTel httpx instrumentation enabled")
    except Exception as e:
        logger.warning(f"httpx instrumentation 失败: {e}")

    logger.info(f"OTel 已初始化: endpoint={settings.otel_endpoint}")
    return provider


class HttpTraceMiddleware:
    """ASGI 中间件: 为每个 HTTP 请求创建标准 span (W3C 上下文提取/注入)。

    从请求头提取 traceparent (外部链路继承), 生成 span 覆盖请求处理,
    并把 traceparent 回写到响应头 (前端可关联 trace)。
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        tracer = otel_trace.get_tracer("soc-backend-http", "2.0.0")
        ctx = TRACE_PROPAGATOR.extract(headers) if headers.get("traceparent") else None
        span = tracer.start_span(
            f"{scope.get('method', 'HTTP')} {scope.get('path', '/')}",
            context=ctx,
            attributes={
                "http.method": scope.get("method", "GET"),
                "http.target": scope.get("path", "/"),
                "http.route": scope.get("route", ""),
                "soc.importance": "normal",
            },
        )
        status = 500
        try:
            with otel_trace.use_span(span, end_on_exit=False):
                async def send_wrapper(message):
                    nonlocal status
                    if message["type"] == "http.response.start":
                        status = message["status"]
                        # 响应头回传 traceparent
                        tp = _traceparent_from_span(span)
                        if tp:
                            headers = list(message.get("headers", []))
                            headers.append((b"traceparent", tp.encode()))
                            message["headers"] = headers
                    await send(message)

                await self.app(scope, receive, send_wrapper)
            span.set_attribute("http.status_code", status)
            if status >= 500:
                span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR, f"HTTP {status}"))
        except Exception as e:
            span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise
        finally:
            span.end()


def _traceparent_from_span(span) -> str:
    sc = span.get_span_context()
    if sc and sc.is_valid:
        return f"00-{format(sc.trace_id, '032x')}-{format(sc.span_id, '016x')}-01"
    return ""


def extract_context(carrier: Optional[dict]) -> Optional[object]:
    """从 dict (含 traceparent 头) 提取 W3C 上下文; 无/非法返回 None"""
    if not HAS_OTEL or not carrier:
        return None
    try:
        if carrier.get("traceparent"):
            return TRACE_PROPAGATOR.extract(carrier)
        if carrier.get("trace_id"):
            from trace_context import make_traceparent
            tp = make_traceparent(carrier["trace_id"])
            return TRACE_PROPAGATOR.extract({"traceparent": tp})
    except Exception as e:
        logger.debug(f"trace context 提取失败: {e}")
    return None
