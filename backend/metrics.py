"""
metrics.py — 轻量 Prometheus 指标 (兼容 FastAPI 0.14x 的 _IncludedRouter 路由模型)

prometheus-fastapi-instrumentator 会内省 app.routes 并访问 route.path,
与 FastAPI 0.141 的 _IncludedRouter (无 .path 属性) 不兼容 → 所有请求 500。
本模块用 prometheus_client 直接实现, 中间件在请求层打点, 稳定可靠。

指标:
  soc_http_requests_total{method,status}      HTTP 请求计数
  soc_http_request_duration_seconds{method}   HTTP 请求耗时直方图
  soc_kafka_consumer_total{topic}             Kafka 消费计数 (由 kafka_consumer 注入)
"""
import logging
import time

from fastapi import Request, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

logger = logging.getLogger(__name__)

HTTP_REQUESTS = Counter(
    "soc_http_requests_total", "HTTP 请求总数",
    ["method", "status"],
)
HTTP_DURATION = Histogram(
    "soc_http_request_duration_seconds", "HTTP 请求耗时 (秒)",
    ["method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
KAFKA_CONSUMED = Counter(
    "soc_kafka_consumer_total", "Kafka 消费事件计数",
    ["topic"],
)

# 供 kafka_consumer 注入消费统计
def inc_kafka_consumed(topic: str) -> None:
    try:
        KAFKA_CONSUMED.labels(topic=topic).inc()
    except Exception:
        pass


async def metrics_endpoint(request: Request) -> Response:
    """GET /metrics — Prometheus 文本格式"""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


class MetricsMiddleware:
    """ASGI 中间件: 记录请求计数/状态/耗时"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/metrics":
            return await self.app(scope, receive, send)

        start = time.perf_counter()
        status = 500
        try:
            async def send_wrapper(message):
                nonlocal status
                if message["type"] == "http.response.start":
                    status = message["status"]
                await send(message)

            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            method = scope.get("method", "GET")
            HTTP_REQUESTS.labels(method=method, status=str(status)).inc()
            HTTP_DURATION.labels(method=method).observe(duration)
