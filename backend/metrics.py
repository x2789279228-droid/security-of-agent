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

# ── B 类高级能力指标 (NDR/EDR/威胁情报/0day/反钓鱼) ──
NDR_FLOWS = Counter("soc_ndr_flows_total", "NDR 网络流计数", ["protocol"])
TLS_SESSIONS = Counter("soc_tls_sessions_total", "TLS 会话计数")
CAPTURE_PACKETS = Counter("soc_capture_packets_total", "NDR 抓包计数")
EDR_EVENTS = Counter("soc_edr_events_total", "EDR 事件计数(按源)", ["source"])
INTEL_IOC = Counter("soc_intel_ioc_total", "威胁情报 IOC 拉取计数(按源)", ["source"])
IOC_MATCHES = Counter("soc_ioc_matches_total", "IOC 匹配命中计数")
SANDBOX_SUBMISSIONS = Counter("soc_sandbox_submissions_total", "沙箱提交计数(按类型)", ["kind"])
PHISHING_DETECTIONS = Counter("soc_phishing_detections_total", "反钓鱼检测计数(按类别)", ["category"])
LLM_TOKENS = Counter("soc_llm_tokens_total", "LLM token 消耗(按组件)", ["component"])
AUDIT_PQ_ENQUEUE = Counter(
    "soc_audit_pq_enqueue_total", "审计优先级队列入队", ["tier"]
)
AUDIT_PQ_DEQUEUE = Counter(
    "soc_audit_pq_dequeue_total", "审计优先级队列出队", ["tier"]
)
AUDIT_LANE_ADMIT = Counter(
    "soc_audit_lane_admit_total", "审计车道准入", ["lane", "tier"]
)


def inc_audit_pq_enqueue(tier: str = "?") -> None:
    try:
        AUDIT_PQ_ENQUEUE.labels(tier=tier or "?").inc()
    except Exception:
        pass


def inc_audit_pq_dequeue(tier: str = "?") -> None:
    try:
        AUDIT_PQ_DEQUEUE.labels(tier=tier or "?").inc()
    except Exception:
        pass


def inc_audit_lane_admit(lane: str = "?", tier: str = "?") -> None:
    try:
        AUDIT_LANE_ADMIT.labels(lane=lane or "?", tier=tier or "?").inc()
    except Exception:
        pass


def inc_llm_tokens(component: str = "llm", amount: int = 0) -> None:
    try:
        if amount and amount > 0:
            LLM_TOKENS.labels(component=component or "llm").inc(amount)
    except Exception:
        pass


def inc_ndr_flow(protocol: str = "tcp") -> None:
    try:
        NDR_FLOWS.labels(protocol=protocol or "tcp").inc()
    except Exception:
        pass


def inc_tls_session() -> None:
    try:
        TLS_SESSIONS.inc()
    except Exception:
        pass


def inc_capture_packet() -> None:
    try:
        CAPTURE_PACKETS.inc()
    except Exception:
        pass


def inc_edr_event(source: str = "sysmon") -> None:
    try:
        EDR_EVENTS.labels(source=source or "sysmon").inc()
    except Exception:
        pass


def inc_intel_ioc(source: str = "misp") -> None:
    try:
        INTEL_IOC.labels(source=source or "misp").inc()
    except Exception:
        pass


def inc_ioc_match() -> None:
    try:
        IOC_MATCHES.inc()
    except Exception:
        pass


def inc_sandbox_submission(kind: str = "file") -> None:
    try:
        SANDBOX_SUBMISSIONS.labels(kind=kind or "file").inc()
    except Exception:
        pass


def inc_phishing_detection(category: str = "email") -> None:
    try:
        PHISHING_DETECTIONS.labels(category=category or "email").inc()
    except Exception:
        pass

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
