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
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

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
AUDIT_COMPLETE = Counter(
    "soc_audit_complete_total", "审计完成(按质量/档位)", ["quality", "tier"]
)
AUDIT_CACHE_HIT = Counter(
    "soc_audit_cache_hit_total", "审计结论缓存命中计数"
)
TEMPORAL_START_TIMEOUT = Counter(
    "soc_audit_temporal_start_timeout_total", "Temporal start_workflow 墙钟超时计数"
)
LLM_429 = Counter("soc_llm_429_total", "LLM HTTP 429")
LLM_INFLIGHT = Gauge("soc_llm_inflight", "当前占用的全局 LLM 槽")
LLM_WAITERS = Gauge("soc_llm_waiters", "等待全局 LLM 槽的协程数")
AUDIT_INFLIGHT = Gauge("soc_audit_inflight", "正在执行的审计 worker 数")
AUDIT_QUEUE_DEPTH = Gauge("soc_audit_queue_depth", "内存审计队列深度")
AUDIT_WORKERS = Gauge("soc_audit_worker_busy", "配置的审计 worker 数")
DB_POOL_CHECKEDOUT = Gauge("soc_db_pool_checkedout", "DB 池已借出连接", ["pool"])
EVENTBUS_SUBSCRIBERS = Gauge("soc_eventbus_subscribers", "SSE 订阅者数")
EVENTBUS_DROPS = Counter("soc_eventbus_drops_total", "SSE 慢消费者丢弃的事件")

# ── P2 接入管道指标 (网关 / 审计不丢 / 阶段耗时) ──
AUDIT_SHED = Counter(
    "soc_audit_shed_total", "审计 shed/overflow/deferred 计数(按档位与原因)",
    ["tier", "reason"],
)
INGEST_STAGE_SECONDS = Histogram(
    "soc_ingest_stage_seconds", "Ingest 各阶段耗时 (秒, stage=detect|persist|dispatch)",
    ["stage"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
INGEST_DETECTOR_ERRORS = Counter(
    "soc_ingest_detector_errors_total", "检测器错误计数(按检测器)",
    ["detector"],
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


def inc_audit_cache_hit() -> None:
    try:
        AUDIT_CACHE_HIT.inc()
    except Exception:
        pass


def inc_temporal_start_timeout() -> None:
    try:
        TEMPORAL_START_TIMEOUT.inc()
    except Exception:
        pass


def inc_audit_complete(quality: str = "llm", tier: str = "?") -> None:
    try:
        AUDIT_COMPLETE.labels(quality=quality or "unknown", tier=tier or "?").inc()
    except Exception:
        pass


def inc_llm_429() -> None:
    try:
        LLM_429.inc()
    except Exception:
        pass


def set_llm_inflight(used: int = 0, waiters: int = 0) -> None:
    try:
        LLM_INFLIGHT.set(int(used or 0))
        LLM_WAITERS.set(int(waiters or 0))
    except Exception:
        pass


def set_audit_runtime(inflight: int = 0, queue_depth: int = 0, workers: int = 0) -> None:
    try:
        AUDIT_INFLIGHT.set(int(inflight or 0))
        AUDIT_QUEUE_DEPTH.set(int(queue_depth or 0))
        AUDIT_WORKERS.set(int(workers or 0))
    except Exception:
        pass


def inc_eventbus_drop(n: int = 1) -> None:
    try:
        EVENTBUS_DROPS.inc(max(1, int(n)))
    except Exception:
        pass


def inc_audit_shed(tier: str = "?", reason: str = "?") -> None:
    """队列满时的处置原因: memory_full / pq_ok / pq_fail / kafka_overflow / local_deque"""
    try:
        AUDIT_SHED.labels(tier=tier or "?", reason=reason or "?").inc()
    except Exception:
        pass


def observe_ingest_stage(stage: str, seconds: float) -> None:
    """记录 ingest 阶段耗时 (detect / persist / dispatch)"""
    try:
        INGEST_STAGE_SECONDS.labels(stage=stage or "?").observe(
            max(0.0, float(seconds or 0.0)))
    except Exception:
        pass


def inc_detector_error(detector: str = "?") -> None:
    try:
        INGEST_DETECTOR_ERRORS.labels(detector=detector or "?").inc()
    except Exception:
        pass


def set_eventbus_subscribers(n: int = 0) -> None:
    try:
        EVENTBUS_SUBSCRIBERS.set(int(n or 0))
    except Exception:
        pass


def refresh_db_pool_gauges() -> None:
    try:
        from models import engine_bg, engine_oltp
        for name, eng in (("oltp", engine_oltp), ("bg", engine_bg)):
            pool = getattr(getattr(eng, "sync_engine", None), "pool", None)
            if pool is None:
                continue
            checked = getattr(pool, "checkedout", lambda: 0)()
            DB_POOL_CHECKEDOUT.labels(pool=name).set(int(checked or 0))
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
    try:
        refresh_db_pool_gauges()
    except Exception:
        pass
    try:
        from event_bus import event_bus
        set_eventbus_subscribers(event_bus.subscriber_count)
    except Exception:
        pass
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
