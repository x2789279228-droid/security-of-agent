"""
标准 OpenTelemetry / W3C trace 单元测试 (Phase: trace 体系)

覆盖:
  - trace_context: W3C traceparent 编解码 (normalize/make/parse/child)
  - otel_setup.extract_context: 从 header 提取上下文 + trace_id 回退
  - pipeline_tracer: OTel 可用时捕获 W3C trace_id 并导出 span
  - kafka_consumer: 从 Kafka header 提取 traceparent/trace_id

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 测试。
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine
def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)
_sa_async.create_async_engine = _patched_create_async_engine


# ── W3C traceparent 编解码 ──

def test_traceparent_roundtrip():
    import trace_context as tc

    tp = tc.make_traceparent("550e8400-e29b-41d4-a716-446655440000", sampled=True)
    parsed = tc.parse_traceparent(tp)
    assert parsed is not None
    assert parsed["trace_id"] == "550e8400e29b41d4a716446655440000"
    assert parsed["version"] == "00"
    assert parsed["sampled"] is True
    assert len(parsed["span_id"]) == 16


def test_normalize_trace_id_variants():
    import trace_context as tc

    assert tc.normalize_trace_id("550e8400-e29b-41d4-a716-446655440000") == "550e8400e29b41d4a716446655440000"
    assert tc.normalize_trace_id("550e8400e29b41d4a716446655440000") == "550e8400e29b41d4a716446655440000"
    # 非 32 hex → MD5 确定性补齐
    a = tc.normalize_trace_id("short-id")
    b = tc.normalize_trace_id("short-id")
    assert a == b and len(a) == 32
    assert tc.normalize_trace_id("")  # 空 → 随机 UUID


def test_make_child_traceparent_inherits_trace_id():
    import trace_context as tc

    parent = tc.make_traceparent("11111111111111111111111111111111")
    child = tc.make_child_traceparent(parent)
    p = tc.parse_traceparent(parent)
    c = tc.parse_traceparent(child)
    assert c["trace_id"] == p["trace_id"]
    assert c["span_id"] != p["span_id"]


def test_parse_invalid_traceparent():
    import trace_context as tc

    assert tc.parse_traceparent("") is None
    assert tc.parse_traceparent("not-a-traceparent") is None
    assert tc.parse_traceparent("00-1234-5678-01") is None  # 长度不足


# ── otel_setup.extract_context ──

def test_extract_context_from_traceparent():
    from otel_setup import extract_context, HAS_OTEL
    if not HAS_OTEL:
        pytest.skip("opentelemetry 未安装")

    from trace_context import make_traceparent
    tp = make_traceparent("550e8400e29b41d4a716446655440000")
    ctx = extract_context({"traceparent": tp})
    assert ctx is not None

    # trace_id 回退: 无 traceparent 但带 trace_id → 仍可提取
    ctx2 = extract_context({"trace_id": "550e8400-e29b-41d4-a716-446655440000"})
    assert ctx2 is not None

    assert extract_context({}) is None
    assert extract_context(None) is None


# ── pipeline_tracer OTel 集成 ──

def test_pipeline_tracer_captures_otel_trace_id():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.resources import Resource
    from observability.pipeline_tracer import PipelineTracer

    # 隔离的 in-memory provider (不影响全局默认)
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = otel_trace.get_tracer("test")  # 绑定当前 provider

    old_provider = otel_trace.get_tracer_provider()
    try:
        otel_trace.set_tracer_provider(provider)
        tracer = otel_trace.get_tracer("soc-backend-test")
        pt = PipelineTracer()
        sp = pt.start_span("executor", event_id=7, session_id="sess-1")
        pt.end_span(sp)
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        exported = spans[0]
        # W3C trace-id 关联: pipeline span 记录了与 OTel span 一致的 trace_id
        assert sp.trace_id == format(exported.get_span_context().trace_id, "032x")
        assert sp.stage == "executor"
    finally:
        # 还原全局 provider (避免影响其它测试)
        otel_trace.set_tracer_provider(old_provider)


# ── kafka_consumer header 提取 ──

class _FakeMsg:
    def __init__(self, headers):
        self.headers = headers


def test_kafka_consumer_extract_trace_carrier():
    from kafka_consumer import KafkaConsumerManager

    msg = _FakeMsg([
        ("traceparent", b"00-550e8400e29b41d4a716446655440000-1111222233334444-01"),
        ("trace_id", b"550e8400-e29b-41d4-a716-446655440000"),
        ("other", b"x"),
    ])
    carrier = KafkaConsumerManager._extract_trace_carrier(msg)
    assert carrier["traceparent"].startswith("00-550e8400e29b41d4a716446655440000")
    assert carrier["trace_id"] == "550e8400-e29b-41d4-a716-446655440000"

    empty = KafkaConsumerManager._extract_trace_carrier(_FakeMsg([]))
    assert empty == {}
