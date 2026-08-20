"""
trace_context.py — W3C Trace Context (traceparent) 工具

标准格式: `00-<trace-id 32hex>-<span-id 16hex>-<flags 2hex>`
  - trace-id: 32 位十六进制 (16 字节)
  - span-id:  16 位十六进制 (8 字节)
  - flags:    01 = sampled

本项目 trace_id (eventId UUID) 直接映射为 W3C trace-id (去横线后为 32 hex),
使自研链路与标准 OTel/Tempo 体系无缝互通。
"""
import os
import re
import uuid

_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def normalize_trace_id(trace_id: str) -> str:
    """把任意来源的 trace_id (可能带横线的 UUID) 规整为 32 hex 无横线。

    不足 32 hex 时用 UUID 补齐 (保持确定性: 同一输入 → 同一 trace-id)。
    """
    if not trace_id:
        return uuid.uuid4().hex
    cleaned = trace_id.replace("-", "").lower()
    if _TRACE_ID_RE.match(cleaned):
        return cleaned
    # 非 32 hex: 用 MD5/确定性补齐为 32 hex
    import hashlib
    return hashlib.md5(trace_id.encode("utf-8")).hexdigest()


def generate_span_id() -> str:
    """生成 16 hex 的 span-id (8 字节随机)"""
    return uuid.uuid4().hex[:16]


def make_traceparent(trace_id: str = "", sampled: bool = True) -> str:
    """构造 W3C traceparent (根 span, span-id 为新随机值)"""
    tid = normalize_trace_id(trace_id)
    flags = "01" if sampled else "00"
    return f"00-{tid}-{generate_span_id()}-{flags}"


def make_child_traceparent(traceparent: str) -> str:
    """基于现有 traceparent 生成子 span 的 traceparent (继承 trace-id, 新 span-id)"""
    parsed = parse_traceparent(traceparent)
    if not parsed:
        return make_traceparent()
    return f"00-{parsed['trace_id']}-{generate_span_id()}-{parsed['flags']}"


def parse_traceparent(tp: str) -> dict | None:
    """解析 W3C traceparent, 非法返回 None"""
    if not tp:
        return None
    m = _TRACEPARENT_RE.match(tp.strip().lower())
    if not m:
        return None
    return {
        "version": m.group("version"),
        "trace_id": m.group("trace_id"),
        "span_id": m.group("span_id"),
        "flags": m.group("flags"),
        "sampled": m.group("flags")[-1] in ("1", "3", "5", "7", "9", "b", "d", "f"),
    }


def span_id_to_bytes(span_id: str) -> bytes:
    """16 hex → 8 字节"""
    return bytes.fromhex(span_id) if _SPAN_ID_RE.match(span_id) else os.urandom(8)
