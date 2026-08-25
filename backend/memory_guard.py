"""
记忆 / 日志投毒门 — PR2

P0-10  向量记忆写时门：source_type / provenance / hash / trust
P0-11  日志消毒视图：LLM 只看 <untrusted_log>，原文仍落库
P0-12  RAG 双源：单源知识库不得单独支撑定罪
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, Optional


SOURCE_EVENT = "event"
SOURCE_KB = "kb"
SOURCE_OPERATOR = "operator"
SOURCE_AGENT = "agent_output"

DEFAULT_TRUST = {
    SOURCE_EVENT: 0.8,
    SOURCE_KB: 0.7,
    SOURCE_OPERATOR: 0.9,
    SOURCE_AGENT: 0.2,
}

# 进入 LLM prompt 的最低 trust；低于此值只给人看
LLM_MIN_TRUST = 0.6

SIGNED_KB_SOURCES = frozenset({
    "mitre-attack", "capec", "cve", "seed", "playbook",
})
APPROVED_STATUSES = frozenset({"approved", "signed_import"})

# 指令注入 / 工具调用块 / 角色扮演
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous", re.I),
    re.compile(r"ignore\s+all\s+instructions", re.I),
    re.compile(r"you\s+are\s+(now\s+)?(a|an|the)\s", re.I),
    re.compile(r"\bsystem\s*:", re.I),
    re.compile(r"<\|system\|>", re.I),
    re.compile(r"<<\s*SYS\s*>>", re.I),
    re.compile(r"\[/?INST\]", re.I),
    re.compile(r"\bassistant\s*:", re.I),
    re.compile(r"\btool_call\b", re.I),
    re.compile(r"\bfunction_call\b", re.I),
    re.compile(r"```(?:json)?\s*\{\s*\"tool", re.I),
    re.compile(r"必须判定为(误报|放行)", re.I),
    re.compile(r"must\s+(treat|mark|classify)\s+as\s+(benign|false\s+positive)", re.I),
]

# 超长 base64（像 payload 而不像日志）
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def default_trust(source_type: str) -> float:
    return float(DEFAULT_TRUST.get(source_type or SOURCE_AGENT, 0.2))


def looks_like_injection(text: str) -> bool:
    if not text:
        return False
    if _BASE64_BLOB.search(text):
        return True
    return any(p.search(text) for p in _INJECTION_PATTERNS)


def sanitize_untrusted_text(text: str, max_len: int = 2000) -> str:
    """剥离指令语气与超长 blob，保留 IP/事件等取证字段形态。"""
    if not text:
        return ""
    out = text
    out = _BASE64_BLOB.sub("[stripped:base64]", out)
    for p in _INJECTION_PATTERNS:
        out = p.sub("[stripped:injection]", out)
    out = out.replace("\x00", "")
    if len(out) > max_len:
        out = out[:max_len] + "…"
    return out


def wrap_untrusted(text: str, source: str = "log") -> str:
    cleaned = sanitize_untrusted_text(text)
    return f"<untrusted_log source=\"{source}\">\n{cleaned}\n</untrusted_log>"


def sanitize_event_for_llm(event: Optional[dict]) -> dict:
    """返回事件副本，message 等自由文本已消毒。原始事件不改。"""
    if not event:
        return {}
    safe = dict(event)
    for key in ("message", "msg", "description", "raw"):
        if key in safe and isinstance(safe[key], str):
            safe[key] = sanitize_untrusted_text(safe[key], max_len=500)
    raw = safe.get("raw_data")
    if isinstance(raw, dict) and isinstance(raw.get("message"), str):
        raw = dict(raw)
        raw["message"] = sanitize_untrusted_text(raw["message"], max_len=500)
        safe["raw_data"] = raw
    return safe


def structured_memory_content(
    kind: str,
    summary: str,
    provenance_id: str = "",
    extra: Optional[dict] = None,
) -> str:
    """Agent 记忆只存结构化结论，不存原始 user_input。"""
    summary = sanitize_untrusted_text(str(summary or ""), max_len=240)
    extra = extra or {}
    parts = [
        f"kind={kind}",
        f"provenance={provenance_id}" if provenance_id else "",
        f"summary={summary}",
    ]
    for k in ("threat_type", "verdict", "event_id"):
        if extra.get(k) not in (None, ""):
            parts.append(f"{k}={extra[k]}")
    return " ".join(p for p in parts if p)


def memory_trust_value(mem: Any) -> float:
    trust = getattr(mem, "trust", None)
    if trust is not None:
        try:
            return float(trust)
        except (TypeError, ValueError):
            pass
    meta = getattr(mem, "metadata_", None) or {}
    if isinstance(meta, dict) and "trust" in meta:
        try:
            return float(meta["trust"])
        except (TypeError, ValueError):
            pass
    content = getattr(mem, "content", "") or ""
    if looks_like_injection(content):
        return 0.1
    return 0.4  # 旧记忆无字段：低于 LLM 门槛


def filter_memories_for_llm(memories: Iterable[Any], min_trust: float = LLM_MIN_TRUST) -> list:
    kept = []
    dropped = 0
    for m in memories or []:
        t = memory_trust_value(m)
        content = getattr(m, "content", "") or ""
        if t < min_trust or looks_like_injection(content):
            dropped += 1
            continue
        kept.append(m)
    return kept


def kb_source_is_signed(source: str) -> bool:
    return (source or "").lower() in SIGNED_KB_SOURCES


def kb_is_retrievable(approval_status: str) -> bool:
    return (approval_status or "") in APPROVED_STATUSES
