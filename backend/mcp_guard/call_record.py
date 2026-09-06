"""工具调用规范记录 + 参数消毒。

CallLogger / 行为签名共用此结构。消毒目标：
- 去掉 CR/LF/`|` 等控制字符，避免审计日志注入（AUDIT_REPORT MEDIUM-14）
- 字符串字段截断、arguments JSON 体积封顶，避免把指纹库打爆
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

ARG_JSON_MAX = 4096
STR_MAX = 256
REASON_MAX = 512
TOOL_NAME_MAX = 64
CALLER_MAX = 64
CHECKS_JSON_MAX = 8192
EXEC_RESULT_JSON_MAX = 2048

# 控制字符 + 管道符（旧日志格式用 | 分隔，注入可伪造字段）
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f|]")


def sanitize_str(value: Any, max_len: int = STR_MAX) -> str:
    """去掉控制字符/`|`，折叠空白，截断。"""
    text = "" if value is None else str(value)
    text = _CONTROL_RE.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > max_len:
        return text[: max(0, max_len - 1)] + "…"
    return text


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "…"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):  # NaN/Inf
            return None
        return value
    if isinstance(value, str):
        return sanitize_str(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (key, item) in enumerate(value.items()):
            if i >= 32:
                out["_truncated_keys"] = True
                break
            out[sanitize_str(str(key), 64)] = _sanitize_value(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, depth + 1) for item in list(value)[:32]]
    return sanitize_str(value)


def sanitize_args(arguments: Any, max_bytes: int = ARG_JSON_MAX) -> dict:
    """消毒并封顶 arguments。非 dict 会被包进占位结构，永不抛错。"""
    if not isinstance(arguments, dict):
        arguments = {"_invalid_args": sanitize_str(arguments, 128)}
    cleaned = _sanitize_value(arguments)
    if not isinstance(cleaned, dict):
        cleaned = {"_invalid_args": sanitize_str(cleaned, 128)}
    try:
        encoded = json.dumps(cleaned, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"_serialization_error": True}
    raw = encoded.encode("utf-8")
    if len(raw) <= max_bytes:
        return cleaned
    preview = raw[: max(0, max_bytes - 80)].decode("utf-8", errors="ignore")
    return {
        "_truncated": True,
        "_preview": preview,
        "_orig_bytes": len(raw),
    }


def arg_digest(arguments: dict) -> str:
    """参数稳定哈希（不含原文），供去重/计数。"""
    try:
        blob = json.dumps(arguments or {}, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = "{}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _coerce_event_id(value: Any) -> int:
    try:
        if isinstance(value, bool):
            return 0
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _coerce_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def truncate_jsonable(value: Any, max_bytes: int) -> Any:
    """把 list/dict 压到 max_bytes；失败返回占位。"""
    if value is None:
        return None
    cleaned = _sanitize_value(value)
    try:
        encoded = json.dumps(cleaned, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"_serialization_error": True}
    raw = encoded.encode("utf-8")
    if len(raw) <= max_bytes:
        return cleaned
    preview = raw[: max(0, max_bytes - 80)].decode("utf-8", errors="ignore")
    return {"_truncated": True, "_preview": preview, "_orig_bytes": len(raw)}


@dataclass
class ToolCallRecord:
    """一次工具调用的规范审计记录。"""

    id: int = 0
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str = ""
    caller: str = "unknown"
    caller_role: str = ""
    source: str = "mcp_guard"
    session_id: str = ""
    trace_id: str = ""
    event_id: int = 0
    arguments: dict = field(default_factory=dict)
    arg_digest: str = ""
    decision: str = ""
    reason: str = ""
    checks: list = field(default_factory=list)
    exec_status: Optional[str] = None
    duration_ms: float = 0.0
    tool_match_method: str = "exact"
    signature_score: Optional[float] = None
    signature_reasons: list = field(default_factory=list)
    exec_result: Optional[dict] = None  # 仅内存，不落库

    def sanitize(self) -> "ToolCallRecord":
        """就地消毒，返回 self。永不抛错。"""
        self.ts = _coerce_ts(self.ts)
        self.tool_name = sanitize_str(self.tool_name, TOOL_NAME_MAX)
        self.caller = sanitize_str(self.caller, CALLER_MAX) or "unknown"
        self.caller_role = sanitize_str(self.caller_role, 32)
        self.source = sanitize_str(self.source, 32) or "mcp_guard"
        self.session_id = sanitize_str(self.session_id, 64)
        self.trace_id = sanitize_str(self.trace_id, 64)
        self.event_id = _coerce_event_id(self.event_id)
        self.arguments = sanitize_args(self.arguments)
        self.arg_digest = self.arg_digest or arg_digest(self.arguments)
        self.arg_digest = sanitize_str(self.arg_digest, 32)
        self.decision = sanitize_str(self.decision, 32)
        self.reason = sanitize_str(self.reason, REASON_MAX)
        checks = truncate_jsonable(self.checks if self.checks is not None else [], CHECKS_JSON_MAX)
        self.checks = checks if isinstance(checks, list) else [checks]
        self.exec_status = sanitize_str(self.exec_status, 32) if self.exec_status is not None else None
        try:
            self.duration_ms = float(self.duration_ms or 0.0)
        except (TypeError, ValueError):
            self.duration_ms = 0.0
        self.tool_match_method = sanitize_str(self.tool_match_method, 16) or "exact"
        if self.signature_score is not None:
            try:
                self.signature_score = float(self.signature_score)
            except (TypeError, ValueError):
                self.signature_score = None
        reasons = self.signature_reasons if isinstance(self.signature_reasons, list) else []
        self.signature_reasons = [sanitize_str(r, 240) for r in reasons[:12]]
        if self.exec_result is not None:
            result = truncate_jsonable(self.exec_result, EXEC_RESULT_JSON_MAX)
            self.exec_result = result if isinstance(result, dict) else {"_value": result}
        return self

    def to_dict(self) -> dict:
        """API / 内存 ring 结构。保留 `time`/`user_role` 以兼容旧前端。"""
        ts = _coerce_ts(self.ts)
        return {
            "id": self.id,
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "ts": ts.isoformat(),
            "user_role": self.caller_role,
            "caller": self.caller,
            "caller_role": self.caller_role,
            "source": self.source,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "arg_digest": self.arg_digest,
            "decision": self.decision,
            "reason": self.reason,
            "checks": self.checks,
            "exec_status": self.exec_status,
            "exec_result": self.exec_result,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "event_id": self.event_id,
            "duration_ms": self.duration_ms,
            "tool_match_method": self.tool_match_method,
            "signature_score": self.signature_score,
            "signature_reasons": list(self.signature_reasons),
        }

    def persist_payload(self) -> dict:
        """落库字段（不含 exec_result）。ts 保持 datetime。"""
        return {
            "ts": _coerce_ts(self.ts),
            "tool_name": self.tool_name,
            "caller": self.caller,
            "caller_role": self.caller_role,
            "source": self.source,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "event_id": self.event_id,
            "arguments": self.arguments,
            "arg_digest": self.arg_digest,
            "decision": self.decision,
            "reason": self.reason,
            "checks": self.checks,
            "exec_status": self.exec_status,
            "duration_ms": self.duration_ms,
            "tool_match_method": self.tool_match_method,
            "signature_score": self.signature_score,
            "signature_reasons": list(self.signature_reasons),
        }

    @classmethod
    def from_kwargs(
        cls,
        *,
        user_role: str = "",
        tool_name: str = "",
        arguments: Optional[dict] = None,
        decision: str = "",
        reason: str = "",
        checks: Optional[list] = None,
        exec_status: Optional[str] = None,
        exec_result: Optional[dict] = None,
        caller: str = "",
        source: str = "",
        session_id: str = "",
        trace_id: str = "",
        event_id: int = 0,
        duration_ms: float = 0.0,
        tool_match_method: str = "exact",
        signature_score: Optional[float] = None,
        signature_reasons: Optional[list] = None,
        record_id: int = 0,
        ts: Optional[datetime] = None,
    ) -> "ToolCallRecord":
        rec = cls(
            id=int(record_id or 0),
            ts=_coerce_ts(ts) if ts is not None else datetime.now(timezone.utc),
            tool_name=tool_name or "",
            caller=caller or "unknown",
            caller_role=user_role or "",
            source=source or "mcp_guard",
            session_id=session_id or "",
            trace_id=trace_id or "",
            event_id=_coerce_event_id(event_id),
            arguments=arguments if isinstance(arguments, dict) else {},
            decision=decision or "",
            reason=reason or "",
            checks=list(checks) if isinstance(checks, list) else [],
            exec_status=exec_status,
            duration_ms=duration_ms or 0.0,
            tool_match_method=tool_match_method or "exact",
            signature_score=signature_score,
            signature_reasons=list(signature_reasons) if isinstance(signature_reasons, list) else [],
            exec_result=exec_result if isinstance(exec_result, dict) else None,
        )
        return rec.sanitize()
