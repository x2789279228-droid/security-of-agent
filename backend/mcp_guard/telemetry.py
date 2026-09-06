"""三链共用的工具调用 telemetry sink。

链 A（MCP Guard）走 GuardServer._finish。
链 B（ResponseEngine / SecurityGuard）和链 C（Audit-LLM Executor）调 ingest_tool_call。
失败一律吞掉，不影响业务路径。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .behavior_detector import BehaviorDetector, SignatureReport
from .call_logger import CallLogger
from .call_record import ToolCallRecord

logger = logging.getLogger("mcp_guard.telemetry")


def _jsonable_args(arguments: Any) -> dict:
    if not isinstance(arguments, dict):
        return {}
    out = {}
    for key, value in arguments.items():
        if key == "session" or str(key).startswith("_"):
            continue
        if hasattr(value, "execute") and hasattr(value, "commit"):
            continue
        out[key] = value
    return out


def _checks_to_dicts(checks: Any) -> list:
    out = []
    for item in checks or []:
        if hasattr(item, "check_name"):
            out.append({
                "check": getattr(item, "check_name", ""),
                "passed": bool(getattr(item, "passed", False)),
                "message": str(getattr(item, "message", "") or ""),
            })
        elif isinstance(item, dict):
            out.append(item)
    return out


def _resolve_source(source: str, caller: str) -> str:
    src = (source or "").strip() or "mcp_guard"
    try:
        from trace_hook import get_trace_context
        ctx = get_trace_context() or {}
        ctx_src = str(ctx.get("source") or "")
        ctx_caller = str(ctx.get("caller") or "")
        if ctx_src in ("self_play", "self-play") or "self_play" in ctx_caller:
            return "self_play"
        if not source and ctx.get("source"):
            src = str(ctx.get("source"))
    except Exception:
        pass
    if "self_play" in (caller or "") or src in ("self-play",):
        return "self_play"
    return src


def _resolve_ids(session_id: str, trace_id: str, event_id: int) -> tuple[str, str, int]:
    try:
        from trace_hook import get_trace_context
        ctx = get_trace_context() or {}
        if not session_id:
            session_id = str(ctx.get("session_id") or "")
        if not trace_id:
            trace_id = str(ctx.get("trace_id") or "")
        if not event_id:
            event_id = int(ctx.get("event_id") or 0)
    except Exception:
        pass
    return session_id, trace_id, int(event_id or 0)


def ingest_tool_call(
    *,
    tool_name: str,
    arguments: Optional[dict] = None,
    caller: str = "unknown",
    source: str = "mcp_guard",
    caller_role: str = "system",
    decision: str = "allow",
    reason: str = "",
    checks: Optional[list] = None,
    exec_status: Optional[str] = None,
    exec_result: Optional[dict] = None,
    duration_ms: float = 0.0,
    session_id: str = "",
    trace_id: str = "",
    event_id: int = 0,
    tool_match_method: str = "exact",
    logger_obj: Optional[CallLogger] = None,
    detector: Optional[BehaviorDetector] = None,
) -> Optional[SignatureReport]:
    """打分（shadow）+ 按规则学习 + 写入 CallLogger。永不向调用方抛错。"""
    try:
        if logger_obj is None or detector is None:
            from mcp_guard import mcp_guard
            if mcp_guard is None:
                return None
            logger_obj = logger_obj or getattr(mcp_guard, "logger", None)
            detector = detector or getattr(mcp_guard, "detector", None)
        if logger_obj is None:
            return None

        session_id, trace_id, event_id = _resolve_ids(session_id, trace_id, event_id)
        source = _resolve_source(source, caller)
        rec = ToolCallRecord.from_kwargs(
            user_role=caller_role,
            tool_name=tool_name,
            arguments=_jsonable_args(arguments),
            decision=decision,
            reason=reason,
            checks=_checks_to_dicts(checks),
            exec_status=exec_status,
            exec_result=exec_result if isinstance(exec_result, dict) else None,
            caller=caller or "unknown",
            source=source,
            session_id=session_id,
            trace_id=trace_id,
            event_id=event_id,
            duration_ms=duration_ms,
            tool_match_method=tool_match_method,
        )
        report = None
        if detector is not None:
            try:
                report = detector.observe(rec)
            except Exception as e:
                logger.warning("ingest observe failed: %s", e)
                report = None
        if report is not None:
            rec.signature_score = report.anomaly_score
            rec.signature_reasons = list(report.reasons)
        logger_obj.log(
            user_role=caller_role,
            tool_name=tool_name,
            arguments=rec.arguments,
            decision=decision,
            reason=reason,
            checks=rec.checks,
            exec_status=exec_status,
            exec_result=exec_result if isinstance(exec_result, dict) else None,
            caller=rec.caller,
            source=rec.source,
            session_id=rec.session_id,
            trace_id=rec.trace_id,
            event_id=rec.event_id,
            duration_ms=rec.duration_ms,
            tool_match_method=rec.tool_match_method,
            signature_score=rec.signature_score,
            signature_reasons=rec.signature_reasons,
            record=rec,
        )
        if rec.event_id:
            try:
                from observability.thought_events import emit_tool_result
                emit_tool_result(
                    tool_name=rec.tool_name,
                    success=exec_status not in ("error", "blocked", "failed"),
                    duration_ms=rec.duration_ms,
                    report=report,
                    event_id=rec.event_id,
                    session_id=rec.session_id,
                    trace_id=rec.trace_id,
                )
            except Exception:
                pass
        return report
    except Exception as e:
        logger.warning("ingest_tool_call failed (non-fatal): %s", e)
        return None


def args_from_threat(action_name: str, threat_info: Optional[dict], extra: Optional[dict] = None) -> dict:
    """从响应动作 + 威胁上下文抽出可指纹化参数。"""
    info = threat_info if isinstance(threat_info, dict) else {}
    args = dict(extra) if isinstance(extra, dict) else {}
    ip = args.get("ip") or info.get("src_ip") or info.get("ip") or info.get("dst_ip") or ""
    host = args.get("host") or info.get("host") or info.get("hostname") or ip
    if action_name in ("block_ip", "rate_limit") and ip:
        args.setdefault("ip", ip)
    if action_name == "rate_limit":
        args.setdefault("rate", info.get("rate") or args.get("rate") or 100)
    if action_name == "isolate_host":
        args.setdefault("host", host or "")
        args.setdefault("isolation_type", info.get("isolation_type") or "network")
    if action_name == "terminate_process":
        pid = info.get("pid") or args.get("pid")
        if pid is not None:
            args.setdefault("pid", pid)
    if action_name in ("alert_only", "send_alert"):
        args.setdefault(
            "message",
            info.get("reason") or info.get("message") or action_name,
        )
        if action_name == "send_alert":
            args.setdefault("ip", ip)
    if ip and "ip" not in args and action_name not in ("alert_only", "send_alert", "isolate_host"):
        args["ip"] = ip
    return args
