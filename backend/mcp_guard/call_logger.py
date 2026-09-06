"""MCP Guard 调用日志记录模块。

职责：记录每次工具调用的完整审计信息。
- 内存 ring（最多 500 条）供热查询
- 参数消毒后异步落库 tool_call_log（失败进离线缓冲，不阻断调用）
- 结构化 logging 不再写入未消毒参数

日志格式：ts | caller_role | tool_name | decision | reason | exec_status | source
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from .call_record import ToolCallRecord

logger = logging.getLogger("mcp_guard.call_logger")

_MAX_RECENT = 500
_FALLBACK_MAX = 1000

PersistImpl = Callable[[dict], Awaitable[None]]


def _row_to_api(obj: Any, *, persisted: bool = True) -> dict:
    ts = getattr(obj, "ts", None)
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts_iso = ts.isoformat()
        time_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    else:
        ts_iso = ""
        time_str = ""
    score = getattr(obj, "signature_score", None)
    reasons = getattr(obj, "signature_reasons", None) or []
    if not isinstance(reasons, list):
        reasons = []
    return {
        "id": getattr(obj, "id", 0),
        "time": time_str,
        "ts": ts_iso,
        "persisted": persisted,
        "user_role": getattr(obj, "caller_role", "") or "",
        "caller": getattr(obj, "caller", "") or "unknown",
        "caller_role": getattr(obj, "caller_role", "") or "",
        "source": getattr(obj, "source", "") or "",
        "tool_name": getattr(obj, "tool_name", "") or "",
        "arguments": getattr(obj, "arguments", None) or {},
        "arg_digest": getattr(obj, "arg_digest", "") or "",
        "decision": getattr(obj, "decision", "") or "",
        "reason": getattr(obj, "reason", "") or "",
        "checks": getattr(obj, "checks", None) or [],
        "exec_status": getattr(obj, "exec_status", None),
        "session_id": getattr(obj, "session_id", "") or "",
        "trace_id": getattr(obj, "trace_id", "") or "",
        "event_id": getattr(obj, "event_id", 0) or 0,
        "duration_ms": getattr(obj, "duration_ms", 0.0) or 0.0,
        "tool_match_method": getattr(obj, "tool_match_method", "") or "exact",
        "signature_score": score,
        "signature_reasons": reasons,
    }


class CallLogger:
    """调用日志记录器。

    - 通过 Python logging 输出审计日志
    - 内存中保留最近 500 条记录，供 API 查询
    - 异步落 PG；无事件循环或写库失败时进离线缓冲
    - 线程安全（使用锁保护 deque）
    """

    def __init__(
        self,
        max_recent: int = _MAX_RECENT,
        persist: Optional[bool] = None,
        persist_impl: Optional[PersistImpl] = None,
    ):
        self._recent: deque = deque(maxlen=max_recent)
        self._fallback: deque = deque(maxlen=_FALLBACK_MAX)
        self._lock = threading.Lock()
        self._counter = 0
        self._dropped = 0
        self._persist_override = persist
        self._persist_impl = persist_impl
        self.detector = None

    def _persist_on(self) -> bool:
        if self._persist_override is not None:
            return bool(self._persist_override)
        try:
            from config import settings
            return bool(getattr(settings, "tool_call_log_persist", True))
        except Exception:
            return True

    def log(
        self,
        user_role: str,
        tool_name: str,
        arguments: dict,
        decision: str,
        reason: str,
        checks: list,
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
        record: Optional[ToolCallRecord] = None,
    ):
        """记录一次工具调用。失败只 warn，不向调用方抛错。"""
        try:
            rec = record.sanitize() if isinstance(record, ToolCallRecord) else ToolCallRecord.from_kwargs(
                user_role=user_role,
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                reason=reason,
                checks=checks,
                exec_status=exec_status,
                exec_result=exec_result,
                caller=caller,
                source=source,
                session_id=session_id,
                trace_id=trace_id,
                event_id=event_id,
                duration_ms=duration_ms,
                tool_match_method=tool_match_method,
                signature_score=signature_score,
                signature_reasons=signature_reasons,
            )
            with self._lock:
                self._counter += 1
                if not rec.id:
                    rec.id = self._counter
                payload = rec.to_dict()
                self._recent.append(payload)

            logger.info(
                "%s | %s | %s | %s | %s | %s | %s",
                rec.ts.isoformat(),
                rec.caller_role or rec.caller,
                rec.tool_name,
                rec.decision,
                rec.reason or "-",
                rec.exec_status or "N/A",
                rec.source,
            )
            if self._persist_on():
                self._schedule_persist(rec.persist_payload())
        except Exception as e:
            logger.warning("CallLogger.log failed (non-fatal): %s", e)

    def _schedule_persist(self, row: dict) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._enqueue(row)
            return
        try:
            loop.create_task(self._persist_one(row))
        except Exception:
            self._enqueue(row)

    async def _persist_one(self, row: dict) -> None:
        try:
            if self._persist_impl is not None:
                await self._persist_impl(row)
                return
            from models import async_session as db_session
            async with db_session() as session:
                await _insert_row(session, row)
        except Exception as e:
            logger.warning("tool_call_log persist failed: %s; enqueue fallback", e)
            self._enqueue(row)

    def _enqueue(self, row: dict) -> None:
        with self._lock:
            if len(self._fallback) >= _FALLBACK_MAX:
                self._dropped += 1
            self._fallback.append(row)

    def recent(self, limit: int = 10) -> list:
        """查询最近的调用记录（内存 ring，按时间倒序）。"""
        with self._lock:
            records = list(self._recent)
        return records[-limit:][::-1]

    def stats(self) -> dict:
        """统计调用情况。"""
        with self._lock:
            records = list(self._recent)
            queued = len(self._fallback)
            dropped = self._dropped
        total = len(records)
        allowed = sum(1 for r in records if r.get("decision") == "allow")
        denied = sum(1 for r in records if r.get("decision") == "deny")
        confirmed = sum(1 for r in records if r.get("decision") == "require_confirmation")
        return {
            "total": total,
            "allow": allowed,
            "deny": denied,
            "require_confirmation": confirmed,
            "persist_enabled": self._persist_on(),
            "persist_queued": queued,
            "persist_dropped": dropped,
        }

    async def flush_fallback(self, session) -> int:
        """冲刷离线缓冲到 DB。先取出本批所有权；失败再连同冲刷期间新入队的一并放回。"""
        with self._lock:
            batch = list(self._fallback)
            self._fallback.clear()
        if not batch:
            return 0
        n = 0
        try:
            for row in batch:
                await _insert_row(session, row, commit=False)
                n += 1
            await session.commit()
            logger.info("tool_call_log flushed %s fallback entries", n)
            return n
        except Exception as e:
            logger.warning("tool_call_log flush failed at #%s: %s", n, e)
            try:
                await session.rollback()
            except Exception:
                pass
            with self._lock:
                arrived = list(self._fallback)
                self._fallback.clear()
                for row in list(batch) + arrived:
                    if len(self._fallback) >= _FALLBACK_MAX:
                        self._dropped += 1
                    else:
                        self._fallback.append(row)
            return 0

    async def query(
        self,
        session=None,
        limit: int = 50,
        source: str = "",
        tool_name: str = "",
        caller: str = "",
    ) -> list:
        """优先读 PG；失败或无 session 时回退内存 ring。"""
        if session is None:
            return self.recent(limit)
        try:
            from sqlalchemy import desc, select
            from models import ToolCallLog

            stmt = select(ToolCallLog).order_by(desc(ToolCallLog.ts)).limit(int(limit))
            if source:
                stmt = stmt.where(ToolCallLog.source == source)
            if tool_name:
                stmt = stmt.where(ToolCallLog.tool_name == tool_name)
            if caller:
                stmt = stmt.where(ToolCallLog.caller == caller)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_row_to_api(obj, persisted=True) for obj in rows]
        except Exception as e:
            logger.warning("tool_call_log query failed, fallback to memory: %s", e)
            records = self.recent(limit)
            if source:
                records = [r for r in records if r.get("source") == source]
            if tool_name:
                records = [r for r in records if r.get("tool_name") == tool_name]
            if caller:
                records = [r for r in records if r.get("caller") == caller]
            return records


async def _insert_row(session, row: dict, commit: bool = True) -> None:
    from models import ToolCallLog

    ts = row.get("ts") or datetime.now(timezone.utc)
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)
    if isinstance(ts, datetime) and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    session.add(ToolCallLog(
        ts=ts,
        tool_name=(row.get("tool_name") or "")[:64],
        caller=(row.get("caller") or "unknown")[:64],
        caller_role=(row.get("caller_role") or "")[:32],
        source=(row.get("source") or "mcp_guard")[:32],
        session_id=(row.get("session_id") or "")[:64],
        trace_id=(row.get("trace_id") or "")[:64],
        event_id=int(row.get("event_id") or 0),
        arguments=row.get("arguments") if isinstance(row.get("arguments"), dict) else {},
        arg_digest=(row.get("arg_digest") or "")[:32],
        decision=(row.get("decision") or "")[:32],
        reason=row.get("reason") or "",
        checks=row.get("checks") if isinstance(row.get("checks"), list) else [],
        exec_status=row.get("exec_status"),
        duration_ms=float(row.get("duration_ms") or 0.0),
        tool_match_method=(row.get("tool_match_method") or "exact")[:16],
        signature_score=row.get("signature_score"),
        signature_reasons=row.get("signature_reasons") if isinstance(row.get("signature_reasons"), list) else [],
    ))
    if commit:
        await session.commit()


async def flush_fallback(session, logger_obj: Optional[CallLogger] = None) -> int:
    """冲刷入口：scheduler / POST /guard/calls/flush。默认冲全局 mcp_guard.logger。"""
    log = logger_obj
    if log is None:
        try:
            from mcp_guard import mcp_guard
            log = getattr(mcp_guard, "logger", None) if mcp_guard is not None else None
        except Exception:
            log = None
    if log is None:
        return 0
    return await log.flush_fallback(session)
