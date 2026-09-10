"""
操作审计 trail (Audit Trail) — P0.H

职责:
  为平台所有关键写操作留下不可篡改的 who-did-what-when 记录，
  供监管取证、内部排查、特权二次审计使用。

设计原则:
  - 纯函数模块，不抢业务逻辑
  - 失败不阻塞业务 (容错降级：DB 写失败仅 warn)
  - 提供 @audited 装饰器最小侵入接入

调用方式:
  from audit_trail import log_action, audited

  # 方式 1：直接调用
  await log_action(session, actor="alice", action="case.transition",
                   target_type="case", target_id="1",
                   before={"status":"open"}, after={"status":"investigating"},
                   reason="开始调查")

  # 方式 2：装饰器 (同步/异步均可)
  @audited(action="rule.publish", target_type="rule")
  async def publish_rule(...): ...
"""
import asyncio
import functools
import logging
import inspect
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── 审计哈希链 (PR1 控制面安全) ──
# 每条记录携带 prev_hash / row_hash:
#   row_hash = hmac_sha256(canonical_json{actor, action, target_type, target_id,
#                                          before, after, reason, prev_hash, created_at_iso})
#   prev_hash = 前一条 row_hash (按 id 倒序取最新); 首条用 64 个 '0'(genesis)
# 写库(_persist_entry / flush_fallback)与校验(verify_chain)共用 _compute_row_hash, 保证一致。
GENESIS_HASH = "0" * 64


def _utc_naive_iso(dt) -> str:
    """统一 UTC-naive ISO 串: 写入(aware datetime)与读回(sqlite naive / PG aware)一致。"""
    if dt is None:
        return ""
    try:
        if getattr(dt, "tzinfo", None) is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.isoformat()
    except Exception:
        return str(dt)


def _compute_row_hash(*, actor, action, target_type, target_id,
                      before, after, reason, prev_hash, created_at) -> str:
    """重算单行 row_hash(写库与校验共用, 输入必须与落库值一致)。"""
    from security_crypto import canonical_json, hmac_hex
    payload = canonical_json({
        "actor": actor,
        "action": action,
        "target_type": target_type or "",
        "target_id": str(target_id) if target_id not in (None, "") else "",
        "before": before or {},
        "after": after or {},
        "reason": reason or "",
        "prev_hash": prev_hash or GENESIS_HASH,
        "created_at": _utc_naive_iso(created_at),
    })
    return hmac_hex(payload)


async def _latest_row_hash(session: AsyncSession) -> str:
    """取当前链尾 row_hash; 无记录或查询失败 → genesis(fail-open)。"""
    from models import AuditTrail
    try:
        last = (await session.execute(
            select(AuditTrail.row_hash).order_by(desc(AuditTrail.id)).limit(1)
        )).scalar()
        return last or GENESIS_HASH
    except Exception as e:
        logger.warning(f"[audit_trail] read latest row_hash failed: {e}")
        return GENESIS_HASH


def _chain_for(entry: dict, created_at, prev_hash: str) -> tuple:
    """计算 (prev_hash, row_hash)。哈希计算失败 → fail-open: 空哈希仍落库, 业务不阻塞。"""
    try:
        row_hash = _compute_row_hash(
            actor=entry["actor"], action=entry["action"],
            target_type=entry["target_type"], target_id=entry["target_id"],
            before=entry["before"], after=entry["after"],
            reason=entry["reason"], prev_hash=prev_hash,
            created_at=created_at,
        )
        return prev_hash, row_hash
    except Exception as e:
        logger.warning(f"[audit_trail] row hash compute failed (fail-open, empty hash): {e}")
        return "", ""


# ── 离线降级缓冲 ──
# DB 不可用时,日志先 enqueue(限量),后台再重试; 进一步场景可改为 Redis 队列。
_fallback_buffer: list[dict] = []
_FALLBACK_MAX = 500


def _build_entry(
    *,
    actor: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    actor_role: str = "",
    reason: str = "",
    ip: str = "",
    user_agent: str = "",
) -> dict:
    return {
        "actor": actor or "anonymous",
        "actor_role": actor_role or "",
        "action": action,
        "target_type": target_type,
        "target_id": str(target_id) if target_id else "",
        "before": _truncate(before or {}),
        "after": _truncate(after or {}),
        "ip": ip or "",
        "user_agent": (user_agent or "")[:200],
        "reason": (reason or "")[:2000],
        "created_at": datetime.now(timezone.utc),
    }


def log_action_sync(
    *,
    actor: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    actor_role: str = "",
    reason: str = "",
    ip: str = "",
    user_agent: str = "",
) -> None:
    """同步路径（MCP Guard 在 to_thread 中调用）。有事件循环则投递，否则进 fallback。"""
    entry = _build_entry(
        actor=actor, action=action, target_type=target_type, target_id=target_id,
        before=before, after=after, actor_role=actor_role, reason=reason,
        ip=ip, user_agent=user_agent,
    )
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None and loop.is_running():
        loop.create_task(_persist_entry_or_fallback(entry))
        return
    _enqueue_fallback(entry)


async def _persist_entry_or_fallback(entry: dict) -> None:
    try:
        from models import async_session as db_session
        async with db_session() as own:
            await _persist_entry(own, entry)
    except Exception as e:
        logger.warning("[audit_trail] async persist failed: %s; enqueue fallback", e)
        _enqueue_fallback(entry)


async def log_action(
    session: Optional[AsyncSession],
    *,
    actor: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    actor_role: str = "",
    reason: str = "",
    ip: str = "",
    user_agent: str = "",
) -> None:
    """
    记录一条操作审计 trail

    Args:
        session: 可选 DB session；为 None 时自行开库写入,失败才进离线缓冲(scheduler 冲刷)
        actor: 操作人（用户名/system/anonymous）
        action: 动作 key，命名空间.动作 (case.transition / order.approve / rule.publish / asset.update / source.revoke)
        target_type: case|work_order|rule|asset|playbook|source|...
        target_id: 目标对象主键字符串
        before/after: 变更前后的字段快照（自动截断过长内容）
        reason: 操作理由（人工填写或自动生成）
    """
    entry = _build_entry(
        actor=actor, action=action, target_type=target_type, target_id=target_id,
        before=before, after=after, actor_role=actor_role, reason=reason,
        ip=ip, user_agent=user_agent,
    )

    if session is None:
        # 调用方未持有 session: 自行开库。失败才进内存缓冲(须由 flush_fallback 冲刷)。
        try:
            from models import async_session as db_session
            async with db_session() as own:
                await _persist_entry(own, entry)
            return
        except Exception as e:
            logger.warning(f"[audit_trail] auto-session persist failed: {e}; enqueue fallback")
            _enqueue_fallback(entry)
            return

    try:
        await _persist_entry(session, entry)
    except Exception as e:
        logger.warning(f"[audit_trail] persist failed: {e}; enqueue fallback")
        _enqueue_fallback(entry)


async def _persist_entry(session: AsyncSession, entry: dict) -> None:
    from models import AuditTrail
    created_at = entry.get("created_at") or datetime.now(timezone.utc)
    prev_hash = await _latest_row_hash(session)
    prev_hash, row_hash = _chain_for(entry, created_at, prev_hash)
    session.add(AuditTrail(
        actor=entry["actor"],
        actor_role=entry["actor_role"],
        action=entry["action"],
        target_type=entry["target_type"],
        target_id=entry["target_id"],
        before=entry["before"],
        after=entry["after"],
        ip=entry["ip"],
        user_agent=entry["user_agent"],
        reason=entry["reason"],
        prev_hash=prev_hash,
        row_hash=row_hash,
        created_at=created_at,
    ))
    await session.commit()


def _enqueue_fallback(entry: dict) -> None:
    """离线缓冲。冲刷入口: scheduler._audit_trail_flush_loop (60s) 与 POST /audit-trail/flush。"""
    _fallback_buffer.append(entry)
    if len(_fallback_buffer) > _FALLBACK_MAX:
        del _fallback_buffer[: len(_fallback_buffer) - _FALLBACK_MAX]


async def log_from_request(
    session: Optional[AsyncSession],
    request,
    user,
    action: str,
    target_type: str = "",
    target_id: str = "",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    reason: str = "",
) -> None:
    """端点便捷接入：actor 强制取 JWT 身份（auth.UserInfo），不信任请求体参数。

    request/user 只要求具备 client/headers/username/role 属性，
    便于测试直接调用端点函数时传入 stub 对象。
    """
    try:
        ip = request.client.host if (request is not None and request.client) else ""
    except Exception:
        ip = ""
    try:
        ua = request.headers.get("user-agent", "") if request is not None else ""
    except Exception:
        ua = ""
    await log_action(
        session,
        actor=getattr(user, "username", "") or "anonymous",
        actor_role=getattr(user, "role", ""),
        action=action,
        target_type=target_type,
        target_id=target_id,
        before=before,
        after=after,
        reason=reason,
        ip=ip,
        user_agent=ua,
    )


async def flush_fallback(session: AsyncSession) -> int:
    """冲刷离线缓冲到 DB。

    调用方: scheduler._audit_trail_flush_loop (每 60s) 与 POST /audit-trail/flush。
    提交成功后再出队; commit 失败则条目留在内存,下一轮重试。
    """
    if not _fallback_buffer:
        return 0
    batch = list(_fallback_buffer)
    n = 0
    try:
        from models import AuditTrail
        prev_hash = await _latest_row_hash(session)
        for entry in batch:
            created_at = entry.get("created_at") or datetime.now(timezone.utc)
            _, row_hash = _chain_for(entry, created_at, prev_hash)
            session.add(AuditTrail(
                actor=entry["actor"], actor_role=entry["actor_role"],
                action=entry["action"], target_type=entry["target_type"],
                target_id=entry["target_id"], before=entry["before"],
                after=entry["after"], ip=entry["ip"],
                user_agent=entry["user_agent"], reason=entry["reason"],
                prev_hash=prev_hash, row_hash=row_hash,
                created_at=created_at,
            ))
            # 链式推进: 同批内后一行 prev = 本行 row_hash(哈希失败则沿用旧 prev, 断链可检出)
            prev_hash = row_hash or prev_hash
            n += 1
        await session.commit()
        del _fallback_buffer[:n]
        logger.info(f"[audit_trail] flushed {n} fallback entries")
        return n
    except Exception as e:
        logger.warning(f"[audit_trail] flush failed at #{n}: {e}")
        try:
            await session.rollback()
        except Exception:
            pass
        return 0


async def verify_chain(session: AsyncSession) -> dict:
    """校验整条审计哈希链。

    按 id 升序遍历, 用每行字段 + prev_hash 重算 row_hash 并与库中值比对。
    返回: {"ok": bool, "checked": int, "first_break_id": Optional[int]}
      - 空表: ok=True, checked=0, first_break_id=None
      - 断点: first_break_id=首个不匹配行 id, checked=断点前通过行数
      注: 空 row_hash/prev_hash 的行(旧数据或 fail-open 落库)会计为断点。
    """
    from models import AuditTrail
    stmt = select(AuditTrail).order_by(AuditTrail.id)
    rows = (await session.execute(stmt)).scalars().all()
    checked = 0
    for row in rows:
        recomputed = _compute_row_hash(
            actor=row.actor, action=row.action,
            target_type=row.target_type or "", target_id=row.target_id or "",
            before=row.before or {}, after=row.after or {},
            reason=row.reason or "", prev_hash=row.prev_hash or "",
            created_at=row.created_at,
        )
        if recomputed != (row.row_hash or ""):
            return {"ok": False, "checked": checked, "first_break_id": row.id}
        checked += 1
    return {"ok": True, "checked": checked, "first_break_id": None}


def _truncate(obj, max_chars: int = 4000) -> dict:
    """限制 before/after 体积，避免日志爆炸"""
    import json
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
        if len(s) > max_chars:
            return {"_truncated": True, "_preview": s[:max_chars]}
        return obj
    except Exception:
        return {"_serialization_error": True}


async def list_trail(
    session: AsyncSession,
    *,
    actor: str = "",
    action: str = "",
    target_type: str = "",
    target_id: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """查询审计 trail"""
    from models import AuditTrail

    stmt = select(AuditTrail)
    if actor:
        stmt = stmt.where(AuditTrail.actor == actor)
    if action:
        stmt = stmt.where(AuditTrail.action == action)
    if target_type:
        stmt = stmt.where(AuditTrail.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditTrail.target_id == str(target_id))
    stmt = stmt.order_by(desc(AuditTrail.created_at)).limit(limit).offset(offset)

    result = await session.execute(stmt)
    return [
        {
            "id": t.id,
            "actor": t.actor,
            "actor_role": t.actor_role,
            "action": t.action,
            "target_type": t.target_type,
            "target_id": t.target_id,
            "before": t.before or {},
            "after": t.after or {},
            "ip": t.ip,
            "reason": t.reason,
            "created_at": t.created_at.isoformat() if t.created_at else "",
        }
        for t in result.scalars().all()
    ]


# ── 装饰器 ──

def audited(
    *,
    action: str,
    target_type: str = "",
    target_id_kwarg: str = "case_id",
    before_kwarg: Optional[str] = None,
    after_kwarg: Optional[str] = None,
    actor_kwarg: str = "by",
    reason_kwarg: str = "reason",
):
    """
    装饰器: 自动记录被装饰函数的写操作
    - 支持 sync/async
    - 若声明 before_kwarg/after_kwarg, 自动从入参里取字段级快照
    - 若未声明, 仅记录 action 调用本身
    - 装饰器不抛异常：业务成功后才记录,失败不记录(避免误审)

    Example:
        @audited(action="case.transition", target_type="case",
                 before_kwarg="old_status", after_kwarg="new_status")
        async def update_status(...): ...
    """
    def decorator(fn):
        is_async = inspect.iscoroutinefunction(fn)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            result = await fn(*args, **kwargs)
            try:
                await _record_from_kwargs(fn, kwargs, action, target_type,
                                          target_id_kwarg, before_kwarg,
                                          after_kwarg, actor_kwarg, reason_kwarg)
            except Exception as e:
                logger.debug(f"[audit_trail] decorator record failed: {e}")
            return result

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            try:
                asyncio.get_event_loop().create_task(
                    _record_from_kwargs(fn, kwargs, action, target_type,
                                        target_id_kwarg, before_kwarg,
                                        after_kwarg, actor_kwarg, reason_kwarg)
                )
            except Exception as e:
                logger.debug(f"[audit_trail] sync record failed: {e}")
            return result

        return async_wrapper if is_async else sync_wrapper

    return decorator


async def _record_from_kwargs(fn, kwargs, action, target_type,
                                target_id_kwarg, before_kwarg,
                                after_kwarg, actor_kwarg, reason_kwarg):
    """从入参中提取审计字段,异步写入"""
    actor = str(kwargs.get(actor_kwarg, "anonymous"))
    target_id = str(kwargs.get(target_id_kwarg, ""))
    before = kwargs.get(before_kwarg) if before_kwarg else None
    after = kwargs.get(after_kwarg) if after_kwarg else None
    reason = str(kwargs.get(reason_kwarg, "")) if reason_kwarg else ""

    from models import async_session
    async with async_session() as s:
        await log_action(
            s, actor=actor, action=action, target_type=target_type,
            target_id=target_id, before=before, after=after,
            reason=reason,
        )