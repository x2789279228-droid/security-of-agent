"""
temporal.client — Temporal client 封装

lazy 连接 Temporal, 提供 start_audit_workflow 供触发边界调用(替换 asyncio.create_task 兜底)。
若 Temporal 未启用/连接失败, 由调用方回退原有 async 编排。

r6 修复:
  - execution_timeout 防止 workflow 永久 RUNNING
  - AUDIT_INFLIGHT_MAX(Redis) 准入,超限返回 "shed" 让调用方写 fallback
"""
import logging
from datetime import timedelta
from typing import Any, Dict, Optional, Union

from config import settings

logger = logging.getLogger(__name__)

_client = None
_client_lock = None  # 惰性 asyncio.Lock
_redis = None
_INFLIGHT_KEY = "soc:audit:inflight"
_INFLIGHT_P0_KEY = "soc:audit:inflight:p0"  # P0 预留槽占用数


def set_redis(redis_client) -> None:
    """由 app/worker 启动时注入,用于跨进程 in-flight 计数。"""
    global _redis
    _redis = redis_client


def _reserved_p0_slots(limit: int) -> int:
    """P0 专槽数量 = ceil(limit * reserve_pct), 至少 1(limit>=5 时)。"""
    pct = float(getattr(settings, "audit_p0_reserve_pct", 0.25) or 0.0)
    pct = max(0.0, min(0.5, pct))
    n = int(limit * pct + 0.999)  # ceil
    if limit >= 5 and pct > 0:
        n = max(1, n)
    return min(n, max(0, limit - 1)) if limit > 1 else 0


async def _inflight_try_acquire(*, tier: str = "P2") -> bool:
    """尝试占一个 in-flight 名额。

    总上限 = audit_inflight_max。
    reserved_p0 槽优先留给 P0: 非 P0 最多占用 (limit - reserved)。
    P0 可占用任意空闲槽(含 reserved)。
    """
    limit = int(getattr(settings, "audit_inflight_max", 0) or 0)
    if limit <= 0 or _redis is None:
        return True
    is_p0 = str(tier or "").upper() == "P0"
    reserved = _reserved_p0_slots(limit)
    shared_cap = max(0, limit - reserved)
    try:
        total = int(await _redis.get(_INFLIGHT_KEY) or 0)
        p0_used = int(await _redis.get(_INFLIGHT_P0_KEY) or 0)
        non_p0 = max(0, total - p0_used)
        if is_p0:
            if total >= limit:
                return False
        else:
            if total >= limit or non_p0 >= shared_cap:
                return False
        pipe = _redis.pipeline()
        pipe.incr(_INFLIGHT_KEY)
        pipe.expire(_INFLIGHT_KEY, 3600)
        if is_p0:
            pipe.incr(_INFLIGHT_P0_KEY)
            pipe.expire(_INFLIGHT_P0_KEY, 3600)
        await pipe.execute()
        return True
    except Exception as e:
        logger.debug(f"[Temporal] inflight acquire skipped: {e}")
        return True


async def inflight_release(*, tier: str = "") -> None:
    """workflow/activity 结束或 shed 时归还名额。"""
    if _redis is None or int(getattr(settings, "audit_inflight_max", 0) or 0) <= 0:
        return
    try:
        n = await _redis.decr(_INFLIGHT_KEY)
        if n < 0:
            await _redis.set(_INFLIGHT_KEY, 0)
        if str(tier or "").upper() == "P0":
            p = await _redis.decr(_INFLIGHT_P0_KEY)
            if p is not None and int(p) < 0:
                await _redis.set(_INFLIGHT_P0_KEY, 0)
    except Exception as e:
        logger.debug(f"[Temporal] inflight release skipped: {e}")


async def pop_workflow_tier(event_id: int) -> str:
    """读取并清除 start 时记录的 tier(供 save_result 归还 P0 槽)。"""
    if _redis is None:
        return ""
    key = f"soc:audit:wf_tier:{event_id}"
    try:
        raw = await _redis.get(key)
        await _redis.delete(key)
        if not raw:
            return ""
        return raw.decode() if isinstance(raw, bytes) else str(raw)
    except Exception:
        return ""


async def inflight_stats() -> dict:
    if _redis is None:
        return {"total": 0, "p0": 0, "limit": int(getattr(settings, "audit_inflight_max", 0) or 0)}
    try:
        total = int(await _redis.get(_INFLIGHT_KEY) or 0)
        p0 = int(await _redis.get(_INFLIGHT_P0_KEY) or 0)
        limit = int(getattr(settings, "audit_inflight_max", 0) or 0)
        return {
            "total": total,
            "p0": p0,
            "limit": limit,
            "reserved_p0": _reserved_p0_slots(limit),
        }
    except Exception:
        return {"total": 0, "p0": 0, "limit": 0}


async def get_client():
    """惰性构造并缓存 temporalio Client。未启用/失败返回 None(触发方降级)。"""
    global _client, _client_lock
    if not settings.temporal_enabled or not settings.temporal_host:
        return None
    if _client is not None:
        return _client
    if _client_lock is None:
        import asyncio
        _client_lock = asyncio.Lock()
    async with _client_lock:
        if _client is not None:
            return _client
        try:
            from temporalio.client import Client
            c = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
            _client = c
            logger.info(f"[Temporal] connected {settings.temporal_host} ns={settings.temporal_namespace} q={settings.temporal_task_queue}")
            return c
        except Exception as e:
            logger.warning(f"[Temporal] connect failed (fallback async): {e}")
            _client = None
            return None


async def start_audit_workflow(
    *,
    session_id: str,
    event_id: int,
    log_data: dict,
    anomaly_score: float,
    anomaly_reasons: list,
    max_rounds: int = 3,
    tier: str = "",
) -> Union[bool, str]:
    """启动 4 层 Agent 编排 Workflow。

    Returns:
      True  — 已 start
      False — Temporal 不可用/启动失败 → 调用方走 async 兜底
      "shed"— in-flight 已满 → 调用方应入 PQ(P0/P1) 或降级
    """
    client = await get_client()
    if client is None:
        return False
    _tier = tier or str((log_data or {}).get("_audit_triage", {}).get("tier") or "P2")
    if not await _inflight_try_acquire(tier=_tier):
        logger.warning(
            f"[Temporal] shed event #{event_id} tier={_tier}: "
            f"inflight>={settings.audit_inflight_max}"
        )
        return "shed"
    try:
        from temporal.workflows import AuditWorkflowInput
        inp = AuditWorkflowInput(
            session_id=session_id,
            event_id=event_id,
            log_data=log_data,
            anomaly_score=float(anomaly_score or 0.0),
            anomaly_reasons=list(anomaly_reasons or []),
            max_rounds=int(max_rounds or 3),
        )
        exec_to = int(getattr(settings, "temporal_workflow_execution_timeout_s", 900) or 900)
        await client.start_workflow(
            "AuditPipelineWorkflow",
            args=[inp],
            id=f"audit-{event_id}",
            task_queue=settings.temporal_task_queue,
            execution_timeout=timedelta(seconds=max(120, exec_to)),
        )
        # 供 save_result 归还时区分 P0 槽
        try:
            if _redis is not None:
                await _redis.set(
                    f"soc:audit:wf_tier:{event_id}", _tier, ex=exec_to + 600
                )
        except Exception:
            pass
        logger.info(
            f"[Temporal] started workflow audit-{event_id} "
            f"tier={_tier} (rounds<={max_rounds})"
        )
        return True
    except Exception as e:
        await inflight_release(tier=_tier)
        logger.warning(f"[Temporal] start_workflow failed (fallback async): {e}")
        return False
