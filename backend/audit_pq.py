"""
审计优先级队列 (Audit Priority Queue)

inflight 满时: P0/P1 入 Redis ZSET 等待拉取, P2/P3 立即降级收口。
score = priority * 1e12 + (max_ts - enqueued_at_ms)  → 高优优先,同优早到优先。

成员 JSON: {event_id, session_id, anomaly_score, anomaly_reasons, max_rounds,
            triage, log_data_ref?} — log_data 内联(事件体通常不大)。
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

PQ_KEY = "soc:audit:pq"
PQ_PAYLOAD_PREFIX = "soc:audit:pq:payload:"  # event_id → JSON payload


def _payload_is_temporal_agent(payload: dict) -> bool:
    """payload 是否 Temporal Agent 车道 (llm_agent/llm_deep) — 用真实 triage 推断。"""
    try:
        from audit_triage import score_event, uses_temporal
        tri = score_event(
            dict(payload.get("log_data") or {}),
            float(payload.get("anomaly_score") or 0),
        )
        return bool(uses_temporal(tri.lane))
    except Exception:
        return False


class AuditPriorityQueue:
    def __init__(self):
        self._redis = None

    def set_redis(self, redis_client) -> None:
        self._redis = redis_client
        logger.info("AuditPQ: Redis enabled (key=%s)", PQ_KEY)

    @property
    def available(self) -> bool:
        return self._redis is not None

    def _score(self, priority: int, enqueued_at_ms: Optional[int] = None) -> float:
        # 高 priority 在前; 同档用 (大时间戳 - now) 让早到的更大? 
        # ZSET 默认小分在前 — 我们用负分或用大数: score = -priority*1e12 - ts
        # 取 ZPOPMIN 时最小分 = 最高优 + 最早
        pri = max(0, min(100, int(priority or 0)))
        ts = int(enqueued_at_ms if enqueued_at_ms is not None else time.time() * 1000)
        return float(-pri * 1_000_000_000_000 - ts)

    async def enqueue(
        self,
        *,
        event_id: int,
        session_id: str,
        log_data: dict,
        anomaly_score: float,
        anomaly_reasons: list,
        max_rounds: int = 3,
        priority: int = 50,
        tier: str = "P1",
        ttl_s: int = 900,
    ) -> bool:
        if self._redis is None:
            return False
        try:
            now_ms = int(time.time() * 1000)
            member = str(int(event_id))
            payload = {
                "event_id": int(event_id),
                "session_id": session_id,
                "log_data": log_data,
                "anomaly_score": float(anomaly_score or 0),
                "anomaly_reasons": list(anomaly_reasons or [])[:20],
                "max_rounds": int(max_rounds or 3),
                "priority": int(priority),
                "tier": tier,
                "enqueued_at_ms": now_ms,
                "retry_count": int((log_data or {}).get("_pq_retry") or 0),
            }
            pipe = self._redis.pipeline()
            pipe.set(
                f"{PQ_PAYLOAD_PREFIX}{member}",
                json.dumps(payload, ensure_ascii=False, default=str),
                ex=max(60, int(ttl_s)),
            )
            pipe.zadd(PQ_KEY, {member: self._score(priority, now_ms)})
            pipe.expire(PQ_KEY, max(60, int(ttl_s) * 2))
            await pipe.execute()
            try:
                from metrics import inc_audit_pq_enqueue
                inc_audit_pq_enqueue(tier)
            except Exception:
                pass
            logger.info(
                f"[AuditPQ] enqueue event#{event_id} tier={tier} pri={priority}"
            )
            return True
        except Exception as e:
            logger.warning(f"[AuditPQ] enqueue failed: {e}")
            return False

    async def pop_highest(self) -> Optional[dict]:
        """弹出最高优先级任务; 空队列返回 None。"""
        if self._redis is None:
            return None
        try:
            # ZPOPMIN: 最小 score = 最高优
            items = await self._redis.zpopmin(PQ_KEY, count=1)
            if not items:
                return None
            member, _score = items[0]
            if isinstance(member, bytes):
                member = member.decode()
            raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{member}")
            await self._redis.delete(f"{PQ_PAYLOAD_PREFIX}{member}")
            if not raw:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode()
            payload = json.loads(raw)
            try:
                from metrics import inc_audit_pq_dequeue
                inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
            except Exception:
                pass
            return payload
        except Exception as e:
            logger.warning(f"[AuditPQ] pop failed: {e}")
            return None

    async def depth(self) -> int:
        if self._redis is None:
            return 0
        try:
            return int(await self._redis.zcard(PQ_KEY) or 0)
        except Exception:
            return 0

    async def peek_highest(self) -> Optional[dict]:
        """窥视最高优任务 (ZRANGE 0 0 + 读 payload), 不弹出; 空队列返回 None。"""
        if self._redis is None:
            return None
        try:
            try:
                items = await self._redis.zrange(PQ_KEY, 0, 0, withscores=True)
                member = items[0][0] if items else None
            except TypeError:
                # fake/旧客户端不支持 withscores kwarg
                members = await self._redis.zrange(PQ_KEY, 0, 0)
                member = members[0] if members else None
            if member is None:
                return None
            if isinstance(member, bytes):
                member = member.decode()
            raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{member}")
            if not raw:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode()
            return json.loads(raw)
        except Exception as e:
            logger.warning(f"[AuditPQ] peek failed: {e}")
            return None

    async def pop_matching(self, predicate=None, *, window: int = 50) -> Optional[dict]:
        """按 ZSET 顺序扫描窗口内第一个满足 predicate 的成员并弹出。

        predicate=None → 等价 pop_highest (ZPOPMIN)。
        弹出成功时计 inc_audit_pq_dequeue(tier); 无匹配返回 None(不弹队头)。
        """
        if self._redis is None:
            return None
        if predicate is None:
            return await self.pop_highest()
        try:
            members = await self._redis.zrange(PQ_KEY, 0, max(0, int(window) - 1))
            for m in members or []:
                if isinstance(m, bytes):
                    m = m.decode()
                raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{m}")
                if not raw:
                    continue  # 幽灵成员; purge_stale 兜底清理
                if isinstance(raw, bytes):
                    raw = raw.decode()
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue
                try:
                    ok = bool(predicate(payload))
                except Exception:
                    ok = False
                if not ok:
                    continue
                removed = await self._redis.zrem(PQ_KEY, m)
                if not removed:
                    continue  # 并发被抢, 继续扫
                await self._redis.delete(f"{PQ_PAYLOAD_PREFIX}{m}")
                try:
                    from metrics import inc_audit_pq_dequeue
                    inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
                except Exception:
                    pass
                return payload
            return None
        except Exception as e:
            logger.warning(f"[AuditPQ] pop_matching failed: {e}")
            return None

    async def pop_first_runnable(self, agent_full: bool = False, *, window: int = 50) -> Optional[dict]:
        """D-D: Agent 槽满时跳过队头 Temporal-agent 任务, 弹出第一个可运行任务。

        agent_full=False → 等价 pop_highest。
        agent_full=True  → 弹出窗口内第一个非 agent 车道 (llm_single/tools) 任务;
                            全是 agent 任务时返回 None, 队头 P0 留在队列不弹出。
        """
        if not agent_full:
            return await self.pop_highest()
        return await self.pop_matching(
            lambda payload: not _payload_is_temporal_agent(payload),
            window=window,
        )

    async def purge_stale(self, max_age_s: int = 900) -> int:
        """清理过期 payload 已消失但仍在 ZSET 的幽灵成员。"""
        if self._redis is None:
            return 0
        n = 0
        try:
            members = await self._redis.zrange(PQ_KEY, 0, 200)
            for m in members or []:
                if isinstance(m, bytes):
                    m = m.decode()
                exists = await self._redis.exists(f"{PQ_PAYLOAD_PREFIX}{m}")
                if not exists:
                    await self._redis.zrem(PQ_KEY, m)
                    n += 1
        except Exception as e:
            logger.debug(f"[AuditPQ] purge skipped: {e}")
        return n


def pq_ttl_for_tier(tier: str) -> int:
    """分档 PQ TTL; 实现放 audit_triage,这里 re-export 避免循环 import 调用点分散。"""
    from audit_triage import pq_ttl_for_tier as _impl
    return _impl(tier)


audit_pq = AuditPriorityQueue()
