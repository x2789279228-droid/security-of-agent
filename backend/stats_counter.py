"""
Approximate real-time stats counters backed by Redis (optional).

Motivation: the Monitor stat cards (security_events / pending / audit completed)
were refreshed only by periodic full SELECT COUNT(*), so they lag on bursts and put
load on the DB during high-pressure arrival. Here we carry short-lived absolute
counters in the shared Redis so a card can bump to "now" on every insert / audit-done,
while a low-frequency job reconciles them against the true COUNT to absorb drift
(restart, delete, rollback, multi-writer analyzed edges). This value is APPROXIMATE
between reconciles by design.

Keys:  soc-stats:total | soc-stats:done | soc-stats:pending
Behaviour when Redis is unavailable: helpers become no-ops and stats() falls back
to the original full-COUNTPATH (see routers/chat.py), so nothing breaks without Redis.
"""
import logging

logger = logging.getLogger(__name__)

_NS = "soc-stats:"
KEY_TOTAL = _NS + "total"
KEY_DONE = _NS + "done"
KEY_PENDING = _NS + "pending"
_KEY_EVER = 0  # not used

_FLAG_ENV = "SHARED_MEMORY_STATS_COUNTER_ENABLED"
_DEFAULT_ON = True


def _enabled() -> bool:
    import os as _os
    try:
        return str(_os.environ.get(_FLAG_ENV, "true")).lower() in ("1", "true", "yes", "on")
    except Exception:
        return _DEFAULT_ON


async def _rc():
    """Best-effort Redis client from the already-shared sliding_window singleton."""
    try:
        from sliding_window import sliding_window
        return await sliding_window.get_redis()
    except Exception as e:  # noqa: BLE001
        logger.debug("stats_counter redis unavailable: %s", e)
        return None


async def inc_insert() -> None:
    """One new SecurityEvent row inserted (not a dedupe/rollback)."""
    if not _enabled():
        return
    try:
        rc = await _rc()
        if rc is None:
            return
        pipe = rc.pipeline()
        pipe.incr(KEY_TOTAL)
        pipe.incr(KEY_PENDING)
        await pipe.execute()
    except Exception as e:  # noqa: BLE001
        logger.debug("stats_counter inc_insert failed: %s", e)


async def inc_analyzed_done() -> None:
    """One event finished audit (pending-- / completed++); approximate, reconcile-based."""
    if not _enabled():
        return
    try:
        rc = await _rc()
        if rc is None:
            return
        pipe = rc.pipeline()
        pipe.incr(KEY_DONE)
        pipe.decr(KEY_PENDING)
        await pipe.execute()
    except Exception as e:  # noqa: BLE001
        logger.debug("stats_counter inc_analyzed_done failed: %s", e)


async def snapshot():
    """Return dict(total, done, pending) or None if Redis missing / never seeded."""
    try:
        rc = await _rc()
        if rc is None:
            return None
        raw = await rc.mget(KEY_TOTAL, KEY_DONE, KEY_PENDING)
        if raw is None or any(v is None for v in raw):
            return None  # not seeded -> caller should reconcile first
        return {
            "total": int(raw[0] or 0),
            "done": int(raw[1] or 0),
            "pending": int(raw[2] or 0),
        }
    except Exception:  # noqa: BLE001
        return None


async def reconcile(total: int, done: int, pending: int) -> None:
    """Set the absolute truth values (from a real COUNT) into Redis."""
    if not _enabled():
        return
    try:
        rc = await _rc()
        if rc is None:
            return
        pipe = rc.pipeline()
        pipe.set(KEY_TOTAL, max(0, int(total)))
        pipe.set(KEY_DONE, max(0, int(done)))
        pipe.set(KEY_PENDING, max(0, int(pending)))
        await pipe.execute()
    except Exception as e:  # noqa: BLE001
        logger.warning("stats_counter reconcile failed: %s", e)
