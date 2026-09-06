"""Audit verdict cache — reuse conclusions for the same signature.

Key: event_type | src_ip | sigma_rule_ids | severity
TTL: settings.audit_cache_ttl_s (default 600). Memory LRU + optional Redis.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger(__name__)

_MEM: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_MEM_MAX = 4096
_REDIS = None
_PREFIX = "soc:audit:cache:"


def set_redis(client) -> None:
    global _REDIS
    _REDIS = client


def cache_key(log_data: dict) -> str:
    sigma = log_data.get("_sigma") or {}
    rules = sigma.get("hits") or sigma.get("rule_ids") or []
    if isinstance(rules, list):
        rule_ids = ",".join(sorted(str(h.get("rule_id") or h) if isinstance(h, dict) else str(h) for h in rules))
    else:
        rule_ids = str(rules)
    et = str(log_data.get("threat_type") or log_data.get("event") or log_data.get("type") or "").upper()
    src = str(log_data.get("src_ip") or "")
    sev = str(log_data.get("severity") or "info").lower()
    raw = f"{et}|{src}|{rule_ids}|{sev}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _ttl() -> int:
    try:
        from config import settings
        return max(30, int(getattr(settings, "audit_cache_ttl_s", 600) or 600))
    except Exception:
        return 600


async def get(log_data: dict) -> Optional[dict]:
    key = cache_key(log_data)
    now = time.time()
    hit = _MEM.get(key)
    if hit and hit[0] > now:
        _MEM.move_to_end(key)
        return dict(hit[1])
    if hit:
        _MEM.pop(key, None)
    if _REDIS is None:
        return None
    try:
        raw = _REDIS.get(_PREFIX + key)
        if hasattr(raw, "__await__"):
            raw = await raw
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        if isinstance(payload, dict):
            _MEM[key] = (now + _ttl(), payload)
            return dict(payload)
    except Exception as e:
        logger.debug("audit_cache get failed: %s", e)
    return None


async def put(log_data: dict, verdict: dict) -> None:
    if not isinstance(verdict, dict):
        return
    key = cache_key(log_data)
    ttl = _ttl()
    exp = time.time() + ttl
    slim = {
        "threat_detected": bool(verdict.get("threat_detected")),
        "confidence": float(verdict.get("confidence") or 0),
        "severity": verdict.get("severity") or log_data.get("severity") or "info",
        "verdict": verdict.get("verdict") or verdict.get("status") or "",
        "lane": "cache",
    }
    _MEM[key] = (exp, slim)
    _MEM.move_to_end(key)
    while len(_MEM) > _MEM_MAX:
        _MEM.popitem(last=False)
    if _REDIS is None:
        return
    try:
        res = _REDIS.set(_PREFIX + key, json.dumps(slim, ensure_ascii=False), ex=ttl)
        if hasattr(res, "__await__"):
            await res
    except Exception as e:
        logger.debug("audit_cache put failed: %s", e)


def inc_hit_metric() -> None:
    try:
        from metrics import inc_audit_cache_hit
        inc_audit_cache_hit()
    except Exception:
        pass
