"""Control-plane HMAC helpers (approval tickets + audit hash chain)."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional


def control_hmac_key() -> bytes:
    from config import settings
    raw = (getattr(settings, "control_hmac_key", "") or "") or (getattr(settings, "jwt_secret", "") or "")
    return raw.encode("utf-8")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_hex(message: str, key: Optional[bytes] = None) -> str:
    k = key if key is not None else control_hmac_key()
    if not k:
        k = b"dev-hmac-unconfigured"
    return hmac.new(k, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_ok(message: str, signature: str, key: Optional[bytes] = None) -> bool:
    expected = hmac_hex(message, key=key)
    got = (signature or "").strip().lower()
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(expected, got)


def actions_digest(actions: list) -> str:
    return sha256_hex(canonical_json(actions or []))


def sign_approval(ticket_id: str, exp: float, digest: str, policy_name: str) -> str:
    msg = f"{ticket_id}|{int(exp)}|{digest}|{policy_name or ''}"
    return hmac_hex(msg)


def verify_approval(ticket_id: str, exp: float, digest: str, policy_name: str, sig: str) -> bool:
    msg = f"{ticket_id}|{int(exp)}|{digest}|{policy_name or ''}"
    return hmac_ok(msg, sig)
