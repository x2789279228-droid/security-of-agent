import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from config import settings

logger = logging.getLogger(__name__)

SECRET_KEY = settings.jwt_secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

security_scheme = HTTPBearer(auto_error=False)

_blocked_jti: dict[str, float] = {}
_user_jtis: dict[str, set[str]] = {}


class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: datetime


class UserInfo(BaseModel):
    username: str
    role: str
    jti: str = ""


def _redis():
    try:
        from sliding_window import sliding_window
        return getattr(sliding_window, "_redis", None)
    except Exception:
        return None


async def remember_jti(username: str, jti: str, ttl_sec: int) -> None:
    if not jti:
        return
    _user_jtis.setdefault(username, set()).add(jti)
    r = _redis()
    if r is None:
        return
    try:
        key = f"jwt:user:{username}"
        await r.sadd(key, jti)
        await r.expire(key, max(int(ttl_sec), 1))
    except Exception as e:
        logger.debug("remember_jti redis failed: %s", e)


async def is_jti_blocked(jti: str) -> bool:
    if not jti:
        return False
    exp = _blocked_jti.get(jti)
    if exp is not None:
        if exp > time.time():
            return True
        _blocked_jti.pop(jti, None)
    r = _redis()
    if r is None:
        return False
    try:
        return bool(await r.exists(f"jwt:block:{jti}"))
    except Exception:
        return False


async def revoke_jti(jti: str, ttl_sec: int = 0) -> None:
    if not jti:
        return
    ttl = int(ttl_sec) if ttl_sec > 0 else ACCESS_TOKEN_EXPIRE_MINUTES * 60
    _blocked_jti[jti] = time.time() + ttl
    r = _redis()
    if r is None:
        return
    try:
        await r.set(f"jwt:block:{jti}", "1", ex=max(ttl, 1))
    except Exception as e:
        logger.debug("revoke_jti redis failed: %s", e)


async def revoke_username(username: str) -> int:
    jtis = set(_user_jtis.get(username) or ())
    r = _redis()
    if r is not None:
        try:
            extra = await r.smembers(f"jwt:user:{username}")
            if extra:
                jtis |= {x.decode() if isinstance(x, bytes) else str(x) for x in extra}
        except Exception:
            pass
    n = 0
    for jti in jtis:
        await revoke_jti(jti)
        n += 1
    return n


def create_access_token(username: str, role: str = "admin") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {"sub": username, "role": role, "exp": expire, "jti": jti}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    try:
        import asyncio
        loop = asyncio.get_running_loop()
        ttl = int((expire - datetime.now(timezone.utc)).total_seconds())
        loop.create_task(remember_jti(username, jti, ttl))
    except Exception:
        _user_jtis.setdefault(username, set()).add(jti)
    return token


async def decode_access_token(token: str) -> dict:
    """Shared JWT decode for middleware + Depends. Raises HTTPException."""
    if not SECRET_KEY:
        logger.error("JWT_SECRET not configured — rejecting all requests")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server misconfigured: JWT_SECRET not set",
        )
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    jti = payload.get("jti") or ""
    if await is_jti_blocked(jti):
        raise HTTPException(status_code=401, detail="Token revoked")
    return payload


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> UserInfo:
    token = credentials.credentials if credentials else ""
    payload = await decode_access_token(token)
    return UserInfo(
        username=payload.get("sub", "unknown"),
        role=payload.get("role", "viewer"),
        jti=payload.get("jti") or "",
    )


class RequireRole:
    def __init__(self, *roles: str):
        """
        支持单一或多个角色位运算:
          RequireRole("admin")              # 仅 admin
          RequireRole("admin", "operator")  # admin 或 operator
        admin 角色恒通过 (向后兼容旧调用)
        """
        self.roles = set(roles)

    async def __call__(self, user: UserInfo = Depends(get_current_user)):
        if user.role == "admin":
            return user
        if user.role not in self.roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {sorted(self.roles)}",
            )
        return user
