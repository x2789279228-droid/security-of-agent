"""认证与健康检查路由"""
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from config import settings
from auth import create_access_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["auth"])

_LOGIN_FAIL_LIMIT = 5
_LOGIN_LOCKOUT_SECONDS = 900  # 15 分钟


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    """登录获取 JWT token（生产环境应接入真实认证源）"""
    # 空口令防护: admin_password 未配置时禁止登录,
    # 否则非 Docker 裸部署可用空密码换取 admin JWT
    if not settings.admin_password:
        logger.error("[Auth] admin_password not configured — login rejected")
        raise HTTPException(status_code=503, detail="Admin password not configured")

    # ── 暴力破解防护: Redis 滑动窗口 (per IP + per username) ──
    client_ip = request.client.host if request.client else "unknown"
    try:
        from sliding_window import sliding_window
        redis = sliding_window._redis
        if redis:
            fail_key = f"login:fail:{client_ip}:{req.username}"
            count = await redis.incr(fail_key)
            if count == 1:
                await redis.expire(fail_key, _LOGIN_LOCKOUT_SECONDS)
            if count > _LOGIN_FAIL_LIMIT:
                ttl = await redis.ttl(fail_key)
                logger.warning(f"[Auth] Brute force blocked: {client_ip} / {req.username} ({count} attempts)")
                raise HTTPException(
                    status_code=429,
                    detail=f"Account locked due to too many failed attempts. Try again in {ttl} seconds.",
                    headers={"Retry-After": str(ttl)},
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.debug(f"[Auth] Rate limit check failed (non-blocking): {e}")

    if req.username == settings.admin_user and req.password == settings.admin_password:
        # 登录成功, 清除失败计数
        try:
            from sliding_window import sliding_window
            redis = sliding_window._redis
            if redis:
                await redis.delete(f"login:fail:{client_ip}:{req.username}")
        except Exception:
            pass
        token = create_access_token(req.username, role="admin")
        return {"access_token": token, "token_type": "bearer"}

    logger.warning(f"[Auth] Failed login: {client_ip} / {req.username}")
    raise HTTPException(status_code=401, detail="Invalid credentials")


_is_prod = os.environ.get("SHARED_MEMORY_ENV_NAME", settings.env_name) == "prod"


@router.get("/health")
async def health():
    # 生产环境仅返回状态, 不暴露模型名/配置
    if _is_prod:
        return {"status": "ok"}
    return {"status": "ok", "services": {
        "llm": settings.llm_model,
        "embedding": settings.embedding_model,
        "kafka": "enabled" if settings.kafka_enabled else "disabled",
        "kafka_bootstrap": settings.kafka_bootstrap if settings.kafka_enabled else "",
    }}
