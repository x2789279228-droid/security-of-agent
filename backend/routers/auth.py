"""认证与健康检查路由"""
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import settings
from auth import create_access_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
async def login(req: LoginRequest):
    """登录获取 JWT token（生产环境应接入真实认证源）"""
    # 空口令防护: admin_password 未配置时禁止登录,
    # 否则非 Docker 裸部署可用空密码换取 admin JWT
    if not settings.admin_password:
        logger.error("[Auth] admin_password not configured — login rejected")
        raise HTTPException(status_code=503, detail="Admin password not configured")
    if req.username == settings.admin_user and req.password == settings.admin_password:
        token = create_access_token(req.username, role="admin")
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/health")
async def health():
    return {"status": "ok", "services": {
        "llm": settings.llm_model,
        "embedding": settings.embedding_model,
        "kafka": "enabled" if settings.kafka_enabled else "disabled",
        "kafka_bootstrap": settings.kafka_bootstrap if settings.kafka_enabled else "",
    }}
