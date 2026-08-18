import logging
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


class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: datetime


class UserInfo(BaseModel):
    username: str
    role: str


def create_access_token(username: str, role: str = "admin") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> UserInfo:
    if not SECRET_KEY:
        logger.error("JWT_SECRET not configured — rejecting all requests")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server misconfigured: JWT_SECRET not set",
        )
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return UserInfo(username=payload.get("sub", "unknown"), role=payload.get("role", "viewer"))
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


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
