"""数据源管理路由"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_session
from auth import RequireRole, UserInfo
from source_registry import source_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sources", tags=["sources"])


class SourceRegisterRequest(BaseModel):
    api_key: str
    name: str
    source_type: str = "generic"


@router.get("")
async def list_sources(
    user: UserInfo = Depends(RequireRole("operator")),
):
    """列出所有已注册的数据源"""
    return {
        "sources": source_registry.list_sources(),
        "stats": source_registry.stats(),
    }


@router.post("/register")
async def register_source(
    req: SourceRegisterRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """注册新数据源（DB 持久化）"""
    source = await source_registry.register(
        session, req.api_key, req.name, req.source_type,
        changed_by=user.username,
    )
    return {"status": "registered", "name": source.name, "source_type": source.source_type}


@router.post("/revoke")
async def revoke_source(
    api_key: str = Query(..., description="要吊销的 API Key"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """吊销数据源（DB 持久化）"""
    ok = await source_registry.revoke(session, api_key, by=user.username)
    if not ok:
        raise HTTPException(404, "Source not found")
    return {"status": "revoked"}


@router.get("/rejections")
async def source_rejections(
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """查看未认证访问的拒绝记录（内存 + DB 全量）"""
    in_mem = source_registry.get_rejection_log(limit)
    db_records: list[dict] = []
    try:
        from models import DataSourceRejection as DR
        from sqlalchemy import select, desc
        stmt = select(DR).order_by(desc(DR.created_at)).limit(limit)
        result = await session.execute(stmt)
        for r in result.scalars().all():
            db_records.append({
                "id": r.id,
                "api_key_prefix": r.api_key_prefix,
                "reason": r.reason,
                "source_ip": r.source_ip,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            })
    except Exception as e:
        logger.warning(f"load DB rejections failed: {e}")
    return {
        "rejections": in_mem,
        "db_records": db_records,
        "total_in_memory": len(in_mem),
        "total_in_db": len(db_records),
    }
