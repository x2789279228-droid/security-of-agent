"""
日志接入与事件管理路由 — 日志注入/批量接入/审核状态/事件查询/记忆管理

端点前缀: /api
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session, SecurityEvent, Memory
from auth import get_current_user, RequireRole, UserInfo
from log_ingestion import log_ingestor
from source_registry import source_registry
from vector_store import vector_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["logs"])


# ── 请求模型 ──

class LogIngestRequest(BaseModel):
    message: str | dict
    session_id: str = ""

class LogBatchRequest(BaseModel):
    logs: list[str | dict]
    session_id: str = ""


# ── 日志接入端点 ──

@router.post("/logs/ingest")
async def ingest_log(
    req: LogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """
    接入单条安全日志

    安全增强: 支持 X-API-Key 头认证。
    - Kafka 模式下: 此端点仅用于兼容测试，生产数据应走 Kafka
    - HTTP 模式下: 建议携带 X-API-Key 头
    """
    # 数据源认证检查
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        source = source_registry.authenticate(api_key)
        if not source:
            raise HTTPException(403, "Invalid or revoked API key")
    elif settings.kafka_enabled:
        logger.warning("[Security] HTTP ingest without API key in Kafka mode — should use Kafka pipeline")

    session_id = req.session_id or str(uuid.uuid4())
    log_data = req.message if isinstance(req.message, dict) else json.loads(req.message)
    result = await log_ingestor.ingest(session, session_id, log_data)
    return {"session_id": session_id, **result}

@router.post("/logs/ingest/batch")
async def ingest_log_batch(
    req: LogBatchRequest,
    session: AsyncSession = Depends(get_session)
):
    """Fast Path: 批量接入安全日志"""
    session_id = req.session_id or str(uuid.uuid4())
    parsed = [d if isinstance(d, dict) else json.loads(d) for d in req.logs]
    result = await log_ingestor.ingest_batch(session, session_id, parsed)
    return {"session_id": session_id, **result}

@router.post("/logs/analyze")
async def trigger_analysis(
    session_id: str = Query(..., description="会话ID"),
):
    """手动触发未分析日志的批量分析"""
    asyncio.create_task(log_ingestor._run_batch_analysis(session_id))
    return {"status": "analysis_triggered", "session_id": session_id}

@router.get("/logs/status")
async def log_status(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """查询日志接入状态"""
    return await log_ingestor.get_status(session, session_id)

@router.get("/logs/review")
async def review_status(
    session_id: str = Query(..., description="会话ID"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询每条日志的审核状态"""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.session_id == session_id)
        .order_by(desc(SecurityEvent.created_at))
        .limit(limit)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    reviewed = sum(1 for r in rows if r.analyzed)
    return {
        "session_id": session_id,
        "total": len(rows),
        "reviewed": reviewed,
        "pending": len(rows) - reviewed,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "message": e.message[:80],
                "analyzed": e.analyzed,
                # Audit-LLM 管道写入键为 _audit_llm（历史键 _review 兼容保留）
                "result": (e.raw_data or {}).get("_audit_llm")
                          or (e.raw_data or {}).get("_review", {}),
                "error": (e.raw_data or {}).get("_audit_llm_error", ""),
                "created_at": e.created_at.isoformat(),
            }
            for e in rows
        ],
    }

@router.get("/logs/stuck")
async def stuck_events(
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session)
):
    """诊断: 查找卡在审核中的事件"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
        .order_by(SecurityEvent.created_at)
        .limit(100)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return {
        "stuck_count": len(rows),
        "cutoff_minutes": minutes,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "created_at": e.created_at.isoformat(),
                "has_error": bool((e.raw_data or {}).get("_audit_llm_error")),
                "error": (e.raw_data or {}).get("_audit_llm_error", ""),
            }
            for e in rows
        ],
    }

@router.post("/logs/reset-stuck")
async def reset_stuck(
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session)
):
    """将所有卡住的事件标记为已分析（含错误标记），释放管道"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    count = 0
    for e in rows:
        e.analyzed = True
        if e.raw_data is None:
            e.raw_data = {}
        e.raw_data["_audit_llm_error"] = "reset_by_admin"
        count += 1
    await session.commit()
    return {"reset_count": count}

@router.get("/logs/events")
async def list_events(
    session_id: str = Query("", description="会话ID"),
    severity: str = Query("", description="按严重度筛选"),
    limit: int = 50, offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    """查询已接入的安全事件"""
    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at))
    if session_id:
        stmt = stmt.where(SecurityEvent.session_id == session_id)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": e.id, "session_id": e.session_id,
            "event_type": e.event_type, "severity": e.severity,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip,
            "message": e.message, "analyzed": e.analyzed,
            "anomaly_score": e.anomaly_score or 0.0,
            "is_anomaly": bool((e.anomaly_score or 0.0) >= 0.6),
            "created_at": e.created_at.isoformat(),
        }
        for e in rows
    ]


# ── 记忆管理端点 ──

@router.get("/memories")
async def list_memories(
    limit: int = 20, offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    stmt = select(Memory).order_by(desc(Memory.created_at)).limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": m.id, "agent_id": m.agent_id, "content": m.content[:200],
            "metadata": m.metadata_, "created_at": m.created_at.isoformat()
        }
        for m in rows
    ]

@router.delete("/memories/{memory_id}")
async def delete_memory(
    memory_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    ok = await vector_store.delete_memory(session, memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"deleted": True}
