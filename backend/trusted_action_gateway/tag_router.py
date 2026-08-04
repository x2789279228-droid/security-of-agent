"""
Trusted Action Gateway — FastAPI 路由

提供以下端点:
  POST   /tag/actions                        — 创建动作计划 (process_action)
  GET    /tag/actions/{action_id}             — 查询动作状态
  POST   /tag/actions/{action_id}/rollback    — 请求回滚
  POST   /tag/grants                          — 申请分步授权
  POST   /tag/grants/{grant_id}/approve       — 批准授权
  POST   /tag/grants/{grant_id}/deny          — 拒绝授权
  POST   /tag/grants/{grant_id}/revoke        — 撤销授权
  GET    /tag/audit                           — 查询审计轨迹
  GET    /tag/circuit/{scope_type}/{scope_key}— 查询熔断状态
  POST   /tag/circuit/{scope_type}/{scope_key}/reset — 解除熔断
  GET    /tag/health                          — 健康检查
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from models import async_session
from trusted_action_gateway.gateway import tag_gateway, ActionPlan
from trusted_action_gateway.state_machine import ExecutionMode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tag", tags=["Trusted Action Gateway"])


# ── 依赖: 数据库会话 ──

async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── 请求 / 响应模型 ──

class CreateActionRequest(BaseModel):
    tool_name: str
    target: str
    parameters: dict = Field(default_factory=dict)
    incident_id: str
    agent_identity: str
    evidence_ids: list[str] = Field(default_factory=list)
    plan_version: str = "v1"
    asset_info: dict = Field(default_factory=dict)
    trace_id: str = ""
    request_id: str = ""
    token_jti: str = ""


class RequestGrantRequest(BaseModel):
    subject: str
    incident_id: str
    tool_name: str
    target_scope: dict
    parameter_constraints: dict = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    approval_level: str = "basic"
    automation_level: str = "A1"
    ttl_seconds: Optional[int] = None
    max_executions: Optional[int] = None
    created_by: str = "api"


class ApproveRequest(BaseModel):
    approver: str = "cad"
    notes: str = ""


class DenyRequest(BaseModel):
    denyer: str = "cad"
    reason: str = ""


class RevokeRequest(BaseModel):
    revoked_by: str = "admin"


class ResetCircuitRequest(BaseModel):
    reset_by: str = "admin"


class SetModeRequest(BaseModel):
    mode: str  # shadow / sandbox / production


# ── 端点 ──

@router.post("/actions")
async def create_action(
    req: CreateActionRequest,
    session: AsyncSession = Depends(get_db),
):
    """创建动作计划 — 完整流程编排"""
    plan = ActionPlan(
        tool_name=req.tool_name,
        target=req.target,
        parameters=req.parameters,
        incident_id=req.incident_id,
        agent_identity=req.agent_identity,
        evidence_ids=req.evidence_ids,
        plan_version=req.plan_version,
        asset_info=req.asset_info,
        trace_id=req.trace_id,
        request_id=req.request_id,
        token_jti=req.token_jti,
    )
    result = await tag_gateway.process_action(session, plan)
    return result.to_dict()


@router.get("/actions/{action_id}")
async def get_action_status(
    action_id: str,
    session: AsyncSession = Depends(get_db),
):
    """查询动作状态"""
    status = await tag_gateway.get_action_status(session, action_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"动作不存在: {action_id}")
    return status


@router.post("/actions/{action_id}/rollback")
async def rollback_action(
    action_id: str,
    operator: str = "admin",
    session: AsyncSession = Depends(get_db),
):
    """请求回滚 — 幂等"""
    result = await tag_gateway.request_rollback(session, action_id, operator)
    return result.to_dict()


@router.post("/grants")
async def request_grant(
    req: RequestGrantRequest,
    session: AsyncSession = Depends(get_db),
):
    """申请分步授权"""
    from trusted_action_gateway.grant_manager import grant_manager
    from trusted_action_gateway.state_machine import AutomationLevel

    try:
        auto_level = AutomationLevel(req.automation_level)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"无效 automation_level: {req.automation_level}")

    grant = await grant_manager.issue_grant(
        session=session,
        subject=req.subject,
        incident_id=req.incident_id,
        tool_name=req.tool_name,
        target_scope=req.target_scope,
        parameter_constraints=req.parameter_constraints,
        evidence_ids=req.evidence_ids,
        approval_level=req.approval_level,
        automation_level=auto_level,
        ttl_seconds=req.ttl_seconds,
        max_executions=req.max_executions,
        created_by=req.created_by,
    )
    return {
        "grant_id": grant.id,
        "subject": grant.subject,
        "incident_id": grant.incident_id,
        "tool_name": grant.tool_name,
        "target_scope": grant.target_scope,
        "max_executions": grant.max_executions,
        "expires_at": grant.expires_at.isoformat(),
        "approval_level": grant.approval_level,
        "status": grant.status,
    }


@router.post("/grants/{grant_id}/approve")
async def approve_grant(
    grant_id: str,
    req: ApproveRequest,
    session: AsyncSession = Depends(get_db),
):
    """批准授权"""
    ok, msg = await tag_gateway.approve_authorization(
        session, grant_id, req.approver, req.notes,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"grant_id": grant_id, "approved": True, "message": msg}


@router.post("/grants/{grant_id}/deny")
async def deny_grant(
    grant_id: str,
    req: DenyRequest,
    session: AsyncSession = Depends(get_db),
):
    """拒绝授权"""
    ok, msg = await tag_gateway.deny_authorization(
        session, grant_id, req.denyer, req.reason,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"grant_id": grant_id, "denied": True, "message": msg}


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant(
    grant_id: str,
    req: RevokeRequest,
    session: AsyncSession = Depends(get_db),
):
    """撤销授权"""
    ok = await tag_gateway.revoke_grant(session, grant_id, req.revoked_by)
    if not ok:
        raise HTTPException(status_code=400, detail="撤销失败")
    return {"grant_id": grant_id, "revoked": True}


@router.get("/audit")
async def get_audit_trail(
    trace_id: str = Query(""),
    incident_id: str = Query(""),
    action_id: str = Query(""),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
):
    """查询审计轨迹"""
    return await tag_gateway.get_audit_trail(
        session, trace_id, incident_id, action_id, limit, offset,
    )


@router.get("/circuit/{scope_type}/{scope_key}")
async def get_circuit_state(
    scope_type: str,
    scope_key: str,
    session: AsyncSession = Depends(get_db),
):
    """查询熔断状态"""
    return await tag_gateway.get_circuit_state(session, scope_type, scope_key)


@router.post("/circuit/{scope_type}/{scope_key}/reset")
async def reset_circuit(
    scope_type: str,
    scope_key: str,
    req: ResetCircuitRequest,
    session: AsyncSession = Depends(get_db),
):
    """解除熔断"""
    ok = await tag_gateway.reset_circuit(
        session, scope_type, scope_key, req.reset_by,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="解除熔断失败")
    return {"scope_type": scope_type, "scope_key": scope_key, "reset": True}


@router.post("/mode")
async def set_execution_mode(req: SetModeRequest):
    """设置运行模式 (shadow / sandbox / production)"""
    try:
        mode = ExecutionMode(req.mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"无效模式: {req.mode}")
    tag_gateway.set_execution_mode(mode)
    return {"mode": mode.value}


@router.get("/health")
async def health():
    """健康检查"""
    return {
        "status": "ok",
        "execution_mode": tag_gateway.execution_mode.value,
        "registered_tools": tag_gateway.tool_registry.list_tools(),
    }


@router.get("/tools")
async def list_tools():
    """列出已注册工具"""
    return {
        "tools": tag_gateway.tool_registry.list_tools(),
    }
