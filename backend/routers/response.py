"""
响应引擎域路由 — 防火墙、SecurityGuard、响应策略/执行/审批/回滚
"""
import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session
from auth import get_current_user, RequireRole, UserInfo
from response_engine import (
    get_orchestrator, get_response_logger,
    response_executor,
    approval_queue, policy_engine, response_registry,
    ApprovalStatus, ssh_transport,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["response"])

response_orchestrator = get_orchestrator()
response_logger = get_response_logger()


# ── SSH 防火墙端点 ──

@router.get("/firewall/status")
async def firewall_status():
    """SSH 防火墙适配器状态"""
    from response_engine.ssh_firewall import ssh_firewall
    return {
        "enabled": ssh_firewall.enabled,
        "connected": ssh_firewall._connected,
        "host": settings.fw_ssh_host,
        "active_rules": ssh_firewall.get_active_rules(),
    }

@router.post("/firewall/connect")
async def firewall_connect(user: UserInfo = Depends(RequireRole("admin"))):
    """连接 SSH 防火墙虚拟机"""
    from response_engine.ssh_firewall import ssh_firewall
    if not settings.fw_ssh_host:
        raise HTTPException(400, "FW_SSH_HOST not configured")
    ssh_firewall.configure(
        host=settings.fw_ssh_host,
        port=settings.fw_ssh_port,
        username=settings.fw_ssh_user,
        password=settings.fw_ssh_password,
        use_sudo=settings.fw_use_sudo,
    )
    try:
        info = await asyncio.to_thread(ssh_firewall.connect)
        return {"status": "connected", "info": info}
    except Exception as e:
        raise HTTPException(500, f"SSH connection failed: {e}")

@router.get("/firewall/rules")
async def firewall_rules(user: UserInfo = Depends(RequireRole("operator"))):
    """查询 iptables 规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    return await asyncio.to_thread(ssh_firewall.list_rules)

@router.post("/firewall/rollback-all")
async def firewall_rollback_all(user: UserInfo = Depends(RequireRole("admin"))):
    """回滚所有防火墙规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    return await asyncio.to_thread(ssh_firewall.rollback_all)

# ── SecurityGuard 端点 ──

@router.get("/security-guard/status")
async def security_guard_status():
    """SecurityGuard 状态"""
    try:
        from security_guard import security_guard
        return {
            "enabled": settings.security_guard_enabled,
            "rate_limiter": security_guard.rate_limiter.get_stats() if hasattr(security_guard, 'rate_limiter') else {},
        }
    except ImportError:
        return {"enabled": False, "error": "security_guard module not available"}

# ── 响应引擎端点 ──

class SimulateThreatRequest(BaseModel):
    threat_type: str = "C2_BEACON"
    confidence: float = 0.85
    severity: str = "critical"
    src_ip: str = "192.168.1.100"
    dst_ip: str = ""
    message: str = ""
    session_id: str = ""
    event_id: int = 0

@router.post("/response/simulate")
async def simulate_threat(
    req: SimulateThreatRequest,
    session: AsyncSession = Depends(get_session)
):
    """模拟威胁事件，触发响应引擎"""
    threat_info = {
        "threat_type": req.threat_type,
        "confidence": req.confidence,
        "severity": req.severity,
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "message": req.message or f"模拟{req.threat_type}攻击",
        "session_id": req.session_id or str(uuid.uuid4()),
        "event_id": req.event_id,
    }
    result = await response_orchestrator.on_threat_detected(
        session=session,
        threat_info=threat_info,
        event_id=req.event_id if req.event_id else None,
        session_id=threat_info["session_id"],
    )
    return result

@router.get("/response/policies")
async def list_response_policies():
    """查看所有响应策略"""
    policies = policy_engine.get_policies()
    return [
        {
            "name": p.name,
            "threat_type": p.threat_type,
            "actions": p.actions,
            "min_confidence": p.min_confidence,
            "min_severity": p.min_severity,
            "auto_execute": p.auto_execute,
            "require_approval": p.require_approval,
            "cooldown_minutes": p.cooldown_minutes,
            "description": p.description,
        }
        for p in policies
    ]

class PolicyUpdateRequest(BaseModel):
    name: str
    auto_execute: bool | None = None
    require_approval: bool | None = None
    cooldown_minutes: int | None = None
    min_confidence: float | None = None

@router.put("/response/policies")
async def update_response_policy(
    req: PolicyUpdateRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """更新响应策略"""
    policy = policy_engine.get_policy(req.name)
    if not policy:
        raise HTTPException(404, f"Policy not found: {req.name}")
    if req.auto_execute is not None:
        policy.auto_execute = req.auto_execute
    if req.require_approval is not None:
        policy.require_approval = req.require_approval
    if req.cooldown_minutes is not None:
        policy.cooldown_minutes = req.cooldown_minutes
    if req.min_confidence is not None:
        policy.min_confidence = req.min_confidence
    return {"status": "updated", "name": req.name}

@router.get("/response/actions")
async def list_response_actions():
    """列出所有可用的响应动作"""
    actions = response_registry.list_actions()
    return [
        {
            "name": a.name,
            "description": a.description,
            "severity": a.severity,
            "category": a.category,
            "reversible": a.reversible,
            "params_schema": a.params_schema,
        }
        for a in actions
    ]

@router.post("/response/execute")
async def execute_response(
    action_name: str = Query(..., description="动作名称"),
    src_ip: str = Query("", description="目标IP"),
    reason: str = Query("", description="原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """手动执行响应动作"""
    threat_info = {"src_ip": src_ip, "threat_type": "manual", "confidence": 1.0, "severity": "high"}
    actions = [{"name": action_name, "params": {"src_ip": src_ip, "reason": reason}}]
    result = await response_executor.execute_actions(actions, threat_info)
    return {
        "action": action_name,
        "target": src_ip,
        "success": result.succeeded > 0,
        "rollback_token": result.batch_rollback_token,
        "detail": [r.to_dict() if hasattr(r, 'to_dict') else {"success": r.success, "error": r.error} for r in result.results],
    }

@router.post("/response/rollback")
async def rollback_response(
    rollback_token: str = Query(..., description="回滚令牌"),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """回滚响应动作"""
    result = await response_executor.rollback_batch(rollback_token)
    return {
        "rollback_token": rollback_token,
        "succeeded": result.succeeded,
        "failed": result.failed,
    }

@router.get("/response/approvals")
async def list_approvals(
    pending_only: bool = Query(False, description="仅待审批"),
):
    """查看审批队列"""
    if pending_only:
        tickets = approval_queue.list_pending()
    else:
        tickets = approval_queue.list_all()
    return [
        {
            "id": t.id,
            "policy_name": t.policy_name,
            "threat_type": t.threat_info.get("threat_type", ""),
            "severity": t.threat_info.get("severity", ""),
            "src_ip": t.threat_info.get("src_ip", ""),
            "confidence": t.threat_info.get("confidence", 0),
            "actions": t.actions,
            "status": t.status.value,
            "created_at": t.created_at,
            "expires_at": t.expires_at,
        }
        for t in tickets
    ]

@router.post("/response/approvals/{ticket_id}/approve")
async def approve_action(
    ticket_id: str,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """批准审批工单"""
    ticket = approval_queue.approve(ticket_id, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    # 触发执行
    result = await response_orchestrator.execute_approved_action(ticket_id)
    return {
        "status": "approved",
        "ticket_id": ticket_id,
        "execution_result": {
            "succeeded": result.succeeded if result else 0,
            "failed": result.failed if result else 0,
        } if result else None,
    }

@router.post("/response/approvals/{ticket_id}/reject")
async def reject_action(
    ticket_id: str,
    reason: str = Query("", description="拒绝原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """拒绝审批工单"""
    ticket = approval_queue.reject(ticket_id, reason, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    return {"status": "rejected", "ticket_id": ticket_id, "reason": reason}

@router.get("/response/logs")
async def query_response_logs(
    session_id: str = Query("", description="会话ID"),
    threat_type: str = Query("", description="威胁类型"),
    src_ip: str = Query("", description="源IP"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询响应日志"""
    logs = await response_logger.query_logs(
        session,
        session_id=session_id,
        threat_type=threat_type,
        src_ip=src_ip,
        limit=limit,
    )
    return [log.to_dict() for log in logs]

@router.post("/response/clear-cooldowns")
async def clear_cooldowns(
    user: UserInfo = Depends(RequireRole("admin")),
):
    """清除所有策略冷却状态（人工干预用）"""
    policy_engine.clear_cooldowns()
    return {"status": "cooldowns_cleared"}
