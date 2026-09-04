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
from audit_trail import log_from_request as _audit
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
async def firewall_status(user: UserInfo = Depends(RequireRole("operator"))):
    """SSH 防火墙适配器状态"""
    from response_engine.ssh_firewall import ssh_firewall
    return {
        "enabled": ssh_firewall.enabled,
        "connected": ssh_firewall._connected,
        "host": settings.fw_ssh_host,
        "active_rules": ssh_firewall.get_active_rules(),
    }

@router.post("/firewall/connect")
async def firewall_connect(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
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
    except Exception as e:
        raise HTTPException(500, f"SSH connection failed: {e}")
    await _audit(
        session, request, user, action="firewall.connect",
        target_type="firewall", target_id=settings.fw_ssh_host,
        after={"info": str(info)[:500]},
    )
    return {"status": "connected", "info": info}

@router.get("/firewall/rules")
async def firewall_rules(user: UserInfo = Depends(RequireRole("operator"))):
    """查询 iptables 规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    return await asyncio.to_thread(ssh_firewall.list_rules)

@router.post("/firewall/rollback-all")
async def firewall_rollback_all(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """回滚所有防火墙规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    result = await asyncio.to_thread(ssh_firewall.rollback_all)
    await _audit(
        session, request, user, action="firewall.rollback_all",
        target_type="firewall", target_id=settings.fw_ssh_host,
        after={"result": str(result)[:500]},
    )
    return result

# ── SecurityGuard 端点 ──

@router.get("/security-guard/status")
async def security_guard_status(user: UserInfo = Depends(RequireRole("operator"))):
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
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
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
    # 人工注入威胁必须留审计痕迹（执行链路本身带全量守卫与 ResponseLog）
    await _audit(
        session, request, user, action="threat.simulate",
        target_type="threat", target_id=threat_info["session_id"],
        after={
            "threat_type": req.threat_type, "severity": req.severity,
            "src_ip": req.src_ip, "confidence": req.confidence,
            "matched": result.get("matched"),
            "policy": result.get("policy_name", ""),
            "actions_executed": result.get("actions_executed", 0),
        },
        reason="人工注入模拟威胁",
    )
    return result

@router.get("/response/policies")
async def list_response_policies(user: UserInfo = Depends(get_current_user)):
    """查看所有响应策略（含 YAML 元数据）"""
    policies = policy_engine.get_policies()
    rows = []
    for p in policies:
        rows.append({
            "id": p.policy_id,
            "name": p.name,
            "threat_type": p.threat_type,
            "category": p.category,
            "actions": p.actions,
            "min_confidence": p.min_confidence,
            "min_severity": p.min_severity,
            "auto_execute": p.auto_execute,
            "require_approval": p.require_approval,
            "cooldown_minutes": p.cooldown_minutes,
            "priority": p.priority,
            "description": p.description,
            "enabled": p.enabled,
            "source": getattr(policy_engine, "_load_source", "code"),
        })
    # Uncertain 模板单独露出，便于运营改 5min 时长
    unc = getattr(policy_engine, "_uncertain_policy", None)
    if unc:
        rows.append({
            "id": unc.policy_id,
            "name": unc.name,
            "threat_type": unc.threat_type,
            "category": unc.category,
            "actions": unc.actions,
            "min_confidence": unc.min_confidence,
            "min_severity": unc.min_severity,
            "auto_execute": unc.auto_execute,
            "require_approval": unc.require_approval,
            "cooldown_minutes": unc.cooldown_minutes,
            "priority": unc.priority,
            "description": unc.description,
            "enabled": unc.enabled,
            "role": "uncertain_template",
            "source": getattr(policy_engine, "_load_source", "code"),
        })
    return rows


class PolicyUpdateRequest(BaseModel):
    name: str
    auto_execute: bool | None = None
    require_approval: bool | None = None
    cooldown_minutes: int | None = None
    min_confidence: float | None = None
    min_severity: str | None = None
    threat_type: str | None = None
    category: str | None = None
    actions: list[dict] | None = None
    priority: int | None = None
    description: str | None = None
    enabled: bool | None = None
    change_summary: str = ""


class PolicyCreateRequest(BaseModel):
    name: str
    threat_type: str
    actions: list[dict]
    id: str | None = None
    category: str = ""
    min_confidence: float = 0.5
    min_severity: str = "medium"
    auto_execute: bool = True
    require_approval: bool = False
    cooldown_minutes: int = 30
    priority: int = 50
    description: str = ""
    enabled: bool = True


@router.post("/response/policies")
async def create_response_policy(
    req: PolicyCreateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """新增响应策略（写 YAML + 热加载，无需发版）"""
    from rule_manager import rule_manager
    content = req.model_dump()
    result = rule_manager.create_rule("response_policy", content, user.username)
    if not result.get("success"):
        raise HTTPException(400, result.get("error") or "create failed")
    if result.get("version_data"):
        await rule_manager.save_version(session, result["version_data"])
    await _audit(
        session, request, user, action="response.policy_create",
        target_type="response_policy", target_id=req.name,
        after=content,
    )
    return result


@router.put("/response/policies")
async def update_response_policy(
    req: PolicyUpdateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """更新响应策略（持久化到 YAML + 热加载）"""
    from rule_manager import rule_manager
    content = {
        k: v for k, v in req.model_dump().items()
        if k not in ("name", "change_summary") and v is not None
    }
    before_pol = policy_engine.get_policy(req.name)
    before = before_pol.to_dict() if before_pol else {}
    result = rule_manager.update_rule(
        "response_policy", req.name, content,
        change_summary=req.change_summary or "API 更新",
        changed_by=user.username,
    )
    if not result.get("success"):
        raise HTTPException(404 if "不存在" in str(result.get("error")) else 400,
                            result.get("error") or "update failed")
    if result.get("version_data"):
        await rule_manager.save_version(session, result["version_data"])
    after_pol = policy_engine.get_policy(req.name)
    await _audit(
        session, request, user, action="response.policy_update",
        target_type="response_policy", target_id=req.name,
        before=before, after=after_pol.to_dict() if after_pol else content,
    )
    return {"status": "updated", "name": req.name, **{k: result[k] for k in ("rule_id",) if k in result}}


@router.delete("/response/policies/{name}")
async def delete_response_policy(
    name: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """软禁用响应策略（enabled=false）"""
    from rule_manager import rule_manager
    result = rule_manager.delete_rule("response_policy", name)
    if not result.get("success"):
        raise HTTPException(404, result.get("error") or "not found")
    await _audit(
        session, request, user, action="response.policy_disable",
        target_type="response_policy", target_id=name,
        after=result,
    )
    return result


@router.post("/response/policies/reload")
async def reload_response_policies(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """手动热加载 YAML 策略"""
    count = policy_engine.reload()
    await _audit(
        session, request, user, action="response.policy_reload",
        target_type="response_policy", target_id="*",
        after={"count": count, "source": getattr(policy_engine, "_load_source", "")},
    )
    return {
        "status": "reloaded",
        "count": count,
        "source": getattr(policy_engine, "_load_source", ""),
    }

@router.get("/response/actions")
async def list_response_actions(user: UserInfo = Depends(get_current_user)):
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
    request: Request,
    action_name: str = Query(..., description="动作名称"),
    src_ip: str = Query("", description="目标IP"),
    reason: str = Query("", description="原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """手动执行响应动作

    经 SecurityGuard 安全护栏执行（意图/序列/频率/上下文四项审查 + 频率限制），
    并写入 ResponseLog 与 audit_trail。CRITICAL 动作不允许手动直执行，
    必须走审批队列（approve 为 admin 权限）。
    """
    action_def = response_registry.get_action(action_name)
    if not action_def:
        raise HTTPException(404, f"Unknown action: {action_name}")
    if action_def.severity == "critical":
        raise HTTPException(
            403,
            f"CRITICAL action '{action_name}' 不允许手动直接执行，请提交审批工单",
        )

    threat_info = {"src_ip": src_ip, "threat_type": "manual", "confidence": 1.0, "severity": "high"}
    actions = [{"name": action_name, "params": {"src_ip": src_ip, "reason": reason}}]

    # 安全护栏路径：SecurityGuard 四项审查 + 频率限制（此前直连 executor 全部绕过）
    batch = await response_orchestrator._guarded_execute(actions, threat_info)

    # 补写逐动作响应日志（此前该端点完全不写）
    await response_orchestrator._log_executed_actions(
        session, batch, threat_info,
        policy_name="manual", auto_execute=True, approval_status="manual_execute",
    )
    await _audit(
        session, request, user, action="response.manual_execute",
        target_type="response_action", target_id=action_name,
        after={
            "src_ip": src_ip, "reason": reason,
            "succeeded": batch.succeeded, "failed": batch.failed,
            "rollback_token": batch.batch_rollback_token,
        },
        reason=reason,
    )
    return {
        "action": action_name,
        "target": src_ip,
        "success": batch.succeeded > 0,
        "rollback_token": batch.batch_rollback_token,
        "detail": [r.to_dict() if hasattr(r, 'to_dict') else {"success": r.success, "error": r.error} for r in batch.results],
    }

@router.post("/response/rollback")
async def rollback_response(
    request: Request,
    rollback_token: str = Query(..., description="回滚令牌"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """回滚响应动作"""
    result = await response_executor.rollback_batch(rollback_token)
    await _audit(
        session, request, user, action="response.rollback",
        target_type="response_action", target_id=rollback_token,
        after={"succeeded": result.succeeded, "failed": result.failed,
               "error": result.error},
    )
    return {
        "rollback_token": rollback_token,
        "succeeded": result.succeeded,
        "failed": result.failed,
    }

@router.get("/response/approvals")
async def list_approvals(
    pending_only: bool = Query(False, description="仅待审批"),
    user: UserInfo = Depends(get_current_user),
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
            "priority": getattr(t, "priority", "p2") or "p2",
            "match_status": getattr(t, "match_status", "") or "",
            "created_at": t.created_at,
            "expires_at": t.expires_at,
        }
        for t in tickets
    ]

@router.post("/response/approvals/{ticket_id}/approve")
async def approve_action(
    ticket_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """批准审批工单"""
    ticket = approval_queue.approve(ticket_id, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    # 触发执行
    result = await response_orchestrator.execute_approved_action(ticket_id)
    await _audit(
        session, request, user, action="response.approval_approve",
        target_type="approval_ticket", target_id=ticket_id,
        after={
            "policy": ticket.policy_name,
            "actions": ticket.actions,
            "execution": {
                "succeeded": result.succeeded if result else 0,
                "failed": result.failed if result else 0,
            } if result else None,
        },
    )
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
    request: Request,
    reason: str = Query("", description="拒绝原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """拒绝审批工单"""
    ticket = approval_queue.reject(ticket_id, reason, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    await _audit(
        session, request, user, action="response.approval_reject",
        target_type="approval_ticket", target_id=ticket_id,
        after={"policy": ticket.policy_name, "actions": ticket.actions},
        reason=reason,
    )
    return {"status": "rejected", "ticket_id": ticket_id, "reason": reason}

@router.get("/response/logs")
async def query_response_logs(
    session_id: str = Query("", description="会话ID"),
    threat_type: str = Query("", description="威胁类型"),
    src_ip: str = Query("", description="源IP"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
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
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """清除所有策略冷却状态（人工干预用）"""
    policy_engine.clear_cooldowns()
    await _audit(
        session, request, user, action="response.clear_cooldowns",
        target_type="response_policy", target_id="*",
        reason="人工干预：清除策略冷却",
    )
    return {"status": "cooldowns_cleared"}
