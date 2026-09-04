"""
审计域路由 — Sigma 检测、MCP Guard、Audit-LLM 流水线、CAD 监督
"""
import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session, SecurityEvent
from auth import get_current_user, RequireRole, UserInfo
from audit_trail import log_from_request
from event_store import event_store
from agents import decomposer, tool_builder, executor, reviewer
from agents.agent_cad import cad_agent
from cad import circuit_breaker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["audit"])


# ── Sigma 检测引擎端点 ──

@router.get("/sigma/stats")
async def sigma_stats(user: UserInfo = Depends(get_current_user)):
    """Sigma 检测引擎状态"""
    from sigma_detector import sigma_detector
    return sigma_detector.stats()

@router.get("/llm/cost")
async def llm_cost(user: UserInfo = Depends(get_current_user)):
    """LLM 成本统计（每日预算/用量/调用次数）"""
    from summary_compression import cost_tracker
    return cost_tracker.stats()

class SigmaDetectRequest(BaseModel):
    events: list[dict]

@router.post("/sigma/detect")
async def sigma_detect(req: SigmaDetectRequest, user: UserInfo = Depends(get_current_user)):
    """批量 Sigma 规则检测"""
    from sigma_detector import sigma_detector
    return sigma_detector.detect_batch(req.events)

# ── MCP Guard 网关端点 ──

@router.get("/guard/status")
async def guard_status(user: UserInfo = Depends(get_current_user)):
    """MCP Guard 网关状态"""
    try:
        from mcp_guard import mcp_guard
        # 初始化失败时单例为 None (不抛 ImportError), 需显式判空
        if mcp_guard is None:
            return {"enabled": False, "error": "mcp_guard init failed (singleton is None)"}
        return {
            "enabled": settings.mcp_guard_enabled,
            "tools": mcp_guard.list_tools(),
            "recent_calls": mcp_guard.logger.recent(20) if hasattr(mcp_guard, 'logger') else [],
        }
    except ImportError:
        return {"enabled": False, "error": "mcp_guard module not available"}

class GuardCallRequest(BaseModel):
    tool_name: str
    arguments: dict = {}
    user_role: str = "security_operator"
    reason: str = ""

@router.post("/guard/call")
async def guard_call(req: GuardCallRequest, user: UserInfo = Depends(get_current_user)):
    """通过 MCP Guard 网关调用安全工具（4 层检查）"""
    if not settings.mcp_guard_enabled:
        raise HTTPException(400, "MCP Guard is disabled")
    try:
        from mcp_guard import mcp_guard
        from mcp_guard.guard_server import ToolCallRequest as GuardReq
        if mcp_guard is None:
            raise HTTPException(500, "mcp_guard init failed (singleton is None)")
        result = await asyncio.to_thread(
            mcp_guard.call_tool,
            GuardReq(
                tool_name=req.tool_name,
                arguments=req.arguments,
                user_role=req.user_role,
                reason=req.reason,
            )
        )
        return result
    except ImportError:
        raise HTTPException(500, "mcp_guard module not available")

# ── Audit-LLM 端点 ──

class AuditLLMRequest(BaseModel):
    event: dict
    session_id: str = ""

@router.post("/audit-llm/run")
async def run_audit_llm_pipeline(
    req: AuditLLMRequest,
    session: AsyncSession = Depends(get_session)
):
    """手动触发 Audit-LLM 四层流水线"""
    from anomaly_detector import anomaly_detector as ad
    from trace_hook import set_trace_context, clear_trace_context
    from datetime import datetime, timezone

    session_id = req.session_id or str(uuid.uuid4())

    # 落库事件 → 获得 event_id (成本面板按事件归属 token 的前提)
    evt = SecurityEvent(
        session_id=session_id,
        event_type=req.event.get("event", req.event.get("type", "MANUAL_AUDIT")),
        severity=req.event.get("severity", "info"),
        src_ip=req.event.get("src_ip", ""),
        dst_ip=req.event.get("dst_ip", ""),
        protocol=req.event.get("protocol", ""),
        action=req.event.get("action", ""),
        message=req.event.get("message", ""),
        raw_data=dict(req.event),
    )
    session.add(evt)
    await session.commit()
    await session.refresh(evt)
    event_id = evt.id

    set_trace_context(caller="audit_pipeline", event_id=event_id, session_id=session_id)
    try:
        # 异常检测
        anomaly_report = await ad.analyze(req.event)

        # Decomposer
        decomp_output = await decomposer.decompose(
            event=req.event,
            session_id=session_id,
            anomaly_score=anomaly_report.anomaly_score,
            anomaly_reasons=anomaly_report.reasons,
        )

        # Tool Builder
        tool_calls = tool_builder.build(
            decomp_output["sub_tasks"], session_id
        )

        # Executor
        audit_result = await executor.execute(
            tool_calls=tool_calls,
            session=session,
            session_id=session_id,
            raw_event=req.event,
            depth=decomp_output["audit_depth"],
        )

        # Reviewer
        tool_data = "\n".join(
            f"[{tr.tool}] {str(tr.data)[:200]}"
            for tr in audit_result.tool_results
        )
        verdict = await reviewer.review(
            raw_event=req.event,
            decomposer_output=decomp_output,
            audit_result=audit_result,
            tool_data_raw=tool_data,
        )

        # 回写审计结果到事件 (与自动流水线保持一致)
        db_evt = await session.get(SecurityEvent, event_id)
        if db_evt:
            db_evt.analyzed = True
            db_evt.raw_data = {
                **(db_evt.raw_data or {}),
                "_audit_llm": {
                    "manual_run": True,
                    "threat_detected": audit_result.threat_detected,
                    "confidence": audit_result.confidence,
                    "verdict": verdict.to_dict(),
                    "pipeline_duration_s": 0,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                },
            }
            await session.commit()

        return {
            "event_id": event_id,
            "session_id": session_id,
            "depth": decomp_output["audit_depth"],
            "audit_result": audit_result.to_dict(),
            "verdict": verdict.to_dict(),
            "pipeline_steps": {
                "decomposer": {
                    "sub_tasks": len(decomp_output["sub_tasks"]),
                    "depth": decomp_output["audit_depth"],
                },
                "tool_builder": {
                    "tool_calls": len(tool_calls),
                },
                "executor": {
                    "tool_results": len(audit_result.tool_results),
                    "threat_detected": audit_result.threat_detected,
                    "confidence": audit_result.confidence,
                },
                "reviewer": {
                    "conclusion": verdict.conclusion,
                    "human_intervention": verdict.human_intervention,
                },
            },
        }
    finally:
        clear_trace_context()

@router.get("/audit-llm/pipeline/{event_id}")
async def get_pipeline_result(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取 Audit-LLM 流水线的审核结果。

    强制 prefer_db: Temporal worker 跨进程写回 `_audit_llm` 后,
    本进程热缓存可能仍是 ingest 时的空快照; 直接读 DB 才能看到报告。
    """
    evt = await event_store.get_by_id(session, event_id, prefer_db=True)
    if not evt:
        raise HTTPException(404, "Event not found")

    raw = evt.raw_data or {}
    pipeline = raw.get("_audit_llm", {}) or {}
    cad = raw.get("_cad_audit", {}) or {}
    error = raw.get("_audit_llm_error", "") or pipeline.get("error", "")
    analyzed = bool(getattr(evt, "analyzed", False) or pipeline or error)
    status = pipeline.get("status") or (
        "failed" if error else ("completed" if pipeline else ("pending" if not analyzed else "unknown"))
    )

    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "analyzed": analyzed,
        "status": status,
        "pipeline_result": pipeline,
        "cad_audit": cad or None,
        "error": error or None,
    }

@router.get("/audit-llm/stats")
async def audit_llm_stats(
    session_id: str = Query("", description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """Audit-LLM 流水线统计"""
    total_val = (await session.execute(
        select(func.count(SecurityEvent.id))
    )).scalar() or 0
    analyzed_val = (await session.execute(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.analyzed == True)
    )).scalar() or 0
    return {
        "total_events": total_val,
        "analyzed": analyzed_val,
        "pending": total_val - analyzed_val,
    }

@router.get("/audit-llm/evidence/{event_id}")
async def get_evidence_trail(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取审计全链路证据追溯（断言↔事件ID映射）"""
    evt = await event_store.get_by_id(session, event_id, prefer_db=True)
    if not evt:
        raise HTTPException(404, "Event not found")

    raw = evt.raw_data or {}
    audit = raw.get("_audit_llm", {}) or {}
    error = raw.get("_audit_llm_error", "") or audit.get("error", "")
    analyzed = bool(getattr(evt, "analyzed", False) or audit or error)
    status = audit.get("status") or (
        "failed" if error else ("completed" if audit else ("pending" if not analyzed else "unknown"))
    )

    evidence_trail = audit.get("evidence_trail") or []
    if not isinstance(evidence_trail, list):
        evidence_trail = []
    hallucination = audit.get("hallucination") or {}
    reviewer = audit.get("reviewer") or audit.get("final_verdict") or {}
    if not isinstance(reviewer, dict):
        reviewer = {"raw": str(reviewer)}
    executor_summary = audit.get("executor") or audit.get("merged") or {}
    if not isinstance(executor_summary, dict):
        executor_summary = {"summary": str(executor_summary)}

    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "analyzed": analyzed,
        "status": status,
        "error": error or None,
        "evidence_trail": evidence_trail,
        "hallucination_risk": hallucination if isinstance(hallucination, dict) else {},
        "executor_summary": executor_summary,
        "reviewer_verdict": reviewer,
        "pipeline_duration_s": audit.get("pipeline_duration_s"),
        "completed_at": audit.get("completed_at"),
        "fallback": bool(audit.get("fallback")),
    }

# ── CAD 审计角色端点 ──

@router.get("/cad/status")
async def cad_status(user: UserInfo = Depends(get_current_user)):
    """获取 CAD 审计角色状态（含熔断器）"""
    cb_status = circuit_breaker.get_status()
    return {
        "circuit_breaker": cb_status,
        "context_audit_interval_s": 3600,
    }

@router.post("/cad/audit-context")
async def trigger_context_audit(user: UserInfo = Depends(RequireRole("admin"))):
    """手动触发上下文审计"""
    report = await cad_agent.audit_context()
    return report

@router.get("/cad/circuit-breaker")
async def get_circuit_breaker(user: UserInfo = Depends(get_current_user)):
    """查询熔断器状态"""
    return circuit_breaker.get_status()

@router.post("/cad/circuit-breaker/reset")
async def reset_circuit_breaker(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """人工重置熔断器"""
    result = circuit_breaker.reset()
    await log_from_request(
        session, request, user, action="circuit_breaker.reset",
        target_type="circuit_breaker", target_id="cad",
        after={"result": str(result)[:500]},
        reason="人工重置 CAD 熔断器",
    )
    return result

@router.put("/cad/thresholds")
async def update_cad_thresholds(
    body: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """运行时更新 CAD 熔断阈值"""
    updated = circuit_breaker.update_thresholds(**body)
    await log_from_request(
        session, request, user, action="cad.thresholds_update",
        target_type="circuit_breaker", target_id="cad",
        before={"thresholds": circuit_breaker.get_status()["thresholds"]},
        after={"updated": updated},
    )
    return {"success": True, "updated": updated, "current": circuit_breaker.get_status()["thresholds"]}

@router.post("/cad/override/{event_id}")
async def cad_override(
    event_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """人工覆盖 CAD 决策（标记为误报）"""
    circuit_breaker.record_override(event_id)
    await log_from_request(
        session, request, user, action="cad.override",
        target_type="security_event", target_id=str(event_id),
        after={"marked_as": "false_positive",
               "accuracy": circuit_breaker.accuracy_stats()},
        reason="人工覆盖 CAD 决策",
    )
    return {"success": True, "event_id": event_id, "accuracy": circuit_breaker.accuracy_stats()}

@router.get("/cad/accuracy")
async def cad_accuracy(user: UserInfo = Depends(get_current_user)):
    """CAD 自身准确率统计"""
    return circuit_breaker.accuracy_stats()

@router.get("/cad/verification/{event_id}")
async def get_cad_verification(
    event_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """获取指定事件的 CAD 穿透验证结果"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")
    raw = evt.raw_data or {}
    cad_data = raw.get("_cad_audit", {})
    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "cad_audit": cad_data,
    }
