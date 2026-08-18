"""钓鱼检测 / LLM 增强 / 数据安全分类 / 钓鱼演练 — 路由模块"""

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from config import settings
from models import get_session, PhishingRecord, PhishingDrill, PhishingDrillRecord
from auth import get_current_user, RequireRole, UserInfo

from phishing_guard import phishing_guard
from phishing_guard.models import (
    EmailPhishingRequest,
    WebPhishingRequest,
    DomainPhishingRequest,
    AttachmentPhishingRequest,
    SmsPhishingRequest,
    QrCodePhishingRequest,
    BecPhishingRequest,
)
from phishing_guard.drill_manager import drill_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["phishing"])


@router.post("/phishing/detect/email")
async def phishing_detect_email(
    req: EmailPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """邮件钓鱼检测"""
    verdict = phishing_guard.detect_email(req)
    record = PhishingRecord(
        detection_type="email",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/web")
async def phishing_detect_web(
    req: WebPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """网页钓鱼检测"""
    verdict = phishing_guard.detect_web(req)
    record = PhishingRecord(
        detection_type="web",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/domain")
async def phishing_detect_domain(
    req: DomainPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """域名访问钓鱼检测"""
    verdict = phishing_guard.detect_domain(req)
    record = PhishingRecord(
        detection_type="domain",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/attachment")
async def phishing_detect_attachment(
    req: AttachmentPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """附件钓鱼检测"""
    verdict = phishing_guard.detect_attachment(req)
    record = PhishingRecord(
        detection_type="attachment",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/sms")
async def phishing_detect_sms(
    req: SmsPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """短信钓鱼检测"""
    verdict = phishing_guard.detect_sms(req)
    record = PhishingRecord(
        detection_type="sms",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/qrcode")
async def phishing_detect_qrcode(
    req: QrCodePhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """二维码钓鱼检测"""
    verdict = phishing_guard.detect_qrcode(req)
    record = PhishingRecord(
        detection_type="qrcode",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@router.post("/phishing/detect/bec")
async def phishing_detect_bec(
    req: BecPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """商务诈骗 (BEC) 检测"""
    verdict = phishing_guard.detect_bec(req)
    record = PhishingRecord(
        detection_type="bec",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

# ════════════════════════════════════════════
# LLM 增强端点 (P0.S) - 流量/钓鱼/数据安全 三大模型
# ════════════════════════════════════════════

@router.get("/llm-enhancer/status")
async def llm_enhancer_status(
    user: UserInfo = Depends(get_current_user),
):
    """LLM 增强器状态：模块开关 / 预算用量 / 并发配置"""
    from llm_enhancer import get_module_budget_status, is_module_enabled
    return {
        "modules": {
            "traffic": is_module_enabled("traffic"),
            "phishing": is_module_enabled("phishing"),
            "data_security": is_module_enabled("data_security"),
        },
        "budgets": get_module_budget_status(),
        "concurrency": settings.llm_enhancer_concurrency,
        "timeout_sec": settings.llm_enhancer_timeout_sec,
    }


@router.post("/llm-enhancer/traffic-analyze")
async def llm_traffic_analyze(
    request: Request,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """
    手动触发流量大模型分析（用于运营人工复核 / 测试）.
    主路径调 seasonal_detector.detect() 后异步派发 LLM 任务,
    本端点直接返回 detect 结果,LLM 结果异步入库 network_flows.raw_data.

    请求体: {ip, metric, current_value, recent_pattern?, flow_id?}
    """
    body = await request.json()
    from traffic_baseline.seasonal import seasonal_detector
    from traffic_baseline import should_trigger_llm

    ip = body.get("ip", "")
    metric = body.get("metric", "bytes_out")
    current_value = body.get("current_value")
    recent_pattern = body.get("recent_pattern", "")
    flow_id = int(body.get("flow_id", 0))

    # 主路径:规则检测 (sync, < 5ms)
    detect_result = seasonal_detector.detect(ip, metric, current_value)

    # 派发 LLM (async, 不等待)
    triggered = should_trigger_llm(detect_result)
    if triggered:
        from traffic_baseline.llm_anomaly import analyze_and_persist
        from llm_enhancer import safe_dispatch
        safe_dispatch(
            analyze_and_persist(
                ip=ip, metric=metric, detect_result=detect_result,
                recent_pattern=recent_pattern, flow_id=flow_id,
            ),
            log_label=f"traffic_api:{ip}",
        )

    return {
        "detect_result": detect_result,
        "llm_triggered": triggered,
        "llm_async": True,
        "hint": "LLM 判定通过 network_flows.raw_data.llm_verdict 字段异步回写",
    }


@router.post("/phishing/detect/email-llm")
async def phishing_detect_email_llm(
    req: EmailPhishingRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """邮件钓鱼检测 + LLM 复核.立即返规则 verdict,LLM 异步广播"""
    from phishing_guard import phishing_guard
    verdict = phishing_guard.detect_email(req, llm_enrich=True)
    record = PhishingRecord(
        detection_type="email",
        target=(req.sender or req.subject or "(邮件)")[:500],
        risk_level=verdict.risk_level, confidence=verdict.confidence,
        score=verdict.score, indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary, suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record); await session.commit()
    return {**verdict.to_dict(), "llm_async": settings.llm_phishing_enabled}


class DataSecurityClassifyRequest(BaseModel):
    url: str = ""
    method: str = "GET"
    response_content_type: str = ""
    response_size: int = 0
    body_snippet: str = ""
    rule_hit: str = "sensitive_data_leak"
    src_ip: str = ""
    dst_ip: str = ""
    sensor_id: str = ""


@router.post("/data-security/classify")
async def data_security_classify(
    req: DataSecurityClassifyRequest,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """
    手动触发数据安全大模型分类（运营人工复核 / 测试）.
    主体 LLM 调用阻塞返结果（控制台测试用），生产路径由 http_linker 异步派发.
    """
    from data_security import classify_and_broadcast, classify_session

    if not settings.llm_data_security_enabled:
        return {
            "verdict": None,
            "llm_async": False,
            "hint": "数据安全大模型未启用 (SHARED_MEMORY_LLM_DATA_SECURITY_ENABLED=false)",
        }

    summary = {
        "url": req.url, "method": req.method,
        "response_content_type": req.response_content_type,
        "response_size": req.response_size,
        "body_snippet": req.body_snippet,
        "rule_hit": req.rule_hit, "src_ip": req.src_ip, "dst_ip": req.dst_ip,
    }
    # 调用方手动触发 → 同步等结果
    verdict = await classify_session(http_summary=summary, sensor_id=req.sensor_id)
    return {
        "verdict": verdict,
        "llm_async": False,
        "manual_trigger": True,
    }


@router.get("/llm-enhancer/events/stream")
async def llm_enhancer_events_stream(
    user: UserInfo = Depends(get_current_user),
):
    """
    SSE: LLM 增强 verdict 实时事件
    订阅 phishing_llm_verdict / data_security_llm_verdict 事件,
    前端运营面板可监听实时显示.
    """
    async def event_gen():
        # 复用 event_bus 订阅机制：订阅全量队列后按 topic 过滤
        from event_bus import event_bus
        q = event_bus.subscribe()
        topics = ("phishing_llm_verdict", "data_security_llm_verdict")
        try:
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=15)
                    if evt.type in topics:
                        yield {
                            "event": evt.type,
                            "data": json.dumps({**evt.data, "_ts": evt.timestamp},
                                               ensure_ascii=False, default=str),
                        }
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            pass
        finally:
            event_bus.unsubscribe(q)

    return EventSourceResponse(event_gen())


@router.get("/phishing/stats")
async def phishing_stats(session: AsyncSession = Depends(get_session)):
    """钓鱼检测统计"""
    total = (await session.execute(
        select(func.count(PhishingRecord.id))
    )).scalar() or 0
    phishing_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "phishing")
    )).scalar() or 0
    suspicious_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "suspicious")
    )).scalar() or 0
    safe_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "safe")
    )).scalar() or 0

    by_type = {}
    for dtype in ("email", "web", "domain", "attachment", "sms", "qrcode", "bec"):
        cnt = (await session.execute(
            select(func.count(PhishingRecord.id)).where(PhishingRecord.detection_type == dtype)
        )).scalar() or 0
        by_type[dtype] = cnt

    return {
        "total": total,
        "phishing": phishing_count,
        "suspicious": suspicious_count,
        "safe": safe_count,
        "by_type": by_type,
    }

@router.get("/phishing/history")
async def phishing_history(
    limit: int = Query(20, ge=1, le=100),
    detection_type: str = Query("", description="email / web / domain"),
    session: AsyncSession = Depends(get_session),
):
    """钓鱼检测历史记录"""
    stmt = select(PhishingRecord).order_by(desc(PhishingRecord.created_at))
    if detection_type:
        stmt = stmt.where(PhishingRecord.detection_type == detection_type)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "detection_type": r.detection_type,
            "target": r.target,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "score": r.score,
            "summary": r.summary,
            "indicator_count": len(r.indicators or []),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]

# ── 钓鱼演练管理端点 ──

class DrillCreateRequest(BaseModel):
    name: str
    drill_type: str = "email"
    template_subject: str = ""
    template_body: str = ""

class DrillLaunchRequest(BaseModel):
    targets: list[str]

class DrillRecordRequest(BaseModel):
    target_identifier: str
    event_type: str  # opened / clicked / reported

@router.post("/phishing/drill")
async def create_drill(
    req: DrillCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    """创建钓鱼演练"""
    return await drill_manager.create_drill(
        session, req.name, req.drill_type,
        req.template_subject, req.template_body,
    )

@router.get("/phishing/drill")
async def list_drills(
    status: str = Query("", description="draft / running / completed"),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    """演练列表"""
    return await drill_manager.list_drills(session, status=status, limit=limit)

@router.get("/phishing/drill/{drill_id}")
async def get_drill(
    drill_id: int,
    session: AsyncSession = Depends(get_session),
):
    """演练详情 + 统计"""
    result = await drill_manager.get_drill(session, drill_id)
    if not result:
        raise HTTPException(404, "Drill not found")
    return result

@router.delete("/phishing/drill/{drill_id}")
async def delete_drill(
    drill_id: int,
    session: AsyncSession = Depends(get_session),
):
    """删除演练"""
    ok = await drill_manager.delete_drill(session, drill_id)
    if not ok:
        raise HTTPException(404, "Drill not found")
    return {"deleted": True}

@router.post("/phishing/drill/{drill_id}/launch")
async def launch_drill(
    drill_id: int,
    req: DrillLaunchRequest,
    session: AsyncSession = Depends(get_session),
):
    """发起演练（批量生成目标记录）"""
    result = await drill_manager.launch_drill(session, drill_id, req.targets)
    if not result:
        raise HTTPException(404, "Drill not found")
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@router.post("/phishing/drill/{drill_id}/record")
async def record_drill_event(
    drill_id: int,
    req: DrillRecordRequest,
    session: AsyncSession = Depends(get_session),
):
    """记录演练目标事件（opened / clicked / reported）"""
    result = await drill_manager.record_event(
        session, drill_id, req.target_identifier, req.event_type,
    )
    if not result:
        raise HTTPException(404, "Drill record not found")
    return result
