"""运营闭环 — 可观测性 / 审计 Trail / KPI / 案例 / 工单 / 复盘 / 反馈 / 规则 / 安全审计 — 路由模块"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_session, async_session, SecurityEvent
from auth import get_current_user, RequireRole, UserInfo
from audit_trail import log_from_request
from event_store import event_store, EventFilter
from correlation_engine import correlation_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["ops"])


# ── Agent 轨迹端点 ──

@router.get("/agent-traces")
async def agent_traces(
    caller: str = Query("", description="调用方"),
    operation: str = Query("", description="操作"),
    status: str = Query("", description="success | error"),
    event_id: int = Query(0),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """查询 Agent LLM 轨迹（分页 + 过滤）"""
    from eval_repository import get_traces
    return await get_traces(
        caller=caller, operation=operation, status=status,
        event_id=event_id, limit=limit, offset=offset,
    )

@router.get("/agent-traces/stats")
async def agent_trace_stats(
    caller: str = Query("", description="调用方"),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """Agent 轨迹聚合统计"""
    from eval_repository import get_trace_stats
    return await get_trace_stats(caller=caller)


# ── Token 成本面板端点 (P0.T) ──

@router.get("/agent-traces/by-event")
async def agent_traces_by_event(
    days: int = Query(30, ge=1, le=365, description="统计窗口(天)"),
    min_tokens: int = Query(0, ge=0, description="事件总 token 下限过滤"),
    event_type: str = Query("", description="事件类型过滤"),
    severity: str = Query("", description="严重度过滤"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """按事件聚合 token 消耗 — 运营中心成本面板主数据"""
    from eval_repository import get_event_token_aggregation, get_cache_channel_stats
    from summary_compression import cost_tracker

    data = await get_event_token_aggregation(
        days=days, min_tokens=min_tokens,
        limit=limit, offset=offset,
        event_type=event_type, severity=severity,
    )
    data["budget"] = cost_tracker.stats()
    # 缓存命中率(LLM/嵌入分通道) — 成本面板统计卡直接消费
    data["cache"] = await get_cache_channel_stats()
    data["estimated_cost_yuan"] = round(cost_tracker.estimate_cost_yuan(
        data["grand"]["prompt_tokens"], data["grand"]["completion_tokens"]
    ), 4)
    return data


@router.get("/agent-traces/daily")
async def agent_traces_daily(
    days: int = Query(14, ge=1, le=365, description="趋势窗口(天)"),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """近 N 天每日 token 用量趋势 + 按调用来源模块分账"""
    from eval_repository import get_daily_token_usage, get_cost_by_caller
    from summary_compression import cost_tracker

    points = await get_daily_token_usage(days=days)
    by_caller = await get_cost_by_caller(days=days)
    return {
        "points": points,
        "by_caller": by_caller,
        "budget": cost_tracker.stats(),
    }


@router.get("/agent-traces/event/{event_id}")
async def agent_traces_by_event_id(
    event_id: int,
    limit: int = Query(100, ge=1, le=500),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """单事件全部 LLM 调用明细 (成本面板 drill-down)"""
    from eval_repository import get_traces
    return await get_traces(event_id=event_id, limit=limit, offset=0)


# ── 全链路可观测性端点 ──

@router.get("/observability/health")
async def observability_health(
    user: UserInfo = Depends(RequireRole("admin")),
):
    """各阶段健康快照（红绿灯）"""
    from observability.health_monitor import health_monitor
    snapshot = health_monitor.get_health_snapshot()
    return snapshot.to_dict()


@router.get("/observability/spans")
async def observability_spans(
    event_id: int = Query(0, description="按事件 ID 过滤"),
    stage: str = Query("", description="按阶段过滤"),
    limit: int = Query(50, ge=1, le=200),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """查询最近 Span（支持 event_id/stage 过滤）"""
    from observability.pipeline_tracer import pipeline_tracer
    return pipeline_tracer.get_recent_spans(
        event_id=event_id or None,
        stage=stage or None,
        limit=limit,
    )


@router.get("/observability/active-pipelines")
async def observability_active_pipelines(
    user: UserInfo = Depends(RequireRole("admin")),
):
    """按 event_id 聚合正在运行的 Agent 接力（Monitor 首屏 hydration）"""
    from observability.pipeline_tracer import pipeline_tracer, STAGES
    from observability.stage_events import DEFAULT_SSE_STAGES, STAGE_LABELS

    active = pipeline_tracer.get_active_spans()
    by_event: dict[int, list[dict]] = {}
    for s in active:
        eid = int(s.get("event_id") or 0)
        if not eid:
            continue
        by_event.setdefault(eid, []).append(s)

    # 近期已完成 span，用于补全 completed_stages
    recent = pipeline_tracer.get_recent_spans(limit=200)
    completed_by_event: dict[int, list[str]] = {}
    for s in recent:
        eid = int(s.get("event_id") or 0)
        if not eid or eid not in by_event:
            continue
        stage = s.get("stage") or ""
        if stage in DEFAULT_SSE_STAGES and s.get("status") == "success":
            completed_by_event.setdefault(eid, [])
            if stage not in completed_by_event[eid]:
                completed_by_event[eid].append(stage)

    stage_order = {st: i for i, st in enumerate(STAGES)}
    pipelines = []
    for eid, spans in by_event.items():
        spans_sorted = sorted(spans, key=lambda x: stage_order.get(x.get("stage", ""), 99))
        current = spans_sorted[-1]
        cur_stage = current.get("stage", "")
        pipelines.append({
            "event_id": eid,
            "session_id": current.get("session_id", ""),
            "trace_id": current.get("trace_id", ""),
            "current_stage": cur_stage,
            "agent_label": STAGE_LABELS.get(cur_stage, cur_stage),
            "completed_stages": completed_by_event.get(eid, []),
            "started_at": current.get("start_time"),
            "running_seconds": current.get("running_seconds", 0),
            "active_spans": spans_sorted,
        })
    pipelines.sort(key=lambda p: p.get("started_at") or 0, reverse=True)
    return {"pipelines": pipelines, "count": len(pipelines)}


@router.get("/observability/thought-chain/{event_id}")
async def observability_thought_chain(
    event_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """组装一条事件的思维链 DAG（live 缓冲 / 落库 / 存量投影）。"""
    from observability.thought_events import assemble_thought_chain, snapshot
    from event_store import event_store

    evt = await event_store.get_by_id(session, event_id, prefer_db=True)
    audit = None
    cad = None
    status = "running"
    session_id = ""
    if evt:
        raw = evt.raw_data or {}
        audit = raw.get("_audit_llm") or {}
        cad = raw.get("_cad_audit") or None
        session_id = getattr(evt, "session_id", "") or ""
        st = (audit or {}).get("status") or ""
        if st in ("completed", "failed", "fallback"):
            status = st
        elif getattr(evt, "analyzed", False) and audit:
            status = "completed"
        elif raw.get("_audit_llm_error"):
            status = "failed"
    elif not snapshot(event_id):
        raise HTTPException(404, "Event not found")

    return assemble_thought_chain(
        event_id, audit=audit, cad=cad, session_id=session_id, status=status,
    )


@router.get("/observability/recent-thought-chains")
async def observability_recent_thought_chains(
    limit: int = Query(8, ge=1, le=40),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """最近可展示思维链的事件（不含 prompt / completion）。"""
    from observability.thought_events import list_recent_thought_chains

    chains = await list_recent_thought_chains(session, limit=limit)
    return {"chains": chains, "count": len(chains)}


@router.get("/observability/recent-pipelines")
async def observability_recent_pipelines(
    limit: int = Query(8, ge=1, le=40),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """最近已结束的 Agent 接力（Monitor「最近完成」hydration）。"""
    from observability.pipeline_tracer import pipeline_tracer

    pipelines = pipeline_tracer.get_recent_completed_pipelines(limit=limit)
    return {"pipelines": pipelines, "count": len(pipelines)}


@router.get("/observability/traces")
async def observability_trace_list(
    limit: int = Query(20, ge=1, le=100),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """列出最近 W3C trace_id — 优先来自 Grafana Tempo (标准 trace 事实源)"""
    import httpx
    from datetime import datetime, timezone, timedelta

    traces: list[dict] = []
    try:
        now = datetime.now(timezone.utc)
        end = int(now.timestamp())
        start = int((now - timedelta(hours=24)).timestamp())
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "http://tempo:3200/api/search",
                params={"start": start, "end": end, "limit": limit},
            )
            if r.status_code == 200:
                for t in r.json().get("traces", []):
                    traces.append({
                        "trace_id": t.get("traceID", ""),
                        "last_seen": t.get("startTimeUnixNano", 0),
                        "root_service": t.get("rootServiceName", ""),
                        "root_span": t.get("rootSpanName", ""),
                        "duration_ms": t.get("durationMs", 0),
                    })
    except Exception as e:
        logger.warning(f"[Traces] Tempo 查询失败: {e}")

    # 补充 pipeline_spans 中的 trace (LLM 审计链路)
    if len(traces) < limit:
        from models import PipelineSpan, async_session as db_session
        async with db_session() as session:
            stmt = (
                select(PipelineSpan.trace_id, func.max(PipelineSpan.created_at).label("last_seen"))
                .where(PipelineSpan.trace_id != "")
                .group_by(PipelineSpan.trace_id)
                .order_by(desc("last_seen"))
                .limit(limit)
            )
            rows = (await session.execute(stmt)).all()
            known = {t["trace_id"] for t in traces}
            for r in rows:
                if r.trace_id not in known:
                    traces.append({
                        "trace_id": r.trace_id,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else "",
                        "root_service": "soc-backend",
                        "root_span": "pipeline",
                        "duration_ms": 0,
                    })
            traces = traces[:limit]

    return {"traces": traces}


@router.get("/observability/traces/{trace_id}")
async def observability_trace_detail(
    trace_id: str,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """按 W3C trace_id 拉全链路: Tempo 完整 span 树 + pipeline_spans + 关联事件"""
    import httpx
    from observability.pipeline_tracer import pipeline_tracer

    # 1) 标准事实源: Tempo 完整 span 树 (Flink + Python)
    tempo_spans: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(f"http://tempo:3200/api/traces/{trace_id}")
            if r.status_code == 200:
                for b in r.json().get("batches", []):
                    svc = "?"
                    for a in b["resource"]["attributes"]:
                        if a["key"] == "service.name":
                            svc = a["value"].get("stringValue", "?")
                    for ss in b.get("scopeSpans", []):
                        for sp in ss.get("spans", []):
                            dur_ms = (int(sp.get("endTimeUnixNano", 0)) - int(sp.get("startTimeUnixNano", 0))) / 1e6
                            attrs = {
                                a["key"]: a["value"].get("stringValue", "")
                                for a in sp.get("attributes", [])
                            }
                            tempo_spans.append({
                                "service": svc,
                                "name": sp.get("name", ""),
                                "span_id": sp.get("spanId", "")[:12],
                                "parent_span_id": sp.get("parentSpanId", ""),
                                "start_time": int(sp.get("startTimeUnixNano", 0)) / 1e9,
                                "latency_ms": round(dur_ms, 1),
                                "status": attrs.get("soc.stage", "unknown"),
                                "stage": attrs.get("soc.stage", ""),
                                "event_type": attrs.get("soc.event_type", ""),
                                "src_ip": attrs.get("soc.src_ip", ""),
                                "importance": attrs.get("soc.importance", ""),
                            })
    except Exception as e:
        logger.warning(f"[Traces] Tempo 详情查询失败: {e}")

    # 2) pipeline_spans (LLM 审计链路)
    from models import PipelineSpan, SecurityEvent, async_session as db_session
    async with db_session() as session:
        stmt = (
            select(PipelineSpan)
            .where(PipelineSpan.trace_id == trace_id)
            .order_by(PipelineSpan.start_time)
        )
        rows = (await session.execute(stmt)).scalars().all()
        pipe_spans = [
            {
                "service": "soc-backend",
                "name": f"pipeline.{r.stage}",
                "span_id": r.span_id,
                "parent_span_id": "",
                "start_time": r.start_time,
                "latency_ms": round(r.latency_ms, 1),
                "status": r.status,
                "stage": r.stage,
                "event_id": r.event_id,
                "session_id": r.session_id,
                "error": r.error,
            }
            for r in rows
        ]
        # 关联事件 (raw_data 内含 _trace_id) — 用 raw SQL 规避 JSON 类型差异
        from sqlalchemy import text as sa_text
        ev_stmt = sa_text(
            "SELECT id, event_type, severity, src_ip, anomaly_score, created_at "
            "FROM security_events WHERE raw_data->>'_trace_id' = :tid "
            "ORDER BY created_at DESC LIMIT 5"
        ).bindparams(tid=trace_id)
        ev_rows = (await session.execute(ev_stmt)).mappings().all()
        events = [
            {
                "id": e["id"], "event_type": e["event_type"], "severity": e["severity"],
                "src_ip": e["src_ip"], "anomaly_score": e["anomaly_score"],
                "created_at": str(e["created_at"]) if e["created_at"] else "",
            }
            for e in ev_rows
        ]

    spans = tempo_spans + pipe_spans
    spans.sort(key=lambda s: s.get("start_time", 0))
    return {
        "trace_id": trace_id,
        "span_count": len(spans),
        "spans": spans,
        "events": events,
        # Grafana Tempo 深链 (在 Tempo 搜索框输入 trace_id 可查看完整瀑布)
        "grafana_url": "http://localhost:3002/grafana/explore?schemaVersion=1&panes=%7B%22a%22%3A%7B%22datasource%22%3A%7B%22type%22%3A%22tempo%22%2C%22uid%22%3A%22tempo%22%7D%2C%22queries%22%3A%5B%7B%22refId%22%3A%22A%22%2C%22queryType%22%3A%22traceql%22%2C%22query%22%3A%22%7B%7D%22%7D%5D%7D%7D",
        "trace_id_note": "在 Grafana Tempo 的 Search→Trace ID 输入框粘贴本 trace_id 可看完整瀑布图",
    }



@router.get("/observability/diagnostics")
async def observability_diagnostics(
    limit: int = Query(20, ge=1, le=100),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """查询历史诊断报告"""
    from models import DiagnosticReport, async_session as db_session
    async with db_session() as session:
        stmt = (
            select(DiagnosticReport)
            .order_by(desc(DiagnosticReport.created_at))
            .limit(limit)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "trigger_reason": r.trigger_reason,
                "trigger_stage": r.trigger_stage,
                "severity": r.severity,
                "root_cause": r.root_cause,
                "recommendations": r.recommendations,
                "affected_event_count": r.affected_event_count,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]


@router.post("/observability/diagnose")
async def observability_diagnose(
    user: UserInfo = Depends(RequireRole("admin")),
):
    """手动触发全链路诊断"""
    from observability.watchdog import watchdog
    report = await watchdog.diagnose(trigger_reason="manual_api_trigger")
    return report


# ── 操作审计 trail (P0.H) ──

@router.get("/audit-trail")
async def audit_trail_list(
    actor: str = Query(""),
    action: str = Query(""),
    target_type: str = Query(""),
    target_id: str = Query(""),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询操作审计 trail"""
    from audit_trail import list_trail
    rows = await list_trail(
        session, actor=actor, action=action, target_type=target_type,
        target_id=target_id, limit=limit, offset=offset,
    )
    return {"records": rows, "count": len(rows)}


@router.post("/audit-trail/flush")
async def audit_trail_flush(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """冲刷离线缓冲到 DB（DB 故障恢复后调用）"""
    from audit_trail import flush_fallback
    n = await flush_fallback(session)
    return {"flushed": n}


# ── 运营 KPI / SLA 端点 (P0.B) ──

@router.get("/ops/kpi")
async def ops_kpi(
    metric: str = Query("", description="指标 key, 留空返回全量 dashboard"),
    period: str = Query("daily"),
    days: int = Query(30, le=365),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """运营 KPI 查询 / dashboard"""
    from ops_metrics.kpi_calculator import kpi_calculator
    if not metric:
        return await kpi_calculator.dashboard(session, days=days)
    return {
        "metric": metric,
        "points": await kpi_calculator.get_kpi(
            session, metric_key=metric, period=period, days=days
        ),
    }


@router.post("/ops/kpi/snapshot")
async def ops_kpi_snapshot(
    period: str = Query("daily", description="daily | weekly"),
    snapshot_date: str = Query("", description="YYYY-MM-DD,留空默认昨天"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """手动触发 KPI 快照（测试或回填）"""
    from ops_metrics.kpi_calculator import kpi_calculator
    from datetime import date as date_cls
    d = None
    if snapshot_date:
        try:
            d = date_cls.fromisoformat(snapshot_date)
        except ValueError:
            raise HTTPException(400, "snapshot_date 格式应为 YYYY-MM-DD")
    if period == "weekly":
        result = await kpi_calculator.snapshot_weekly(session, snapshot_date=d)
    else:
        result = await kpi_calculator.snapshot_daily(session, snapshot_date=d)
    return result


@router.get("/ops/sla")
async def ops_sla(
    hours: int = Query(24, le=720),
    priority: str = Query(""),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """SLA breach 实时率（DB 直查）+ 最近 breach 列表（内存）"""
    from ops_metrics.sla_tracker import sla_tracker
    rate = await sla_tracker.breach_rate(
        session, hours=hours, priority=priority
    )
    return {
        "rate": rate,
        "recent": sla_tracker.recent_breaches(hours=hours),
    }


@router.get("/ops/competition-metrics")
async def competition_metrics(
    days: int = Query(30, le=365),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """竞赛量化指标仪表板 — MTTD/MTTR/准确率/自动化率/误报率"""
    from datetime import datetime, timezone, timedelta
    from ops_metrics.kpi_calculator import kpi_calculator

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    metrics = {
        "mttd_hours": await kpi_calculator.compute_mttd(session, start=start, end=end),
        "mttr_hours": await kpi_calculator.compute_mttr(session, start=start, end=end),
        "automation_rate": await kpi_calculator.compute_automation_rate(session, start=start, end=end),
        "grounding_pass_rate": await kpi_calculator.compute_grounding_pass_rate(session, start=start, end=end),
        "fp_rate": await kpi_calculator.compute_fp_rate(session, start=start, end=end),
        "case_count": await kpi_calculator.compute_case_count(session, start=start, end=end),
        "sla_breach_rate": await kpi_calculator.compute_sla_breach_rate(session, start=start, end=end),
    }

    # 安全事件统计
    from sqlalchemy import func as sqlfunc
    total_events = (await session.execute(
        sqlfunc.count(SecurityEvent.id)
    )).scalar() or 0
    analyzed_events = (await session.execute(
        sqlfunc.count(SecurityEvent.id).where(SecurityEvent.analyzed == True)
    )).scalar() or 0

    return {
        "period_days": days,
        "metrics": metrics,
        "events": {
            "total": total_events,
            "analyzed": analyzed_events,
            "analysis_rate": round(analyzed_events / total_events, 4) if total_events > 0 else 0,
        },
        "capability_tiers": {
            "L1_基础感知": {
                "sigma_rules": 11,
                "cep_patterns": 3,
                "anomaly_dimensions": 3,
            },
            "L2_智能研判": {
                "audit_pipeline_layers": 4,
                "grounding_verifier_layers": 7,
                "cad_supervision": True,
            },
            "L3_自主处置": {
                "response_policies": 8,
                "action_types": 5,
                "safe_executor_layers": 6,
                "mcp_guard_layers": 4,
            },
        },
    }


# ── 事件运营闭环端点 ──

# 案例管理
@router.get("/cases")
async def list_cases(
    status: str = Query(""), priority: str = Query(""),
    assignee: str = Query(""), limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from case_manager import case_manager
    async with async_session() as session:
        return await case_manager.list_cases(session, status, priority, assignee, limit, offset)

@router.post("/cases")
async def create_case(
    body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from case_manager import case_manager
    async with async_session() as session:
        case = await case_manager.create_case(
            session, title=body.get("title", ""),
            event_ids=body.get("event_ids", []),
            priority=body.get("priority", "medium"),
            threat_type=body.get("threat_type", ""),
            assignee=body.get("assignee", ""),
            tags=body.get("tags", []),
        )
        return {"success": True, "case": case_manager._case_to_dict(case)}

@router.get("/cases/{case_id}")
async def get_case(case_id: int, user: UserInfo = Depends(RequireRole("admin"))):
    from case_manager import case_manager
    async with async_session() as session:
        result = await case_manager.get_case(session, case_id)
        if not result:
            raise HTTPException(404, "案例不存在")
        return result

@router.put("/cases/{case_id}/status")
async def update_case_status(
    case_id: int, body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from case_manager import case_manager
    async with async_session() as session:
        return await case_manager.update_status(session, case_id, body.get("status", ""), body.get("by", ""))

@router.put("/cases/{case_id}/assign")
async def assign_case(
    case_id: int, body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from case_manager import case_manager
    async with async_session() as session:
        return await case_manager.assign(session, case_id, body.get("assignee", ""))

@router.put("/cases/{case_id}/disposition")
async def set_case_disposition(
    case_id: int, body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from case_manager import case_manager
    async with async_session() as session:
        return await case_manager.set_disposition(session, case_id, body.get("disposition", ""), body.get("by", ""))

@router.get("/cases/{case_id}/timeline")
async def get_case_timeline(case_id: int, user: UserInfo = Depends(RequireRole("admin"))):
    from case_manager import case_manager
    async with async_session() as session:
        return await case_manager.get_case_timeline(session, case_id)

# 工单
@router.get("/work-orders")
async def list_work_orders(
    case_id: int = Query(0), order_type: str = Query(""),
    status: str = Query(""), limit: int = Query(50, ge=1, le=200),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from work_order_service import work_order_service
    async with async_session() as session:
        return await work_order_service.list_orders(session, case_id, order_type, status, limit)

@router.post("/work-orders")
async def create_work_order(body: dict, user: UserInfo = Depends(RequireRole("admin"))):
    from work_order_service import work_order_service
    async with async_session() as session:
        order = await work_order_service.create_order(
            session, case_id=body.get("case_id"),
            order_type=body.get("order_type", "disposition"),
            title=body.get("title", ""), description=body.get("description", ""),
            priority=body.get("priority", "medium"),
            assignee=body.get("assignee", ""),
            created_by=body.get("created_by", "admin"),
        )
        return {"success": True, "order": work_order_service._order_to_dict(order)}

@router.put("/work-orders/{order_id}/status")
async def update_work_order_status(
    order_id: int, body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from work_order_service import work_order_service
    async with async_session() as session:
        return await work_order_service.update_status(session, order_id, body.get("status", ""))

@router.post("/work-orders/{order_id}/approve")
async def approve_work_order(
    order_id: int, body: dict = None, user: UserInfo = Depends(RequireRole("admin")),
):
    from work_order_service import work_order_service
    async with async_session() as session:
        return await work_order_service.approve(session, order_id, (body or {}).get("approved_by", "admin"))

@router.post("/work-orders/{order_id}/reject")
async def reject_work_order(
    order_id: int, body: dict = None, user: UserInfo = Depends(RequireRole("admin")),
):
    from work_order_service import work_order_service
    b = body or {}
    async with async_session() as session:
        return await work_order_service.reject(session, order_id, b.get("reason", ""), b.get("rejected_by", "admin"))

# 复盘
@router.post("/post-mortems")
async def create_post_mortem(body: dict, user: UserInfo = Depends(RequireRole("admin"))):
    from post_mortem_service import post_mortem_service
    async with async_session() as session:
        return await post_mortem_service.create_post_mortem(session, body.get("case_id", 0), body.get("author", ""))

@router.get("/post-mortems/{case_id}")
async def get_post_mortem(case_id: int, user: UserInfo = Depends(RequireRole("admin"))):
    from post_mortem_service import post_mortem_service
    async with async_session() as session:
        result = await post_mortem_service.get_post_mortem(session, case_id)
        if not result:
            raise HTTPException(404, "复盘报告不存在")
        return result

@router.put("/post-mortems/{case_id}")
async def update_post_mortem(
    case_id: int, body: dict, user: UserInfo = Depends(RequireRole("admin")),
):
    from post_mortem_service import post_mortem_service
    async with async_session() as session:
        return await post_mortem_service.update_post_mortem(session, case_id, body)

@router.put("/post-mortems/{case_id}/publish")
async def publish_post_mortem(
    case_id: int, body: dict = None, user: UserInfo = Depends(RequireRole("admin")),
):
    from post_mortem_service import post_mortem_service
    async with async_session() as session:
        return await post_mortem_service.publish(session, case_id, (body or {}).get("reviewer", ""))

# 反馈 + 规则
@router.post("/feedback")
async def submit_feedback(body: dict, user: UserInfo = Depends(RequireRole("admin"))):
    from feedback_loop import feedback_loop
    async with async_session() as session:
        record = await feedback_loop.submit_feedback(
            session, event_id=body.get("event_id"),
            case_id=body.get("case_id"),
            feedback_type=body.get("feedback_type", "false_positive"),
            original_conclusion=body.get("original_conclusion", ""),
            operator_conclusion=body.get("operator_conclusion", ""),
            reason=body.get("reason", ""),
            rule_id=body.get("rule_id", ""),
            rule_suggestion=body.get("rule_suggestion", ""),
            submitted_by=body.get("submitted_by", ""),
        )
        return {"success": True, "id": record.id}

@router.get("/feedback/stats")
async def feedback_stats(
    rule_id: str = Query(""), days: int = Query(30, ge=1, le=365),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from feedback_loop import feedback_loop
    async with async_session() as session:
        return await feedback_loop.get_fp_statistics(session, rule_id, days)

@router.get("/feedback/suggestions")
async def feedback_suggestions(user: UserInfo = Depends(RequireRole("admin"))):
    from feedback_loop import feedback_loop
    async with async_session() as session:
        return await feedback_loop.generate_tuning_suggestions(session)

@router.get("/rules")
async def list_rules(
    rule_type: str = Query("sigma"), user: UserInfo = Depends(RequireRole("admin")),
):
    from rule_manager import rule_manager
    return rule_manager.list_rules(rule_type)

@router.post("/rules")
async def create_rule(
    body: dict, request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from rule_manager import rule_manager
    result = rule_manager.create_rule(body.get("rule_type", "sigma"), body.get("content", {}), body.get("changed_by", "admin"))
    if result.get("success") and result.get("version_data"):
        async with async_session() as session:
            await rule_manager.save_version(session, result["version_data"])
    async with async_session() as audit_session:
        await log_from_request(
            audit_session, request, user, action="rule.create",
            target_type="rule",
            target_id=str(result.get("rule_id") or result.get("version_data", {}).get("rule_id") or ""),
            after={"rule_type": body.get("rule_type", "sigma"),
                   "success": result.get("success")},
        )
    return result

@router.put("/rules/{rule_type}/{rule_id}")
async def update_rule(
    rule_type: str, rule_id: str, body: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from rule_manager import rule_manager
    result = rule_manager.update_rule(
        rule_type, rule_id, body.get("content", {}),
        body.get("change_summary", ""), body.get("changed_by", "admin"),
    )
    if result.get("success") and result.get("version_data"):
        async with async_session() as session:
            await rule_manager.save_version(session, result["version_data"])
    async with async_session() as audit_session:
        await log_from_request(
            audit_session, request, user, action="rule.update",
            target_type="rule", target_id=f"{rule_type}:{rule_id}",
            after={"success": result.get("success"),
                   "change_summary": body.get("change_summary", "")},
        )
    return result


@router.delete("/rules/{rule_type}/{rule_id}")
async def delete_rule(
    rule_type: str, rule_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """禁用/删除规则（response_policy 为软禁用）。"""
    from rule_manager import rule_manager
    result = rule_manager.delete_rule(rule_type, rule_id)
    async with async_session() as audit_session:
        await log_from_request(
            audit_session, request, user, action="rule.delete",
            target_type="rule", target_id=f"{rule_type}:{rule_id}",
            after={"success": result.get("success")},
        )
    return result

@router.get("/rules/{rule_type}/{rule_id}/versions")
async def get_rule_versions(
    rule_type: str, rule_id: str, user: UserInfo = Depends(RequireRole("admin")),
):
    from rule_manager import rule_manager
    async with async_session() as session:
        return await rule_manager.get_versions(session, rule_type, rule_id)

@router.post("/rules/{rule_type}/{rule_id}/rollback")
async def rollback_rule(
    rule_type: str, rule_id: str, body: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from rule_manager import rule_manager
    async with async_session() as session:
        result = await rule_manager.rollback(session, rule_type, rule_id, body.get("target_version", 1), body.get("changed_by", "admin"))
    async with async_session() as audit_session:
        await log_from_request(
            audit_session, request, user, action="rule.rollback",
            target_type="rule", target_id=f"{rule_type}:{rule_id}",
            after={"target_version": body.get("target_version", 1),
                   "result": str(result)[:500]},
        )
    return result

@router.post("/rules/sandbox")
async def sandbox_test_rule(body: dict, user: UserInfo = Depends(RequireRole("admin"))):
    from rule_manager import rule_manager
    async with async_session() as session:
        return await rule_manager.sandbox_test(
            session, body.get("rule_content", {}),
            body.get("event_ids"), body.get("limit", 100),
        )

@router.post("/rules/sigma/{rule_id}/toggle")
async def sigma_rule_toggle(rule_id: str, user: UserInfo = Depends(RequireRole("admin"))):
    """启用/停用 Sigma 规则"""
    from sigma_detector import sigma_detector
    if hasattr(sigma_detector, "reload"):
        from sigma_engine import store
        cur = store.get_rule(rule_id)
        if not cur:
            return {"success": False, "error": f"规则 {rule_id} 不存在"}
        enable = not bool(cur.get("x-soc-enabled", True))
        res = store.toggle(rule_id, enable)
        if res["success"]:
            sigma_detector.reload()
            return {"success": True, "rule_id": rule_id, "enabled": enable}
        return res
    for r in sigma_detector.rules:
        if r.rule_id == rule_id:
            r.enabled = not r.enabled
            return {"success": True, "rule_id": rule_id, "enabled": r.enabled}
    return {"success": False, "error": f"规则 {rule_id} 不存在"}

@router.post("/rules/sigma/{rule_id}/shadow")
async def sigma_rule_shadow(rule_id: str, user: UserInfo = Depends(RequireRole("admin"))):
    """切换 Sigma 规则灰度模式（shadow: 仅记录不触发响应）"""
    from sigma_detector import sigma_detector
    if hasattr(sigma_detector, "reload"):
        from sigma_engine import store
        cur = store.get_rule(rule_id)
        if not cur:
            return {"success": False, "error": f"规则 {rule_id} 不存在"}
        on = not bool(cur.get("x-soc-shadow", False))
        res = store.shadow(rule_id, on)
        if res["success"]:
            sigma_detector.reload()
            return {"success": True, "rule_id": rule_id, "shadow_mode": on}
        return res
    for r in sigma_detector.rules:
        if r.rule_id == rule_id:
            r.shadow_mode = not r.shadow_mode
            return {"success": True, "rule_id": rule_id, "shadow_mode": r.shadow_mode}
    return {"success": False, "error": f"规则 {rule_id} 不存在"}

# ── Sigma 规则测试集 ──
_SIGMA_TEST_CASES: list[dict] = [
    # SIG-007 带聚合条件 (同 src_ip 5 分钟内 count>3), 需重放 4 次才能命中
    {"name": "SSH爆破命中", "event": {"event": "BRUTE_FORCE", "severity": "high", "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1:22", "message": "SSH brute force"}, "expected_rule": "SIG-007", "expected_hit": True, "repeat": 4},
    {"name": "正常登录不命中", "event": {"event": "USER_LOGIN", "severity": "info", "src_ip": "10.0.0.5", "message": "Admin login success"}, "expected_rule": "SIG-007", "expected_hit": False},
    {"name": "C2通信命中", "event": {"event": "C2_BEACON", "severity": "critical", "src_ip": "192.168.1.100", "message": "C2 beacon detected"}, "expected_rule": "SIG-008", "expected_hit": True},
    {"name": "路径遍历命中", "event": {"event": "PATH_TRAVERSAL", "severity": "critical", "src_ip": "5.6.7.8", "url": "/../../etc/passwd", "message": "path traversal"}, "expected_rule": "SIG-003", "expected_hit": True},
    {"name": "端口扫描命中", "event": {"event": "PORT_SCAN", "severity": "medium", "src_ip": "9.10.11.12", "message": "port scan detected"}, "expected_rule": "SIG-009", "expected_hit": True},
    {"name": "正常DNS不命中", "event": {"event": "DNS_QUERY", "severity": "info", "src_ip": "10.0.0.10", "message": "DNS resolution"}, "expected_rule": "SIG-009", "expected_hit": False},
]

@router.get("/sigma/test-cases")
async def sigma_test_cases():
    """列出 Sigma 规则测试集"""
    return {"test_cases": _SIGMA_TEST_CASES, "count": len(_SIGMA_TEST_CASES)}

@router.post("/sigma/run-tests")
async def sigma_run_tests(user: UserInfo = Depends(RequireRole("admin"))):
    """运行 Sigma 规则测试集，验证命中/不命中"""
    from sigma_detector import sigma_detector
    results = []
    passed = 0
    for tc in _SIGMA_TEST_CASES:
        # 聚合规则需重放多次填满滑动窗口（取最后一次检测结果）
        hits = []
        for _ in range(tc.get("repeat", 1)):
            hits = sigma_detector.detect(tc["event"])
        hit_ids = [h.rule_id for h in hits]
        actual_hit = tc["expected_rule"] in hit_ids
        ok = actual_hit == tc["expected_hit"]
        if ok:
            passed += 1
        results.append({
            "name": tc["name"],
            "expected_hit": tc["expected_hit"],
            "actual_hit": actual_hit,
            "matched_rules": hit_ids,
            "passed": ok,
        })
    return {
        "total": len(_SIGMA_TEST_CASES),
        "passed": passed,
        "failed": len(_SIGMA_TEST_CASES) - passed,
        "pass_rate": round(passed / max(len(_SIGMA_TEST_CASES), 1), 4),
        "results": results,
    }


# ── 安全审计专用端点 ──

@router.get("/security/anomalies")
async def list_anomalies(
    session_id: str = Query(..., description="会话ID"),
    min_score: float = Query(0.5, description="最低异常分数"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """获取异常检测标记的事件"""
    events = await event_store.get_unreviewed_anomalies(
        session, session_id, min_score=min_score, limit=limit
    )
    return [
        {
            "id": evt.id,
            "event_type": evt.event_type,
            "severity": evt.severity,
            "message": evt.message[:200],
            "anomaly_score": evt.anomaly_score,
            "correlation_id": evt.correlation_id,
            "src_ip": evt.src_ip,
            "created_at": evt.created_at,
        }
        for evt in events
    ]

@router.get("/security/chains")
async def list_chains(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """获取攻击链关联结果"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=1440
    )
    chains = [
        {
            "chain_id": c.chain_id,
            "pattern_name": c.pattern_name,
            "confidence": c.confidence,
            "event_ids": [e["id"] for e in c.events],
            "events": [{"id": e["id"], "event_type": e.get("event_type")} for e in c.events],
            "src_ips": list(c.src_ips),
            "dst_ips": list(c.dst_ips),
            "time_span_minutes": c.time_span_minutes,
            "alert": c.alert,
        }
        for c in result.chains
    ]
    causal_graph = None
    try:
        from causal_chain.store import latest_graph
        from causal_chain.learn import annotate_chains
        g = await latest_graph(session)
        if g:
            causal_graph = {
                "id": g.get("id"),
                "ok": g.get("ok"),
                "directed": g.get("directed") or [],
                "agree_rate": g.get("agree_rate"),
                "n": g.get("n"),
            }
            chains = annotate_chains(chains, g, data=None)
    except Exception as e:
        logger.debug("[chains] causal annotate skipped: %s", e)
    return {
        "session_id": session_id,
        "causal_graph": causal_graph,
        "chains": chains,
        "temporal_groups": [
            {
                "src_ip": g["src_ip"],
                "event_count": g["count"],
                "types": g["types"],
                "start": g["start"],
                "end": g["end"],
            }
            for g in result.temporal_groups[:20]
        ],
        "total_events_analyzed": result.total_events_analyzed,
    }

@router.get("/security/events")
async def query_events(
    session_id: str = Query("", description="会话ID"),
    src_ip: str = Query("", description="源IP"),
    event_type: str = Query("", description="事件类型"),
    severity: str = Query("", description="严重度"),
    limit: int = Query(100, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询完整原始事件（EventStore 溯源）"""
    events = await event_store.query(
        session, EventFilter(
            session_id=session_id,
            src_ip=src_ip,
            event_type=event_type,
            severity=severity,
            limit=limit,
        )
    )
    return [
        {
            "id": evt.id,
            "event_type": evt.event_type,
            "severity": evt.severity,
            "src_ip": evt.src_ip,
            "dst_ip": evt.dst_ip,
            "message": evt.message,
            "anomaly_score": evt.anomaly_score,
            "correlation_id": evt.correlation_id,
            "created_at": evt.created_at,
        }
        for evt in events
    ]

@router.get("/security/events/{event_id}")
async def get_event_detail(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取单条事件的完整原始数据"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")
    return {
        "id": evt.id,
        "session_id": evt.session_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "src_ip": evt.src_ip,
        "dst_ip": evt.dst_ip,
        "message": evt.message,
        "raw_data": evt.raw_data,
        "anomaly_score": evt.anomaly_score,
        "correlation_id": evt.correlation_id,
        "created_at": evt.created_at,
    }

@router.post("/security/review")
async def trigger_agent_d_review(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """手动触发 Agent-D 审查（检查已审核事件中是否有遗漏）"""
    asyncio.create_task(_run_agent_d_review(session_id))
    return {"status": "agent_d_review_triggered", "session_id": session_id}

async def _run_agent_d_review(session_id: str):
    """后台运行 Agent-D 审查"""
    from agents import AgentD
    from models import async_session as db_session

    agent_d = AgentD()
    async with db_session() as session:
        try:
            result = await agent_d.process(session, "", session_id, {})
            logger.info(f"Agent-D review completed for {session_id}: {result.get('result', '')[:100]}")
        except Exception as e:
            logger.error(f"Agent-D review failed: {e}")
