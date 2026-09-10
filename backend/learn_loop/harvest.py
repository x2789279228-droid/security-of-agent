"""
learn_loop.harvest — 收割窗口内的闭环证据

七大既有非对抗机制(基线/信誉/反馈/降级/调优/复盘/案例)在 [window_start, window_end)
窗口内的证据汇总。所有子查询都带时间窗口 + limit, 禁止无界 SELECT *。

返回 dict 必须 JSON 可序列化; 任一子项失败 → 该键 = {"error": str(e), "count": 0},
不影响其它键(单键 fail-open, 由 orchestrator 决定整体状态)。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from config import settings

logger = logging.getLogger(__name__)

_FEEDBACK_LIMIT = 500          # 收割反馈记录上限
_POSTMORTEM_LIMIT = 100        # 收割已发布复盘上限
_IP_COUNT_LIMIT = 100          # 收割信誉 IP 明细上限
_JOIN_FEEDBACK_LIMIT = 2000    # feedback↔event 联表扫描上限
_SHADOW_RULE_LIMIT = 20        # shadow 规则列表上限


def _iso(dt) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt)


def _events_limit() -> int:
    return int(getattr(settings, "learn_loop_harvest_events_limit", 5000) or 5000)


def _cases_limit() -> int:
    return int(getattr(settings, "learn_loop_harvest_cases_limit", 500) or 500)


# ═══════════════════════════════════════════
# 各机制收割子函数 (带窗口 + limit)
# ═══════════════════════════════════════════

async def _harvest_baseline(session, ws, we) -> dict:
    """基线快照收割: 窗口内新增快照计数 + 少量最新快照。"""
    from sqlalchemy import select, func
    from models import BaselineSnapshot

    row = await session.execute(
        select(BaselineSnapshot.entity_type, func.count(BaselineSnapshot.id))
        .where(BaselineSnapshot.created_at >= ws, BaselineSnapshot.created_at < we)
        .group_by(BaselineSnapshot.entity_type)
    )
    by_type = {t: int(c) for t, c in row.all()}
    latest = (await session.execute(
        select(BaselineSnapshot)
        .where(BaselineSnapshot.created_at >= ws, BaselineSnapshot.created_at < we)
        .order_by(BaselineSnapshot.created_at.desc())
        .limit(5)
    )).scalars().all()
    return {
        "count": sum(by_type.values()),
        "by_type": by_type,
        "latest": [
            {
                "entity_type": r.entity_type,
                "entity_key": r.entity_key,
                "total_count": int((r.snapshot or {}).get("total_count", 0)),
                "created_at": _iso(r.created_at),
            }
            for r in latest
        ],
    }


async def _harvest_reputation(session, ws, we) -> dict:
    """信誉收割: feedback 驱动的 (ip → tp/fp) 计数 + 带情报富化的事件样本。"""
    from sqlalchemy import select
    from models import FeedbackRecord, SecurityEvent

    # 1) FP/TP 反馈 → 关联事件 src_ip 计数(供信誉先验 / 基线衰减)
    stmt = (
        select(SecurityEvent.src_ip, FeedbackRecord.feedback_type)
        .join(SecurityEvent, FeedbackRecord.event_id == SecurityEvent.id)
        .where(
            FeedbackRecord.created_at >= ws,
            FeedbackRecord.created_at < we,
            FeedbackRecord.feedback_type.in_(("false_positive", "true_positive")),
        )
        .limit(_JOIN_FEEDBACK_LIMIT)
    )
    ip_counts: dict[str, dict] = {}
    for src_ip, ftype in (await session.execute(stmt)).all():
        if not src_ip:
            continue
        bucket = ip_counts.setdefault(str(src_ip), {"tp": 0, "fp": 0})
        bucket["tp" if ftype == "true_positive" else "fp"] += 1

    # 2) 窗口内带信誉富化(_sourceReputation / threat_intel)的事件(有界扫描)
    events = (await session.execute(
        select(SecurityEvent)
        .where(SecurityEvent.created_at >= ws, SecurityEvent.created_at < we)
        .order_by(SecurityEvent.created_at.desc())
        .limit(_events_limit())
    )).scalars().all()

    scanned = len(events)
    with_rep = 0
    ip_scores: dict[str, float] = {}
    for evt in events:
        raw = evt.raw_data or {}
        ti = raw.get("threat_intel")
        if not ti and raw.get("_sourceReputation") is not None:
            ti = {"_source": raw.get("_sourceReputation")}
        if not ti:
            continue
        with_rep += 1
        for ip in (evt.src_ip, evt.dst_ip):
            if not ip or ip in ip_scores:
                continue
            score = None
            if isinstance(ti, dict):
                for k in ("src_ip_reputation", "dst_ip_reputation"):
                    rep = ti.get(k)
                    if isinstance(rep, dict) and rep.get("score") is not None:
                        score = max(score or 0.0, float(rep["score"]))
            ip_scores[str(ip)] = score if score is not None else 0.0

    return {
        "count": with_rep,
        "events_scanned": scanned,
        "with_reputation": with_rep,
        "ips": [
            {"ip": ip, "score": round(score, 3)}
            for ip, score in list(ip_scores.items())[:_IP_COUNT_LIMIT]
        ],
        "ip_counts": ip_counts,
    }


async def _harvest_feedback(session, ws, we) -> dict:
    """反馈收割: 窗口内 FeedbackRecord 列表(有界)。"""
    from sqlalchemy import select
    from models import FeedbackRecord

    rows = (await session.execute(
        select(FeedbackRecord)
        .where(FeedbackRecord.created_at >= ws, FeedbackRecord.created_at < we)
        .order_by(FeedbackRecord.created_at.desc())
        .limit(_FEEDBACK_LIMIT)
    )).scalars().all()
    return {
        "count": len(rows),
        "records": [
            {
                "id": r.id,
                "feedback_type": r.feedback_type,
                "rule_id": r.rule_id or "",
                "status": r.status or "",
                "event_id": r.event_id,
                "case_id": r.case_id,
                "original_conclusion": r.original_conclusion or "",
                "operator_conclusion": r.operator_conclusion or "",
                "reason": (r.reason or "")[:300],
                "rule_suggestion": (r.rule_suggestion or "")[:300],
                "submitted_by": r.submitted_by or "",
                "created_at": _iso(r.created_at),
            }
            for r in rows
        ],
    }


async def _harvest_degrade(session, ws, we) -> dict:
    """降级收割: degraded 轨迹计数 + 现存 shadow 规则 + LLM fallback 事件样本。"""
    from sqlalchemy import select, func
    from models import AgentTrace, SecurityEvent

    cnt = (await session.execute(
        select(func.count(AgentTrace.id))
        .where(
            AgentTrace.status == "degraded",
            AgentTrace.created_at >= ws,
            AgentTrace.created_at < we,
        )
    )).scalar() or 0

    # sigma 规则当前是否已有 shadow(仅 pySigma 档可读 YAML)
    shadow_rules = []
    try:
        from sigma_engine import store as sigma_store
        for r in sigma_store.list_rules()[:_SHADOW_RULE_LIMIT]:
            if r.get("shadow_mode"):
                shadow_rules.append({
                    "rule_id": r.get("rule_id", ""),
                    "name": r.get("name", ""),
                })
    except Exception as e:
        logger.debug("[learn_loop.harvest] shadow rules scan skipped: %s", e)

    # 窗口内 LLM 审计回退事件(有界扫描 raw_data._audit_llm.fallback)
    fallback_events = []
    fallback_count = 0
    rows = (await session.execute(
        select(SecurityEvent)
        .where(SecurityEvent.created_at >= ws, SecurityEvent.created_at < we)
        .order_by(SecurityEvent.created_at.desc())
        .limit(_events_limit())
    )).scalars().all()
    for evt in rows:
        audit = (evt.raw_data or {}).get("_audit_llm") or {}
        if not isinstance(audit, dict) or not audit.get("fallback"):
            continue
        fallback_count += 1
        if len(fallback_events) < 20:
            fallback_events.append({
                "id": evt.id,
                "event_type": evt.event_type,
                "status": evt.status,
            })

    return {
        "count": cnt,
        "shadow_rules": shadow_rules,
        "llm_fallback_count": fallback_count,
        "llm_fallback_events": fallback_events,
    }


async def _harvest_tune(session, ws, we) -> dict:
    """调优收割: 复用 feedback_loop 的建议生成(失败返回空表, 不阻断)。"""
    from feedback_loop import feedback_loop

    suggestions = await feedback_loop.generate_tuning_suggestions(session)
    return {"count": len(suggestions), "suggestions": suggestions}


async def _harvest_postmortem(session, ws, we) -> dict:
    """复盘收割: 已发布复盘 + 已关闭但缺复盘的案例。"""
    from sqlalchemy import select, exists
    from models import PostMortem, SecurityCase

    pms = (await session.execute(
        select(PostMortem)
        .where(
            PostMortem.status == "published",
            PostMortem.updated_at >= ws,
            PostMortem.updated_at < we,
        )
        .order_by(PostMortem.updated_at.desc())
        .limit(_POSTMORTEM_LIMIT)
    )).scalars().all()

    pending_items = []
    for pm in pms:
        for item in (pm.action_items or []):
            if isinstance(item, dict) and not item.get("done"):
                pending_items.append({
                    "item": str(item.get("item", ""))[:200],
                    "owner": str(item.get("owner", "")),
                    "deadline": str(item.get("deadline", ""))[:40],
                })

    pm_exists = exists().where(PostMortem.case_id == SecurityCase.id)
    closed_rows = (await session.execute(
        select(SecurityCase)
        .where(
            SecurityCase.status.in_(["closed", "false_positive"]),
            SecurityCase.updated_at >= ws,
            SecurityCase.updated_at < we,
            ~pm_exists,
        )
        .order_by(SecurityCase.updated_at.desc())
        .limit(_cases_limit())
    )).scalars().all()

    return {
        "count": len(pms),
        "published": [
            {
                "id": pm.id,
                "case_id": pm.case_id,
                "title": pm.title or "",
                "pending_action_items": pending_items,
            }
            for pm in pms
        ],
        "closed_without_pm": [
            {
                "id": c.id,
                "case_number": c.case_number or "",
                "status": c.status,
                "updated_at": _iso(c.updated_at),
            }
            for c in closed_rows
        ],
    }


async def _harvest_case(session, ws, we) -> dict:
    """案例收割: 窗口内 closed/false_positive 案例(序列/复盘证据源)。"""
    from sqlalchemy import select
    from models import SecurityCase

    rows = (await session.execute(
        select(SecurityCase)
        .where(
            SecurityCase.status.in_(["closed", "false_positive"]),
            SecurityCase.updated_at >= ws,
            SecurityCase.updated_at < we,
        )
        .order_by(SecurityCase.updated_at.desc())
        .limit(_cases_limit())
    )).scalars().all()
    return {
        "count": len(rows),
        "cases": [
            {
                "id": c.id,
                "case_number": c.case_number or "",
                "status": c.status,
                "threat_type": c.threat_type or "",
                "priority": c.priority or "medium",
                "src_ips": list(c.src_ips or []),
                "dst_ips": list(c.dst_ips or []),
                "event_ids": [int(i) for i in (c.event_ids or [])],
                "disposition": (c.disposition or "")[:300],
                "created_at": _iso(c.created_at),
                "updated_at": _iso(c.updated_at),
            }
            for c in rows
        ],
    }


# ═══════════════════════════════════════════
# 主入口: 单键 fail-open
# ═══════════════════════════════════════════

async def harvest(session, window_start: datetime, window_end: datetime) -> dict:
    """收割 [window_start, window_end) 内七类机制证据。

    任一子收割抛错 → 该键 {"error": ..., "count": 0}, 其余键不受影响。
    """
    ws = window_start
    we = window_end
    tasks = {
        "baseline": _harvest_baseline,
        "reputation": _harvest_reputation,
        "feedback": _harvest_feedback,
        "degrade": _harvest_degrade,
        "tune": _harvest_tune,
        "postmortem": _harvest_postmortem,
        "case": _harvest_case,
    }
    out: dict = {}
    for key, fn in tasks.items():
        try:
            out[key] = await fn(session, ws, we)
        except Exception as e:
            logger.warning("[learn_loop.harvest] %s failed: %s", key, e)
            out[key] = {"error": str(e), "count": 0}
    return out


def harvest_summary(harvest_data: dict) -> dict:
    """把收割结果压成小计数表(用于 event_bus / run 摘要)。"""
    summary: dict = {}
    for key, val in (harvest_data or {}).items():
        if not isinstance(val, dict):
            summary[key] = 0
            continue
        if "error" in val:
            summary[key] = {"error": str(val["error"])[:120], "count": int(val.get("count") or 0)}
            continue
        count = val.get("count", 0)
        summary[key] = count
    return summary
