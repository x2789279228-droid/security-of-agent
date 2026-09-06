"""因果攻击链 API:学习 / 图 / 干预查询。不改 Flink CEP 热路径。"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from auth import RequireRole, UserInfo, get_current_user
from config import settings
from models import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/causal", tags=["causal"])


class QueryRequest(BaseModel):
    x: str = Field(..., description="干预变量,如 PORT_SCAN")
    y: str = Field(..., description="结果变量,如 C2_BEACON")
    do: int = Field(0, ge=0, le=1)


@router.post("/learn")
async def causal_learn(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    from causal_chain.store import learn_and_save
    from audit_trail import log_action

    if not getattr(settings, "causal_enabled", True):
        return {"ok": False, "reason": "disabled"}
    result = await learn_and_save(
        session,
        hours=int(getattr(settings, "causal_lookback_hours", 48) or 48),
        bin_minutes=int(getattr(settings, "causal_bin_minutes", 30) or 30),
        min_windows=int(getattr(settings, "causal_min_windows", 40) or 40),
        alpha=float(getattr(settings, "causal_alpha", 0.05) or 0.05),
    )
    try:
        await log_action(
            session, actor=user.username, actor_role=user.role,
            action="causal.learn", target_type="causal_graph",
            target_id=str(result.get("graph_id") or ""),
            after={"ok": result.get("ok"), "n": result.get("n"),
                   "agree_rate": result.get("agree_rate")},
        )
    except Exception as e:
        logger.debug("[causal] audit skipped: %s", e)
    return {
        "ok": result.get("ok"),
        "reason": result.get("reason") or "",
        "graph_id": result.get("graph_id"),
        "n": result.get("n"),
        "names": result.get("names") or [],
        "directed": result.get("directed") or [],
        "edges": result.get("edges") or [],
        "agree_rate": result.get("agree_rate"),
        "candidates": result.get("candidates") or [],
        "ladder": 2,
    }


@router.get("/graph")
async def causal_graph(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    from causal_chain.store import latest_graph
    g = await latest_graph(session)
    if not g:
        return {"ok": False, "reason": "no_graph", "directed": [], "edges": []}
    return g


@router.post("/query")
async def causal_query(
    req: QueryRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """P(Y | do(X=x)) 后门估计。不可识别时 identifiable=false。"""
    from causal_chain.store import latest_graph
    from causal_chain.learn import query_do
    from models import SecurityEvent
    from sqlalchemy import select
    from datetime import datetime, timezone, timedelta
    from causal_chain.variables import events_to_matrix

    g = await latest_graph(session)
    if not g or not g.get("ok"):
        return {"identifiable": False, "reason": g.get("reason") if g else "no_graph",
                "x": req.x, "y": req.y, "do": req.do}
    hours = int(getattr(settings, "causal_lookback_hours", 48) or 48)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (await session.execute(
        select(SecurityEvent).where(SecurityEvent.created_at >= cutoff)
    )).scalars().all()
    mat = events_to_matrix(
        rows,
        bin_minutes=int(g.get("bin_minutes") or 30),
        min_windows=1,
    )
    data = mat["X"] if mat.get("ok") or mat.get("n", 0) else None
    names = mat.get("names") or g.get("names") or []
    if data is None or data.shape[0] == 0:
        return {"identifiable": False, "reason": "insufficient_data",
                "x": req.x, "y": req.y, "do": req.do}
    # 对齐学图时的列名
    graph_names = g.get("names") or names
    if list(names) != list(graph_names):
        # 用当前矩阵列做 do,图的 directed 仍用名字
        graph_names = names
    out = query_do(g, req.x, req.y, do_value=req.do, data=data, names=graph_names)
    out["asked_by"] = user.username
    return out


@router.get("/candidates")
async def causal_candidates(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    from causal_chain.store import latest_graph
    g = await latest_graph(session)
    return {"candidates": (g or {}).get("candidates") or []}
