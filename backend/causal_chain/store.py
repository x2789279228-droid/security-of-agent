"""因果图落库 / 读取最近一次学习结果。"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from causal_chain.learn import learn_from_events
from causal_chain.variables import DEFAULT_BIN_MINUTES, DEFAULT_MIN_WINDOWS


async def save_graph(session: AsyncSession, result: dict) -> dict:
    from models import CausalEdge, CausalGraph

    row = CausalGraph(
        algorithm="pc+ges",
        n_windows=int(result.get("n") or 0),
        bin_minutes=int(result.get("bin_minutes") or 30),
        names=list(result.get("names") or []),
        directed=[[a, b] for a, b in (result.get("directed") or [])],
        edges=list(result.get("edges") or []),
        pc=result.get("pc") or {},
        ges=result.get("ges") or {},
        agree_rate=float(result.get("agree_rate") or 0.0),
        reason=str(result.get("reason") or ""),
        ok=bool(result.get("ok")),
        candidates=list(result.get("candidates") or []),
        created_at=datetime.now(timezone.utc),
    )
    session.add(row)
    await session.flush()
    for e in result.get("edges") or []:
        session.add(CausalEdge(
            graph_id=row.id,
            cause=str(e.get("cause") or ""),
            effect=str(e.get("effect") or ""),
            confidence=str(e.get("confidence") or ""),
            ace=e.get("ace"),
            identifiable=bool(e.get("identifiable")),
            prior_violation=bool(e.get("prior_violation")),
        ))
    await session.commit()
    await session.refresh(row)
    return {"id": row.id, "n": row.n_windows, "ok": row.ok, "agree_rate": row.agree_rate}


async def latest_graph(session: AsyncSession) -> Optional[dict]:
    from models import CausalGraph

    stmt = select(CausalGraph).order_by(desc(CausalGraph.created_at)).limit(1)
    row = (await session.execute(stmt)).scalars().first()
    if not row:
        return None
    return {
        "id": row.id,
        "ok": bool(row.ok),
        "reason": row.reason or "",
        "n": row.n_windows,
        "bin_minutes": row.bin_minutes,
        "names": row.names or [],
        "directed": _coerce_directed(row.directed),
        "edges": row.edges or [],
        "pc": row.pc or {},
        "ges": row.ges or {},
        "agree_rate": row.agree_rate,
        "candidates": row.candidates or [],
        "created_at": row.created_at.isoformat() if row.created_at else "",
    }


def _coerce_directed(raw) -> list[tuple[str, str]]:
    out = []
    for e in raw or []:
        if isinstance(e, (list, tuple)) and len(e) == 2:
            out.append((str(e[0]), str(e[1])))
    return out


async def learn_and_save(
    session: AsyncSession,
    *,
    hours: int = 48,
    bin_minutes: int = DEFAULT_BIN_MINUTES,
    min_windows: int = DEFAULT_MIN_WINDOWS,
    alpha: float = 0.05,
) -> dict:
    from models import SecurityEvent
    from config import settings

    hours = int(hours or getattr(settings, "causal_lookback_hours", 48) or 48)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (await session.execute(
        select(SecurityEvent).where(SecurityEvent.created_at >= cutoff)
    )).scalars().all()
    result = learn_from_events(
        rows, bin_minutes=bin_minutes, min_windows=min_windows, alpha=alpha,
    )
    saved = await save_graph(session, result)
    result["graph_id"] = saved.get("id")
    return result
