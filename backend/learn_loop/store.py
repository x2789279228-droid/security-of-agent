"""
learn_loop.store — LearningRun / LearningAction 的 CRUD 助手

insert_run / finish_run / insert_actions / list_recent_action_keys /
get_run_with_actions。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def insert_run(
    session: AsyncSession, *,
    window_start=None, window_end=None, trigger: str = "daily",
) -> int:
    """新建 learning_runs 行, 返回 run_id。"""
    from models import LearningRun

    run = LearningRun(
        window_start=window_start,
        window_end=window_end,
        trigger=str(trigger or "daily")[:20],
        status="running",
        harvest={},
        model_summary={},
    )
    session.add(run)
    await session.flush()
    return run.id


async def finish_run(
    session: AsyncSession, run_id: int, *,
    status: str = "completed",
    harvest: dict = None,
    model_summary: dict = None,
    actions_proposed: int = 0,
    actions_auto_applied: int = 0,
    actions_failed: int = 0,
    error: str = "",
) -> None:
    """收口 learning_runs 行(running → completed|failed)。"""
    from models import LearningRun

    run = await session.get(LearningRun, run_id)
    if run is None:
        return
    run.status = "completed" if status == "completed" else "failed"
    if harvest is not None:
        run.harvest = harvest
    if model_summary is not None:
        run.model_summary = model_summary
    run.actions_proposed = int(actions_proposed or 0)
    run.actions_auto_applied = int(actions_auto_applied or 0)
    run.actions_failed = int(actions_failed or 0)
    run.error = str(error or "")[:2000]
    await session.commit()


async def insert_actions(session: AsyncSession, run_id: int, actions: list[dict]) -> int:
    """把 propose 出的动作批量落库(返回行数)。"""
    from models import LearningAction

    rows = []
    for act in actions or []:
        if not isinstance(act, dict):
            continue
        row = LearningAction(
            run_id=run_id,
            action_type=str(act.get("action_type") or "")[:40],
            target_type=str(act.get("target_type") or "")[:30],
            target_id=str(act.get("target_id") or "")[:120],
            mechanism=str(act.get("mechanism") or "")[:20],
            payload=dict(act.get("payload") or {}),
            confidence=float(act.get("confidence") or 0.0),
            status="proposed",
            apply_result={},
        )
        session.add(row)
        rows.append(row)
    if rows:
        await session.commit()
    return len(rows)


async def list_recent_action_keys(session: AsyncSession, hours: int = 24) -> set:
    """近 hours 小时已提议动作的去重键集合 {"action_type:target_id"}。"""
    from models import LearningAction

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours or 24)))
    rows = (await session.execute(
        select(LearningAction.action_type, LearningAction.target_id)
        .where(LearningAction.created_at >= cutoff)
    )).all()
    keys = set()
    for action_type, target_id in rows:
        if action_type:
            keys.add(f"{action_type}:{target_id or ''}")
    return keys


async def get_run_with_actions(session: AsyncSession, run_id: int) -> dict:
    """读取一次运行及其动作列表(摘要形态)。"""
    from models import LearningAction, LearningRun

    run = await session.get(LearningRun, run_id)
    if run is None:
        return {}
    actions = (await session.execute(
        select(LearningAction)
        .where(LearningAction.run_id == run_id)
        .order_by(LearningAction.created_at)
    )).scalars().all()
    return {
        "id": run.id,
        "window_start": run.window_start.isoformat() if run.window_start else "",
        "window_end": run.window_end.isoformat() if run.window_end else "",
        "trigger": run.trigger,
        "status": run.status,
        "actions_proposed": run.actions_proposed,
        "actions_auto_applied": run.actions_auto_applied,
        "actions_failed": run.actions_failed,
        "error": run.error or "",
        "created_at": run.created_at.isoformat() if run.created_at else "",
        "harvest": run.harvest or {},
        "model_summary": run.model_summary or {},
        "actions": [
            {
                "id": a.id,
                "action_type": a.action_type,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "mechanism": a.mechanism,
                "confidence": a.confidence,
                "status": a.status,
                "apply_result": a.apply_result or {},
                "created_at": a.created_at.isoformat() if a.created_at else "",
            }
            for a in actions
        ],
    }
