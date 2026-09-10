"""Persist / query ContainmentRecord. Fail-open: DB errors never raise to callers."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .types import STATUS_APPLIED

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def insert_record(
    session: Optional[AsyncSession],
    *,
    action_name: str,
    target_type: str = "",
    target_id: str = "",
    host_ip: str = "",
    families: Optional[list] = None,
    rule_ids: Optional[list] = None,
    backend: str = "",
    status: str = STATUS_APPLIED,
    snapshot_id: str = "",
    payload: Optional[dict] = None,
    rollback_token: str = "",
    expires_at: Optional[datetime] = None,
) -> Optional[dict]:
    if session is None:
        return None
    try:
        from models import ContainmentRecord

        row = ContainmentRecord(
            action_name=action_name,
            target_type=target_type or "",
            target_id=str(target_id or "")[:500],
            host_ip=host_ip or "",
            families=list(families or []),
            rule_ids=list(rule_ids or []),
            backend=backend or "",
            status=status,
            snapshot_id=snapshot_id or "",
            payload=dict(payload or {}),
            rollback_token=rollback_token or "",
            expires_at=expires_at,
            created_at=_utcnow(),
        )
        session.add(row)
        await session.flush()
        return {"id": row.id, "status": row.status, "action_name": row.action_name}
    except Exception as e:
        logger.warning("containment insert failed: %s", e)
        return None


async def mark_rolled_back(
    session: Optional[AsyncSession],
    *,
    record_id: Optional[int] = None,
    rollback_token: str = "",
    target_id: str = "",
    action_name: str = "",
) -> int:
    if session is None:
        return 0
    try:
        from models import ContainmentRecord
        from .types import STATUS_ROLLED_BACK

        stmt = select(ContainmentRecord)
        if record_id:
            stmt = stmt.where(ContainmentRecord.id == int(record_id))
        elif rollback_token:
            stmt = stmt.where(ContainmentRecord.rollback_token == rollback_token)
        elif target_id:
            stmt = stmt.where(ContainmentRecord.target_id == target_id)
            if action_name:
                stmt = stmt.where(ContainmentRecord.action_name == action_name)
        else:
            return 0
        rows = (await session.execute(stmt)).scalars().all()
        n = 0
        for row in rows:
            if row.status == STATUS_ROLLED_BACK:
                continue
            row.status = STATUS_ROLLED_BACK
            n += 1
        if n:
            await session.flush()
        return n
    except Exception as e:
        logger.warning("containment mark_rolled_back failed: %s", e)
        return 0


async def list_records(
    session: AsyncSession,
    *,
    status: str = "",
    action_name: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    from models import ContainmentRecord

    stmt = select(ContainmentRecord).order_by(ContainmentRecord.id.desc()).limit(int(limit))
    if status:
        stmt = stmt.where(ContainmentRecord.status == status)
    if action_name:
        stmt = stmt.where(ContainmentRecord.action_name == action_name)
    rows = (await session.execute(stmt)).scalars().all()
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "action_name": r.action_name,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "host_ip": r.host_ip,
            "families": list(r.families or []),
            "rule_ids": list(r.rule_ids or []),
            "backend": r.backend,
            "status": r.status,
            "snapshot_id": r.snapshot_id,
            "payload": dict(r.payload or {}),
            "rollback_token": r.rollback_token,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return out
