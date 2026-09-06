"""Self-Play 对局 / 回合 / 学到的规则 持久化。"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def save_match_start(cfg: dict, match_id: str) -> None:
    from models import SelfPlayMatch, async_session
    async with async_session() as session:
        row = await _get_match(session, match_id)
        if row is None:
            row = SelfPlayMatch(
                match_id=match_id,
                status="running",
                mode=_mode(cfg),
                curriculum_level=int(cfg.get("start_level") or 0),
                total_rounds=int(cfg.get("rounds") or 0),
                completed_rounds=0,
                config=dict(cfg),
                metrics={},
                winner="",
                started_at=datetime.now(timezone.utc),
            )
            session.add(row)
        else:
            row.status = "running"
            row.config = dict(cfg)
            row.total_rounds = int(cfg.get("rounds") or row.total_rounds or 0)
            row.started_at = row.started_at or datetime.now(timezone.utc)
        await session.commit()


async def save_round(match_id: str, payload: dict) -> None:
    from models import SelfPlayMatch, SelfPlayRound, async_session
    async with async_session() as session:
        session.add(SelfPlayRound(
            match_id=match_id,
            round_num=int(payload.get("round_num") or 0),
            curriculum_level=int(payload.get("curriculum_level") or 0),
            red_plan=dict(payload.get("red_plan") or {}),
            events=list(payload.get("events") or []),
            blue_obs=list(payload.get("blue_obs") or []),
            outcome=str(payload.get("outcome") or ""),
            metrics=dict(payload.get("metrics") or {}),
            learned=list(payload.get("learned") or []),
        ))
        row = await _get_match(session, match_id)
        if row is not None:
            row.completed_rounds = int(payload.get("round_num") or 0)
            row.curriculum_level = int(payload.get("curriculum_level") or 0)
            row.metrics = payload.get("cumulative") or row.metrics or {}
            row.status = "running"
            row.updated_at = datetime.now(timezone.utc)
        await session.commit()


async def save_learned_rules(match_id: str, round_num: int, rules: list[dict]) -> None:
    if not rules:
        return
    from models import SelfPlayLearnedRule, async_session
    async with async_session() as session:
        for rule in rules:
            session.add(SelfPlayLearnedRule(
                rule_id=str(rule.get("rule_id") or ""),
                match_id=match_id,
                source_round=round_num,
                title=str(rule.get("title") or ""),
                attack_type=str(rule.get("attack_type") or ""),
                mitre_id=str(rule.get("mitre_id") or ""),
                severity=str(rule.get("severity") or "medium"),
                conditions=rule.get("conditions") or {},
                sigma_yaml=str(rule.get("sigma_yaml") or ""),
                status=str(rule.get("status") or "candidate"),
            ))
        await session.commit()


async def save_match_end(match_id: str, *, status: str, winner: str, metrics: dict) -> None:
    from models import SelfPlayMatch, async_session
    async with async_session() as session:
        row = await _get_match(session, match_id)
        if row is None:
            return
        row.status = status
        row.winner = winner
        row.metrics = metrics or {}
        row.finished_at = datetime.now(timezone.utc)
        row.updated_at = datetime.now(timezone.utc)
        await session.commit()


async def load_candidate_rules(limit: int = 200) -> list[dict]:
    from models import SelfPlayLearnedRule, async_session
    from sqlalchemy import select, desc
    async with async_session() as session:
        stmt = (
            select(SelfPlayLearnedRule)
            .where(SelfPlayLearnedRule.status.in_(("candidate", "overlay", "shadow", "promoted")))
            .order_by(desc(SelfPlayLearnedRule.id))
            .limit(limit)
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [_rule_row(r) for r in rows]


async def get_match(match_id: str) -> Optional[dict]:
    from models import SelfPlayMatch, SelfPlayRound, async_session
    from sqlalchemy import select
    async with async_session() as session:
        row = await _get_match(session, match_id)
        if row is None:
            return None
        rounds = (await session.execute(
            select(SelfPlayRound)
            .where(SelfPlayRound.match_id == match_id)
            .order_by(SelfPlayRound.round_num.asc())
        )).scalars().all()
        data = _match_row(row)
        data["rounds"] = [_round_row(r) for r in rounds]
        return data


async def list_matches(limit: int = 30) -> list[dict]:
    from models import SelfPlayMatch, async_session
    from sqlalchemy import select, desc
    async with async_session() as session:
        rows = (await session.execute(
            select(SelfPlayMatch).order_by(desc(SelfPlayMatch.id)).limit(limit)
        )).scalars().all()
        return [_match_row(r) for r in rows]


async def list_learned_rules(status: str = "", limit: int = 100) -> list[dict]:
    from models import SelfPlayLearnedRule, async_session
    from sqlalchemy import select, desc
    async with async_session() as session:
        stmt = select(SelfPlayLearnedRule).order_by(desc(SelfPlayLearnedRule.id)).limit(limit)
        if status:
            stmt = stmt.where(SelfPlayLearnedRule.status == status)
        rows = (await session.execute(stmt)).scalars().all()
        return [_rule_row(r) for r in rows]


async def get_learned_rule(rule_pk: int) -> Optional[dict]:
    from models import SelfPlayLearnedRule, async_session
    async with async_session() as session:
        row = await session.get(SelfPlayLearnedRule, rule_pk)
        return _rule_row(row) if row is not None else None


async def set_rule_status(
    rule_pk: int, status: str, *,
    sigma_yaml: str = "",
    review_report: Optional[dict] = None,
) -> Optional[dict]:
    from models import SelfPlayLearnedRule, async_session
    async with async_session() as session:
        row = await session.get(SelfPlayLearnedRule, rule_pk)
        if row is None:
            return None
        row.status = status
        if sigma_yaml:
            row.sigma_yaml = sigma_yaml
        if review_report is not None:
            if hasattr(row, "review_report"):
                row.review_report = dict(review_report)
            else:
                meta = dict(row.conditions or {})
                meta["_review"] = review_report
                row.conditions = meta
        await session.commit()
        await session.refresh(row)
        return _rule_row(row)


async def aggregate_metrics() -> dict:
    from models import SelfPlayMatch, async_session
    from sqlalchemy import select
    async with async_session() as session:
        rows = (await session.execute(select(SelfPlayMatch))).scalars().all()
    if not rows:
        return {"matches": 0}
    winners = {"red": 0, "blue": 0, "draw": 0}
    asr, rec, prec, nov, comp = [], [], [], [], []
    for r in rows:
        w = (r.winner or "draw")
        winners[w] = winners.get(w, 0) + 1
        m = r.metrics or {}
        if "asr" in m:
            asr.append(float(m.get("asr") or 0))
        if "recall" in m:
            rec.append(float(m.get("recall") or 0))
        if "precision" in m:
            prec.append(float(m.get("precision") or 0))
        if "novelty" in m:
            nov.append(float(m.get("novelty") or 0))
        if "compounding" in m:
            comp.append(float(m.get("compounding") or 0))
    avg = (lambda xs: sum(xs) / len(xs) if xs else 0.0)
    return {
        "matches": len(rows),
        "winners": winners,
        "avg_asr": avg(asr),
        "avg_recall": avg(rec),
        "avg_precision": avg(prec),
        "avg_novelty": avg(nov),
        "avg_compounding": avg(comp),
        "completed": sum(1 for r in rows if r.status == "completed"),
    }


def _mode(cfg: dict) -> str:
    if cfg.get("wait_audit"):
        return "full"
    if cfg.get("inject"):
        return "inject"
    return "sigma"


async def _get_match(session, match_id: str):
    from models import SelfPlayMatch
    from sqlalchemy import select
    return (await session.execute(
        select(SelfPlayMatch).where(SelfPlayMatch.match_id == match_id)
    )).scalar_one_or_none()


def _match_row(r: Any) -> dict:
    return {
        "id": r.id,
        "match_id": r.match_id,
        "status": r.status,
        "mode": r.mode,
        "curriculum_level": r.curriculum_level,
        "total_rounds": r.total_rounds,
        "completed_rounds": r.completed_rounds,
        "config": r.config or {},
        "metrics": r.metrics or {},
        "winner": r.winner or "",
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _round_row(r: Any) -> dict:
    return {
        "id": r.id,
        "match_id": r.match_id,
        "round_num": r.round_num,
        "curriculum_level": r.curriculum_level,
        "red_plan": r.red_plan or {},
        "events": r.events or [],
        "blue_obs": r.blue_obs or [],
        "outcome": r.outcome,
        "metrics": r.metrics or {},
        "learned": r.learned or [],
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _rule_row(r: Any) -> dict:
    return {
        "id": r.id,
        "rule_id": r.rule_id,
        "match_id": r.match_id,
        "source_round": r.source_round,
        "title": r.title,
        "attack_type": r.attack_type,
        "mitre_id": r.mitre_id,
        "severity": r.severity,
        "conditions": r.conditions or {},
        "sigma_yaml": r.sigma_yaml or "",
        "status": r.status,
        "review_report": getattr(r, "review_report", None) or (r.conditions or {}).get("_review") or {},
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
