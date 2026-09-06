"""红蓝自博弈 API — 开局 / 回放 / 指标 / 学到的规则。"""
from __future__ import annotations

import asyncio
import logging
import uuid

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth import RequireRole, UserInfo
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/self-play", tags=["self-play"])


class StartMatchRequest(BaseModel):
    rounds: int = Field(8, ge=1, le=50)
    curriculum: bool = True
    start_level: int = Field(0, ge=0, le=6)
    inject: bool = False
    wait_audit: bool = False
    use_llm: bool | None = None
    decoy_ratio: float = Field(0.2, ge=0.0, le=1.0)
    persist_kb: bool = False
    diverse_env: bool = False
    background_traffic: bool = False
    eval_channel: str = "sim"


def _cfg_from_req(req: StartMatchRequest, match_id: str) -> dict:
    use_llm = bool(settings.self_play_use_llm) if req.use_llm is None else bool(req.use_llm)
    return {
        "match_id": match_id,
        "rounds": req.rounds,
        "curriculum": req.curriculum,
        "start_level": req.start_level,
        "inject": req.inject if req.inject else bool(settings.self_play_inject),
        "wait_audit": req.wait_audit if req.wait_audit else bool(settings.self_play_wait_audit),
        "wait_audit_s": float(settings.self_play_wait_audit_s),
        "use_llm": use_llm,
        "decoy_ratio": req.decoy_ratio,
        "persist": True,
        "persist_kb": req.persist_kb,
        "diverse_env": bool(req.diverse_env) or bool(getattr(settings, "self_play_diverse_env", False)),
        "background_traffic": bool(req.background_traffic) or bool(getattr(settings, "self_play_background_traffic", False)),
        "eval_channel": str(req.eval_channel or "sim"),
    }


@router.get("/catalog")
async def get_catalog():
    from self_play.catalog import catalog_overview
    from self_play.sim_env import topology
    overview = catalog_overview()
    return {
        **overview,
        "ttps": overview.get("curriculum") or [],
        "topology": topology(),
    }


@router.get("/matches")
async def list_matches():
    from self_play.orchestrator import live_matches
    from self_play import store
    live = {m["match_id"]: m for m in live_matches()}
    try:
        rows = await store.list_matches(limit=40)
    except Exception as e:
        logger.info("list matches db skipped: %s", e)
        rows = []
    out = []
    seen = set()
    for m in list(live.values()) + rows:
        mid = m.get("match_id")
        if not mid or mid in seen:
            continue
        seen.add(mid)
        if mid in live:
            merged = dict(m)
            merged.update(live[mid])
            out.append(merged)
        else:
            out.append(m)
    return {"matches": out}


@router.get("/matches/{match_id}")
async def get_match(match_id: str):
    from self_play.orchestrator import live_match
    live = live_match(match_id)
    try:
        from self_play import store
        stored = await store.get_match(match_id)
    except Exception:
        stored = None
    if live is None and stored is None:
        raise HTTPException(404, "对局不存在")
    data = dict(stored or {})
    if live:
        data.update(live)
        if live.get("rounds") and not data.get("rounds"):
            data["rounds"] = live["rounds"]
        if live.get("last_round"):
            data["last_round"] = live["last_round"]
    return data


@router.post("/matches")
async def start_match(
    req: StartMatchRequest,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    if not settings.self_play_enabled:
        raise HTTPException(403, "自博弈未启用")
    from self_play.orchestrator import live_matches
    running = [m for m in live_matches() if m.get("status") in ("running", "stopping")]
    if len(running) >= int(settings.self_play_max_inflight or 1):
        raise HTTPException(409, "已有对局在进行,请等待结束或先停止")

    match_id = f"sp-{uuid.uuid4().hex[:12]}"
    cfg = _cfg_from_req(req, match_id)

    try:
        from self_play import store
        await store.save_match_start(cfg, match_id)
    except Exception as e:
        logger.info("self-play pre-persist skipped: %s", e)

    started = False
    if settings.temporal_enabled:
        try:
            from temporal.client import start_selfplay_workflow
            started = bool(await start_selfplay_workflow(cfg))
        except Exception as e:
            logger.warning("self-play temporal start failed: %s", e)
            started = False

    if not started:
        from self_play.orchestrator import orchestrator
        from self_play.types import MatchConfig

        async def _run():
            try:
                await orchestrator.run_match(MatchConfig.from_dict(cfg))
            except Exception:
                logger.exception("self-play async match failed")

        asyncio.create_task(_run())

    return {
        "match_id": match_id,
        "status": "running",
        "via": "temporal" if started else "async",
        "config": cfg,
        "started_by": user.username,
    }


@router.post("/matches/{match_id}/stop")
async def stop_match(
    match_id: str,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    from self_play.orchestrator import request_stop, live_match
    request_stop(match_id)
    return {"match_id": match_id, "status": "stopping", "stopped_by": user.username, "live": live_match(match_id)}


@router.get("/metrics")
async def metrics():
    from self_play import store
    try:
        return await store.aggregate_metrics()
    except Exception as e:
        return {"matches": 0, "error": str(e)}


@router.get("/learned-rules")
async def learned_rules(status: str = ""):
    from self_play import store
    try:
        return {"rules": await store.list_learned_rules(status=status, limit=200)}
    except Exception as e:
        return {"rules": [], "error": str(e)}


class RuleStatusBody(BaseModel):
    status: str = "shadow"
    reason: str = ""


@router.post("/learned-rules/{rule_pk}/status")
async def set_learned_rule_status(
    rule_pk: int,
    body: RuleStatusBody,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    allowed = {"candidate", "shadow", "promoted", "dismissed"}
    if body.status not in allowed:
        raise HTTPException(400, f"status 必须是 {sorted(allowed)}")
    from self_play import store
    from self_play.reviewer import apply_review
    row = await store.get_learned_rule(rule_pk)
    if row is None:
        raise HTTPException(404, "规则不存在")
    applied = await apply_review(
        row,
        {
            "decision": body.status,
            "gates": [],
            "failed": [],
            "actor": user.username,
            "forced": True,
            "reason": body.reason or f"manual:{body.status}",
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        },
        force=True,
        actor=user.username,
    )
    return {"ok": True, "rule": applied.get("rule"), "updated_by": user.username, "yaml_path": applied.get("yaml_path")}


@router.post("/review/run")
async def run_review(
    limit: int = 20,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    if not settings.self_play_review_enabled:
        raise HTTPException(403, "审核 Agent 未启用")
    from self_play.reviewer import drain
    result = await drain(limit=max(1, min(int(limit or 20), 100)))
    result["started_by"] = user.username
    return result
