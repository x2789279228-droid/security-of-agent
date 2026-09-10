"""
learn_loop.orchestrator — 每日学习闭环主循环

run_cycle(session, trigger=daily) 流程:
  1. insert LearningRun(running)
  2. harvest(窗口证据, 单键 fail-open)
  3. stats(analyze_feedback + 可选 fp_stats)
  4. clusters(FP/漏报事件贪心聚类; hourly 跳过)
  5. sequences(案例有序事件类型一阶转移; hourly 跳过)
  6. existing_keys(近 24h 去重键)
  7. actions = propose(...)
  8. insert_actions
  9. learn_loop_auto_apply → 白名单动作自动落地(auto_applied), 失败只计数
  10. hourly: 跳过 4/5 省 DB
  11. event_bus.publish("pipeline_health", ...) — 同步调用(同 scheduler._fp_analytics_loop)
  12. finish_run(completed|failed)

Fail-open: run_cycle 对调度器绝不抛异常; 收割/统计/聚类/序列/提议的局部异常
记为 partial(仍 completed), 只有写库级硬失败才置 failed。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from config import settings
from learn_loop.types import AUTO_APPLY_TYPES

logger = logging.getLogger(__name__)


def _aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt) -> str:
    dt = _aware(dt)
    return dt.isoformat() if dt else ""


def _settings_int(name: str, default: int) -> int:
    try:
        return int(getattr(settings, name, default) or default)
    except (TypeError, ValueError):
        return default


def _settings_float(name: str, default: float) -> float:
    try:
        return float(getattr(settings, name, default) or default)
    except (TypeError, ValueError):
        return default


def _settings_bool(name: str, default: bool) -> bool:
    try:
        return bool(getattr(settings, name, default))
    except Exception:
        return default


# ═══════════════════════════════════════════
# 分析步骤(各自 try/except 吸收局部失败)
# ═══════════════════════════════════════════

async def _step_stats(session, harvest_data: dict) -> dict:
    """反馈误报率统计 + 可选 fp_stats(失败 → 空表)。"""
    from learn_loop.models_stats import analyze_feedback

    records = (harvest_data.get("feedback") or {}).get("records") or []
    stats = analyze_feedback(records)
    try:
        from feedback_loop import feedback_loop
        stats["fp_stats"] = await feedback_loop.get_fp_statistics(session)
    except Exception as e:
        logger.debug("[learn_loop] fp_stats skipped: %s", e)
        stats["fp_stats"] = {}
    return stats


async def _step_clusters(session, harvest_data: dict, trigger: str) -> list:
    """FP/漏报反馈事件 → 聚类(hourly 跳过)。"""
    if trigger == "hourly":
        return []
    from learn_loop.models_cluster import build_clusters

    feedback = harvest_data.get("feedback") or {}
    if feedback.get("error"):
        return []
    rule_by_event = {}
    want_ids = []
    for rec in feedback.get("records") or []:
        if not isinstance(rec, dict):
            continue
        if rec.get("feedback_type") not in ("false_positive", "missed_threat"):
            continue
        eid = rec.get("event_id")
        if not eid:
            continue
        if eid not in rule_by_event:
            rule_by_event[eid] = rec.get("rule_id", "")
        want_ids.append(eid)
    if not want_ids:
        return []
    want_ids = sorted({int(i) for i in want_ids})
    want_ids = want_ids[:_settings_int("learn_loop_harvest_events_limit", 5000)]

    from sqlalchemy import select
    from models import SecurityEvent
    events = (await session.execute(
        select(SecurityEvent).where(SecurityEvent.id.in_(want_ids))
    )).scalars().all()
    evt_dicts = [
        {
            "id": evt.id,
            "event_type": evt.event_type,
            "src_ip": evt.src_ip or "",
            "message": evt.message or "",
            "rule_id": rule_by_event.get(evt.id, ""),
        }
        for evt in events
    ]
    return build_clusters(
        evt_dicts,
        min_size=_settings_int("learn_loop_cluster_min_size", 3),
        threshold=_settings_float("learn_loop_jaccard", 0.5),
    )


async def _step_sequences(session, harvest_data: dict, trigger: str) -> dict:
    """案例内有序事件类型 → 一阶转移(hourly 跳过)。"""
    from learn_loop.models_sequence import build_sequences

    if trigger == "hourly":
        return {"sequences_count": 0, "transitions": {}, "signatures": []}

    cases = (harvest_data.get("case") or {}).get("cases") or []
    want_ids = []
    for c in cases:
        want_ids.extend(int(i) for i in (c.get("event_ids") or []))
    if not want_ids:
        return {"sequences_count": 0, "transitions": {}, "signatures": []}
    want_ids = sorted(set(want_ids))
    want_ids = want_ids[:_settings_int("learn_loop_harvest_events_limit", 5000)]

    from sqlalchemy import select
    from models import SecurityEvent
    events = (await session.execute(
        select(SecurityEvent).where(SecurityEvent.id.in_(want_ids))
    )).scalars().all()

    by_case: dict = {}
    for evt in events:
        if evt.case_id is None:
            continue
        by_case.setdefault(evt.case_id, []).append(evt)
    seq_lists = []
    for cid, evts in by_case.items():
        evts.sort(key=lambda e: e.created_at or datetime.min.replace(tzinfo=timezone.utc))
        seq_lists.append([e.event_type for e in evts])
    return build_sequences(seq_lists)


# ═══════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════

async def run_cycle(
    session,
    *,
    trigger: str = "daily",
    window_start: datetime = None,
    window_end: datetime = None,
) -> dict:
    """执行一轮学习闭环。绝不向上抛出(调度器安全)。"""
    from learn_loop.harvest import harvest, harvest_summary

    try:
        if not _settings_bool("learn_loop_enabled", True):
            return {"skipped": True}
    except Exception:
        return {"skipped": True}

    now = datetime.now(timezone.utc)
    lookback_h = _settings_int("learn_loop_lookback_hours", 24)
    ws = _aware(window_start) or (now - timedelta(hours=lookback_h))
    we = _aware(window_end) or now
    if ws >= we:
        ws = we - timedelta(hours=lookback_h)

    run_id = None
    harvest_data: dict = {}
    stats: dict = {}
    clusters: list = []
    sequences: dict = {}
    actions: list = []
    partial_errors: list[str] = []

    # ── 1. 建 run ──
    try:
        from learn_loop.store import insert_run
        run_id = await insert_run(session, window_start=ws, window_end=we, trigger=trigger)
    except Exception as e:
        logger.warning("[learn_loop] insert_run failed: %s", e)
        return {
            "id": None, "status": "failed", "trigger": trigger,
            "window_start": _iso(ws), "window_end": _iso(we),
            "error": f"insert_run_failed:{e}",
            "actions_proposed": 0, "actions_auto_applied": 0, "actions_failed": 0,
        }

    # ── 2. 收割 ──
    try:
        harvest_data = await harvest(session, ws, we)
    except Exception as e:
        partial_errors.append(f"harvest:{e}")
        harvest_data = {k: {"error": "harvest_aborted", "count": 0}
                        for k in ("baseline", "reputation", "feedback",
                                  "degrade", "tune", "postmortem", "case")}

    # ── 3. 统计 ──
    try:
        stats = await _step_stats(session, harvest_data)
    except Exception as e:
        partial_errors.append(f"stats:{e}")
        stats = {}

    # ── 4/5. 聚类 / 序列 ──
    try:
        clusters = await _step_clusters(session, harvest_data, trigger)
    except Exception as e:
        partial_errors.append(f"clusters:{e}")
        clusters = []
    try:
        sequences = await _step_sequences(session, harvest_data, trigger)
    except Exception as e:
        partial_errors.append(f"sequences:{e}")
        sequences = {}

    actions_proposed = 0
    actions_auto_applied = 0
    actions_failed = 0

    # ── 6-8. 去重 + 提议 + 落库 ──
    try:
        from learn_loop.store import insert_actions, list_recent_action_keys
        existing_keys = await list_recent_action_keys(session, hours=24)
        from learn_loop.propose import propose
        actions = propose(harvest_data, stats, clusters, sequences,
                          existing_keys=existing_keys)
        actions_proposed = len(actions)
        await insert_actions(session, run_id, actions)
    except Exception as e:
        logger.warning("[learn_loop] propose/insert failed: %s", e)
        partial_errors.append(f"actions:{e}")

    # ── 9. 自动应用(白名单) ──
    try:
        if _settings_bool("learn_loop_auto_apply", True):
            from models import LearningAction
            from sqlalchemy import select
            from learn_loop.apply import apply_action

            rows = (await session.execute(
                select(LearningAction)
                .where(LearningAction.run_id == run_id)
                .order_by(LearningAction.id)
            )).scalars().all()
            for row in rows:
                if row.action_type not in AUTO_APPLY_TYPES:
                    continue
                if not (row.payload or {}).get("_auto"):
                    continue
                try:
                    result = await apply_action(session, row, actor="learn_loop", auto=True)
                except Exception as e:
                    result = {"success": False, "error": f"apply_exception:{e}"}
                row.apply_result = result or {}
                if result and result.get("success"):
                    row.status = "auto_applied"
                    row.applied_at = datetime.now(timezone.utc)
                    row.applied_by = "learn_loop"
                    actions_auto_applied += 1
                else:
                    actions_failed += 1
            try:
                await session.commit()
            except Exception as e:
                partial_errors.append(f"auto_apply_commit:{e}")
    except Exception as e:
        logger.warning("[learn_loop] auto-apply pass failed: %s", e)
        partial_errors.append(f"auto_apply_pass:{e}")

    # 信誉先验缓存刷新(供无 session 的信誉查询)
    try:
        from threat_intel.reputation import load_priors_into_cache
        await load_priors_into_cache(session)
    except Exception as e:
        logger.debug("[learn_loop] prior cache refresh skipped: %s", e)

    model_summary = {
        "stats": stats,
        "clusters": {"count": len(clusters),
                     "sizes": [c.get("size", 0) for c in clusters[:10]]},
        "sequences": sequences,
        "partial_errors": partial_errors,
    }

    error_str = "; ".join(partial_errors)[:2000]

    # ── 11. pipeline_health 事件(同步 publish) ──
    try:
        from event_bus import event_bus
        event_bus.publish("pipeline_health", {
            "type": "learn_cycle",
            "run_id": run_id,
            "trigger": trigger,
            "status": "completed" if not error_str else "partial",
            "actions_proposed": actions_proposed,
            "actions_auto_applied": actions_auto_applied,
            "actions_failed": actions_failed,
            "harvest": harvest_summary(harvest_data),
        })
    except Exception as e:
        logger.debug("[learn_loop] event_bus publish skipped: %s", e)

    # ── 12. 收口 ──
    try:
        from learn_loop.store import finish_run
        await finish_run(
            session, run_id,
            status="completed",
            harvest=harvest_data,
            model_summary=model_summary,
            actions_proposed=actions_proposed,
            actions_auto_applied=actions_auto_applied,
            actions_failed=actions_failed,
            error=error_str,
        )
    except Exception as e:
        logger.warning("[learn_loop] finish_run failed: %s", e)
        return {
            "id": run_id, "status": "failed", "trigger": trigger,
            "window_start": _iso(ws), "window_end": _iso(we),
            "actions_proposed": actions_proposed,
            "actions_auto_applied": actions_auto_applied,
            "actions_failed": actions_failed,
            "error": f"finish_run_failed:{e}",
        }

    return {
        "id": run_id,
        "status": "completed",
        "trigger": trigger,
        "window_start": _iso(ws),
        "window_end": _iso(we),
        "actions_proposed": actions_proposed,
        "actions_auto_applied": actions_auto_applied,
        "actions_failed": actions_failed,
        "harvest": harvest_summary(harvest_data),
        "error": error_str,
    }
