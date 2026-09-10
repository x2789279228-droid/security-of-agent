"""
learn_loop.apply — 动作落地(自动白名单 / 人工) + 回滚

auto=True 且 action_type 不在 AUTO_APPLY_TYPES → 直接 skipped(绝不越权)。
auto=False(人工复核触发)仍拒绝 llm: 来源的 apply_sigma_change / shadow_rule。

自动白名单动作必须真实可落地:
  - draft_post_mortem            → post_mortem_service.create_post_mortem(幂等)
  - shadow_rule                  → ops_loop.apply_rule_downgrade + RuleVersion 留痕
  - decay_baseline_entity        → anomaly_detector.decay_entity + 强制存 Redis
  - update_reputation_prior      → ReputationPrior upsert(clip 有界 delta)
  - persist_tuning_suggestion    → 行即持久化, 无需额外写
  - open_review_work_order       → work_order_service(无 API 则 note, 不崩)

其余人工动作未实现的返回 not_implemented_pending_human。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from config import settings
from learn_loop.types import AUTO_APPLY_TYPES, LLM_PREFIX

logger = logging.getLogger(__name__)

# rule_manager.update_rule 允许的字段(sigma)
_SIGMA_EDITABLE = {
    "name", "description", "severity", "attack_type", "confidence",
    "action_recommend", "enabled", "shadow_mode", "level", "tags",
    "logsource", "detection", "status",
}


def _getf(obj, name, default=None):
    if hasattr(obj, name):
        return getattr(obj, name, default)
    if isinstance(obj, dict):
        return obj.get(name, default)
    return default


def _llm_locked(payload: dict) -> bool:
    """payload 是否带 llm: 来源(禁止自动写回规则)。"""
    if not isinstance(payload, dict):
        return False
    if payload.get("llm_sourced"):
        return True
    for key in ("original_conclusion", "conclusion"):
        v = payload.get(key)
        if isinstance(v, str) and v.startswith(LLM_PREFIX):
            return True
    return False


async def apply_action(session, action_row_or_dict, *, actor: str = "learn_loop", auto: bool = False) -> dict:
    """执行单条动作, 返回 JSON 可序列化结果(不抛异常给调度器)。"""
    action_type = str(_getf(action_row_or_dict, "action_type", "") or "")
    target_type = str(_getf(action_row_or_dict, "target_type", "") or "")
    target_id = str(_getf(action_row_or_dict, "target_id", "") or "")
    payload = _getf(action_row_or_dict, "payload", {}) or {}
    if not isinstance(payload, dict):
        payload = {}

    base = {
        "action_type": action_type,
        "target_type": target_type,
        "target_id": target_id,
        "mechanism": str(_getf(action_row_or_dict, "mechanism", "") or ""),
    }

    if auto and action_type not in AUTO_APPLY_TYPES:
        return {**base, "success": False, "skipped": True,
                "reason": f"not_in_auto_whitelist:{action_type}"}

    # ── 自动白名单 ──
    if action_type == "draft_post_mortem":
        return await _apply_draft_post_mortem(session, base, payload, actor)
    if action_type == "shadow_rule":
        if _llm_locked(payload):
            return {**base, "success": False,
                    "error": "llm_conclusion_requires_human"}
        return await _apply_shadow_rule(session, base, payload, actor)
    if action_type == "decay_baseline_entity":
        return await _apply_decay_baseline(session, base, payload, target_id)
    if action_type == "update_reputation_prior":
        return await _apply_update_reputation_prior(session, base, payload, target_id)
    if action_type == "persist_tuning_suggestion":
        return {**base, "success": True, "note": "recorded_in_learning_actions"}
    if action_type == "open_review_work_order":
        return await _apply_open_review_work_order(session, base, payload, target_id, actor)

    # ── 人工动作 ──
    if action_type == "apply_sigma_change":
        if _llm_locked(payload):
            return {**base, "success": False,
                    "error": "llm_conclusion_cannot_change_sigma"}
        return await _apply_sigma_change(session, base, payload, target_id, actor)

    return {**base, "success": False, "error": "not_implemented_pending_human"}


# ═══════════════════════════════════════════
# 自动白名单实现
# ═══════════════════════════════════════════

async def _apply_draft_post_mortem(session, base: dict, payload: dict, actor: str) -> dict:
    """已关闭案例无复盘 → 自动补复盘草稿(该案例已有复盘视为幂等成功)。"""
    try:
        case_id = int(payload.get("case_id") or base["target_id"] or 0)
    except (TypeError, ValueError):
        case_id = 0
    if not case_id:
        return {**base, "success": False, "error": "missing_case_id"}
    try:
        from post_mortem_service import post_mortem_service
        result = await post_mortem_service.create_post_mortem(
            session, case_id, author=actor
        )
    except Exception as e:
        logger.warning("[learn_loop.apply] draft_post_mortem failed: %s", e)
        return {**base, "success": False, "error": f"create_post_mortem_exception:{e}"}
    err = str(result.get("error") or "")
    if result.get("success") or "该案例已有复盘" in err:
        return {**base, "success": True, "idempotent": not result.get("success"),
                "detail": result}
    return {**base, "success": False, "error": err or "create_post_mortem_failed"}


async def _apply_shadow_rule(session, base: dict, payload: dict, actor: str) -> dict:
    """Sigma 降级为 shadow(仅告警) + RuleVersion 留痕。"""
    rule_id = str(payload.get("rule_id") or base["target_id"] or "")
    if not rule_id:
        return {**base, "success": False, "error": "missing_rule_id"}
    try:
        from ops_loop import apply_rule_downgrade
        result = apply_rule_downgrade(rule_id)  # 同步(内部已触发 reload)
    except Exception as e:
        logger.warning("[learn_loop.apply] shadow_rule downgrade failed: %s", e)
        return {**base, "success": False, "error": f"apply_rule_downgrade_exception:{e}"}

    sigma_res = result.get("sigma") or {}
    ok = bool(sigma_res.get("success"))
    if ok:
        try:
            from models import RuleVersion
            session.add(RuleVersion(
                rule_type="sigma",
                rule_id=rule_id,
                content={"shadow_mode": True},
                change_summary="fp_auto_downgrade",
                changed_by=actor,
                is_active=True,
            ))
            await session.commit()
        except Exception as e:
            logger.warning("[learn_loop.apply] rule version persist failed: %s", e)
    return {
        **base,
        "success": ok,
        "sigma": sigma_res,
        "response_policy": result.get("response_policy"),
        "version_written": ok,
    }


async def _apply_decay_baseline(session, base: dict, payload: dict, target_id: str) -> dict:
    """FP 源 IP 基线衰减(永不删除实体; 衰减不可回滚)。"""
    try:
        from anomaly_detector import anomaly_detector
    except Exception as e:
        return {**base, "success": False, "error": f"anomaly_detector_unavailable:{e}"}
    entity_type = str(payload.get("entity_type") or "src_ip")
    entity_key = str(payload.get("entity_key") or target_id or "")
    try:
        factor = float(payload.get("factor") or 0.5)
    except (TypeError, ValueError):
        factor = 0.5
    ok = anomaly_detector.decay_entity(entity_type, entity_key, factor)
    try:
        await anomaly_detector._save_baselines_to_redis(force=True)
    except Exception as e:
        logger.warning("[learn_loop.apply] baseline redis save failed: %s", e)
    if not ok:
        return {**base, "success": False, "error": "entity_not_found",
                "entity_type": entity_type, "entity_key": entity_key}
    return {
        **base, "success": True,
        "entity_type": entity_type, "entity_key": entity_key, "factor": factor,
        "decay_irreversible": True,
    }


async def _apply_update_reputation_prior(session, base: dict, payload: dict, target_id: str) -> dict:
    """TP/FP 计数 upsert 到 reputation_priors, delta 按 clip 有界。"""
    from sqlalchemy import select
    from models import ReputationPrior

    target = str(payload.get("target") or target_id or "")
    target_type = str(payload.get("target_type") or "")
    if target_type not in ("ip", "domain"):
        target_type = base["target_type"] if base["target_type"] in ("ip", "domain") else "ip"
    if not target:
        return {**base, "success": False, "error": "missing_target"}
    try:
        tp = max(0, int(payload.get("tp") or 0))
        fp = max(0, int(payload.get("fp") or 0))
    except (TypeError, ValueError):
        tp = fp = 0

    row = (await session.execute(
        select(ReputationPrior).where(
            ReputationPrior.target == target,
            ReputationPrior.target_type == target_type,
        )
    )).scalars().first()
    if row is None:
        row = ReputationPrior(target=target, target_type=target_type,
                              delta=0.0, tp_count=0, fp_count=0)
        session.add(row)
    row.tp_count += tp
    row.fp_count += fp
    row.updated_at = datetime.now(timezone.utc)

    clip = float(getattr(settings, "learn_loop_prior_clip", 0.2) or 0.2)
    delta = max(-clip, min(clip, 0.05 * (row.tp_count - row.fp_count)))
    row.delta = round(float(delta), 4)
    try:
        await session.commit()
    except Exception as e:
        logger.warning("[learn_loop.apply] prior upsert commit failed: %s", e)
        return {**base, "success": False, "error": f"prior_commit_failed:{e}"}
    try:
        from threat_intel.reputation import set_prior_cache
        set_prior_cache(target_type, target, row.delta)
    except Exception:
        pass
    return {
        **base, "success": True, "target": target, "target_type": target_type,
        "delta": row.delta, "tp_count": row.tp_count, "fp_count": row.fp_count,
    }


async def _apply_open_review_work_order(session, base: dict, payload: dict, target_id: str, actor: str) -> dict:
    """复盘 action_items 未完成 → 开 review 工单(无 API 时 note, 不崩)。"""
    try:
        case_raw = payload.get("case_id") or target_id or None
        case_id = int(case_raw) if str(case_raw).strip().lstrip("-").isdigit() else None
    except (TypeError, ValueError):
        case_id = None
    title = str(payload.get("title") or "复盘待办跟进 (learn_loop)")
    description = str(payload.get("item") or payload.get("description") or
                      "来自复盘报告 action_items 的未完成项, 请跟进")[:500]
    try:
        from work_order_service import work_order_service
        creator = getattr(work_order_service, "create", None) or getattr(
            work_order_service, "create_order", None)
        if creator is None:
            return {**base, "success": True, "note": "no_work_order_api",
                    "case_id": case_id}
        order = await creator(
            session, case_id=case_id, order_type="review",
            title=title, description=description,
            priority=str(payload.get("priority") or "medium"),
            created_by=actor,
        )
        return {**base, "success": True, "order_id": getattr(order, "id", None),
                "order_number": getattr(order, "order_number", "")}
    except Exception as e:
        logger.warning("[learn_loop.apply] open review work order failed: %s", e)
        return {**base, "success": False, "error": f"work_order_failed:{e}"}


# ═══════════════════════════════════════════
# 人工动作
# ═══════════════════════════════════════════

async def _apply_sigma_change(session, base: dict, payload: dict, target_id: str, actor: str) -> dict:
    """人工显式修改 Sigma(经 rule_manager + 版本留痕); 不满足则 pending。"""
    rule_id = str(payload.get("rule_id") or target_id or "")
    if not rule_id:
        return {**base, "success": False, "error": "missing_rule_id"}

    content = payload.get("content")
    if isinstance(content, dict):
        patch = {k: v for k, v in content.items() if k in _SIGMA_EDITABLE}
        if not patch:
            return {**base, "success": False, "error": "not_implemented_pending_human"}
    else:
        patch = {k: v for k, v in payload.items()
                 if k in _SIGMA_EDITABLE and v is not None}
        if not patch:
            return {**base, "success": False, "error": "not_implemented_pending_human"}
    try:
        from rule_manager import rule_manager
        result = rule_manager.update_rule(
            "sigma", rule_id, patch,
            change_summary=str(payload.get("change_summary") or "learn_loop_human_apply"),
            changed_by=actor,
        )
        if result.get("success") and result.get("version_data"):
            try:
                await rule_manager.save_version(session, result["version_data"])
            except Exception as e:
                logger.warning("[learn_loop.apply] sigma version save failed: %s", e)
        return {**base, "success": bool(result.get("success")), "detail": result}
    except Exception as e:
        logger.warning("[learn_loop.apply] sigma change failed: %s", e)
        return {**base, "success": False, "error": f"not_implemented_pending_human:{e}"}


# ═══════════════════════════════════════════
# 回滚
# ═══════════════════════════════════════════

async def rollback_action(session, action_row_or_dict) -> dict:
    """回滚已应用动作。decay_baseline_entity 不可逆, draft_post_mortem 不删除。"""
    action_type = str(_getf(action_row_or_dict, "action_type", "") or "")
    target_id = str(_getf(action_row_or_dict, "target_id", "") or "")
    payload = _getf(action_row_or_dict, "payload", {}) or {}
    if not isinstance(payload, dict):
        payload = {}
    notes: list[str] = []

    if action_type == "shadow_rule":
        rule_id = str(payload.get("rule_id") or target_id or "")
        if rule_id:
            try:
                from sigma_engine import store as sigma_store
                sigma_store.shadow(rule_id, False)
                notes.append("shadow_removed")
            except Exception as e:
                notes.append(f"shadow_remove_failed:{e}")
            try:
                from sigma_detector import sigma_detector
                if hasattr(sigma_detector, "reload"):
                    sigma_detector.reload()
            except Exception as e:
                notes.append(f"reload_failed:{e}")
    elif action_type == "update_reputation_prior":
        try:
            from sqlalchemy import select
            from models import ReputationPrior
            target = str(payload.get("target") or target_id or "")
            target_type = str(payload.get("target_type") or "ip")
            row = (await session.execute(
                select(ReputationPrior).where(
                    ReputationPrior.target == target,
                    ReputationPrior.target_type == target_type,
                )
            )).scalars().first()
            if row is not None:
                row.delta = 0.0
                row.updated_at = datetime.now(timezone.utc)
                await session.commit()
                notes.append("prior_delta_reset")
                try:
                    from threat_intel.reputation import set_prior_cache
                    set_prior_cache(target_type, target, 0.0)
                except Exception:
                    pass
        except Exception as e:
            notes.append(f"prior_reset_failed:{e}")
    elif action_type == "decay_baseline_entity":
        notes.append("decay_irreversible_not_rolled_back")
    elif action_type == "draft_post_mortem":
        notes.append("post_mortem_not_deleted")

    return {"success": True, "action_type": action_type, "target_id": target_id,
            "notes": notes}
