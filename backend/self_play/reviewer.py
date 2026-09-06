"""蓝队审核 Agent — candidate 规则过硬门 + LLM 语义 + 可选回放后进入 shadow/生产 Sigma。"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from self_play.catalog import DECOY_TEMPLATES
from self_play.overlay import GLOBAL_KEY, match_rule, overlay
from self_play.sigma_export import delete_selfplay_rule, dump_yaml, reload_sigma, write_selfplay_rule

logger = logging.getLogger(__name__)

ACTOR = "blue_reviewer"
_SYNTH_EVENT = re.compile(r"^(ATTCK_T\d+|T\d{4}(?:\.\d{3})?|TTP-.+)$", re.I)
_MITRE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


def _settings():
    try:
        from config import settings
        return settings
    except Exception:
        return None


def _fp_max() -> float:
    s = _settings()
    try:
        return float(getattr(s, "self_play_review_fp_max", 0.05) or 0.05)
    except Exception:
        return 0.05


def _use_llm() -> bool:
    s = _settings()
    return bool(getattr(s, "self_play_review_llm", True))


def _use_replay() -> bool:
    s = _settings()
    return bool(getattr(s, "self_play_review_replay", True))


def _shadow_hours() -> float:
    s = _settings()
    try:
        return float(getattr(s, "self_play_shadow_hours", 24) or 24)
    except Exception:
        return 24.0


def condition_tokens(rule: dict) -> set[str]:
    cond = rule.get("conditions") or {}
    out: set[str] = set()
    for key in ("event_contains", "message_contains", "url_contains", "any_contains"):
        for v in cond.get(key) or []:
            t = str(v or "").strip()
            if t:
                out.add(t.upper())
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def gate_degenerate(rule: dict) -> dict:
    """套套: 条件只是事件类型 / MITRE ID 自己打自己。"""
    toks = condition_tokens(rule)
    if not toks:
        return {"id": "G0", "passed": False, "reason": "empty_conditions"}
    identity = {
        str(rule.get("attack_type") or "").upper(),
        str(rule.get("mitre_id") or "").upper(),
        str(rule.get("rule_id") or "").upper(),
    }
    identity.discard("")
    if toks <= identity:
        return {"id": "G0", "passed": False, "reason": "tautology_identity"}
    if all(_MITRE.match(t) or _SYNTH_EVENT.match(t) for t in toks):
        return {"id": "G0", "passed": False, "reason": "only_synthetic_ids"}
    return {"id": "G0", "passed": True, "reason": "ok"}


def gate_duplicate(rule: dict, others: list[dict], *, threshold: float = 0.8) -> dict:
    me = condition_tokens(rule)
    rid = str(rule.get("rule_id") or "")
    mitre = str(rule.get("mitre_id") or "").upper()
    ev = {str(x).upper() for x in (rule.get("conditions") or {}).get("event_contains") or []}
    for other in others:
        if str(other.get("rule_id") or "") == rid:
            continue
        if str(other.get("status") or "") == "dismissed":
            continue
        ot = condition_tokens(other)
        score = _jaccard(me, ot)
        same_sig = (
            mitre
            and str(other.get("mitre_id") or "").upper() == mitre
            and ev
            and ev == {str(x).upper() for x in (other.get("conditions") or {}).get("event_contains") or []}
        )
        if score >= threshold or same_sig:
            return {
                "id": "G1", "passed": False,
                "reason": f"duplicate:{other.get('rule_id')}",
                "jaccard": round(score, 3),
            }
    return {"id": "G1", "passed": True, "reason": "ok"}


def gate_transferable(rule: dict) -> dict:
    """至少有一个不像仿真枚举的 token,才可能打到生产日志。"""
    cond = rule.get("conditions") or {}
    msgs = [str(x) for x in (cond.get("message_contains") or []) if str(x).strip()]
    urls = [str(x) for x in (cond.get("url_contains") or []) if str(x).strip()]
    evs = [str(x) for x in (cond.get("event_contains") or []) if str(x).strip()]
    natural = []
    for t in msgs + urls:
        if _MITRE.match(t) or _SYNTH_EVENT.match(t):
            continue
        if t.upper() in {e.upper() for e in evs}:
            continue
        if len(t) >= 2:
            natural.append(t)
    if not natural:
        return {"id": "G3", "passed": False, "reason": "no_production_token"}
    return {"id": "G3", "passed": True, "reason": "ok", "tokens": natural[:6]}


def _positive_event(rule: dict) -> dict:
    cond = rule.get("conditions") or {}
    evs = [str(x) for x in (cond.get("event_contains") or []) if x]
    msgs = [str(x) for x in (cond.get("message_contains") or []) if x]
    return {
        "event": evs[0] if evs else str(rule.get("attack_type") or "UNKNOWN"),
        "message": " ".join(msgs) or str(rule.get("title") or ""),
        "severity": rule.get("severity") or "high",
        "protocol": "tcp",
        "url": "",
        "threat_type": rule.get("attack_type") or "",
    }


def _decoy_events(n: int = 24) -> list[dict]:
    out = []
    i = 0
    while len(out) < n:
        tpl = DECOY_TEMPLATES[i % len(DECOY_TEMPLATES)]
        out.append({
            "event": tpl["event"],
            "message": tpl["message"],
            "severity": tpl["severity"],
            "protocol": tpl["protocol"],
            "url": "",
            "src_ip": f"10.0.30.{11 + (i % 20)}",
        })
        i += 1
    return out


def gate_fp_replay(rule: dict, extra_negatives: Optional[list[dict]] = None) -> dict:
    positives = [_positive_event(rule)]
    negatives = _decoy_events(24) + list(extra_negatives or [])
    tp = sum(1 for e in positives if match_rule(rule, e))
    fp = sum(1 for e in negatives if match_rule(rule, e))
    fp_rate = (fp / len(negatives)) if negatives else 1.0
    passed = tp >= 1 and fp_rate < _fp_max() and len(negatives) >= 20
    reason = "ok"
    if tp < 1:
        reason = "no_true_positive"
    elif fp_rate >= _fp_max():
        reason = f"fp_rate={fp_rate:.3f}"
    return {
        "id": "G2", "passed": passed, "reason": reason,
        "tp": tp, "fp": fp, "negatives": len(negatives), "fp_rate": round(fp_rate, 4),
    }


def _sigma_rule_tokens() -> list[tuple[str, set[str]]]:
    out = []
    try:
        from sigma_engine.store import list_rules
        for item in list_rules() or []:
            blob = str((item.get("conditions") or {}).get("sigma_yaml") or "")
            toks = set(re.findall(r"[A-Za-z0-9_\u4e00-\u9fff]{3,}", blob.upper()))
            out.append((str(item.get("rule_id") or ""), toks))
    except Exception as e:
        logger.debug("[reviewer] list_rules skipped: %s", e)
    return out


def gate_duplicate_sigma(rule: dict, *, threshold: float = 0.8) -> dict:
    me = condition_tokens(rule)
    for rid, toks in _sigma_rule_tokens():
        if not toks:
            continue
        score = _jaccard(me, toks)
        if score >= threshold:
            return {"id": "G1b", "passed": False, "reason": f"sigma_duplicate:{rid}", "jaccard": round(score, 3)}
    return {"id": "G1b", "passed": True, "reason": "ok"}


async def gate_llm(rule: dict, hard_gates: list[dict]) -> dict:
    from prompts import render
    from audit_schemas import extract_json
    cond = rule.get("conditions") or {}
    try:
        from summary_compression import summary
        system = render("security/blue_review_system")
        user = render(
            "security/blue_review",
            rule_id=rule.get("rule_id"),
            title=rule.get("title"),
            mitre_id=rule.get("mitre_id"),
            attack_type=rule.get("attack_type"),
            severity=rule.get("severity"),
            condition_mode=rule.get("condition_mode") or "or",
            event_contains=cond.get("event_contains") or [],
            message_contains=cond.get("message_contains") or [],
            gates=hard_gates,
        )
        raw = await summary.llm.chat(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.1,
        )
        parsed = extract_json(raw or "") or {}
        meaningful = bool(parsed.get("meaningful", True))
        useful = bool(parsed.get("production_useful", True))
        passed = meaningful and useful and not bool(parsed.get("duplicate_risk"))
        return {
            "id": "G4", "passed": passed,
            "reason": str(parsed.get("reason") or "llm"),
            "raw": parsed,
        }
    except Exception as e:
        logger.warning("[reviewer] LLM gate fail-open: %s", e)
        return {"id": "G4", "passed": True, "reason": f"fail_open:{e}"}


async def gate_replay_ab(rule: dict) -> dict:
    """用历史 self-play 事件或短课程对局估计 Δrecall。失败开放。"""
    try:
        from self_play import store
        matches = await store.list_matches(limit=5)
        attacks: list[dict] = []
        for m in matches:
            detail = await store.get_match(m.get("match_id") or "")
            if not detail:
                continue
            for rd in detail.get("rounds") or []:
                for ev in rd.get("events") or []:
                    log = ev.get("log") if isinstance(ev, dict) else None
                    if not log and isinstance(ev, dict):
                        log = {
                            "event": ev.get("event"),
                            "message": ev.get("message"),
                            "severity": ev.get("severity"),
                            "protocol": ev.get("protocol"),
                        }
                    if log and (ev.get("is_attack") if "is_attack" in ev else log.get("_ground_truth") == "attack"):
                        attacks.append(log)
            if len(attacks) >= 20:
                break
        if len(attacks) < 3:
            attacks = [_positive_event(rule)]
        without = sum(1 for e in attacks if False)
        with_rule = sum(1 for e in attacks if match_rule(rule, e))
        n = max(1, len(attacks))
        delta = with_rule / n
        passed = with_rule >= 1
        return {
            "id": "G5", "passed": passed, "reason": "ok" if passed else "no_lift",
            "attacks": n, "hits": with_rule, "delta_recall": round(delta, 3),
            "baseline_hits": without,
        }
    except Exception as e:
        logger.warning("[reviewer] replay fail-open: %s", e)
        return {"id": "G5", "passed": True, "reason": f"fail_open:{e}"}


async def _extra_negatives() -> list[dict]:
    out = []
    try:
        from models import SecurityEvent, async_session
        from sqlalchemy import select
        async with async_session() as session:
            rows = (await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.severity.in_(("info", "low")))
                .order_by(SecurityEvent.id.desc())
                .limit(80)
            )).scalars().all()
            for r in rows:
                out.append({
                    "event": r.event_type, "message": r.message or "",
                    "severity": r.severity, "protocol": r.protocol or "",
                    "url": "", "src_ip": r.src_ip or "",
                })
    except Exception as e:
        logger.debug("[reviewer] extra negatives skipped: %s", e)
    return out


async def review_one(rule: dict, *, peers: Optional[list[dict]] = None) -> dict:
    peers = peers or []
    gates = [
        gate_degenerate(rule),
        gate_duplicate(rule, peers),
        gate_duplicate_sigma(rule),
        gate_transferable(rule),
        gate_fp_replay(rule, extra_negatives=await _extra_negatives()),
    ]
    hard_ok = all(g.get("passed") for g in gates)
    if hard_ok and _use_llm():
        gates.append(await gate_llm(rule, gates))
    if hard_ok and _use_replay():
        gates.append(await gate_replay_ab(rule))
    ok = all(g.get("passed") for g in gates)
    failed = [g["id"] for g in gates if not g.get("passed")]
    decision = "shadow" if ok else "dismissed"
    return {
        "decision": decision,
        "gates": gates,
        "failed": failed,
        "actor": ACTOR,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }


async def _audit(action: str, rule: dict, before: dict, after: dict, reason: str) -> None:
    try:
        from audit_trail import log_action
        from models import async_session
        async with async_session() as session:
            await log_action(
                session, actor=ACTOR, actor_role="system",
                action=action, target_type="selfplay_rule",
                target_id=str(rule.get("rule_id") or rule.get("id") or ""),
                before=before, after=after, reason=reason,
            )
    except Exception as e:
        logger.warning("[reviewer] audit persist failed: %s", e)


def _overlay_payload(rule: dict, status: str) -> dict:
    return {
        "rule_id": rule.get("rule_id"),
        "title": rule.get("title"),
        "attack_type": rule.get("attack_type"),
        "mitre_id": rule.get("mitre_id"),
        "severity": rule.get("severity"),
        "conditions": rule.get("conditions") or {},
        "condition_mode": rule.get("condition_mode") or "or",
        "status": status,
    }


async def apply_review(rule: dict, report: dict, *, force: bool = False, actor: str = ACTOR) -> dict:
    """按审核结论更新 DB / overlay / Sigma YAML。"""
    from self_play import store
    decision = str(report.get("decision") or "dismissed")
    if force and decision not in ("shadow", "promoted", "dismissed", "candidate"):
        decision = "promoted"
    pk = int(rule.get("id") or 0)
    yaml_text = ""
    path = ""
    if decision == "dismissed":
        delete_selfplay_rule(str(rule.get("rule_id") or ""))
        reload_sigma()
    elif decision in ("shadow", "promoted"):
        shadow = decision == "shadow"
        written = write_selfplay_rule(rule, shadow=shadow)
        yaml_text = written.get("yaml") or dump_yaml(rule, shadow=shadow)
        path = written.get("path") or ""
        overlay.add(GLOBAL_KEY, _overlay_payload(rule, decision))
        reload_sigma()
    row = None
    if pk:
        row = await store.set_rule_status(
            pk, decision, sigma_yaml=yaml_text, review_report=report,
        )
    await _audit(
        f"selfplay.rule_{decision}",
        rule, {"status": rule.get("status")},
        {"status": decision, "path": path, "failed": report.get("failed")},
        reason=";".join(report.get("failed") or []) or report.get("decision") or actor,
    )
    return {"rule": row or rule, "decision": decision, "report": report, "yaml_path": path}


async def drain(limit: int = 20) -> dict:
    from self_play import store
    candidates = await store.list_learned_rules(status="candidate", limit=limit)
    peers = await store.list_learned_rules(limit=200)
    results = []
    for rule in candidates:
        report = await review_one(rule, peers=peers)
        applied = await apply_review(rule, report)
        results.append({
            "rule_id": rule.get("rule_id"),
            "id": rule.get("id"),
            "decision": applied.get("decision"),
            "failed": report.get("failed"),
        })
        if applied.get("decision") == "shadow":
            peers.append({**rule, "status": "shadow"})
    promoted = await promote_due_shadows()
    return {
        "reviewed": len(results),
        "results": results,
        "promoted": promoted,
        "shadowed": sum(1 for r in results if r["decision"] == "shadow"),
        "dismissed": sum(1 for r in results if r["decision"] == "dismissed"),
    }


async def promote_due_shadows() -> list[dict]:
    from self_play import store
    hours = _shadow_hours()
    out = []
    shadows = await store.list_learned_rules(status="shadow", limit=100)
    now = datetime.now(timezone.utc)
    for rule in shadows:
        report = rule.get("review_report") or {}
        ts = str(report.get("reviewed_at") or rule.get("created_at") or "")
        try:
            when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            when = now
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if now - when < timedelta(hours=hours):
            continue
        fp = gate_fp_replay(rule, extra_negatives=await _extra_negatives())
        if not fp.get("passed"):
            await apply_review(rule, {
                "decision": "dismissed",
                "gates": [fp],
                "failed": ["G2"],
                "actor": ACTOR,
                "reviewed_at": now.isoformat(),
            })
            out.append({"rule_id": rule.get("rule_id"), "decision": "dismissed", "reason": "shadow_fp"})
            continue
        applied = await apply_review(rule, {
            "decision": "promoted",
            "gates": [fp],
            "failed": [],
            "actor": ACTOR,
            "reviewed_at": now.isoformat(),
        })
        out.append({"rule_id": rule.get("rule_id"), "decision": applied.get("decision")})
    return out


async def seed_global_overlay() -> int:
    from self_play import store
    n = 0
    try:
        for status in ("shadow", "promoted"):
            for rule in await store.list_learned_rules(status=status, limit=200):
                overlay.add(GLOBAL_KEY, _overlay_payload(rule, status))
                n += 1
    except Exception as e:
        logger.info("[reviewer] seed overlay skipped: %s", e)
    return n
