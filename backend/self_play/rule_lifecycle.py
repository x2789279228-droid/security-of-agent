"""P1 蓝队规则生命周期 — 泛化 / 去重 / 独立验证 / 版本化。

同步、无 LLM、无网络。闭环:

    miss → generalize (去掉 IP / 超长命令行 / base64 / 长十六进制)
         → dedup     (Jaccard≥0.8 或同 mitre+event 族 → dismissed)
         → validate  (decoy + 历史 benign 上 FPR<0.05; 无独立 TP 时仅 provisional)
         → status=overlay 参与下一回合及以后的评分; 未过 → candidate
"""
from __future__ import annotations

import re
from typing import Optional

from self_play.catalog import DECOY_TEMPLATES
from self_play.overlay import match_rule, overlay
from self_play.types import LearnedRule, MaterializedEvent

FPR_MAX = 0.05
NEGATIVES_MIN = 24
DUP_THRESHOLD = 0.8
MIN_NEGATIVES = 20

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/]{20,}")
_LONG_HEX_RE = re.compile(r"^[a-fA-F0-9]{16,}$")
_TOKEN_KEYS = ("message_contains", "url_contains", "any_contains")
_COND_KEYS = ("event_contains", "message_contains", "url_contains", "any_contains")


# --------------------------------------------------------------------- helpers
def condition_tokens(rule: dict) -> set[str]:
    cond = rule.get("conditions") or {}
    out: set[str] = set()
    for key in _COND_KEYS:
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


def _as_log(e: dict) -> dict:
    """历史事件可能是 MaterializedEvent.to_dict() 或 log 字典,统一取可匹配层。"""
    if isinstance(e, dict):
        log = e.get("log")
        if isinstance(log, dict):
            return log
    return e or {}


def _is_benign(e: dict) -> bool:
    if isinstance(e, dict) and e.get("is_attack") is not None:
        return e.get("is_attack") is False
    gt = str(_as_log(e).get("_ground_truth") or "")
    return gt == "benign" if gt else False


def _is_attack(e: dict) -> bool:
    if isinstance(e, dict) and e.get("is_attack") is not None:
        return bool(e.get("is_attack"))
    return str(_as_log(e).get("_ground_truth") or "") == "attack"


def _event_fingerprint(e: dict, log: Optional[dict] = None) -> str:
    log = log if log is not None else _as_log(e)
    fp = e.get("fingerprint") if isinstance(e, dict) else ""
    return str(fp or log.get("_fingerprint") or "")


def _identity(fp: str, log: dict) -> tuple:
    return (
        fp or "",
        str(log.get("event") or log.get("type") or "").upper(),
        str(log.get("message") or ""),
        str(log.get("mitre_id") or log.get("_mitre_id") or "").upper(),
    )


def _noise_token(tok: str, *, ips: frozenset[str] = frozenset()) -> bool:
    """exact cmdline / base64-ish / 长 hex / IP 视为过拟合噪声。"""
    t = str(tok or "").strip()
    if not t:
        return True
    if t in ips or _IPV4_RE.match(t):
        return True
    if len(t) > 40:
        return True
    if _BASE64ISH_RE.search(t):
        return True
    if _LONG_HEX_RE.match(t):
        return True
    return False


def _decoy_negatives(n: int = NEGATIVES_MIN) -> list[dict]:
    out: list[dict] = []
    i = 0
    while len(out) < n:
        tpl = DECOY_TEMPLATES[i % len(DECOY_TEMPLATES)]
        out.append({
            "event": tpl.get("event"),
            "message": tpl.get("message"),
            "severity": tpl.get("severity"),
            "protocol": tpl.get("protocol"),
            "url": "",
            "src_ip": f"10.0.30.{11 + (i % 20)}",
            "_ground_truth": "benign",
        })
        i += 1
    return out


# ------------------------------------------------------------------ generalize
def generalize_rule(rule: LearnedRule, evt: MaterializedEvent) -> LearnedRule:
    """P1-D: 保 event 族,丢 src/dst IP / 超长命令行 / base64 / 长 hex,留 1–2 个行为 token。"""
    cond = dict(rule.conditions or {})
    event_family = [str(x) for x in (cond.get("event_contains") or []) if str(x).strip()]
    ips = frozenset(
        str(x) for x in (evt.src_ip, evt.dst_ip)
        if str(x or "").strip()
    )
    kept: list[str] = []
    for key in _TOKEN_KEYS:
        for tok in cond.get(key) or []:
            t = str(tok or "").strip()
            if t and not _noise_token(t, ips=ips):
                kept.append(t)
    behavior = list(dict.fromkeys(kept))[:2]

    new_cond = {k: v for k, v in cond.items() if k not in ("event_contains",) + _TOKEN_KEYS}
    new_cond["event_contains"] = event_family
    if behavior:
        new_cond["message_contains"] = behavior

    changed = new_cond != cond
    rule.conditions = new_cond
    rule.generalized = True
    if changed:
        if not rule.parent_rule_id:
            rule.parent_rule_id = rule.rule_id
        rule.version = int(rule.version or 1) + 1
    return rule


# ---------------------------------------------------------------------- dedup
def dedup_rule(
    rule: LearnedRule,
    existing: list[dict],
    threshold: float = DUP_THRESHOLD,
) -> tuple[Optional[LearnedRule], dict]:
    """P1-E: Jaccard≥threshold 或同 mitre_id + 同 event 族 → 视为重复。"""
    me = condition_tokens(rule.to_dict())
    my_ev = {str(x).upper() for x in (rule.conditions or {}).get("event_contains") or []}
    for other in existing or []:
        if not isinstance(other, dict):
            continue
        if str(other.get("rule_id") or "") == rule.rule_id:
            continue
        if str(other.get("status") or "") == "dismissed":
            continue
        score = _jaccard(me, condition_tokens(other))
        other_ev = {
            str(x).upper()
            for x in (other.get("conditions") or {}).get("event_contains") or []
        }
        same_sig = (
            bool(rule.mitre_id)
            and str(other.get("mitre_id") or "").upper() == str(rule.mitre_id).upper()
            and bool(my_ev)
            and my_ev == other_ev
        )
        if score >= threshold or same_sig:
            return None, {
                "reason": f"duplicate:{other.get('rule_id') or 'unknown'}",
                "jaccard": round(score, 3),
                "matched_rule_id": str(other.get("rule_id") or ""),
            }
    return rule, {"reason": "ok"}


# -------------------------------------------------------------------- validate
def validate_rule(
    rule: LearnedRule | dict,
    *,
    source_event: dict,
    history_events: Optional[list[dict]] = None,
) -> dict:
    """P1-C: 独立验证。FPR<0.05 才可升 overlay;源 miss 不能当唯一正样本宣称泛化。"""
    rule_d = rule.to_dict() if isinstance(rule, LearnedRule) else dict(rule or {})
    src = _as_log(source_event if isinstance(source_event, dict) else {})
    src_fp = _event_fingerprint(source_event if isinstance(source_event, dict) else {}, src)
    src_id = _identity(src_fp, src)

    negatives = _decoy_negatives(NEGATIVES_MIN)
    history = [e for e in (history_events or []) if isinstance(e, dict)]
    benign = [_as_log(e) for e in history if _is_benign(e)]
    attacks = [e for e in history if _is_attack(e)]
    negatives.extend(benign)

    fp = sum(1 for e in negatives if match_rule(rule_d, e))
    n = len(negatives)
    fpr = (fp / n) if n else 1.0

    tp_source = bool(match_rule(rule_d, src))
    tp_independent = 0
    for e in attacks:
        log = _as_log(e)
        if _identity(_event_fingerprint(e, log), log) == src_id:
            continue  # 源 miss 本身不算独立正样本
        if match_rule(rule_d, log):
            tp_independent += 1

    fpr_ok = n >= MIN_NEGATIVES and fpr < FPR_MAX
    provisional = False
    if not fpr_ok:
        passed = False
        reason = f"fp_rate={fpr:.3f}" if fp else "not_enough_negatives"
    elif tp_independent > 0:
        passed = True
        reason = "ok"
    elif tp_source:
        passed = True
        provisional = True
        reason = "provisional:source_only"
    else:
        passed = False
        reason = "no_true_positive"

    return {
        "passed": bool(passed),
        "fpr": round(float(fpr), 4),
        "fp": int(fp),
        "negatives": int(n),
        "tp_source": bool(tp_source),
        "tp_independent": int(tp_independent),
        "independent_tp": bool(tp_independent > 0),
        "provisional": bool(provisional),
        "reason": reason,
    }


# --------------------------------------------------------------------- ingest
def ingest_learned_rule(
    match_id: str,
    rule: LearnedRule,
    evt: MaterializedEvent,
    *,
    existing_rules: list[dict],
    history_events: Optional[list[dict]] = None,
) -> LearnedRule:
    """generalize → dedup → validate → 写 validation → 定 status → 进 overlay。"""
    rule = generalize_rule(rule, evt)
    deduped, info = dedup_rule(rule, existing_rules)
    if deduped is None:
        rule.status = "dismissed"
        rule.validation = dict(info)
        overlay.add(match_id, rule.to_dict())
        return rule
    report = validate_rule(rule, source_event=evt.to_log(), history_events=history_events)
    rule.validation = report
    rule.status = "overlay" if report.get("passed") else "candidate"
    overlay.add(match_id, rule.to_dict())
    return rule
