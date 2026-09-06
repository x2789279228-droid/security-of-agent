"""蓝队在线规则叠加层。

Self-Play 学到的规则先进入 overlay,不写生产 Sigma YAML。
运营确认后再 promote。叠加层按 match 隔离,另有全局(已 promote / 历史候选)池。
"""
from __future__ import annotations

from typing import Any, Optional

GLOBAL_KEY = "*"

# P1-B: 参与评分的状态分层。candidate 仅评估,不计入 TP/FN。
SCORING_STATUSES = frozenset({"overlay", "shadow", "promoted", "production"})
CANDIDATE_STATUSES = frozenset({"candidate"})


def _haystack(event: dict) -> str:
    parts = [
        event.get("event"), event.get("type"), event.get("message"),
        event.get("url"), event.get("protocol"), event.get("threat_type"),
    ]
    return " ".join(str(p or "") for p in parts).upper()


def match_rule(rule: dict, event: dict) -> bool:
    conditions = rule.get("conditions") or {}
    if not conditions:
        return False
    mode = str(rule.get("condition_mode") or "or").lower()
    text = _haystack(event)
    hits = []
    for key, patterns in conditions.items():
        pats = patterns if isinstance(patterns, (list, tuple)) else [patterns]
        pats = [str(p) for p in pats if str(p).strip()]
        if not pats:
            continue
        if key in ("event_contains", "message_contains", "url_contains", "any_contains"):
            hit = any(p.upper() in text for p in pats)
        elif key == "protocol_in":
            proto = str(event.get("protocol") or "").lower()
            hit = bool(proto) and any(str(p).lower() == proto for p in pats)
        else:
            hit = any(p.upper() in text for p in pats)
        hits.append(hit)
    if not hits:
        return False
    return all(hits) if mode == "and" else any(hits)


class RuleOverlay:
    def __init__(self) -> None:
        self._rules: dict[str, list[dict]] = {GLOBAL_KEY: []}

    def clear(self, match_id: Optional[str] = None) -> None:
        if match_id is None:
            self._rules = {GLOBAL_KEY: []}
            return
        self._rules[match_id] = []

    def seed(self, match_id: str, rules: list[dict]) -> None:
        bucket = self._rules.setdefault(match_id, [])
        seen = {r.get("rule_id") for r in bucket}
        for rule in rules or []:
            rid = rule.get("rule_id")
            if rid and rid in seen:
                continue
            bucket.append(dict(rule))
            if rid:
                seen.add(rid)

    def add(self, match_id: str, rule: dict) -> dict:
        bucket = self._rules.setdefault(match_id, [])
        rid = rule.get("rule_id")
        for i, existing in enumerate(bucket):
            if rid and existing.get("rule_id") == rid:
                bucket[i] = dict(rule)
                return bucket[i]
        bucket.append(dict(rule))
        return bucket[-1]

    def rules_for(self, match_id: str) -> list[dict]:
        out: list[dict] = []
        out.extend(self._rules.get(GLOBAL_KEY) or [])
        if match_id != GLOBAL_KEY:
            out.extend(self._rules.get(match_id) or [])
        return out

    def detect(
        self,
        match_id: str,
        event: dict,
        *,
        for_scoring: Optional[bool] = None,
        statuses: Optional[set] = None,
    ) -> dict[str, Any]:
        # for_scoring None  => 旧行为: 除 dismissed 外全部匹配 (向后兼容)
        # for_scoring True  => 仅 SCORING_STATUSES (评分通道)
        # for_scoring False => 仅 candidate (评估通道)
        if statuses is not None:
            allowed = {str(s) for s in statuses}
        elif for_scoring is True:
            allowed = SCORING_STATUSES
        elif for_scoring is False:
            allowed = CANDIDATE_STATUSES
        else:
            allowed = None
        hits = []
        for rule in self.rules_for(match_id):
            status = str(rule.get("status") or "candidate")
            if status == "dismissed":
                continue
            if allowed is not None and status not in allowed:
                continue
            if match_rule(rule, event):
                hits.append({
                    "rule_id": rule.get("rule_id", ""),
                    "title": rule.get("title", ""),
                    "attack_type": rule.get("attack_type", ""),
                    "severity": rule.get("severity", "medium"),
                    "mitre_id": rule.get("mitre_id", ""),
                })
        if not hits:
            return {"detected": False, "hits": [], "rule_ids": [], "attack_types": []}
        return {
            "detected": True,
            "hits": hits,
            "rule_ids": [h["rule_id"] for h in hits],
            "attack_types": list({h["attack_type"] for h in hits if h.get("attack_type")}),
        }

    def detect_scoring(self, match_id: str, event: dict) -> dict[str, Any]:
        """P1-B: 仅 overlay/shadow/promoted/production 参与评分。"""
        return self.detect(match_id, event, for_scoring=True)

    def detect_candidates(self, match_id: str, event: dict) -> dict[str, Any]:
        """P1-A: candidate 仅评估,不影响本回合 TP/FN。"""
        return self.detect(match_id, event, for_scoring=False)


overlay = RuleOverlay()
