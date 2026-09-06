"""蓝队学习器 — 漏报样本 → overlay 候选规则 (+ 可选反馈/知识库)。

候选规则默认不写生产 Sigma 文件,需运营 promote。
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from self_play.novelty import tokenize
from self_play.overlay import overlay
from self_play.rule_lifecycle import ingest_learned_rule
from self_play.types import LearnedRule, MaterializedEvent

logger = logging.getLogger(__name__)

_GENERIC = frozenset({
    "event", "host", "user", "from", "with", "http", "https", "tcp",
    "message", "info", "high", "medium", "low", "critical",
})


def distinctive_tokens(evt: MaterializedEvent, limit: int = 4) -> list[str]:
    toks = []
    if evt.event:
        toks.append(evt.event)
    for t in sorted(tokenize(evt.event, evt.message, evt.mitre_id)):
        if t.lower() in _GENERIC:
            continue
        if t.upper() == evt.event.upper():
            continue
        if t not in toks:
            toks.append(t)
        if len(toks) >= limit:
            break
    return toks[:limit]


def rule_from_miss(evt: MaterializedEvent, rule_id: str) -> LearnedRule:
    tokens = distinctive_tokens(evt)
    event_contains = [evt.event] if evt.event else []
    message_contains = [t for t in tokens if t.upper() != (evt.event or "").upper()]
    title = f"Self-Play 学到: {evt.event or evt.mitre_id or 'novel'}"
    return LearnedRule(
        rule_id=rule_id,
        title=title,
        attack_type=evt.event or "unknown",
        mitre_id=evt.mitre_id,
        severity=evt.severity or "medium",
        conditions={
            "event_contains": event_contains,
            "message_contains": message_contains,
        },
        condition_mode="or",
        source_fingerprint=evt.fingerprint,
        status="candidate",
    )


def _next_rule_id(match_id: str, seq: int) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "", match_id)[-8:] or "sp"
    return f"SP-{slug}-{seq:03d}"


class BlueLearner:
    def __init__(self) -> None:
        self._seq = 0

    async def learn_from_misses(
        self,
        match_id: str,
        events: list[MaterializedEvent],
        detected: list[bool],
        *,
        use_llm: bool = False,
        persist_kb: bool = False,
        round_num: int = 0,
        history_events: Optional[list[dict]] = None,
    ) -> list[LearnedRule]:
        learned: list[LearnedRule] = []
        for evt, hit in zip(events, detected):
            if not evt.is_attack or hit:
                continue
            self._seq += 1
            rule = rule_from_miss(evt, _next_rule_id(match_id, self._seq))
            if use_llm:
                llm_rule = await self._llm_enrich(evt)
                if llm_rule:
                    rule.title = str(llm_rule.get("title") or rule.title)
                    rule.attack_type = str(llm_rule.get("attack_type") or rule.attack_type)
                    extra_ev = llm_rule.get("event_contains") or []
                    extra_msg = llm_rule.get("message_contains") or []
                    if isinstance(extra_ev, list):
                        rule.conditions["event_contains"] = list(dict.fromkeys(
                            (rule.conditions.get("event_contains") or []) + [str(x) for x in extra_ev if x]
                        ))
                    if isinstance(extra_msg, list):
                        rule.conditions["message_contains"] = list(dict.fromkeys(
                            (rule.conditions.get("message_contains") or []) + [str(x) for x in extra_msg if x]
                        ))
            # P1: generalize → dedup → validate → overlay/candidate/dismissed
            rule = ingest_learned_rule(
                match_id,
                rule,
                evt,
                existing_rules=overlay.rules_for(match_id),
                history_events=history_events,
            )
            learned.append(rule)
            if persist_kb:
                await self._persist_kb(rule, evt, round_num)
        return learned

    async def _llm_enrich(self, evt: MaterializedEvent) -> Optional[dict]:
        from prompts import render
        from audit_schemas import extract_json
        try:
            from summary_compression import summary
            system = render("security/blue_learn_system")
            user = render(
                "security/blue_learn",
                event_type=evt.event,
                severity=evt.severity,
                protocol=evt.protocol,
                message=evt.message,
                mitre_id=evt.mitre_id,
                url=evt.url,
            )
            raw = await summary.llm.chat(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                temperature=0.1,
            )
            parsed = extract_json(raw or "") or {}
            return parsed if isinstance(parsed, dict) else None
        except Exception as e:
            logger.info("[BlueLearner] LLM enrich skipped: %s", e)
            return None

    async def _persist_kb(self, rule: LearnedRule, evt: MaterializedEvent, round_num: int) -> None:
        try:
            from models import async_session
            from rag.knowledge_base import kb_manager
            content = (
                f"Self-Play 漏报反哺候选规则 {rule.rule_id}\n"
                f"MITRE {rule.mitre_id} event={evt.event}\n"
                f"message={evt.message}\n"
                f"conditions={rule.conditions}\n"
                f"status=candidate (未写入生产 Sigma)"
            )
            async with async_session() as session:
                await kb_manager.add_document(
                    session,
                    title=rule.title,
                    content=content,
                    source="self-play",
                    threat_types=[rule.attack_type] if rule.attack_type else [],
                    severity=rule.severity,
                    tags=["self-play", "candidate", rule.mitre_id or ""],
                    metadata={"rule_id": rule.rule_id, "round": round_num},
                    submitted_by="blue_learner",
                    auto_signed=False,
                )
        except Exception as e:
            logger.info("[BlueLearner] KB persist skipped: %s", e)
