"""红队 Agent — 规划对抗场景(仿真日志),根据蓝队覆盖做规避。

不调用真实攻击工具。LLM 可选;默认走课程目录 + 规则规划,保证离线可复现。
use_llm=true 时: RAG 召回 ATT&CK 候选(最多 8 条) → LLM 编排 2–5 步杀伤链。
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from typing import Any, Optional

from self_play.catalog import (
    DECOY_TEMPLATES, MAX_CURRICULUM_LEVEL, TTPSpec,
    enterprise_pool, get_ttp, lexical_candidates, ttps_at_level,
)
from self_play.planner import ExecutablePlanner
from self_play.types import AttackPlan, AttackStep, BlueView, RoundGoal

logger = logging.getLogger(__name__)

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_MAX_CHAIN = 5
_DEFAULT_RAG_K = 8


def _clip(text: Any, n: int = 240) -> str:
    s = str(text or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _rag_top_k() -> int:
    try:
        from config import settings
        return max(3, int(getattr(settings, "self_play_rag_top_k", _DEFAULT_RAG_K) or _DEFAULT_RAG_K))
    except Exception:
        return _DEFAULT_RAG_K


def _llm_timeout() -> float:
    try:
        from config import settings
        return float(getattr(settings, "self_play_llm_timeout_s", 20) or 20)
    except Exception:
        return 20.0


class RedAgent:
    """红队策略:课程学习 + 规避已检出特征 + 可选 LLM 多步规划。"""

    def __init__(self, *, use_llm: bool = False) -> None:
        self.use_llm = bool(use_llm)
        self.memory: dict[str, dict] = {}

    def remember(self, key: str, *, detected: bool) -> None:
        if not key:
            return
        slot = self.memory.setdefault(key, {"detected": False, "count": 0})
        slot["detected"] = bool(detected)
        slot["count"] = int(slot.get("count") or 0) + 1

    def observe_gaps(self, missed: list[str], covered: list[str]) -> None:
        """P5-A: 蓝队盲区回灌 — missed 记为未检出(FN 累计),covered 记为已检出。"""
        for key in missed or []:
            k = str(key or "").strip()
            if not k:
                continue
            slot = self.memory.setdefault(k, {"detected": False, "count": 0})
            slot["detected"] = False
            slot["count"] = int(slot.get("count") or 0) + 1
        for key in covered or []:
            k = str(key or "").strip()
            if not k:
                continue
            slot = self.memory.setdefault(k, {"detected": False, "count": 0})
            slot["detected"] = True
            slot["count"] = int(slot.get("count") or 0) + 1

    def prefer_gap_specs(self, pool: list[TTPSpec]) -> list[TTPSpec]:
        """P5-B: 按 (未检出优先, FN 次数多优先) 排序候选 TTP。"""

        def _rank(t: TTPSpec) -> tuple[int, int]:
            mem: dict = {}
            for key in (t.ttp_id, t.mitre_id, t.event_type):
                slot = self.memory.get(key)
                if slot:
                    mem = slot
                    break
            detected = bool(mem.get("detected"))
            count = int(mem.get("count") or 0)
            return (1 if detected else 0, -count)

        return sorted(list(pool or []), key=_rank)

    def covered_tokens(self, extra: Optional[list[str]] = None) -> set[str]:
        out = {k.upper() for k, v in self.memory.items() if v.get("detected")}
        for t in extra or []:
            if t:
                out.add(str(t).upper())
        return out

    def _wants_evasion(self, spec: TTPSpec, coverage: set[str]) -> bool:
        if spec.event_type.upper() in coverage:
            return True
        mem = self.memory.get(spec.event_type) or self.memory.get(spec.ttp_id) or {}
        return bool(mem.get("detected"))

    def _pick_variant(self, spec: TTPSpec, coverage: set[str]) -> tuple[str, str, str, bool, int]:
        if not self._wants_evasion(spec, coverage) or not spec.variants:
            return spec.event_type, spec.message, spec.protocol, False, -1
        for i, var in enumerate(spec.variants):
            ev = str(var.get("event") or "")
            if ev.upper() not in coverage:
                return (
                    ev,
                    str(var.get("message") or spec.message),
                    str(var.get("protocol") or spec.protocol),
                    True,
                    i,
                )
        var = spec.variants[-1]
        return (
            str(var.get("event") or spec.event_type),
            str(var.get("message") or spec.message),
            str(var.get("protocol") or spec.protocol),
            True,
            len(spec.variants) - 1,
        )

    def _spec_from_goal(self, goal: Optional[RoundGoal]) -> Optional[TTPSpec]:
        if goal is None:
            return None
        for key in (
            getattr(goal, "ttp_id", ""),
            getattr(goal, "sub_technique_id", ""),
            getattr(goal, "technique_id", ""),
        ):
            spec = get_ttp(str(key or ""))
            if spec is not None:
                return spec
        return None

    def _choose_spec(
        self, level: int, coverage: set[str], *,
        pool: Optional[list[TTPSpec]] = None, blue: Optional[BlueView] = None,
        goal: Optional[RoundGoal] = None,
    ) -> TTPSpec:
        # P2-A: 有 RoundGoal 时,无论 LLM / 目录路径都先锁 goal 的技术/子技术
        goal_spec = self._spec_from_goal(goal)
        if goal_spec is not None:
            return goal_spec

        src = ttps_at_level(level, inclusive=True, pool=pool)
        if not src:
            src = ttps_at_level(0, inclusive=True, pool=pool)
        current = [t for t in src if t.curriculum_level == level] or src

        if blue and blue.last_outcome == "red_win":
            for key in blue.last_missed or []:
                hit = get_ttp(str(key))
                if hit:
                    return hit

        # P5-B: 无 goal 强制时,盲区(未检出/FN 多)优先;空记忆时排序稳定,行为不变
        if self.memory:
            current = self.prefer_gap_specs(current)

        for spec in current:
            if spec.event_type.upper() not in coverage:
                return spec
        for spec in reversed(src):
            if spec.event_type.upper() not in coverage:
                return spec
        return current[0]

    def _step_from_spec(
        self, spec: TTPSpec, coverage: set[str], *,
        force_evasion: Optional[bool] = None, variant_index: int = -1,
    ) -> AttackStep:
        if force_evasion is False:
            event, message, protocol, evasion, vidx = (
                spec.event_type, spec.message, spec.protocol, False, -1,
            )
        elif force_evasion is True or variant_index >= 0:
            variants = spec.variants
            if variants:
                vidx = max(0, min(int(variant_index), len(variants) - 1)) if variant_index >= 0 else 0
                var = variants[vidx]
                event = str(var.get("event") or spec.event_type)
                message = str(var.get("message") or spec.message)
                protocol = str(var.get("protocol") or spec.protocol)
                evasion, vidx = True, vidx
            else:
                event, message, protocol, evasion, vidx = (
                    spec.event_type, spec.message, spec.protocol, False, -1,
                )
        else:
            event, message, protocol, evasion, vidx = self._pick_variant(spec, coverage)
        return AttackStep(
            step_id=f"s-{uuid.uuid4().hex[:8]}",
            ttp_id=spec.ttp_id,
            mitre_id=spec.mitre_id,
            tactic=spec.tactic,
            kill_chain=spec.kill_chain,
            name=spec.name,
            event_type=event,
            severity=spec.severity,
            protocol=protocol,
            message=message,
            dst_role=spec.dst_role,
            tool=spec.tool,
            evasion=evasion,
            variant_of=spec.event_type if evasion else "",
            is_attack=True,
            sub_technique_id=spec.sub_technique_id or "",
            behaviors=list(spec.behaviors),
            data_sources=list(spec.data_sources),
            extra={"variant_index": vidx},
        )

    def _decoy_step(self, idx: int = 0) -> AttackStep:
        tpl = DECOY_TEMPLATES[idx % len(DECOY_TEMPLATES)]
        return AttackStep(
            step_id=f"d-{uuid.uuid4().hex[:8]}",
            ttp_id="decoy",
            mitre_id="",
            tactic="benign",
            kill_chain="benign",
            name="Benign traffic",
            event_type=str(tpl["event"]),
            severity=str(tpl["severity"]),
            protocol=str(tpl["protocol"]),
            message=str(tpl["message"]),
            dst_role=str(tpl.get("dst_role") or "ws"),
            tool="sim:benign",
            is_attack=False,
        )

    def _candidate_rows(self, specs: list[TTPSpec]) -> list[dict]:
        return [
            {
                "ttp_id": t.ttp_id,
                "mitre_id": t.mitre_id,
                "name": t.name,
                "tactic": t.tactic,
                "level": t.curriculum_level,
                "event_type": t.event_type,
                "variants": [v.get("event") for v in t.variants],
            }
            for t in specs
        ]

    def _resolve_spec(self, raw: Any, allowed: list[TTPSpec]) -> Optional[TTPSpec]:
        key = str(raw or "").strip()
        if not key:
            return None
        hit = get_ttp(key)
        allow_ids = {t.ttp_id.lower() for t in allowed} | {t.mitre_id.upper() for t in allowed}
        if hit and (hit.ttp_id.lower() in allow_ids or hit.mitre_id.upper() in allow_ids):
            return next(
                (t for t in allowed if t.mitre_id.upper() == hit.mitre_id.upper()),
                hit,
            )
        ku = key.upper()
        for t in allowed:
            if t.ttp_id.lower() == key.lower() or t.mitre_id.upper() == ku:
                return t
        return None

    async def _rag_hints_and_specs(
        self, query: str, *, level: int, covered: list[str], prefer: list[str],
    ) -> tuple[list[str], list[TTPSpec]]:
        hints: list[str] = []
        found: list[TTPSpec] = []
        seen: set[str] = set()
        top_k = _rag_top_k()
        try:
            from models import async_session
            from rag.retriever import retriever
            async with async_session() as session:
                result = await retriever.retrieve(
                    session, query=query, source="mitre-attack",
                    top_k=top_k, skip_llm=True, min_score=0.0,
                )
            for c in (result.chunks or [])[:top_k]:
                if not isinstance(c, dict):
                    continue
                title = str(c.get("title") or "")
                content = str(c.get("content") or c.get("text") or "")
                blob = f"{title} {content}"
                hints.append(_clip(blob, 200))
                for tid in _TID_RE.findall(blob):
                    spec = get_ttp(tid)
                    if spec and spec.mitre_id.upper() not in seen:
                        seen.add(spec.mitre_id.upper())
                        found.append(spec)
        except Exception as e:
            logger.debug("[RedAgent] RAG retrieve skipped: %s", e)

        if len(found) < 3:
            for spec in lexical_candidates(
                query, level=level, top_k=top_k,
                covered=covered, prefer_ids=prefer, use_enterprise=True,
            ):
                if spec.mitre_id.upper() not in seen:
                    seen.add(spec.mitre_id.upper())
                    found.append(spec)
                if len(found) >= top_k:
                    break
        return hints[:top_k], found[:top_k]

    async def _llm_pick(
        self,
        level: int,
        coverage: list[str],
        last_outcome: str,
        rag_hints: list[str],
        candidates: list[TTPSpec],
        blue: BlueView,
        goal: Optional[RoundGoal] = None,
    ) -> Optional[dict]:
        from prompts import render
        from audit_schemas import extract_json

        blue_payload = blue.to_dict()
        if goal is not None:
            # 课程目标随既有字段进 prompt(模板不变,保持 strict_render 兼容)
            blue_payload = dict(blue_payload)
            blue_payload["round_goal"] = goal.to_dict() if hasattr(goal, "to_dict") else dict(goal)

        system = render("security/red_plan_system")
        user = render(
            "security/red_plan",
            level=level,
            coverage="\n".join(coverage) or "(empty)",
            catalog=json.dumps(self._candidate_rows(candidates), ensure_ascii=False),
            rag_hints="\n".join(_clip(h, 200) for h in rag_hints) or "(none)",
            last_outcome=last_outcome or "(none)",
            blue_view=json.dumps(blue_payload, ensure_ascii=False),
        )
        try:
            from summary_compression import summary
            raw = await asyncio.wait_for(
                summary.llm.chat(
                    [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.2,
                ),
                timeout=_llm_timeout(),
            )
            parsed = extract_json(raw or "") or {}
            return parsed if isinstance(parsed, dict) else None
        except Exception as e:
            logger.warning("[RedAgent] LLM plan skipped: %s", e)
            return None

    def _steps_from_llm(
        self, llm_choice: dict, allowed: list[TTPSpec], coverage: set[str],
    ) -> tuple[list[AttackStep], Optional[bool]]:
        raw_steps = llm_choice.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            # 兼容旧单步 schema
            raw_steps = [{
                "ttp_id": llm_choice.get("ttp_id"),
                "use_evasion": llm_choice.get("use_evasion"),
                "variant_index": llm_choice.get("variant_index", -1),
            }]
        out: list[AttackStep] = []
        add_decoy: Optional[bool] = None
        if "add_decoy" in llm_choice:
            add_decoy = bool(llm_choice.get("add_decoy"))
        for item in raw_steps[:_MAX_CHAIN]:
            if not isinstance(item, dict):
                continue
            spec = self._resolve_spec(item.get("ttp_id") or item.get("mitre_id"), allowed)
            if spec is None:
                continue
            force: Optional[bool] = None
            if "use_evasion" in item:
                force = bool(item.get("use_evasion"))
            try:
                vidx = int(item.get("variant_index", -1))
            except (TypeError, ValueError):
                vidx = -1
            out.append(self._step_from_spec(
                spec, coverage, force_evasion=force, variant_index=vidx,
            ))
        return out, add_decoy

    async def plan_attack(
        self,
        *,
        match_id: str,
        round_num: int,
        level: int,
        blue_coverage: Optional[list[str]] = None,
        last_outcome: str = "",
        decoy_ratio: float = 0.2,
        use_llm: Optional[bool] = None,
        curriculum: bool = True,
        blue_view: Optional[BlueView] = None,
        goal: Optional[RoundGoal] = None,
    ) -> AttackPlan:
        level = max(0, min(int(level), MAX_CURRICULUM_LEVEL))
        want_llm = self.use_llm if use_llm is None else bool(use_llm)
        blue = blue_view or BlueView(last_outcome=last_outcome)
        if last_outcome and not blue.last_outcome:
            blue.last_outcome = last_outcome
        coverage = self.covered_tokens(list(blue_coverage or []) + list(blue.covered_events or []))
        coverage_list = sorted(coverage)
        rag_hints: list[str] = []
        llm_choice: Optional[dict] = None

        # P2: 课程统一下发的目标,LLM 与目录两条路径都必须围绕它
        goal_spec = self._spec_from_goal(goal)
        use_enterprise = want_llm or (not curriculum)
        pool = enterprise_pool() if use_enterprise else None
        prefer = list(blue.last_missed or []) + list(blue.learned_tokens or [])
        if goal_spec is not None:
            prefer = [goal_spec.mitre_id, goal_spec.ttp_id] + prefer

        candidates: list[TTPSpec] = []
        if want_llm:
            query = " ".join([
                "MITRE ATT&CK",
                blue.last_outcome,
                " ".join(blue.last_missed[:6]),
                " ".join(blue.learned_tokens[:6]),
                goal_spec.mitre_id if goal_spec is not None else "",
                "uncovered gap" if blue.recall >= 0.8 else "next kill chain",
            ]).strip()
            rag_hints, candidates = await self._rag_hints_and_specs(
                query, level=level, covered=coverage_list, prefer=prefer,
            )
            if candidates:
                llm_choice = await self._llm_pick(
                    level, coverage_list, blue.last_outcome or last_outcome,
                    rag_hints, candidates, blue, goal=goal,
                )

        allowed = candidates or ttps_at_level(level, inclusive=True, pool=pool)
        if goal_spec is not None and all(
            t.mitre_id.upper() != goal_spec.mitre_id.upper() for t in allowed
        ):
            allowed = [goal_spec] + list(allowed)

        steps: list[AttackStep] = []
        rationale = f"curriculum L{level}"
        add_decoy = decoy_ratio > 0

        if llm_choice:
            raw_steps, decoy_flag = self._steps_from_llm(llm_choice, allowed, coverage)
            if decoy_flag is not None:
                add_decoy = decoy_flag
            rationale = _clip(llm_choice.get("rationale") or rationale, 300)
            if goal is not None:
                # P2-B: LLM 步骤必须落在 goal 允许集;全被拒则回退 goal 金标
                planner = ExecutablePlanner()
                steps = planner.constrain_steps(raw_steps, goal, allowed)
                if not steps:
                    spec = goal_spec or self._choose_spec(level, coverage, pool=pool, goal=goal)
                    steps = [self._step_from_spec(spec, coverage)]
                    rationale = f"{rationale} → goal fallback {spec.mitre_id}"
            else:
                steps = raw_steps

        if not steps:
            if goal_spec is not None:
                spec = goal_spec
                rationale = f"curriculum L{level} goal → {spec.ttp_id} ({spec.mitre_id})"
            else:
                spec = self._choose_spec(level, coverage, pool=pool, blue=blue if use_enterprise else None)
                rationale = f"curriculum L{level} → {spec.ttp_id} ({spec.mitre_id})"
            force_evasion: Optional[bool] = None
            if goal is not None:
                # P5-C: goal 锁技术;盲区/覆盖只影响变体与参数,不推翻课程
                if spec.event_type.upper() in coverage or blue.recall >= 0.8 or blue.last_outcome == "blue_win":
                    force_evasion = True
            elif blue.last_outcome == "blue_win" or blue.recall >= 0.8:
                force_evasion = True
            elif blue.last_outcome == "red_win":
                force_evasion = True
            steps = [self._step_from_spec(spec, coverage, force_evasion=force_evasion)]

        decoys = [self._decoy_step(round_num)] if add_decoy else []
        return AttackPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:10]}",
            match_id=match_id,
            round_num=round_num,
            curriculum_level=level,
            rationale=rationale,
            steps=steps,
            decoys=decoys,
            rag_hints=rag_hints,
            blue_visible=coverage_list,
            goal=dict(goal.to_dict()) if goal is not None else {},
        )
