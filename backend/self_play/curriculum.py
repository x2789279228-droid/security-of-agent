"""CurriculumPolicy — 统一课程控制器 (P2)。

唯一给红队下发 RoundGoal 的入口;升级/降级只看 P(level_clear) 与 rounds_at_level,
不再使用 consecutive_blue_wins 作为升级触发。
全部状态可 JSON 序列化 (CapabilityState),供 Temporal activity 使用。
"""
from __future__ import annotations

from typing import Optional

from self_play.catalog import MAX_CURRICULUM_LEVEL, TTPSpec, get_ttp, ttps_at_level
from self_play.types import CapabilityState, RoundGoal

_EMA_ALPHA = 0.4
_OUTCOME_WINDOW = 5
_UPGRADE_ROUNDS = 3
_UPGRADE_P = 0.8
_DOWNGRADE_ROUNDS = 4
_DOWNGRADE_P = 0.25


def _parent_id(mitre_id: str) -> str:
    mid = str(mitre_id or "").upper().strip()
    return mid.split(".")[0] if mid else ""


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


class CurriculumPolicy:
    """课程策略: 选目标 → 红队执行 → update() 能力模型 → maybe_advance() 升降级。"""

    def __init__(self) -> None:
        # 每个等级见过的 technique key(进程内簿记,用于把 p_level_clear 限定在当前等级)
        self._seen: dict[int, set[str]] = {}

    # ------------------------------------------------------------------ select
    def select_goal(
        self,
        *,
        level: int,
        coverage: list[str],
        last_missed: list[str],
        capability: CapabilityState | dict | None,
        gaps: list[str] | None = None,
    ) -> RoundGoal:
        """在当前等级内选 technique / sub-technique。

        - 优先未覆盖的 event_type / sub-technique;
        - last_missed / gaps 只有属于当前等级(含该等级父技术的子技术)才优先,不跳级;
        - 约束: dst_role / protocol / kill_chain / require_variant(事件已覆盖时要求变体);
        - allowed_ttps: 本等级全部 mitre id + 所选父技术的全部子技术。
        """
        level = max(0, min(int(level), MAX_CURRICULUM_LEVEL))
        cov = {str(c).upper() for c in (coverage or []) if c}
        specs = ttps_at_level(level, inclusive=False) or ttps_at_level(level, inclusive=True)
        if not specs:
            fallback = get_ttp("T1046")
            specs = [fallback] if fallback is not None else []

        def _covered(spec: TTPSpec) -> bool:
            return (
                spec.event_type.upper() in cov
                or spec.mitre_id.upper() in cov
                or spec.ttp_id.upper() in cov
            )

        chosen: Optional[TTPSpec] = None
        prefer_gap = False
        for key in list(last_missed or []) + list(gaps or []):
            spec = get_ttp(str(key))
            if spec is None:
                ku = str(key).upper()
                spec = next((s for s in specs if s.event_type.upper() == ku), None)
            if spec is None or _covered(spec):
                continue
            if spec.curriculum_level != level:
                # 子技术跟随其父技术的等级,父技术在当前等级才允许
                parent = _parent_id(spec.mitre_id)
                parent_spec = get_ttp(parent) if spec.sub_technique_id else None
                if parent_spec is None or parent_spec.curriculum_level != level:
                    continue
            chosen = spec
            prefer_gap = True
            break

        if chosen is None:
            uncovered = [s for s in specs if not _covered(s)]
            if uncovered:
                chosen = uncovered[0]
        if chosen is None:
            chosen = specs[0]

        parent = _parent_id(chosen.mitre_id) or chosen.mitre_id
        allowed: list[str] = []
        for s in ttps_at_level(level, inclusive=False):
            mid = s.mitre_id.upper()
            if mid not in allowed:
                allowed.append(mid)
        for s in ttps_at_level(MAX_CURRICULUM_LEVEL, inclusive=True):
            if _parent_id(s.mitre_id) == parent:
                mid = s.mitre_id.upper()
                if mid not in allowed:
                    allowed.append(mid)

        p_clear = 0.0
        if capability is not None:
            try:
                p_clear = float(getattr(capability, "p_level_clear", 0.0) or 0.0)
            except (TypeError, ValueError):
                p_clear = 0.0

        return RoundGoal(
            technique_id=parent,
            sub_technique_id=chosen.sub_technique_id or "",
            ttp_id=chosen.ttp_id,
            event_type=chosen.event_type,
            scenario=chosen.kill_chain,
            difficulty=level,
            constraints={
                "dst_role": chosen.dst_role,
                "protocol": chosen.protocol,
                "kill_chain": chosen.kill_chain,
                "require_variant": _covered(chosen),
            },
            prefer_gap=prefer_gap,
            rationale=(
                f"curriculum L{level} → {chosen.ttp_id} ({chosen.mitre_id}) "
                f"p_clear={p_clear:.2f}"
            ),
            allowed_ttps=allowed,
        )

    # ----------------------------------------------------------------- update
    def update(
        self,
        capability: CapabilityState,
        *,
        technique_id: str,
        detected: bool,
        outcome: str,
        tick_round: bool = True,
    ) -> CapabilityState:
        """EMA α=0.4 更新 recall / asr (asr=1 if miss),滚动 outcome,重算 P(level_clear)。

        tick_round=False 时只更新技术 EMA,不增加 rounds_at_level(多步杀伤链同一回合)。
        """
        cap = capability if capability is not None else CapabilityState()
        tid = str(technique_id or "").upper().strip()
        if tid:
            rec = 1.0 if detected else 0.0
            asr = 0.0 if detected else 1.0
            keys = [tid]
            parent = _parent_id(tid)
            if parent and parent != tid:
                keys.append(parent)
            for key in keys:
                old_r = cap.technique_recalls.get(key)
                cap.technique_recalls[key] = (
                    rec if old_r is None else (1 - _EMA_ALPHA) * float(old_r) + _EMA_ALPHA * rec
                )
                old_a = cap.technique_asrs.get(key)
                cap.technique_asrs[key] = (
                    asr if old_a is None else (1 - _EMA_ALPHA) * float(old_a) + _EMA_ALPHA * asr
                )
            lv = int(cap.level or 0)
            seen = self._seen.setdefault(lv, set())
            seen.update(keys)
            bucket = list((cap.seen_by_level or {}).get(str(lv)) or [])
            for key in keys:
                if key not in bucket:
                    bucket.append(key)
            cap.seen_by_level[str(lv)] = bucket

        if tick_round:
            outcomes = [str(o) for o in (cap.recent_outcomes or [])]
            outcomes.append(str(outcome or ""))
            cap.recent_outcomes = outcomes[-_OUTCOME_WINDOW:]
            cap.rounds_at_level = int(cap.rounds_at_level or 0) + 1
            wins = sum(1 for o in cap.recent_outcomes if o == "blue_win")
            cap.blue_win_rate = (wins / len(cap.recent_outcomes)) if cap.recent_outcomes else 0.0
        cap.p_level_clear = self.p_level_clear(cap)
        return cap

    # ---------------------------------------------------------- p_level_clear
    def p_level_clear(self, capability: CapabilityState) -> float:
        """P(本等级清关) = 0.4*mean_recall + 0.3*(1-mean_asr) + 0.3*blue_win_rate。"""
        cap = capability if capability is not None else CapabilityState()
        level = int(getattr(cap, "level", 0) or 0)
        seen = self._seen.get(level) or set()
        if not seen:
            extra = (getattr(cap, "seen_by_level", None) or {}).get(str(level)) or []
            seen = set(str(x).upper() for x in extra if x)

        recalls = dict(getattr(cap, "technique_recalls", {}) or {})
        asrs = dict(getattr(cap, "technique_asrs", {}) or {})
        if seen:
            rec_vals = [float(v) for k, v in recalls.items() if k in seen]
            asr_vals = [float(v) for k, v in asrs.items() if k in seen]
        else:
            rec_vals = [float(v) for v in recalls.values()]
            asr_vals = [float(v) for v in asrs.values()]

        mean_recall = (sum(rec_vals) / len(rec_vals)) if rec_vals else 0.0
        mean_asr = (sum(asr_vals) / len(asr_vals)) if asr_vals else 0.0

        outcomes = [str(o) for o in (getattr(cap, "recent_outcomes", []) or [])]
        if outcomes:
            win_rate = sum(1 for o in outcomes if o == "blue_win") / len(outcomes)
        else:
            win_rate = float(getattr(cap, "blue_win_rate", 0.0) or 0.0)

        p = 0.4 * mean_recall + 0.3 * (1.0 - mean_asr) + 0.3 * win_rate
        return _clamp01(p)

    # ---------------------------------------------------------- maybe_advance
    def maybe_advance(self, capability: CapabilityState, *, max_level: int = 6) -> CapabilityState:
        """升级: rounds_at_level>=3 且 P>0.8;降级: rounds_at_level>=4 且 P<0.25 且 level>0。"""
        cap = capability if capability is not None else CapabilityState()
        level = int(getattr(cap, "level", 0) or 0)
        rounds = int(getattr(cap, "rounds_at_level", 0) or 0)
        p = float(getattr(cap, "p_level_clear", 0.0) or 0.0)

        def _reset(lv: int) -> None:
            cap.level = int(lv)
            cap.rounds_at_level = 0
            cap.recent_outcomes = []
            cap.blue_win_rate = 0.0
            cap.p_level_clear = 0.0

        if rounds >= _UPGRADE_ROUNDS and p > _UPGRADE_P and level < int(max_level):
            _reset(level + 1)
        elif rounds >= _DOWNGRADE_ROUNDS and p < _DOWNGRADE_P and level > 0:
            _reset(level - 1)
        return cap
