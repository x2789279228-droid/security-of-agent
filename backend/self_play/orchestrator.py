"""Self-Play 编排器 — 红队规划 → 仿真物化 → 蓝队观察 → 评分 → 双方更新策略。"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Optional

from self_play.blue_learner import BlueLearner
from self_play.blue_observer import BlueObserver
from self_play.catalog import MAX_CURRICULUM_LEVEL
from self_play.curriculum import CurriculumPolicy
from self_play.events import publish
from self_play.metrics import decide_winner, merge_metrics, round_metrics_from_dict, score_round
from self_play.novelty import NoveltyIndex, fingerprint
from self_play.overlay import overlay
from self_play.planner import ExecutablePlanner
from self_play.red_agent import RedAgent
from self_play.sim_env import SimEnv
from self_play.types import BlueView, CapabilityState, MatchConfig, RoundGoal, RoundMetrics

logger = logging.getLogger(__name__)

_LIVE: dict[str, dict] = {}
_STOP: set[str] = set()
_LOCK = asyncio.Lock()
_RUNNING = 0


def live_match(match_id: str) -> Optional[dict]:
    return _LIVE.get(match_id)


def live_matches() -> list[dict]:
    return list(_LIVE.values())


def request_stop(match_id: str) -> bool:
    _STOP.add(match_id)
    snap = _LIVE.get(match_id)
    if snap is not None:
        snap["status"] = "stopping"
    return True


def _new_match_id() -> str:
    return f"sp-{uuid.uuid4().hex[:12]}"


def _outcome(metrics: RoundMetrics) -> str:
    if metrics.attacks <= 0:
        return "decoy_only"
    if metrics.fn > 0 and metrics.tp == 0:
        return "red_win"
    if metrics.fn == 0 and metrics.tp > 0:
        return "blue_win"
    return "mixed"


def _winner(cum: dict) -> str:
    """综合分胜负;旧硬阈值见 metrics.decide_winner_legacy。"""
    return decide_winner(cum)


def _seed_from_match_id(match_id: str) -> int:
    hexish = re.sub(r"[^0-9a-fA-F]", "", str(match_id or ""))[-4:] or "1"
    try:
        return max(1, int(hexish, 16))
    except ValueError:
        return 1


def _restore_policy(state: dict) -> tuple[CurriculumPolicy, CapabilityState]:
    policy = CurriculumPolicy()
    cap = CapabilityState.from_dict(state.get("capability") or {})
    cap.level = int(state.get("level") or cap.level or 0)
    seen_raw = cap.seen_by_level or state.get("capability_seen") or {}
    restored: dict[int, set[str]] = {}
    for k, v in dict(seen_raw).items():
        try:
            restored[int(k)] = {str(x).upper() for x in (v or []) if x}
        except (TypeError, ValueError):
            continue
    policy._seen = restored
    cap.seen_by_level = {str(k): sorted(v) for k, v in restored.items()}
    return policy, cap


class SelfPlayOrchestrator:
    def __init__(self) -> None:
        self.env = SimEnv()
        self.observer = BlueObserver()

    def _make_env(self, cfg: MatchConfig, match_id: str) -> SimEnv:
        if cfg.diverse_env:
            seed = int(cfg.env_seed or 0) or _seed_from_match_id(match_id)
            return SimEnv(diverse=True, seed=seed)
        return self.env

    def _empty_state(self, cfg: MatchConfig) -> dict:
        match_id = cfg.match_id or _new_match_id()
        cfg.match_id = match_id
        return {
            "match_id": match_id,
            "config": cfg.to_dict(),
            "round_num": 0,
            "level": int(cfg.start_level or 0),
            "blue_coverage": [],
            "history_tokens": [],
            "round_metrics": [],
            "rounds": [],
            "consecutive_blue_wins": 0,
            "last_outcome": "",
            "last_missed": [],
            "last_metrics": {},
            "stopped": False,
            "red_memory": {},
            "learner_seq": 0,
            "overlay_rules": [],
            "capability": CapabilityState(level=int(cfg.start_level or 0)).to_dict(),
            "capability_seen": {},
            "history_layered": {},
            "history_events": [],
            "last_goal": {},
        }

    async def init_match(self, cfg: MatchConfig | dict) -> dict:
        cfg = cfg if isinstance(cfg, MatchConfig) else MatchConfig.from_dict(cfg)
        state = self._empty_state(cfg)
        match_id = state["match_id"]
        overlay.clear(match_id)
        if cfg.persist:
            try:
                from self_play import store
                prior = await store.load_candidate_rules()
                overlay.seed(match_id, prior)
                await store.save_match_start(cfg.to_dict(), match_id)
            except Exception as e:
                logger.info("[SelfPlay] persist init skipped: %s", e)
        _LIVE[match_id] = {
            "match_id": match_id,
            "status": "running",
            "round_num": 0,
            "level": state["level"],
            "metrics": {},
            "rounds": [],
            "config": cfg.to_dict(),
        }
        publish("selfplay_match", {
            "match_id": match_id, "status": "running", "phase": "init",
            "level": state["level"], "rounds": cfg.rounds,
        })
        return state

    async def play_round(self, state: dict) -> dict:
        cfg = MatchConfig.from_dict(state.get("config") or {})
        match_id = state["match_id"]
        if match_id in _STOP:
            state["stopped"] = True
            return state

        for rule in state.get("overlay_rules") or []:
            if isinstance(rule, dict):
                overlay.add(match_id, rule)

        state["round_num"] = int(state.get("round_num") or 0) + 1
        round_num = state["round_num"]
        level = int(state.get("level") or 0)
        coverage = list(state.get("blue_coverage") or [])
        env = self._make_env(cfg, match_id)

        last_metrics = dict(state.get("last_metrics") or {})
        learned_tokens: list[str] = []
        for rule in state.get("overlay_rules") or []:
            if not isinstance(rule, dict):
                continue
            cond = rule.get("conditions") or {}
            for key in ("event_contains", "message_contains"):
                for tok in cond.get(key) or []:
                    if tok:
                        learned_tokens.append(str(tok))
        blue = BlueView(
            last_outcome=str(state.get("last_outcome") or ""),
            recall=float(last_metrics.get("recall") or 0.0),
            asr=float(last_metrics.get("asr") or 0.0),
            covered_events=list(coverage),
            last_missed=list(state.get("last_missed") or []),
            overlay_rule_count=len(state.get("overlay_rules") or []),
            consecutive_blue_wins=int(state.get("consecutive_blue_wins") or 0),
            learned_tokens=learned_tokens[:12],
            last_goal=dict(state.get("last_goal") or {}),
            detection_gaps=list(state.get("last_missed") or []),
        )

        policy, cap = _restore_policy(state)
        goal: Optional[RoundGoal] = None
        if cfg.curriculum:
            goal = policy.select_goal(
                level=level,
                coverage=coverage,
                last_missed=list(state.get("last_missed") or []),
                capability=cap,
                gaps=list(state.get("last_missed") or []),
            )

        red = RedAgent(use_llm=cfg.use_llm)
        red.memory = dict(state.get("red_memory") or {})
        plan = await red.plan_attack(
            match_id=match_id,
            round_num=round_num,
            level=level,
            blue_coverage=coverage,
            last_outcome=str(state.get("last_outcome") or ""),
            decoy_ratio=float(cfg.decoy_ratio or 0),
            use_llm=cfg.use_llm,
            curriculum=bool(cfg.curriculum),
            blue_view=blue,
            goal=goal,
        )
        if cfg.diverse_env and plan.steps:
            planner = ExecutablePlanner(env)
            if goal is not None:
                plan.steps = planner.constrain_steps(plan.steps, goal)
            for step in plan.steps:
                if not planner.role_available(step.dst_role):
                    step.dst_role = planner.similar_role(step.dst_role)

        bg_n = 4 if cfg.background_traffic else 0
        events = env.materialize_plan(plan.steps, plan.decoys, background_n=bg_n)
        channel = str(cfg.eval_channel or "sim")
        for evt in events:
            evt.eval_channel = channel
            evt.fingerprint = fingerprint(evt.event, evt.message, evt.mitre_id, evt.protocol)

        observations = await self.observer.observe_many(
            match_id, events,
            inject=bool(cfg.inject),
            session_id=f"selfplay-{match_id}",
            wait_audit=bool(cfg.wait_audit),
            wait_audit_s=float(cfg.wait_audit_s or 8),
            eval_channel=channel,
        )

        novelty = NoveltyIndex()
        novelty.load(state.get("history_tokens") or [])
        if hasattr(novelty, "load_layered"):
            novelty.load_layered(state.get("history_layered") or {})
        metrics = score_round(events, observations, novelty)

        for evt in events:
            if evt.is_attack:
                if hasattr(novelty, "observe_event"):
                    novelty.observe_event(evt)
                else:
                    novelty.observe({evt.event, evt.mitre_id, evt.protocol})
        state["history_tokens"] = novelty.dump()
        if hasattr(novelty, "dump_layered"):
            state["history_layered"] = novelty.dump_layered()

        history = list(state.get("history_events") or [])
        learner = BlueLearner()
        learner._seq = int(state.get("learner_seq") or 0)
        learned = await learner.learn_from_misses(
            match_id, events, [o.detected for o in observations],
            use_llm=cfg.use_llm, persist_kb=cfg.persist_kb, round_num=round_num,
            history_events=history,
        )
        state["learner_seq"] = learner._seq
        if learned:
            existing = list(state.get("overlay_rules") or [])
            existing.extend(r.to_dict() for r in learned)
            state["overlay_rules"] = existing
        for evt in events:
            history.append(evt.to_dict())
        state["history_events"] = history[-240:]

        new_coverage = list(coverage)
        for evt, obs in zip(events, observations):
            if not evt.is_attack:
                continue
            red.remember(evt.event, detected=obs.detected)
            red.remember(evt.ttp_id, detected=obs.detected)
            if evt.mitre_id:
                red.remember(evt.mitre_id, detected=obs.detected)
            if obs.detected:
                token = evt.event.upper()
                if token not in new_coverage:
                    new_coverage.append(token)
                for rid in obs.rule_ids:
                    if rid and rid not in new_coverage:
                        new_coverage.append(str(rid))
        missed: list[str] = []
        covered_now: list[str] = []
        for evt, obs in zip(events, observations):
            if not evt.is_attack:
                continue
            if obs.detected:
                for key in (evt.event, evt.mitre_id, evt.ttp_id):
                    if key and str(key) not in covered_now:
                        covered_now.append(str(key))
            else:
                for key in (evt.event, evt.mitre_id, evt.ttp_id):
                    if key and str(key) not in missed:
                        missed.append(str(key))
        red.observe_gaps(missed, covered_now)
        state["red_memory"] = red.memory
        state["blue_coverage"] = new_coverage
        state["last_missed"] = missed
        state["last_metrics"] = metrics.to_dict()
        state["last_goal"] = goal.to_dict() if goal is not None else dict(plan.goal or {})

        outcome = _outcome(metrics)
        if outcome == "blue_win":
            state["consecutive_blue_wins"] = int(state.get("consecutive_blue_wins") or 0) + 1
        else:
            state["consecutive_blue_wins"] = 0

        attacks = [(e, o) for e, o in zip(events, observations) if e.is_attack]
        if attacks:
            for i, (evt, obs) in enumerate(attacks):
                cap = policy.update(
                    cap,
                    technique_id=evt.mitre_id or evt.ttp_id,
                    detected=obs.detected,
                    outcome=outcome,
                    tick_round=(i == len(attacks) - 1),
                )
        else:
            cap = policy.update(
                cap, technique_id="", detected=False, outcome=outcome, tick_round=True,
            )
        if cfg.curriculum:
            cap = policy.maybe_advance(cap, max_level=MAX_CURRICULUM_LEVEL)
        state["level"] = int(cap.level)
        state["capability"] = cap.to_dict()
        state["capability_seen"] = {
            str(k): sorted(v) for k, v in (policy._seen or {}).items()
        }

        state["last_outcome"] = outcome
        metrics_d = metrics.to_dict()
        state.setdefault("round_metrics", []).append(metrics_d)
        cum = merge_metrics([
            round_metrics_from_dict(r) if isinstance(r, dict) else r
            for r in state["round_metrics"]
        ])

        goal_d = goal.to_dict() if goal is not None else dict(plan.goal or {})
        round_payload = {
            "round_num": round_num,
            "curriculum_level": level,
            "goal": goal_d,
            "red_plan": plan.to_dict(),
            "events": [e.to_dict() for e in events],
            "blue_obs": [o.to_dict() for o in observations],
            "outcome": outcome,
            "metrics": metrics_d,
            "learned": [r.to_dict() for r in learned],
            "cumulative": cum,
            "next_level": state["level"],
            "p_level_clear": float(cap.p_level_clear or 0),
            "eval_channel": channel,
        }
        state.setdefault("rounds", []).append({
            "round_num": round_num,
            "outcome": outcome,
            "metrics": metrics_d,
            "level": level,
            "goal": goal_d,
            "learned": [r.rule_id for r in learned],
            "plan": {
                "rationale": plan.rationale,
                "steps": [
                    {"event": s.event_type, "mitre_id": s.mitre_id, "evasion": s.evasion, "name": s.name}
                    for s in plan.steps
                ],
            },
        })

        snap = _LIVE.get(match_id) or {}
        snap.update({
            "match_id": match_id,
            "status": "running",
            "round_num": round_num,
            "level": state["level"],
            "metrics": cum,
            "radar": cum.get("radar") or {},
            "capability": state.get("capability") or {},
            "last_round": round_payload,
            "rounds": state["rounds"],
            "config": cfg.to_dict(),
        })
        _LIVE[match_id] = snap

        publish("selfplay_round", {
            "match_id": match_id,
            "round_num": round_num,
            "outcome": outcome,
            "level": level,
            "next_level": state["level"],
            "metrics": metrics_d,
            "cumulative": cum,
            "red": {
                "rationale": plan.rationale,
                "steps": [
                    {"event": s.event_type, "mitre_id": s.mitre_id,
                     "evasion": s.evasion, "name": s.name, "message": s.message}
                    for s in plan.steps
                ],
            },
            "blue": {
                "detected": [o.detected for o in observations],
                "detectors": [o.detector for o in observations],
                "learned": [r.to_dict() for r in learned],
                "candidate_detected": [o.candidate_detected for o in observations],
            },
            "goal": goal_d,
            "radar": (metrics_d.get("radar") or {}),
            "p_level_clear": float(cap.p_level_clear or 0),
        })

        if cfg.persist:
            from self_play import store
            try:
                await store.save_round(match_id, round_payload)
            except Exception as e:
                logger.warning("[SelfPlay] persist round skipped: %s", e)
            try:
                await store.save_learned_rules(
                    match_id, round_num, [r.to_dict() for r in learned],
                )
            except Exception as e:
                logger.warning("[SelfPlay] persist learned rules skipped: %s", e)
        return state

    async def finalize(self, state: dict, *, status: str = "completed") -> dict:
        cfg = MatchConfig.from_dict(state.get("config") or {})
        match_id = state["match_id"]
        rows = [
            round_metrics_from_dict(r) if isinstance(r, dict) else r
            for r in (state.get("round_metrics") or [])
        ]
        cum = merge_metrics(rows)
        winner = _winner(cum) if status == "completed" else ""
        result = {
            "match_id": match_id,
            "status": status,
            "winner": winner,
            "metrics": cum,
            "radar": cum.get("radar") or {},
            "capability": state.get("capability") or {},
            "rounds": state.get("rounds") or [],
            "level": state.get("level"),
            "config": cfg.to_dict(),
        }
        if match_id in _LIVE:
            _LIVE[match_id].update({
                "status": status, "winner": winner, "metrics": cum, "level": state.get("level"),
                "radar": cum.get("radar") or {},
                "capability": state.get("capability") or {},
            })
        _STOP.discard(match_id)
        publish("selfplay_match", {
            "match_id": match_id, "status": status, "phase": "done",
            "winner": winner, "metrics": cum,
        })
        if cfg.persist:
            try:
                from self_play import store
                await store.save_match_end(match_id, status=status, winner=winner, metrics=cum)
            except Exception as e:
                logger.info("[SelfPlay] persist end skipped: %s", e)
        return result

    async def run_match(self, cfg: MatchConfig | dict) -> dict:
        global _RUNNING
        cfg = cfg if isinstance(cfg, MatchConfig) else MatchConfig.from_dict(cfg)
        async with _LOCK:
            _RUNNING += 1
        try:
            state = await self.init_match(cfg)
            total = max(1, int(cfg.rounds or 8))
            for _ in range(total):
                if state.get("stopped") or state["match_id"] in _STOP:
                    return await self.finalize(state, status="stopped")
                state = await self.play_round(state)
            return await self.finalize(state, status="completed")
        except Exception:
            logger.exception("[SelfPlay] match failed")
            try:
                return await self.finalize(
                    {"match_id": cfg.match_id or "unknown", "config": cfg.to_dict(),
                     "round_metrics": [], "rounds": [], "level": cfg.start_level},
                    status="failed",
                )
            except Exception:
                return {"status": "failed", "match_id": cfg.match_id}
        finally:
            async with _LOCK:
                _RUNNING = max(0, _RUNNING - 1)


orchestrator = SelfPlayOrchestrator()
