"""P2/P5 单元测试 — 统一课程 CurriculumPolicy + 红队 goal 消费 + 盲区学习。

不依赖 LLM / 外部服务。覆盖:
- select_goal 等级/子技术/不跳级/约束填充
- ExecutablePlanner 的 goal 允许集约束与角色重映射
- RedAgent goal 覆盖 last_missed、LLM 输出被约束回 goal 家族
- update EMA / recent_outcomes / p_level_clear / maybe_advance 升降级
- observe_gaps + prefer_gap_specs 盲区优先 (仅 goal=None 时生效)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import asyncio

from self_play.catalog import get_ttp
from self_play.curriculum import CurriculumPolicy
from self_play.planner import ExecutablePlanner
from self_play.red_agent import RedAgent
from self_play.sim_env import SimEnv
from self_play.types import AttackStep, BlueView, CapabilityState, RoundGoal


def _run(coro):
    return asyncio.run(coro)


def _step(mitre_id: str) -> AttackStep:
    return AttackStep(
        step_id=f"s-{mitre_id}", ttp_id=f"ttp-{mitre_id.lower()}",
        mitre_id=mitre_id, tactic="execution", kill_chain="execution",
        name="n", event_type="E", severity="high", protocol="local", message="m",
    )


class TestSelectGoal:
    def test_level0_returns_t1046_port_scan(self):
        policy = CurriculumPolicy()
        goal = policy.select_goal(
            level=0, coverage=[], last_missed=[], capability=CapabilityState(),
        )
        assert goal.technique_id == "T1046"
        assert goal.event_type == "PORT_SCAN"
        assert goal.ttp_id == "ttp-t1046-scan"

    def test_level3_sub_technique_granularity(self):
        policy = CurriculumPolicy()
        goal = policy.select_goal(
            level=3,
            coverage=["SCRIPT_EXEC", "PRIVILEGE_ESCALATION"],
            last_missed=[],
            capability=CapabilityState(level=3),
        )
        assert goal.technique_id == "T1059"
        assert goal.sub_technique_id in ("T1059.001", "T1059.006")
        assert "T1059.001" in goal.allowed_ttps
        assert "T1059.006" in goal.allowed_ttps

    def test_missed_t1046_does_not_jump_levels(self):
        policy = CurriculumPolicy()
        goal = policy.select_goal(
            level=3,
            coverage=["SCRIPT_EXEC", "PRIVILEGE_ESCALATION"],
            last_missed=["T1046"],
            capability=CapabilityState(level=3),
        )
        assert goal.sub_technique_id in ("T1059.001", "T1059.006")
        assert goal.prefer_gap is False

    def test_missed_ttp_at_current_level_is_preferred(self):
        policy = CurriculumPolicy()
        goal = policy.select_goal(
            level=1, coverage=[], last_missed=["T1110"],
            capability=CapabilityState(level=1),
        )
        assert goal.technique_id == "T1110"
        assert goal.prefer_gap is True

    def test_constraints_filled_and_require_variant(self):
        policy = CurriculumPolicy()
        goal = policy.select_goal(
            level=0, coverage=["PORT_SCAN"], last_missed=[], capability=None,
        )
        assert goal.constraints["dst_role"] == "web"
        assert goal.constraints["protocol"] == "tcp"
        assert goal.constraints["kill_chain"] == "recon"
        assert goal.constraints["require_variant"] is True


class TestExecutablePlanner:
    def test_constrain_keeps_goal_family_only(self):
        planner = ExecutablePlanner()
        goal = RoundGoal(technique_id="T1059", sub_technique_id="T1059.001")
        out = planner.constrain_steps(
            [_step("T1059"), _step("T1059.001"), _step("T1021")],
            goal,
            [get_ttp("T1059"), get_ttp("T1059.001"), get_ttp("T1059.006"), get_ttp("T1021")],
        )
        assert [s.mitre_id for s in out] == ["T1059", "T1059.001"]

    def test_constrain_synthesizes_goal_gold_step_when_all_rejected(self):
        planner = ExecutablePlanner()
        goal = RoundGoal(
            technique_id="T1059", sub_technique_id="T1059.001",
            ttp_id="ttp-t1059-001-ps",
        )
        out = planner.constrain_steps([_step("T1021")], goal, [])
        assert len(out) == 1
        assert out[0].mitre_id == "T1059.001"
        assert out[0].sub_technique_id == "T1059.001"

    def test_executable_and_role_remap(self):
        env = SimEnv()
        planner = ExecutablePlanner(env)
        assert planner.executable(get_ttp("T1059"), env) is True   # ws 存在
        assert planner.executable(get_ttp("T1021"), env) is True   # fs 存在
        env.hosts = [dict(id="web-01", ip="10.0.10.10", zone="dmz", role="web", port=80)]
        assert planner.executable(get_ttp("T1021"), env) is False  # fs 不存在
        step = planner.map_spec(get_ttp("T1021"), [])
        assert step.dst_role in {h["role"] for h in env.hosts}


class TestRedAgentGoal:
    def test_goal_overrides_blueview_last_missed(self):
        red = RedAgent()
        goal = RoundGoal(
            technique_id="T1059", sub_technique_id="T1059.001",
            ttp_id="ttp-t1059-001-ps", event_type="POSH_EXEC",
            allowed_ttps=["T1059", "T1059.001", "T1059.006"],
        )
        plan = _run(red.plan_attack(
            match_id="m", round_num=1, level=3,
            curriculum=True, use_llm=False, decoy_ratio=0.0,
            blue_view=BlueView(last_outcome="red_win", last_missed=["T1046"]),
            goal=goal,
        ))
        assert plan.steps[0].mitre_id == "T1059.001"
        assert plan.steps[0].sub_technique_id == "T1059.001"
        assert plan.goal["technique_id"] == "T1059"

    def test_llm_off_goal_step_constrained_back_to_goal(self):
        red = RedAgent(use_llm=True)

        async def fake_rag(*_a, **_k):
            return ["T1021 lateral"], [
                get_ttp("T1046"), get_ttp("T1059"), get_ttp("T1021"),
            ]

        async def fake_llm(*_a, **_k):
            return {
                "steps": [{"ttp_id": "T1021", "use_evasion": False}],
                "rationale": "off-goal",
                "add_decoy": False,
            }

        red._rag_hints_and_specs = fake_rag  # type: ignore[method-assign]
        red._llm_pick = fake_llm  # type: ignore[method-assign]
        goal = RoundGoal(
            technique_id="T1059", sub_technique_id="T1059.001",
            ttp_id="ttp-t1059-001-ps",
            allowed_ttps=["T1059", "T1059.001", "T1059.006"],
        )
        plan = _run(red.plan_attack(
            match_id="m", round_num=1, level=3,
            curriculum=False, use_llm=True, decoy_ratio=0.0,
            goal=goal,
        ))
        assert [s.mitre_id for s in plan.steps] == ["T1059.001"]
        # 回退步骤在默认拓扑可执行: T1059.001 落在 ws-01
        evs = SimEnv().materialize_plan(plan.steps, [])
        assert evs[0].dst_ip == "10.0.30.11"
        assert evs[0].event == "POSH_EXEC"


class TestCurriculumUpdate:
    def test_update_ema_alpha_04(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=1)
        cap = policy.update(cap, technique_id="T1110", detected=True, outcome="blue_win")
        assert cap.rounds_at_level == 1
        assert cap.technique_recalls["T1110"] == 1.0
        assert cap.technique_asrs["T1110"] == 0.0
        cap = policy.update(cap, technique_id="T1110", detected=False, outcome="red_win")
        assert abs(cap.technique_recalls["T1110"] - 0.6) < 1e-9
        assert abs(cap.technique_asrs["T1110"] - 0.4) < 1e-9
        assert cap.recent_outcomes == ["blue_win", "red_win"]
        assert abs(cap.blue_win_rate - 0.5) < 1e-9

    def test_recent_outcomes_keep_last_5(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=0)
        for i in range(7):
            hit = i % 2 == 0
            cap = policy.update(
                cap, technique_id="T1046", detected=hit,
                outcome="blue_win" if hit else "red_win",
            )
        assert len(cap.recent_outcomes) == 5
        assert cap.rounds_at_level == 7

    def test_update_recomputes_p_level_clear(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=0)
        cap = policy.update(cap, technique_id="T1046", detected=True, outcome="blue_win")
        # 0.4*1.0 + 0.3*(1-0.0) + 0.3*1.0 = 1.0
        assert abs(cap.p_level_clear - 1.0) < 1e-9

    def test_p_level_clear_manual_state(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(
            level=3,
            technique_recalls={"T1059": 0.9},
            technique_asrs={"T1059": 0.1},
            recent_outcomes=["blue_win", "blue_win", "blue_win"],
        )
        # 0.4*0.9 + 0.3*(1-0.1) + 0.3*1.0 = 0.93
        assert abs(policy.p_level_clear(cap) - 0.93) < 1e-9


class TestMaybeAdvance:
    def test_upgrade_after_3_rounds_high_p(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=0, rounds_at_level=3, p_level_clear=0.9)
        out = policy.maybe_advance(cap)
        assert out.level == 1
        assert out.rounds_at_level == 0
        assert out.recent_outcomes == []
        assert out.p_level_clear == 0.0

    def test_no_upgrade_with_only_2_rounds(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=0, rounds_at_level=2, p_level_clear=0.9)
        assert policy.maybe_advance(cap).level == 0

    def test_downgrade_after_4_rounds_low_p(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=2, rounds_at_level=4, p_level_clear=0.1)
        assert policy.maybe_advance(cap).level == 1

    def test_no_downgrade_before_4_rounds(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(level=2, rounds_at_level=3, p_level_clear=0.1)
        assert policy.maybe_advance(cap).level == 2

    def test_upgrade_uses_p_not_consecutive_blue_wins(self):
        policy = CurriculumPolicy()
        cap = CapabilityState(
            level=0, rounds_at_level=3, p_level_clear=0.9,
            blue_win_rate=0.0, recent_outcomes=["red_win", "mixed", "red_win"],
        )
        assert policy.maybe_advance(cap).level == 1


class TestRedAgentGaps:
    def test_observe_gaps_updates_memory(self):
        red = RedAgent()
        red.observe_gaps(missed=["T1068"], covered=["T1059"])
        assert red.memory["T1068"]["detected"] is False
        assert red.memory["T1068"]["count"] == 1
        assert red.memory["T1059"]["detected"] is True
        red.observe_gaps(missed=["T1068"], covered=[])
        assert red.memory["T1068"]["count"] == 2

    def test_prefer_gap_specs_ranks_missed_first(self):
        red = RedAgent()
        red.observe_gaps(missed=["T1068"], covered=["T1059"])
        ranked = red.prefer_gap_specs([get_ttp("T1059"), get_ttp("T1068")])
        assert ranked[0].mitre_id == "T1068"

    def test_gap_memory_drives_planning_when_goal_none(self):
        red = RedAgent()
        red.observe_gaps(missed=["T1068"], covered=["T1059"])
        plan = _run(red.plan_attack(
            match_id="m", round_num=1, level=3,
            curriculum=True, use_llm=False, decoy_ratio=0.0,
        ))
        assert plan.steps[0].mitre_id == "T1068"
        # 同一记忆 + goal 时不得被盲区带偏 (P5-C)
        goal = RoundGoal(
            technique_id="T1059", sub_technique_id="T1059.001",
            ttp_id="ttp-t1059-001-ps",
        )
        plan2 = _run(red.plan_attack(
            match_id="m", round_num=2, level=3,
            curriculum=True, use_llm=False, decoy_ratio=0.0,
            goal=goal,
        ))
        assert plan2.steps[0].mitre_id == "T1059.001"
