"""Red vs Blue Self-Play 单元测试 — 不依赖 LLM / 外部服务。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import asyncio

from self_play.blue_learner import BlueLearner, distinctive_tokens, rule_from_miss
from self_play.blue_observer import BlueObserver
from self_play.catalog import (
    MAX_CURRICULUM_LEVEL, all_ttps, enterprise_pool, get_ttp, ttps_at_level,
)
from self_play.metrics import score_round
from self_play.novelty import NoveltyIndex, fingerprint, tokenize
from self_play.orchestrator import SelfPlayOrchestrator
from self_play.overlay import RuleOverlay, overlay
from self_play.red_agent import RedAgent
from self_play.sim_env import SimEnv, topology
from self_play.types import BlueView, EventObservation, MatchConfig, MaterializedEvent


def _run(coro):
    return asyncio.run(coro)


def _evt(**kw) -> MaterializedEvent:
    base = dict(
        event="PORT_SCAN", severity="medium", protocol="tcp",
        message="外部主机对内网进行端口扫描",
        src_ip="203.0.113.50", dst_ip="10.0.10.10",
        is_attack=True, ttp_id="ttp-t1046-scan", mitre_id="T1046",
    )
    base.update(kw)
    return MaterializedEvent(**base)


class TestCatalogAndSim:
    def test_curriculum_levels_cover_kill_chain(self):
        assert MAX_CURRICULUM_LEVEL == 6
        assert get_ttp("ttp-t1046-scan") is not None
        assert all(ttps_at_level(i) for i in range(MAX_CURRICULUM_LEVEL + 1))

    def test_topology_has_ten_hosts_and_isolation_note(self):
        topo = topology()
        assert len(topo["hosts"]) == 10
        assert topo["isolation"] == "in-process-sim"

    def test_materialize_is_soc_log_not_exploit(self):
        spec = get_ttp("ttp-t1190-web")
        red = RedAgent()
        step = red._step_from_spec(spec, set())
        env = SimEnv()
        evt = env.materialize(step)
        log = evt.to_log()
        blob = (log["message"] + log.get("url", "")).lower()
        assert log["_self_play"] is True
        assert log["_ground_truth"] == "attack"
        assert "or 1=1" not in blob
        assert "msfvenom" not in blob
        assert "sqlmap" not in blob
        assert step.tool.startswith("sim:")

    def test_enterprise_pool_covers_attack_parent_techniques(self):
        pool = enterprise_pool()
        assert len(pool) >= 180
        assert get_ttp("T1059") is not None
        assert get_ttp("T1059").mitre_id == "T1059"
        assert get_ttp("ttp-t1046-scan").event_type == "PORT_SCAN"
        assert len(all_ttps()) >= 180
        assert [t.event_type for t in ttps_at_level(0)] == ["PORT_SCAN"]


class TestNovelty:
    def test_unseen_is_one_then_drops(self):
        idx = NoveltyIndex()
        a = tokenize("PORT_SCAN", "外部主机对内网进行端口扫描")
        assert idx.score(a) == 1.0
        idx.observe(a)
        assert idx.score(a) == 0.0
        b = tokenize("SYN_ENUM", "大量半开连接探测服务存活状态")
        assert idx.score(b) > 0.3

    def test_fingerprint_stable(self):
        assert fingerprint("A", "hello world", "T1046") == fingerprint("A", "hello world", "T1046")


class TestOverlayAndLearner:
    def setup_method(self):
        overlay.clear()

    def test_miss_then_learn_then_hit(self):
        miss = _evt(
            event="SYN_ENUM",
            message="大量半开连接探测服务存活状态",
            extra={"_evasion": True},
        )
        ov = RuleOverlay()
        assert ov.detect("m1", miss.to_log())["detected"] is False
        rule = rule_from_miss(miss, "SP-TEST-001")
        ov.add("m1", rule.to_dict())
        hit = ov.detect("m1", miss.to_log())
        assert hit["detected"] is True
        assert "SP-TEST-001" in hit["rule_ids"]

    def test_distinctive_tokens_keep_event_type(self):
        toks = distinctive_tokens(_evt(event="CLOUD_SYNC", message="工作站向未备案对象存储同步大批文件"))
        assert "CLOUD_SYNC" in toks


class TestBlueObserverSigma:
    def test_canonical_port_scan_detected(self):
        obs = _run(BlueObserver().observe_one("t", _evt()))
        assert obs.detected is True
        assert "sigma" in obs.detector

    def test_evasion_variant_misses_stock_sigma(self):
        obs = _run(BlueObserver().observe_one("t", _evt(
            event="SYN_ENUM", message="大量半开连接探测服务存活状态",
        )))
        assert obs.detected is False


class TestMetrics:
    def test_asr_recall_precision_and_compounding(self):
        attacks = [
            _evt(),
            _evt(event="SYN_ENUM", message="半开连接", extra={"_evasion": True}, is_attack=True),
            _evt(event="USER_LOGIN", message="管理员登录成功", is_attack=False, severity="info"),
        ]
        obs = [
            EventObservation(detected=True, detector="sigma"),
            EventObservation(detected=True, detector="overlay"),
            EventObservation(detected=False, detector=""),
        ]
        m = score_round(attacks, obs)
        assert m.tp == 2 and m.fn == 0 and m.tn == 1
        assert m.recall == 1.0
        assert m.asr == 0.0
        assert m.precision == 1.0
        assert m.compounding == 1.0


class TestRedAgent:
    def test_after_detection_switches_to_variant(self):
        red = RedAgent()
        red.remember("PORT_SCAN", detected=True)
        plan = _run(red.plan_attack(
            match_id="m", round_num=2, level=0,
            blue_coverage=["PORT_SCAN"], decoy_ratio=0.0, use_llm=False,
        ))
        assert plan.steps[0].evasion is True
        assert plan.steps[0].event_type != "PORT_SCAN"
        assert plan.steps[0].event_type in ("SYN_ENUM", "SVC_MAP")

    def test_blueview_reuses_missed_ttp_on_full_pool(self):
        red = RedAgent()
        plan = _run(red.plan_attack(
            match_id="m", round_num=2, level=0,
            curriculum=False, use_llm=False, decoy_ratio=0.0,
            blue_view=BlueView(last_outcome="red_win", last_missed=["T1046"]),
        ))
        assert plan.steps[0].mitre_id == "T1046"

    def test_llm_multi_step_kill_chain(self):
        red = RedAgent(use_llm=True)

        async def fake_rag(*_a, **_k):
            return ["T1046 discovery"], [
                get_ttp("T1046"), get_ttp("T1059"), get_ttp("T1021"),
            ]

        async def fake_llm(*_a, **_k):
            return {
                "steps": [
                    {"ttp_id": "T1046", "use_evasion": False},
                    {"ttp_id": "T1059", "use_evasion": True},
                    {"ttp_id": "T1021", "use_evasion": True},
                ],
                "rationale": "mock kill chain",
                "add_decoy": False,
            }

        red._rag_hints_and_specs = fake_rag  # type: ignore[method-assign]
        red._llm_pick = fake_llm  # type: ignore[method-assign]
        plan = _run(red.plan_attack(
            match_id="m", round_num=1, level=6,
            curriculum=False, use_llm=True, decoy_ratio=0.0,
        ))
        assert len(plan.steps) == 3
        assert [s.mitre_id for s in plan.steps] == ["T1046", "T1059", "T1021"]
        assert plan.rag_hints
        evs = SimEnv().materialize_plan(plan.steps, [])
        assert evs[0].src_ip == "203.0.113.50"
        assert evs[1].src_ip == "10.0.30.11"
        assert all(e.extra.get("_tool", "").startswith("sim:") for e in evs)

    def test_prompts_render(self):
        from prompts import render
        sys_p = render("security/red_plan_system")
        usr = render(
            "security/red_plan", level=0, coverage="PORT_SCAN",
            catalog="[]", rag_hints="(none)", last_outcome="blue_win",
            blue_view="{}",
        )
        assert "JSON" in sys_p
        assert "课程等级" in usr
        bsys = render("security/blue_learn_system")
        busr = render(
            "security/blue_learn", event_type="SYN_ENUM", severity="medium",
            protocol="tcp", message="x", mitre_id="T1046", url="",
        )
        assert "candidate" in bsys
        assert "SYN_ENUM" in busr


class TestOrchestratorLoop:
    def setup_method(self):
        overlay.clear()

    def test_three_rounds_learn_evasion(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=3, curriculum=True, start_level=0,
            inject=False, use_llm=False, persist=False, decoy_ratio=0.0,
            match_id="sp-test-loop",
        )))
        assert result["status"] == "completed"
        rounds = result["rounds"]
        assert len(rounds) == 3
        # R1 规范 PORT_SCAN → 库存 Sigma 应检出
        assert rounds[0]["outcome"] == "blue_win"
        # R2 规避变体 → 漏报,红胜,并写入 overlay
        assert rounds[1]["outcome"] == "red_win"
        assert rounds[1]["learned"]
        # R3 同类变体应被 overlay 抓住
        assert rounds[2]["outcome"] == "blue_win"
        assert result["metrics"]["overlay_hits"] >= 1

    def test_decoy_does_not_inflate_asr(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=1, curriculum=False, start_level=0,
            inject=False, persist=False, decoy_ratio=1.0,
            match_id="sp-test-decoy",
        )))
        m = result["metrics"]
        assert m["decoys"] >= 1
        assert m["fp"] == 0


async def _reset_db():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


class TestPersist:
    def setup_method(self):
        overlay.clear()
        _run(_reset_db())

    def test_round_row_accepts_list_json_columns(self):
        """复现: MutableJSON(dict) 拒收 list → rounds/learned 全部写不进去。"""
        from models import SelfPlayRound, async_session

        async def _go():
            async with async_session() as session:
                session.add(SelfPlayRound(
                    match_id="sp-coerce",
                    round_num=1,
                    curriculum_level=0,
                    red_plan={"plan_id": "p"},
                    events=[{"event": "SYN_ENUM"}],
                    blue_obs=[{"detected": False}],
                    outcome="red_win",
                    metrics={"asr": 1.0},
                    learned=[{"rule_id": "SP-x-001"}],
                ))
                await session.commit()
            from self_play import store
            await store.save_round("sp-coerce-2", {
                "round_num": 1,
                "curriculum_level": 0,
                "red_plan": {"plan_id": "p2"},
                "events": [{"event": "PORT_SCAN"}],
                "blue_obs": [{"detected": True}],
                "outcome": "blue_win",
                "metrics": {"recall": 1.0},
                "learned": [],
                "cumulative": {"recall": 1.0},
            })
            row = await store.get_match("sp-coerce-2")
            # save_round 会更新 match,但 match 行可能还不存在
            from models import SelfPlayRound as R
            from sqlalchemy import select
            async with async_session() as session:
                rows = (await session.execute(select(R))).scalars().all()
                assert len(rows) == 2
                assert isinstance(rows[0].events, list)
                assert isinstance(rows[0].blue_obs, list)
                assert isinstance(rows[0].learned, list)

        _run(_go())

    def test_persist_writes_rounds_and_learned_rules(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=3, curriculum=True, start_level=0,
            inject=False, use_llm=False, persist=True, decoy_ratio=0.0,
            match_id="sp-persist-a",
        )))
        assert result["status"] == "completed"

        async def _assert():
            from self_play import store
            from models import SelfPlayRound, SelfPlayLearnedRule, async_session
            from sqlalchemy import select
            stored = await store.get_match("sp-persist-a")
            assert stored is not None
            assert len(stored["rounds"]) == 3
            assert all(isinstance(r["events"], list) for r in stored["rounds"])
            miss_rounds = [r for r in stored["rounds"] if r["outcome"] == "red_win"]
            assert miss_rounds
            assert miss_rounds[0]["learned"]
            async with async_session() as session:
                rules = (await session.execute(select(SelfPlayLearnedRule))).scalars().all()
                rounds = (await session.execute(select(SelfPlayRound))).scalars().all()
            assert len(rounds) == 3
            assert len(rules) >= 1
            assert all(r.status in ("candidate", "overlay", "dismissed") for r in rules)
            assert any(r.status in ("overlay", "candidate") for r in rules)

        _run(_assert())

    def test_next_match_seeds_overlay_from_db(self):
        orch = SelfPlayOrchestrator()
        _run(orch.run_match(MatchConfig(
            rounds=3, curriculum=True, start_level=0,
            inject=False, persist=True, decoy_ratio=0.0,
            match_id="sp-persist-a",
        )))
        overlay.clear()
        _run(orch.init_match(MatchConfig(
            rounds=1, persist=True, decoy_ratio=0.0, match_id="sp-persist-b",
        )))
        miss = _evt(
            event="SYN_ENUM",
            message="大量半开连接探测服务存活状态",
            extra={"_evasion": True},
        )
        hit = overlay.detect("sp-persist-b", miss.to_log())
        assert hit["detected"] is True
        assert hit["rule_ids"]
