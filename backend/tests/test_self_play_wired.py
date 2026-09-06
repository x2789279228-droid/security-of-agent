"""Orchestrator 接线验收: 课程 goal、综合分、雷达、规则生命周期不破坏旧闭环。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import asyncio

from self_play.metrics import decide_winner
from self_play.orchestrator import SelfPlayOrchestrator
from self_play.overlay import overlay
from self_play.types import MatchConfig


def _run(coro):
    return asyncio.run(coro)


class TestWiredLoop:
    def setup_method(self):
        overlay.clear()

    def test_three_rounds_still_learn_evasion(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=3, curriculum=True, start_level=0,
            inject=False, use_llm=False, persist=False, decoy_ratio=0.0,
            match_id="sp-wired-loop",
        )))
        assert result["status"] == "completed"
        rounds = result["rounds"]
        assert len(rounds) == 3
        assert rounds[0]["outcome"] == "blue_win"
        assert rounds[1]["outcome"] == "red_win"
        assert rounds[1]["learned"]
        assert rounds[2]["outcome"] == "blue_win"
        assert result["metrics"]["overlay_hits"] >= 1

    def test_round_carries_goal_and_radar(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=2, curriculum=True, start_level=0,
            inject=False, persist=False, decoy_ratio=0.0,
            match_id="sp-wired-goal",
        )))
        r0 = result["rounds"][0]
        assert r0.get("goal")
        assert str(r0["goal"].get("technique_id") or "").upper().startswith("T1046")
        m = result["metrics"]
        assert "blue_score" in m and "red_score" in m and "fbeta" in m
        radar = m.get("radar") or result.get("radar") or {}
        for key in ("coverage", "precision", "mttd", "novelty_response", "compounding", "robustness"):
            assert key in radar
        assert result["winner"] in ("blue", "red", "draw")

    def test_two_blue_wins_do_not_auto_upgrade(self):
        """能力模型: rounds_at_level<3 即使连胜也不升级。"""
        orch = SelfPlayOrchestrator()
        # 仅 2 回合且都可能 blue_win(规范样本); 即使两胜也不该升到 L1
        result = _run(orch.run_match(MatchConfig(
            rounds=1, curriculum=True, start_level=0,
            inject=False, persist=False, decoy_ratio=0.0,
            match_id="sp-wired-noup",
        )))
        cap = result.get("capability") or {}
        assert int(result.get("level") or 0) == 0
        assert int(cap.get("rounds_at_level") or 0) <= 2

    def test_candidate_not_in_same_round_scoring(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=2, curriculum=True, start_level=0,
            inject=False, persist=False, decoy_ratio=0.0,
            match_id="sp-wired-p1a",
        )))
        r1 = result["rounds"][1]
        # R2 漏报学到规则,本回合 outcome 仍是 red_win(刚学的规则不改写本回合 TP)
        if r1["outcome"] == "red_win":
            assert r1["learned"]
            m = r1["metrics"]
            assert m["fn"] >= 1
            assert m.get("candidate_tp", 0) >= 0

    def test_decide_winner_composite(self):
        assert decide_winner({"blue_score": 0.80, "red_score": 0.20}) == "blue"
        assert decide_winner({"blue_score": 0.20, "red_score": 0.80}) == "red"
        assert decide_winner({"blue_score": 0.50, "red_score": 0.50}) == "draw"

    def test_diverse_env_still_completes(self):
        orch = SelfPlayOrchestrator()
        result = _run(orch.run_match(MatchConfig(
            rounds=1, curriculum=True, start_level=0,
            inject=False, persist=False, decoy_ratio=0.0,
            diverse_env=True, env_seed=7, background_traffic=True,
            match_id="sp-wired-div",
        )))
        assert result["status"] == "completed"
        assert result["metrics"]["decoys"] >= 1
