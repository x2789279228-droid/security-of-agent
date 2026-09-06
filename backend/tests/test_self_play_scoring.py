"""P4 多指标评分测试 — 无 LLM / 无网络。

覆盖:
- score_round 复现 test_self_play.TestMetrics 的口径 (tp=2/fn=0/tn=1/recall=1/asr=0/precision=1/compounding=1)
- Fβ(β=1.5) 落在 precision 与 recall 之间且偏向 recall
- decide_winner 蓝胜 / 红胜 / 平局阈值
- candidate 命中不进 TP/FN
- merge_metrics 对 dict/radar 缺键稳健, rounds == len(rows)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import pytest

from self_play.metrics import (
    decide_winner,
    decide_winner_legacy,
    fbeta,
    merge_metrics,
    round_metrics_from_dict,
    score_round,
)
from self_play.novelty import NoveltyIndex
from self_play.types import EventObservation, MaterializedEvent, RoundMetrics


def _evt(**kw) -> MaterializedEvent:
    base = dict(
        event="PORT_SCAN", severity="medium", protocol="tcp",
        message="外部主机对内网进行端口扫描",
        src_ip="203.0.113.50", dst_ip="10.0.10.10",
        is_attack=True, ttp_id="ttp-t1046-scan", mitre_id="T1046",
    )
    base.update(kw)
    return MaterializedEvent(**base)


class TestScoreRoundParity:
    def test_reproduces_legacy_test_metrics_numbers(self):
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
        m = score_round(attacks, obs, NoveltyIndex())
        assert (m.tp, m.fn, m.tn, m.fp) == (2, 0, 1, 0)
        assert m.recall == 1.0
        assert m.asr == 0.0
        assert m.precision == 1.0
        assert m.compounding == 1.0
        # NoveltyIndex.score_layered 内部 0.4+0.3+0.2+0.1 存在浮点误差,用 approx 校验
        assert m.novelty == pytest.approx(1.0)
        assert m.fbeta == 1.0
        assert m.blue_score == pytest.approx(1.0)
        assert m.red_score == 0.0
        assert m.mttc_ms == 0.0
        assert m.eval_channel == "sim"
        assert m.candidate_tp == 0
        assert m.overlay_hits == 1
        radar = m.radar
        assert radar["coverage"] == 1.0
        assert radar["precision"] == 1.0
        assert radar["mttd"] == 1.0
        assert radar["novelty_response"] == 1.0
        assert radar["compounding"] == 1.0
        assert radar["robustness"] == 1.0


class TestFbeta:
    def test_fbeta_between_precision_and_recall_favors_recall(self):
        recall_side = fbeta(0.5, 1.0, beta=1.5)
        precision_side = fbeta(1.0, 0.5, beta=1.5)
        for v in (recall_side, precision_side):
            assert 0.5 < v < 1.0
        assert recall_side > precision_side

    def test_fbeta_perfect_and_degenerate(self):
        assert fbeta(1.0, 1.0) == 1.0
        assert fbeta(0.0, 0.0) == 0.0
        assert fbeta(1.0, 0.0) == 0.0


class TestDecideWinner:
    def test_blue_when_recall_precision_high_asr_low(self):
        cum = {
            "recall": 1.0, "precision": 1.0, "asr": 0.0,
            "mttd_ms": 0.0, "compounding": 1.0, "novelty": 1.0,
        }
        assert decide_winner(cum) == "blue"

    def test_red_when_asr_high_recall_low(self):
        cum = {
            "recall": 0.0, "precision": 0.0, "asr": 1.0,
            "mttd_ms": 0.0, "compounding": 0.0, "novelty": 0.0,
        }
        assert decide_winner(cum) == "red"

    def test_draw_when_middling(self):
        cum = {
            "recall": 0.5, "precision": 0.5, "asr": 0.5,
            "mttd_ms": 0.0, "compounding": 0.5, "novelty": 0.5,
        }
        assert decide_winner(cum) == "draw"

    def test_explicit_scores_are_used_when_present(self):
        assert decide_winner({"blue_score": 0.9, "red_score": 0.2}) == "blue"
        assert decide_winner({"blue_score": 0.3, "red_score": 0.9}) == "red"
        assert decide_winner({"blue_score": 0.55, "red_score": 0.52}) == "draw"

    def test_legacy_thresholds_unchanged(self):
        assert decide_winner_legacy({"recall": 0.8, "asr": 0.2}) == "blue"
        assert decide_winner_legacy({"recall": 0.2, "asr": 0.8}) == "red"
        assert decide_winner_legacy({"recall": 0.5, "asr": 0.4}) == "draw"


class TestCandidateChannel:
    def test_candidate_detected_not_counted_as_tp(self):
        attacks = [_evt(), _evt(event="SVC_MAP", message="对常见管理端口做连通性探测")]
        obs = [
            EventObservation(candidate_detected=True, candidate_rule_ids=["SP-X-1"], detected=False),
            EventObservation(detected=True, detector="overlay"),
        ]
        m = score_round(attacks, obs)
        assert m.candidate_tp == 1
        assert m.tp == 1 and m.fn == 1
        assert m.recall == 0.5


class TestMergeMetrics:
    def test_rounds_match_rows_and_radar_stays_dict(self):
        rows = [
            RoundMetrics(
                tp=2, fn=0, tn=1, attacks=2, decoys=1,
                recall=1.0, asr=0.0, precision=1.0,
                compounding=1.0, novelty=1.0,
                radar={"coverage": 1.0, "precision": 1.0},
            ),
        ]
        cum = merge_metrics(rows)
        assert cum["rounds"] == 1 == len(rows)
        assert isinstance(cum["radar"], dict)
        assert cum["attacks"] == 2 and cum["tp"] == 2

    def test_multiple_rows_and_missing_keys_no_crash(self):
        rows = [
            {"tp": 1, "attacks": 1, "recall": 1.0, "radar": {"coverage": 1.0}},
            round_metrics_from_dict({"tp": 1, "attacks": 1, "recall": 1.0}),
            RoundMetrics(),
        ]
        cum = merge_metrics(rows)
        assert cum["rounds"] == 3 == len(rows)
        assert isinstance(cum["radar"], dict)
        assert cum["radar"]["coverage"] > 0
        assert cum["recall"] > 0

    def test_empty_rows(self):
        cum = merge_metrics([])
        assert cum["rounds"] == 0
        assert isinstance(cum["radar"], dict)

    def test_round_metrics_from_dict_fills_defaults(self):
        m = round_metrics_from_dict({"tp": 1})
        assert m.tp == 1
        assert m.radar == {}
        assert m.recall == 0.0
        assert m.eval_channel == "sim"
