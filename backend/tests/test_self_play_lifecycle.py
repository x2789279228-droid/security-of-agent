"""P1 蓝队规则生命周期测试 — 无 LLM / 无网络。

覆盖:
- ingest miss → provisional 通过 → status=overlay → detect_scoring 命中 (P1-A/P1-C)
- 源 miss 不算独立正样本 (P1-C)
- 宽规则 FPR 不过 → 留在 candidate (P1-C)
- 重复 ingest → dismissed (P1-E)
- 泛化丢 IP / base64,留行为 token (P1-D)
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

from self_play.blue_learner import BlueLearner, rule_from_miss
from self_play.overlay import overlay
from self_play.rule_lifecycle import generalize_rule, ingest_learned_rule, validate_rule
from self_play.types import LearnedRule, MaterializedEvent


def _run(coro):
    return asyncio.run(coro)


def _evt(**kw) -> MaterializedEvent:
    base = dict(
        event="SYN_ENUM", severity="medium", protocol="tcp",
        message="大量半开连接探测服务存活状态",
        src_ip="203.0.113.50", dst_ip="10.0.10.10",
        is_attack=True, ttp_id="ttp-t1046-scan", mitre_id="T1046",
    )
    base.update(kw)
    return MaterializedEvent(**base)


class TestIngestLifecycle:
    def setup_method(self):
        overlay.clear()

    def test_ingest_miss_promotes_provisional_overlay_and_scoring_hit(self):
        miss = _evt()
        log = miss.to_log()
        # 摄取前: candidate/无规则 → 评分通道必须不命中
        assert overlay.detect_scoring("m-lc-1", log)["detected"] is False
        rule = rule_from_miss(miss, "SP-LC-001")
        out = ingest_learned_rule("m-lc-1", rule, miss, existing_rules=[])
        assert out.status == "overlay"
        assert out.validation["passed"] is True
        assert out.validation["provisional"] is True
        assert out.validation["tp_independent"] == 0
        assert out.validation["tp_source"] is True
        hit = overlay.detect_scoring("m-lc-1", log)
        assert hit["detected"] is True
        assert "SP-LC-001" in hit["rule_ids"]

    def test_source_miss_never_counts_as_independent_tp(self):
        miss = _evt()
        log = miss.to_log()
        rule = rule_from_miss(miss, "SP-LC-002")
        empty = validate_rule(rule, source_event=log, history_events=[])
        assert empty["tp_independent"] == 0
        assert empty["independent_tp"] is False
        assert empty["provisional"] is True
        assert empty["passed"] is True
        only_source = validate_rule(rule, source_event=log, history_events=[log])
        assert only_source["tp_independent"] == 0
        assert only_source["provisional"] is True

        other = _evt(
            event="BRUTE_FORCE", message="SSH 暴力破解攻击,已尝试大量口令",
            mitre_id="T1110", protocol="ssh",
        ).to_dict()
        non_hit = validate_rule(rule, source_event=log, history_events=[other])
        assert non_hit["tp_independent"] == 0

        variant = _evt(message="半开连接探测再次出现", fingerprint="fp-variant-1").to_dict()
        lifted = validate_rule(rule, source_event=log, history_events=[other, variant])
        assert lifted["tp_independent"] == 1
        assert lifted["provisional"] is False
        assert lifted["passed"] is True

    def test_wide_rule_failing_fpr_stays_candidate(self):
        miss = _evt(
            event="USER_LOGIN", message="管理员登录成功",
            mitre_id="T1078", protocol="rdp", severity="info",
        )
        wide = LearnedRule(
            rule_id="SP-LC-003", title="过宽规则", attack_type="LOGIN",
            mitre_id="T1078",
            conditions={"event_contains": [
                "USER_LOGIN", "FILE_ACCESS", "DNS_QUERY", "VPN_CONNECT", "BACKUP_COMPLETE",
            ]},
            condition_mode="or",
        )
        report = validate_rule(wide, source_event=miss.to_log())
        assert report["passed"] is False
        assert report["fpr"] >= 0.05
        assert report["fp"] == report["negatives"]
        assert report["negatives"] >= 24

        out = ingest_learned_rule("m-lc-3", wide, miss, existing_rules=[])
        assert out.status == "candidate"
        assert overlay.detect_scoring("m-lc-3", miss.to_log())["detected"] is False
        assert overlay.detect_candidates("m-lc-3", miss.to_log())["detected"] is True

    def test_duplicate_ingest_is_dismissed_not_overlay(self):
        miss = _evt()
        first = ingest_learned_rule(
            "m-lc-4", rule_from_miss(miss, "SP-LC-004A"), miss, existing_rules=[],
        )
        assert first.status == "overlay"
        second = ingest_learned_rule(
            "m-lc-4", rule_from_miss(miss, "SP-LC-004B"), miss,
            existing_rules=overlay.rules_for("m-lc-4"),
        )
        assert second.status == "dismissed"
        assert str(second.validation.get("reason") or "").startswith("duplicate:")
        hit = overlay.detect_scoring("m-lc-4", miss.to_log())
        assert hit["detected"] is True
        assert "SP-LC-004B" not in hit["rule_ids"]

    def test_learner_routes_misses_through_lifecycle(self):
        miss = _evt()
        learner = BlueLearner()
        learned = _run(learner.learn_from_misses("m-lc-5", [miss], [False]))
        assert len(learned) == 1
        assert learned[0].status == "overlay"
        assert learned[0].validation["passed"] is True
        assert overlay.detect_scoring("m-lc-5", miss.to_log())["detected"] is True
        assert overlay.detect_candidates("m-lc-5", miss.to_log())["detected"] is False


class TestGeneralize:
    def test_drops_ip_and_base64_keeps_short_behavior_tokens(self):
        evt = _evt(
            message="port sweep from 203.0.113.50 with payload cGF5bG9hZFBheWxvYWRQYXlsb2Fk",
        )
        rule = LearnedRule(
            rule_id="SP-LC-006", title="gen", attack_type="SYN_ENUM", mitre_id="T1046",
            conditions={
                "event_contains": ["SYN_ENUM"],
                "message_contains": [
                    "203.0.113.50", "10.0.10.10",
                    "cGF5bG9hZFBheWxvYWRQYXlsb2Fk", "port", "sweep",
                ],
            },
            condition_mode="or",
        )
        out = generalize_rule(rule, evt)
        msgs = [str(x) for x in out.conditions.get("message_contains") or []]
        assert "203.0.113.50" not in msgs
        assert "10.0.10.10" not in msgs
        assert "cGF5bG9hZFBheWxvYWRQYXlsb2Fk" not in msgs
        assert "port" in msgs and "sweep" in msgs
        assert len(msgs) == 2
        assert out.conditions.get("event_contains") == ["SYN_ENUM"]
        assert out.generalized is True
        assert out.version == 2
        assert out.parent_rule_id == "SP-LC-006"

    def test_unchanged_conditions_keep_version(self):
        evt = _evt()
        rule = LearnedRule(
            rule_id="SP-LC-007", title="keep", attack_type="SYN_ENUM", mitre_id="T1046",
            conditions={
                "event_contains": ["SYN_ENUM"],
                "message_contains": ["半开连接"],
            },
            condition_mode="or",
        )
        before_cond = dict(rule.conditions)
        out = generalize_rule(rule, evt)
        assert out.generalized is True
        assert out.version == 1
        assert out.parent_rule_id == ""
        assert out.conditions == before_cond
