"""Self-Play 审核 Agent: 套套/重复/FP 门 + YAML 导出。"""
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from self_play.reviewer import (
    gate_degenerate, gate_duplicate, gate_fp_replay, gate_transferable,
)
from self_play.sigma_export import dump_yaml, sigma_uuid_for, to_sigma_dict, write_selfplay_rule


def _rule(**kw):
    base = {
        "rule_id": "SP-TEST-001",
        "title": "Self-Play 学到: SYN_ENUM",
        "attack_type": "SYN_ENUM",
        "mitre_id": "T1046",
        "severity": "medium",
        "condition_mode": "or",
        "conditions": {
            "event_contains": ["SYN_ENUM"],
            "message_contains": ["半开连接"],
        },
        "status": "candidate",
    }
    base.update(kw)
    return base


class TestGates:
    def test_tautology_mitre_only_fails(self):
        g = gate_degenerate(_rule(
            attack_type="T1046",
            mitre_id="T1046",
            conditions={"event_contains": ["T1046"], "message_contains": []},
        ))
        assert g["passed"] is False

    def test_synthetic_event_only_fails(self):
        g = gate_degenerate(_rule(
            attack_type="ATTCK_T1046",
            conditions={"event_contains": ["ATTCK_T1046"], "message_contains": ["T1046"]},
        ))
        assert g["passed"] is False

    def test_natural_message_passes_degenerate(self):
        g = gate_degenerate(_rule())
        assert g["passed"] is True

    def test_duplicate_same_event_contains(self):
        a = _rule()
        b = _rule(rule_id="SP-TEST-002", status="shadow")
        g = gate_duplicate(a, [b])
        assert g["passed"] is False

    def test_transferable_requires_message_token(self):
        bad = gate_transferable(_rule(conditions={"event_contains": ["SYN_ENUM"], "message_contains": []}))
        assert bad["passed"] is False
        good = gate_transferable(_rule())
        assert good["passed"] is True

    def test_fp_gate_rejects_wide_message(self):
        rule = _rule(conditions={
            "event_contains": ["SYN_ENUM"],
            "message_contains": ["probe-token"],
        })
        negs = [{"event": "USER_LOGIN", "message": "probe-token x", "severity": "info", "protocol": "rdp"}] * 24
        g = gate_fp_replay(rule, extra_negatives=negs)
        assert g["passed"] is False
        assert g["fp_rate"] >= 0.05

    def test_fp_gate_accepts_specific_pattern(self):
        g = gate_fp_replay(_rule())
        assert g["passed"] is True
        assert g["tp"] >= 1


class TestSigmaExport:
    def test_yaml_has_shadow_and_sp_id(self):
        data = to_sigma_dict(_rule(), shadow=True)
        assert data["x-soc-id"] == "SP-TEST-001"
        uuid.UUID(str(data["id"]))
        assert data["id"] == sigma_uuid_for("SP-TEST-001")
        assert not str(data["id"]).startswith("sp-")
        assert data["x-soc-shadow"] is True
        assert data["x-soc-action"] == "alert"
        assert "sel_event" in data["detection"]
        text = dump_yaml(_rule(), shadow=True)
        assert "SYN_ENUM" in text
        assert "半开连接" in text
        assert "id: sp-sp-" not in text
        assert "x-soc-id: SP-TEST-001" in text
        assert "- self-play\n" not in text
        assert "detection.selfplay" in text

    def test_sigma_id_is_stable_uuid(self):
        a = to_sigma_dict(_rule())
        b = to_sigma_dict(_rule())
        assert a["id"] == b["id"]
        uuid.UUID(a["id"])

    def test_write_does_not_touch_sig_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = write_selfplay_rule(_rule(), shadow=True, rules_dir=tmp)
            assert os.path.isfile(written["path"])
            assert "SIG-001" not in written["path"]
            names = os.listdir(tmp)
            assert names == ["SP-TEST-001.yml"]
            text = open(written["path"], encoding="utf-8").read()
            assert "id: sp-sp-" not in text
            uuid.UUID(to_sigma_dict(_rule())["id"])


import asyncio


def _run(coro):
    return asyncio.run(coro)


async def _reset_db():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


class TestDrain:
    def test_tautology_candidate_is_dismissed(self):
        async def _go():
            await _reset_db()
            from self_play import store
            from self_play.reviewer import drain
            await store.save_learned_rules("m", 1, [{
                "rule_id": "SP-TAUT",
                "title": "tautology",
                "attack_type": "T1046",
                "mitre_id": "T1046",
                "conditions": {"event_contains": ["T1046"], "message_contains": []},
                "status": "candidate",
            }])
            result = await drain(limit=10)
            assert result["dismissed"] >= 1
            rules = await store.list_learned_rules(status="dismissed")
            assert any(r["rule_id"] == "SP-TAUT" for r in rules)
            assert (rules[0].get("review_report") or {}).get("failed")
            from audit_trail import list_trail
            from models import async_session
            async with async_session() as s:
                trails = await list_trail(s, actor="blue_reviewer")
            assert trails
            assert any(t["action"].startswith("selfplay.rule_") for t in trails)

        _run(_go())

    def test_quality_rule_goes_shadow_and_writes_yaml(self, tmp_path, monkeypatch):
        import self_play.reviewer as rv
        monkeypatch.setattr(rv, "_use_llm", lambda: False)
        monkeypatch.setattr(rv, "_use_replay", lambda: False)
        monkeypatch.setattr("self_play.sigma_export.SELFPLAY_DIR", str(tmp_path))
        monkeypatch.setattr(rv, "reload_sigma", lambda: True)

        async def _go():
            await _reset_db()
            from self_play import store
            from self_play.reviewer import drain
            await store.save_learned_rules("m", 2, [{
                "rule_id": "SP-GOOD",
                "title": "半开连接探测",
                "attack_type": "SYN_ENUM",
                "mitre_id": "T1046",
                "severity": "medium",
                "conditions": {
                    "event_contains": ["SYN_ENUM"],
                    "message_contains": ["半开连接"],
                },
                "status": "candidate",
            }])
            result = await drain(limit=10)
            assert result["shadowed"] >= 1
            rules = await store.list_learned_rules(status="shadow")
            assert any(r["rule_id"] == "SP-GOOD" for r in rules)
            assert (tmp_path / "SP-GOOD.yml").is_file()
            text = (tmp_path / "SP-GOOD.yml").read_text(encoding="utf-8")
            assert "x-soc-shadow: true" in text
            assert "SIG-001" not in text

        _run(_go())
