"""PR4 运营闭环：FP 降级、CAD 第一失败 hop、LLM 特征钳制、KB 过期。"""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from ops_loop import (
    locate_first_failed_hop,
    clamp_llm_risk_level,
    llm_may_open_work_order,
    kb_chunk_is_fresh,
    filter_fresh_chunks,
    downgrade_response_policy,
    FP_RATE_DOWNGRADE,
)
from feedback_loop import FP_RATE_ALERT_THRESHOLD


def test_fp_threshold_is_fifteen_percent():
    assert FP_RATE_ALERT_THRESHOLD == 0.15
    assert FP_RATE_DOWNGRADE == 0.15


def test_locate_first_failed_hop_sub_auditor():
    data = {
        "hop_trace": [
            {"hop": "sub_auditor", "avg_hallucination_risk": 0.8, "avg_grounding": 0.2,
             "skip_reasoning": True},
            {"hop": "synthesize", "verdict": "suspicious", "reason": "ok"},
        ],
        "merged": {"faithfulness": {"passed": True, "reasons": []}},
    }
    loc = locate_first_failed_hop(data)
    assert loc["hop"] == "sub_auditor"
    assert loc["reason"]


def test_locate_first_failed_hop_faithfulness_if_only_gate_fails():
    data = {
        "hop_trace": [
            {"hop": "synthesize", "verdict": "confirmed", "reason": "grounded+non_llm_signal"},
        ],
        "merged": {"faithfulness": {"passed": False, "reasons": ["phantom_entities"]}},
    }
    loc = locate_first_failed_hop(data)
    assert loc["hop"] == "faithfulness_gate"


def test_locate_no_failure():
    loc = locate_first_failed_hop({
        "hop_trace": [{"hop": "synthesize", "reason": "grounded+non_llm_signal"}],
        "merged": {"faithfulness": {"passed": True}},
    })
    assert loc["hop"] == ""


def test_clamp_llm_cannot_promote_safe_to_phishing():
    assert clamp_llm_risk_level("safe", "phishing") == "safe"
    assert clamp_llm_risk_level("suspicious", "phishing") == "suspicious"
    assert clamp_llm_risk_level("phishing", "suspicious") == "suspicious"


def test_llm_cannot_open_work_order_without_rule_hit():
    assert llm_may_open_work_order(rule_hit=False, llm_sensitive=True) is False
    assert llm_may_open_work_order(rule_hit=True, llm_sensitive=True) is True
    assert llm_may_open_work_order(rule_hit=True, llm_sensitive=False) is False


def test_stale_kb_chunk_rejected():
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    stale = {"threat_types": ["C2"], "valid_until": past}
    fresh = {"threat_types": ["C2"], "valid_until": future}
    immortal = {"threat_types": ["C2"]}
    assert kb_chunk_is_fresh(stale) is False
    assert kb_chunk_is_fresh(fresh) is True
    assert kb_chunk_is_fresh(immortal) is True
    kept = filter_fresh_chunks([stale, fresh, immortal])
    assert stale not in kept
    assert len(kept) == 2


def test_downgrade_response_policy_strips_block():
    p = SimpleNamespace(
        name="block_c2",
        auto_execute=True,
        require_approval=False,
        actions=[{"name": "block_ip", "params": {}}, {"name": "send_alert", "params": {}}],
    )
    out = downgrade_response_policy(p)
    assert p.auto_execute is False
    assert p.require_approval is True
    names = [a.get("name") for a in p.actions]
    assert "block_ip" not in names
    assert "alert_only" in names
    assert out["changes"]


def test_grounding_skips_expired_kb():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "grounding_mod_pr4", BACKEND / "grounding_verifier.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    gv = mod.grounding_verifier
    past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ok = gv._verify_knowledge_consistency(
        "C2",
        [{"threat_types": ["C2"], "valid_until": past}],
        has_event_evidence=True,
    )
    assert ok is False
    ok2 = gv._verify_knowledge_consistency(
        "C2",
        [{"threat_types": ["C2"]}],
        has_event_evidence=True,
    )
    assert ok2 is True
