"""
L3 分类树 + 父类策略回归
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from correlation_engine import infer_threat_classification, infer_threat_type
from response_engine.human_approval import ApprovalStatus, approval_queue
from response_engine.response_executor import (
    ActionResult, BatchActionResult, response_executor,
)
from response_engine.response_orchestrator import response_orchestrator
from response_engine.response_policies import MatchStatus, policy_engine
from response_engine.threat_taxonomy import classify, reload_taxonomy
from security_guard.security_guard import security_guard


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _patch_executor(calls: list):
    async def fake_execute(actions, threat_info, **kw):
        calls.append([a.get("name", "") for a in actions])
        return BatchActionResult(
            total=len(actions), succeeded=len(actions), failed=0,
            results=[
                ActionResult(action_name=a.get("name", ""), success=True)
                for a in actions
            ],
            batch_rollback_token="tok_tax",
        )

    response_executor.execute_actions = fake_execute

    def restore():
        try:
            del response_executor.execute_actions
        except AttributeError:
            pass

    return restore


async def _trigger(info: dict, **kw):
    from models import async_session
    async with async_session() as s:
        return await response_orchestrator.on_threat_detected(s, info, **kw)


def test_taxonomy_loaded():
    reload_taxonomy()
    c = classify("未授权获取密码信息")
    assert c.leaf == "UNAUTHORIZED_ACCESS"
    assert c.category == "AUTH_ATTACK"
    assert c.source == "alias"


def test_credential_enum_alias_category_only():
    """异常凭证枚举 → 可无 leaf，但 category=AUTH_ATTACK。"""
    leaf, cat = infer_threat_classification("异常凭证枚举")
    assert cat == "AUTH_ATTACK"
    # leaf 可能为空或 UNAUTHORIZED_ACCESS（看 alias_leaves）
    assert leaf in ("", "UNAUTHORIZED_ACCESS")


def test_infer_still_returns_leaf_string():
    assert infer_threat_type("C2 通信") == "C2_BEACON"
    assert infer_threat_type("未授权获取密码信息") == "UNAUTHORIZED_ACCESS"


def test_auth_attack_category_policy_match():
    policy_engine.clear_cooldowns()
    # 确保 YAML 已加载父类策略
    policy_engine.reload()
    am = policy_engine.match(
        threat_type="UNAUTHORIZED_ACCESS",
        confidence=0.85,
        severity="high",
        src_ip="10.8.9.1",
        category="AUTH_ATTACK",
    )
    assert am.matched
    assert am.match_status == MatchStatus.MATCHED_CATEGORY
    assert am.policy_name == "认证类攻击通用遏制"
    block = next(a for a in am.actions if a["name"] == "block_ip")
    assert block["params"]["duration_minutes"] == 30


def test_c2_leaf_still_beats_category():
    policy_engine.clear_cooldowns()
    policy_engine.reload()
    am = policy_engine.match(
        "C2_BEACON", 0.9, "critical", "10.8.9.2", category="C2",
    )
    assert am.match_status == MatchStatus.MATCHED
    assert am.policy_name == "C2通信自动封禁"
    assert am.actions[0]["params"]["duration_minutes"] == 120


def test_brute_force_leaf_beats_auth_category():
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        "BRUTE_FORCE", 0.9, "high", "10.8.9.3", category="AUTH_ATTACK",
    )
    assert am.match_status == MatchStatus.MATCHED
    assert am.policy_name == "暴力破解自动阻断"
    assert am.actions[0]["params"]["duration_minutes"] == 30


def test_unknown_still_uncertain():
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        "TOTALLY_UNKNOWN_XYZ", 0.9, "high", "10.8.9.4", category="",
    )
    assert am.match_status == MatchStatus.UNCERTAIN


def test_orchestrator_sangfor_password_hits_auth_category():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        policy_engine.reload()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "",
                "event": "未授权获取密码信息",
                "confidence": 0.85,
                "severity": "high",
                "src_ip": "10.8.9.5",
                "session_id": "sess-tax-1",
            })
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "matched_category"
        assert result["policy_name"] == "认证类攻击通用遏制"
        assert "block_ip" in calls[0]
    _run(t())


def test_orchestrator_credential_enum_hits_auth_category():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "",
                "event": "异常凭证枚举",
                "confidence": 0.8,
                "severity": "high",
                "src_ip": "10.8.9.6",
                "session_id": "sess-tax-2",
            })
        finally:
            restore()
        assert result["match_status"] == "matched_category"
        assert result["policy_name"] == "认证类攻击通用遏制"
    _run(t())
