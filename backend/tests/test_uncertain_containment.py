"""
L1 Uncertain 遏制回归

未知 threat_type 不再静默 matched=False：
  - match_status=UNCERTAIN → block_ip(5min) + send_alert + P1 工单
  - 良性类型 → NO_ACTION
  - IP / Uncertain 冷却 → SKIPPED（可观测）
  - medium / allow_blocking=False → 不封禁，仍建 P1 PENDING 工单
  - C2 等专属策略优先，不掉进 Uncertain
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from correlation_engine import infer_threat_type
from response_engine.human_approval import ApprovalStatus, approval_queue
from response_engine.response_executor import (
    ActionResult,
    BatchActionResult,
    response_executor,
)
from response_engine.response_orchestrator import response_orchestrator
from response_engine.response_policies import (
    BENIGN_TYPES,
    MatchStatus,
    UNCERTAIN_POLICY_NAME,
    policy_engine,
)
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
            batch_rollback_token="tok_uncertain",
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


# ── 推断映射纠偏 ──

def test_sangfor_password_maps_to_unauthorized_access():
    assert infer_threat_type("未授权获取密码信息") == "UNAUTHORIZED_ACCESS"
    assert infer_threat_type("未授权获取明文密码信息") == "UNAUTHORIZED_ACCESS"


# ── PolicyEngine ──

def test_unknown_type_is_uncertain_not_any():
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        threat_type="SOME_UNKNOWN_THREAT", confidence=0.9, severity="high",
        src_ip="10.8.2.1",
    )
    assert am.matched
    assert am.match_status == MatchStatus.UNCERTAIN
    assert am.policy_name == UNCERTAIN_POLICY_NAME
    assert am.needs_approval is True
    assert am.auto_execute is True
    names = [a["name"] for a in am.actions]
    assert "send_alert" in names and "block_ip" in names
    block = next(a for a in am.actions if a["name"] == "block_ip")
    assert block["params"]["duration_minutes"] == 5


def test_unauthorized_access_hits_auth_category_not_uncertain():
    """L3: UNAUTHORIZED_ACCESS 无 leaf 专属策略 → AUTH_ATTACK 父类，不再 Uncertain。"""
    policy_engine.clear_cooldowns()
    policy_engine.reload()
    am = policy_engine.match(
        "UNAUTHORIZED_ACCESS", 0.85, "high", "10.8.2.2",
        category="AUTH_ATTACK",
    )
    assert am.match_status == MatchStatus.MATCHED_CATEGORY
    assert am.policy_name == "认证类攻击通用遏制"
    block = next(a for a in am.actions if a["name"] == "block_ip")
    assert block["params"]["duration_minutes"] == 30


def test_benign_type_no_action():
    policy_engine.clear_cooldowns()
    for tt in BENIGN_TYPES:
        am = policy_engine.match(tt, 0.9, "info", "10.8.2.3")
        assert am.match_status == MatchStatus.NO_ACTION, tt
        assert am.matched is False
        assert am.skip_reason == "benign_type"


def test_c2_still_exact_match():
    policy_engine.clear_cooldowns()
    am = policy_engine.match("C2_BEACON", 0.85, "critical", "10.8.2.4")
    assert am.match_status == MatchStatus.MATCHED
    assert am.policy_name == "C2通信自动封禁"
    assert am.actions[0]["name"] == "block_ip"
    assert am.actions[0]["params"]["duration_minutes"] == 120


def test_known_type_threshold_miss_not_uncertain():
    """有专属策略但置信度不够 → NO_ACTION，不掉进 Uncertain。"""
    policy_engine.clear_cooldowns()
    am = policy_engine.match("C2_BEACON", 0.1, "info", "10.8.2.5")
    assert am.match_status == MatchStatus.NO_ACTION
    assert am.skip_reason == "threshold_not_met"
    assert am.matched is False


def test_uncertain_cooldown_skips_second_hit():
    policy_engine.clear_cooldowns()
    r1 = policy_engine.match("WEIRD_NEW_ATTACK", 0.9, "high", "10.8.2.6")
    assert r1.match_status == MatchStatus.UNCERTAIN
    # 清掉 IP 聚合冷却，专测 uncertain 冷却
    policy_engine._ip_last_match.clear()
    r2 = policy_engine.match("WEIRD_NEW_ATTACK", 0.9, "high", "10.8.2.6")
    assert r2.match_status == MatchStatus.SKIPPED
    assert r2.skip_reason == "uncertain_cooldown"


def test_ip_cooldown_is_observable_skipped():
    policy_engine.clear_cooldowns()
    policy_engine.match("C2_BEACON", 0.9, "critical", "10.8.2.7")
    r2 = policy_engine.match("BRUTE_FORCE", 0.9, "high", "10.8.2.7")
    assert r2.match_status == MatchStatus.SKIPPED
    assert r2.skip_reason == "ip_cooldown"


# ── Orchestrator 端到端 ──

def test_high_truly_unknown_blocks_and_auto_executed_ticket():
    """完全未知类型仍走 Uncertain 5min + P1。"""
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "VENDOR_BRAND_NEW_ALERT",
                "confidence": 0.9, "severity": "high",
                "src_ip": "10.8.3.1", "session_id": "sess-unc-1",
            })
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "uncertain"
        assert result["policy_name"] == UNCERTAIN_POLICY_NAME
        assert set(calls[0]) == {"send_alert", "block_ip"}
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket is not None
        assert ticket.priority == "p1"
        assert ticket.match_status == "uncertain"
        assert ticket.status == ApprovalStatus.AUTO_EXECUTED
    _run(t())


def test_sangfor_event_name_resolves_to_auth_category_block():
    """自然语言事件名 → AUTH_ATTACK 父类 30min 封禁（L3）。"""
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
                "threat_type": "", "event": "未授权获取密码信息",
                "confidence": 0.85, "severity": "high",
                "src_ip": "10.8.3.2", "session_id": "sess-unc-2",
            })
        finally:
            restore()
        assert result["match_status"] == "matched_category"
        assert result["policy_name"] == "认证类攻击通用遏制"
        assert "block_ip" in calls[0]
    _run(t())


def test_medium_uncertain_alert_only_pending_ticket():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "SOME_UNKNOWN_THREAT",
                "confidence": 0.9, "severity": "medium",
                "src_ip": "10.8.3.3", "session_id": "sess-unc-3",
            })
        finally:
            restore()
        assert result["match_status"] == "uncertain"
        assert calls[0] == ["send_alert"]
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket.status == ApprovalStatus.PENDING
        assert ticket.priority == "p1"
    _run(t())


def test_allow_blocking_false_uncertain_still_p1_ticket():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger(
                {
                    "threat_type": "SOME_UNKNOWN_THREAT",
                    "confidence": 0.9, "severity": "critical",
                    "src_ip": "10.8.3.4", "session_id": "sess-unc-4",
                },
                allow_blocking=False,
            )
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "uncertain"
        assert calls[0] == ["send_alert"]
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket.priority == "p1"
        assert ticket.status == ApprovalStatus.PENDING
    _run(t())


def test_user_login_orchestrator_no_action():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "USER_LOGIN",
                "confidence": 0.9, "severity": "info",
                "src_ip": "10.8.3.5", "session_id": "sess-unc-5",
            })
        finally:
            restore()
        assert result["matched"] is False
        assert result["match_status"] == "no_action"
        assert calls == []
    _run(t())
