"""
P0 修复回归: 审批分级强制

修复前: needs_approval 分支中 auto_execute=True 的高危动作先直接执行，
        再把工单伪造标为 AUTO_APPROVED，"高危需审批"形同虚设。
修复后: 含 CRITICAL 动作（如 isolate_host）一律人工审批；
        仅 HIGH 动作（如 block_ip）且策略显式 auto_execute=True 才自动执行，
        工单状态为 AUTO_EXECUTED（供事后审查/回滚，非审批结果）。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from response_engine.response_executor import ActionResult, BatchActionResult
from response_engine.response_orchestrator import (
    ResponseOrchestrator,
    response_orchestrator,
)
from response_engine.response_policies import ResponsePolicy, policy_engine
from response_engine.human_approval import ApprovalStatus, approval_queue


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _fake_batch(action_name: str = "block_ip") -> BatchActionResult:
    return BatchActionResult(
        total=1, succeeded=1, failed=0,
        results=[ActionResult(action_name=action_name, success=True)],
        batch_rollback_token="batch_test_token",
    )


def _patch_execute(calls: list):
    """把 _guarded_execute 替换为记录调用的 fake，返回恢复函数。"""
    orig = response_orchestrator._guarded_execute  # bound method

    async def fake(actions, threat_info, parallel=False):
        calls.append([dict(a) for a in actions])
        return _fake_batch(actions[0].get("name", "") if actions else "")

    response_orchestrator._guarded_execute = fake

    def restore():
        response_orchestrator._guarded_execute = orig

    return restore


async def _trigger(threat_type: str, conf=0.9, severity="high", src_ip="9.9.9.9"):
    from models import async_session
    async with async_session() as s:
        return await response_orchestrator.on_threat_detected(
            s,
            {
                "threat_type": threat_type,
                "confidence": conf,
                "severity": severity,
                "src_ip": src_ip,
                "session_id": "sess-appr",
            },
        )


class TestApprovalTiering:
    def test_high_action_with_explicit_auto_executes_and_marks_auto_executed(self):
        """暴力破解自动阻断: block_ip(HIGH) + auto_execute=True → 执行 + AUTO_EXECUTED。"""
        async def t():
            await _reset()
            policy_engine.clear_cooldowns()
            approval_queue._tickets.clear()
            calls = []
            restore = _patch_execute(calls)
            try:
                result = await _trigger("BRUTE_FORCE", src_ip="9.9.9.1")
            finally:
                restore()
            assert result["matched"]
            assert len(calls) == 1, "HIGH 动作 + 策略显式 auto_execute 应直接执行"
            ticket = approval_queue.get_ticket(result["approval_ticket_id"])
            assert ticket is not None
            assert ticket.status == ApprovalStatus.AUTO_EXECUTED
        _run(t())

    def test_critical_action_forces_manual_approval_even_with_auto_execute(self):
        """含 CRITICAL 动作(isolate_host)的策略即使 auto_execute=True 也必须人工审批。"""
        async def t():
            await _reset()
            policy_engine.clear_cooldowns()
            approval_queue._tickets.clear()
            policy_engine.add_policy(ResponsePolicy(
                name="测试CRITICAL自动策略",
                threat_type="TEST_CRIT",
                min_confidence=0.5,
                min_severity="medium",
                actions=[
                    {"name": "isolate_host", "params": {}},
                    {"name": "send_alert", "params": {"severity": "critical"}},
                ],
                auto_execute=True,   # 故意与 CRITICAL 动作组合
                require_approval=False,
                priority=1000,
            ))
            calls = []
            restore = _patch_execute(calls)
            try:
                result = await _trigger("TEST_CRIT", src_ip="9.9.9.2")
            finally:
                restore()
            assert result["matched"]
            assert not calls, "含 CRITICAL 动作不应自动执行"
            assert result["actions_executed"] == 0
            ticket = approval_queue.get_ticket(result["approval_ticket_id"])
            assert ticket is not None
            assert ticket.status == ApprovalStatus.PENDING, "应等待人工审批"
        _run(t())

    def test_manual_approval_path_unchanged(self):
        """数据外泄紧急隔离(auto_execute=False, 含 isolate_host)仍走人工审批。"""
        async def t():
            await _reset()
            policy_engine.clear_cooldowns()
            approval_queue._tickets.clear()
            calls = []
            restore = _patch_execute(calls)
            try:
                result = await _trigger("DATA_EXFIL", src_ip="9.9.9.3")
            finally:
                restore()
            assert result["matched"]
            assert not calls, "auto_execute=False 不应执行"
            ticket = approval_queue.get_ticket(result["approval_ticket_id"])
            assert ticket is not None
            assert ticket.status == ApprovalStatus.PENDING
        _run(t())

    def test_uncertain_medium_alerts_with_pending_p1_ticket(self):
        """未知类型走 Uncertain: medium 下护栏只放行 send_alert,
        建 PENDING P1 工单等人审决定是否升级封禁。

        本用例走真实 SecurityGuard（不用 _patch_execute 绕过护栏），
        否则 fake 会把 block_ip 也标成功，误判为 AUTO_EXECUTED。
        """
        from response_engine.response_executor import response_executor
        from security_guard.security_guard import security_guard

        async def t():
            await _reset()
            security_guard.reset()
            policy_engine.clear_cooldowns()
            approval_queue._tickets.clear()
            calls = []

            async def fake_execute(actions, threat_info, **kw):
                calls.append([a.get("name", "") for a in actions])
                return BatchActionResult(
                    total=len(actions), succeeded=len(actions), failed=0,
                    results=[
                        ActionResult(action_name=a.get("name", ""), success=True)
                        for a in actions
                    ],
                    batch_rollback_token="tok_appr_unc",
                )

            response_executor.execute_actions = fake_execute
            try:
                result = await _trigger(
                    "SOME_UNKNOWN_THREAT", conf=0.5, severity="medium",
                    src_ip="9.9.9.4",
                )
            finally:
                try:
                    del response_executor.execute_actions
                except AttributeError:
                    pass
            assert result["matched"], "应命中 Uncertain 遏制"
            assert result.get("match_status") == "uncertain"
            assert calls == [["send_alert"]], "medium 下 block_ip 应被护栏拦截"
            ticket = approval_queue.get_ticket(result.get("approval_ticket_id", ""))
            assert ticket is not None, "Uncertain 必须建 P1 工单"
            assert ticket.priority == "p1"
            assert ticket.status == ApprovalStatus.PENDING
        _run(t())


class TestSeverityHelper:
    def test_has_critical_action(self):
        from response_engine.response_registry import (
            has_critical_action,
            max_action_severity,
        )
        assert has_critical_action([{"name": "isolate_host", "params": {}}])
        assert not has_critical_action([{"name": "block_ip", "params": {}}])
        assert max_action_severity(
            [{"name": "block_ip"}, {"name": "isolate_host"}]
        ) == "critical"
        # 未知动作按 CRITICAL 保守处理
        assert has_critical_action([{"name": "no_such_action"}])
        assert not has_critical_action([])
