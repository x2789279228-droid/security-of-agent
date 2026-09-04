"""
v5 修复回归: 响应引擎去重 + 双轨封禁门槛 + 词表对齐

覆盖:
  C1-1  per-IP 聚合冷却 — 同 IP 不同 threat_type 短窗口内只允许一次响应编排
        (修复: 同 IP 1.4s 内 5 策略连发 / 累计 15+ 次 policy_match)
  C1-2  冷却写入时机后移 — 护栏拦截全部动作时不烧 per-policy 冷却;
        mark_executed 后冷却生效
  C2-1  策略匹配大小写不敏感 — "DDOS_TRAFFIC" 能命中 "DDoS_TRAFFIC" 策略
  C2-2  「命令注入」词表补齐 — infer_threat_type 映射 + TYPE_SIGNAL_EVENTS
  A-1   双轨门槛 — allow_blocking=False 时仅 send_alert 执行, 封禁类被过滤
  A-2   policy_match 日志记录 response_source(封禁决策来源可追溯)
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from correlation_engine import infer_threat_type
from response_engine.response_executor import (
    ActionResult,
    BatchActionResult,
    response_executor,
)
from response_engine.response_orchestrator import response_orchestrator
from response_engine.response_policies import PolicyEngine, ResponsePolicy, policy_engine
from response_engine.human_approval import ApprovalStatus, approval_queue
from security_guard.security_guard import security_guard
from veto_gates import extract_non_llm_signals


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _patch_executor(calls: list, fail_all: bool = False):
    """替换底层动作执行器(护栏仍真实运行), 记录通过审查的动作名列表。"""
    async def fake_execute(actions, threat_info, **kw):
        calls.append([a.get("name", "") for a in actions])
        if fail_all:
            return BatchActionResult(total=len(actions), succeeded=0, failed=len(actions), results=[])
        return BatchActionResult(
            total=len(actions), succeeded=len(actions), failed=0,
            results=[
                ActionResult(action_name=a.get("name", ""), success=True)
                for a in actions
            ],
            batch_rollback_token="tok_dedup_test",
        )

    response_executor.execute_actions = fake_execute

    def restore():
        try:
            del response_executor.execute_actions
        except AttributeError:
            pass

    return restore


def test_per_ip_aggregate_cooldown_blocks_second_match():
    """同 IP 第 1 次命中后, 60s 内任何其他策略命中都被聚合冷却抑制。"""
    engine = PolicyEngine()
    engine.load_defaults()
    engine.ip_cooldown_sec = 60
    engine.clear_cooldowns()
    r1 = engine.match("C2_BEACON", 0.85, "critical", "10.9.0.1")
    assert r1.matched and r1.policy_name == "C2通信自动封禁"
    # 不同 threat_type (此前会因 per-policy 冷却互不感知而再次命中)
    r2 = engine.match("DATA_EXFIL", 0.9, "critical", "10.9.0.1")
    assert not r2.matched, "同 IP 聚合冷却窗口内不应再次编排响应"
    r3 = engine.match("BRUTE_FORCE", 0.8, "high", "10.9.0.1")
    assert not r3.matched, "聚合冷却与威胁类型无关"
    # 不同 IP 不受影响
    r4 = engine.match("BRUTE_FORCE", 0.8, "high", "10.9.0.2")
    assert r4.matched, "聚合冷却只针对同一 src_ip"


def test_per_ip_aggregate_cooldown_expires():
    """超过 ip_cooldown_sec 后同 IP 可再次编排(模拟窗口过期)。"""
    engine = PolicyEngine()
    engine.load_defaults()
    engine.ip_cooldown_sec = 60
    engine.clear_cooldowns()
    r1 = engine.match("C2_BEACON", 0.85, "critical", "10.9.0.3")
    assert r1.matched
    # 手动把聚合冷却时间戳回拨到窗口外
    import time
    engine._ip_last_match["10.9.0.3"] = time.time() - 61
    r2 = engine.match("C2_BEACON", 0.85, "critical", "10.9.0.3")
    assert r2.matched, "聚合冷却过期后应可再次命中"


def test_ddos_policy_matches_uppercase_input():
    """修复: 策略定义 DDoS_TRAFFIC / 事件实际 DDOS_TRAFFIC, 大小写不敏感后可命中。"""
    engine = PolicyEngine()
    engine.load_defaults()
    engine.ip_cooldown_sec = 0  # 关闭聚合冷却, 专测大小写匹配
    engine.clear_cooldowns()
    r = engine.match("DDOS_TRAFFIC", 0.72, "high", "10.9.0.4")
    assert r.matched, "DDOS_TRAFFIC 应命中 DDoS 专属策略"
    assert r.policy_name == "DDoS流量自动防护", f"实际命中: {r.policy_name}"


def test_cooldown_not_burned_when_guard_blocks_all():
    """护栏拦截全部动作时不写冷却: 同策略同 IP 可立即重试; mark_executed 后才冷却。"""
    policy_engine.ip_cooldown_sec = 0  # 关闭聚合冷却, 专测 per-policy 冷却时机
    policy_engine.clear_cooldowns()
    policy_engine.add_policy(ResponsePolicy(
        name="测试仅封禁策略",
        threat_type="TEST_BLOCK_ONLY",
        min_confidence=0.5,
        min_severity="medium",
        actions=[{"name": "block_ip", "params": {"duration_minutes": 30}}],
        auto_execute=True,
        priority=2000,
        cooldown_minutes=15,
    ))
    calls = []
    restore = _patch_executor(calls)
    try:
        async def t():
            await _reset()
            security_guard.reset()
            approval_queue._tickets.clear()
            from models import async_session
            async with async_session() as s:
                # severity=medium → IntentChecker 拦截 block_ip → 全部动作被拦
                r1 = await response_orchestrator.on_threat_detected(s, {
                    "threat_type": "TEST_BLOCK_ONLY",
                    "confidence": 0.9, "severity": "medium",
                    "src_ip": "10.9.0.5", "session_id": "sess-dedup-1",
                })
            assert r1["matched"]
            assert r1["actions_executed"] == 0, "护栏应拦截 medium 级 block_ip"
            assert not calls
        _run(t())
        # 冷却未被消耗 → 同 IP 同策略立即可再次命中
        r2 = policy_engine.match("TEST_BLOCK_ONLY", 0.9, "medium", "10.9.0.5")
        assert r2.matched and r2.policy_name == "测试仅封禁策略", \
            "护栏拦截不应消耗冷却窗口"
        # 模拟动作真正执行后 → 冷却生效(该策略被跳过, 仅 fall-through 到兜底)
        policy_engine.mark_executed("测试仅封禁策略", "10.9.0.5")
        r3 = policy_engine.match("TEST_BLOCK_ONLY", 0.9, "medium", "10.9.0.5")
        assert r3.policy_name != "测试仅封禁策略", \
            "mark_executed 后该策略应处于冷却(允许 fall-through 到其他策略)"
        assert "10.9.0.5" in policy_engine._cooldowns.get("测试仅封禁策略", {}), \
            "冷却条目应已写入"
    finally:
        policy_engine.remove_policy("测试仅封禁策略")
        policy_engine.clear_cooldowns()
        policy_engine.ip_cooldown_sec = 60
        restore()


def test_alert_only_mode_filters_blocking_actions():
    """双轨门槛: allow_blocking=False 时 block_ip 被过滤, 仅 send_alert 执行。"""
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            from models import async_session
            async with async_session() as s:
                result = await response_orchestrator.on_threat_detected(
                    s,
                    {
                        "threat_type": "SOME_UNKNOWN_THREAT",
                        "confidence": 0.34, "severity": "critical",
                        "src_ip": "10.9.0.6", "session_id": "sess-dedup-2",
                    },
                    allow_blocking=False,
                )
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "uncertain"
        assert result["policy_name"] == "未知威胁保守遏制"
        assert len(calls) == 1
        assert calls[0] == ["send_alert"], \
            "告警-only 模式下 block_ip 必须被双轨门槛过滤"
        assert result["actions_executed"] == 1
        # Uncertain 即使只剩告警也强制建 P1 工单
        assert result.get("approval_required")
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket is not None
        assert ticket.priority == "p1"
        assert ticket.status == ApprovalStatus.PENDING
    _run(t())


def test_cooldown_not_burned_when_all_actions_fail():
    """全部动作执行失败(如瞬时 DNS 抖动)也不烧 per-policy 冷却, 后续可重试。"""
    policy_engine.ip_cooldown_sec = 0
    policy_engine.clear_cooldowns()
    policy_engine.add_policy(ResponsePolicy(
        name="测试失败重试策略",
        threat_type="TEST_RETRY",
        min_confidence=0.5,
        min_severity="high",
        actions=[{"name": "block_ip", "params": {"duration_minutes": 30}}],
        auto_execute=True,
        priority=2000,
        cooldown_minutes=30,
    ))
    calls = []
    restore = _patch_executor(calls, fail_all=True)
    try:
        async def t():
            await _reset()
            security_guard.reset()
            approval_queue._tickets.clear()
            from models import async_session
            async with async_session() as s:
                r = await response_orchestrator.on_threat_detected(s, {
                    "threat_type": "TEST_RETRY",
                    "confidence": 0.9, "severity": "high",
                    "src_ip": "10.9.0.8", "session_id": "sess-dedup-4",
                })
            # guard 放行(high)但执行器全部失败 → results 含失败项
            assert r["matched"] and r["actions_executed"] == 0
        _run(t())
        r2 = policy_engine.match("TEST_RETRY", 0.9, "high", "10.9.0.8")
        assert r2.matched and r2.policy_name == "测试失败重试策略", \
            "全部执行失败不应烧冷却(应可重试)"
    finally:
        policy_engine.remove_policy("测试失败重试策略")
        policy_engine.clear_cooldowns()
        policy_engine.ip_cooldown_sec = 60
        restore()


def test_command_injection_inference_and_type_signal():
    """「命令注入」: 自然语言 → COMMAND_INJECTION 枚举; 且可作为 type_signal。"""
    assert infer_threat_type("命令注入") == "COMMAND_INJECTION"
    signals = extract_non_llm_signals({"event": "命令注入"})
    assert signals.type_signal, "COMMAND_INJECTION 应在 TYPE_SIGNAL_EVENTS 中"
    assert signals.has_signal


def test_ddos_type_signal_uppercase():
    """事件类型 upper() 归一后 DDOS_TRAFFIC 应命中 type_signal(修大小写 bug)。"""
    signals = extract_non_llm_signals({"event": "DDoS_TRAFFIC"})
    assert signals.type_signal, "DDoS_TRAFFIC upper() 后应命中词表"


def test_response_source_recorded_in_policy_match_log():
    """policy_match 日志的 action_params 记录 response_source(封禁决策来源)。"""
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        calls = []
        restore = _patch_executor(calls)
        try:
            from models import async_session
            from models import ResponseLog
            from sqlalchemy import select, desc
            async with async_session() as s:
                await response_orchestrator.on_threat_detected(
                    s,
                    {
                        "threat_type": "SOME_UNKNOWN_THREAT",
                        "confidence": 0.9, "severity": "critical",
                        "src_ip": "10.9.0.7", "session_id": "sess-dedup-3",
                        "response_source": "fastpath_severity",
                        "allow_blocking": False,
                    },
                    allow_blocking=False,
                )
                row = (await s.execute(
                    select(ResponseLog)
                    .where(ResponseLog.action_name == "policy_match")
                    .order_by(desc(ResponseLog.id))
                    .limit(1)
                )).scalars().first()
        finally:
            restore()
        assert row is not None
        params = row.action_params or {}
        assert params.get("source") == "fastpath_severity"
        assert params.get("allow_blocking") is False
        # 推断后的 threat_type 已回写(不再出现裸自然语言名)
        assert row.threat_type == "SOME_UNKNOWN_THREAT"
    _run(t())
