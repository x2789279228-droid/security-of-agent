"""
L4 行为基线：策略匹配 + Kafka handler + 评分语义回归

Flink BehaviorAnomalyJob 的 evaluate() 逻辑在此用 Python 镜像校验，
保证阈值约定与 Java 一致；编排层验证 BEHAVIOR_ANOMALY → matched_behavior。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from response_engine.human_approval import approval_queue
from response_engine.response_executor import (
    ActionResult, BatchActionResult, response_executor,
)
from response_engine.response_orchestrator import response_orchestrator
from response_engine.response_policies import MatchStatus, policy_engine
from security_guard.security_guard import security_guard


# ── 与 BehaviorAnomalyJob.evaluate 对齐的镜像实现 ──

ABSOLUTE_DST_PORTS = 50
ZSCORE_THRESHOLD = 3.0
COLD_START_WINDOWS = 10


def evaluate_behavior(
    flow_count, bytes_out, unique_dst_ports, unique_dst_ips,
    flow_mean, flow_m2, flow_samples,
    bytes_mean, bytes_m2, bytes_samples,
    cold_start_windows=COLD_START_WINDOWS,
):
    reasons = []
    if unique_dst_ports >= ABSOLUTE_DST_PORTS:
        reasons.append(f"unique_dst_ports={unique_dst_ports}>={ABSOLUTE_DST_PORTS}")
    if unique_dst_ips >= 40:
        reasons.append(f"unique_dst_ips={unique_dst_ips}>=40")
    warmed = flow_samples >= cold_start_windows and bytes_samples >= cold_start_windows
    if warmed:
        flow_std = (flow_m2 / max(1, flow_samples)) ** 0.5
        if flow_std > 0:
            z = (flow_count - flow_mean) / flow_std
            if z >= ZSCORE_THRESHOLD:
                reasons.append(f"flow_count z={z:.2f}")
        bytes_std = (bytes_m2 / max(1, bytes_samples)) ** 0.5
        if bytes_std > 0 and bytes_out >= bytes_mean + ZSCORE_THRESHOLD * bytes_std:
            reasons.append("bytes_out>=μ+3σ")
    else:
        if flow_count >= 200:
            reasons.append("flow_count cold-start static")
        if bytes_out >= 200 * 1024 * 1024:
            reasons.append("bytes_out cold-start static")
    return reasons


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
            batch_rollback_token="tok_beh",
        )

    response_executor.execute_actions = fake_execute

    def restore():
        try:
            del response_executor.execute_actions
        except AttributeError:
            pass

    return restore


def test_scan_ports_absolute_threshold_even_in_cold_start():
    reasons = evaluate_behavior(
        flow_count=10, bytes_out=1000,
        unique_dst_ports=80, unique_dst_ips=5,
        flow_mean=0, flow_m2=0, flow_samples=1,
        bytes_mean=0, bytes_m2=0, bytes_samples=1,
    )
    assert any("unique_dst_ports=" in r for r in reasons)


def test_cold_start_no_zscore_without_extreme():
    reasons = evaluate_behavior(
        flow_count=30, bytes_out=10000,
        unique_dst_ports=10, unique_dst_ips=5,
        flow_mean=5, flow_m2=10, flow_samples=3,
        bytes_mean=1000, bytes_m2=100, bytes_samples=3,
    )
    assert reasons == []


def test_warm_zscore_triggers():
    # μ=10, σ≈1 → flow_count=20 → z≈10
    reasons = evaluate_behavior(
        flow_count=20, bytes_out=1000,
        unique_dst_ports=5, unique_dst_ips=2,
        flow_mean=10, flow_m2=10, flow_samples=10,  # var=1, σ=1
        bytes_mean=1000, bytes_m2=0, bytes_samples=10,
    )
    assert any("flow_count z=" in r for r in reasons)


def test_behavior_policy_match_status():
    policy_engine.reload()
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        "BEHAVIOR_ANOMALY", 0.8, "high", "203.0.113.50",
        category="SCAN",
    )
    assert am.matched
    assert am.match_status == MatchStatus.MATCHED_BEHAVIOR
    assert am.policy_name == "行为基线异常遏制"
    block = next(a for a in am.actions if a["name"] == "block_ip")
    assert block["params"]["duration_minutes"] == 15


def test_orchestrator_behavior_anomaly_blocks():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.reload()
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
                        "threat_type": "BEHAVIOR_ANOMALY",
                        "category": "SCAN",
                        "confidence": 0.8,
                        "severity": "high",
                        "src_ip": "203.0.113.51",
                        "session_id": "flink-behavior",
                        "response_source": "flink_baseline",
                        "allow_blocking": True,
                        "message": "unique_dst_ports=73",
                        "reason": "flink_baseline unique_dst_ports=73",
                    },
                    allow_blocking=True,
                )
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "matched_behavior"
        assert result["policy_name"] == "行为基线异常遏制"
        assert "block_ip" in calls[0]
    _run(t())


def test_kafka_behavior_handler_triggers_orchestrator():
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.reload()
        policy_engine.clear_cooldowns()
        calls = []
        restore = _patch_executor(calls)
        try:
            from kafka_consumer import KafkaConsumerManager
            mgr = KafkaConsumerManager()
            await mgr._handle_behavior_alert(
                {
                    "alertType": "BEHAVIOR_ANOMALY",
                    "srcIp": "203.0.113.52",
                    "severity": "high",
                    "anomalyScore": 0.82,
                    "reasons": ["unique_dst_ports=73"],
                    "category": "SCAN",
                    "message": "scan burst",
                },
                trace_id="abcd1234ffff",
            )
        finally:
            restore()
        assert calls, "handler should execute response actions"
        assert "block_ip" in calls[0]
    _run(t())
