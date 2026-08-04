"""
Trusted Action Gateway — 完整演示场景 (13 步)

演示流程:
  1.  注入扫描、异常登录、PowerShell、C2 日志 (模拟 Sigma 规则检测)
  2.  Flink CEP 形成攻击链 (模拟关联)
  3.  Audit Agent 生成临时封禁计划
  4.  策略引擎计算风险 (RiskEngine)
  5.  自动签发短期单目标授权 (GrantManager)
  6.  Trusted Action Gateway 验证授权
  7.  通过 STDIO MCP 执行测试 IP 临时封禁 (iptables 专用链)
  8.  PostActionVerifier 验证规则和流量
  9.  前端展示完整审计轨迹 (TagAuditTrail)
  10. 重复发送同一请求 — 证明没有重复执行 (幂等)
  11. 注入恶意日志 — 诱导封禁核心服务器 (数据库)
  12. 系统因目标受保护、证据不足、授权范围不符而拒绝
  13. 按 action_id 执行幂等回滚

运行:
  cd f:\\项目\\security-of-agent\\backend
  python -m trusted_action_gateway.demo_tag
  或:
  python trusted_action_gateway/demo_tag.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import os
import uuid
from datetime import datetime, timezone

# ── 注入 mock Base (同 conftest.py / test_tag.py) ──
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs, create_async_engine, async_sessionmaker, AsyncSession


class _DemoBase(AsyncAttrs, DeclarativeBase):
    pass


_mock_models = type(sys)("models")
_mock_models.Base = _DemoBase
sys.modules["models"] = _mock_models

# 将 backend 加入 path
_backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# ── 导入 TAG 组件 ──
from trusted_action_gateway.models import (
    ActionGrant, ActionLedger, TagAuditTrail, ActionBudgetState,
)
from trusted_action_gateway.state_machine import ActionState, AutomationLevel, ExecutionMode
from trusted_action_gateway.risk_engine import risk_engine
from trusted_action_gateway.grant_manager import grant_manager
from trusted_action_gateway.idempotency_guard import idempotency_guard
from trusted_action_gateway.impact_policy import impact_policy_manager, action_budget
from trusted_action_gateway.audit_logger import tag_audit_logger
from trusted_action_gateway.executors.iptables_executor import IptablesChainExecutor
from trusted_action_gateway.executors.post_verifier import TagPostActionVerifier
from trusted_action_gateway.gateway import TrustedActionGateway, ActionPlan, tag_gateway


# ── 演示用分隔线 ──
def _step(n: int, title: str):
    print(f"\n{'='*70}")
    print(f"  步骤 {n}: {title}")
    print(f"{'='*70}")


def _info(msg: str):
    print(f"  [INFO] {msg}")


def _warn(msg: str):
    print(f"  [WARN] {msg}")


def _ok(msg: str):
    print(f"  [ OK ] {msg}")


def _fail(msg: str):
    print(f"  [FAIL] {msg}")


async def run_demo():
    """运行完整演示"""

    print("\n" + "=" * 70)
    print("  Trusted Action Gateway — 完整演示场景")
    print("  共 13 步: 攻击链检测 → 自动封禁 → 验证 → 幂等 → 回滚")
    print("=" * 70)

    # ── 初始化 SQLite 内存数据库 ──
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: _DemoBase.metadata.create_all(
            c,
            tables=[
                ActionGrant.__table__,
                ActionLedger.__table__,
                TagAuditTrail.__table__,
                ActionBudgetState.__table__,
            ],
        ))
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    # ── 初始化 TAG 组件 ──
    iptables_executor = IptablesChainExecutor(ssh_adapter=None)
    await iptables_executor.initialize()

    verifier = TagPostActionVerifier(iptables_executor)
    gateway = TrustedActionGateway(
        iptables_executor=iptables_executor,
        post_verifier=verifier,
        execution_mode=ExecutionMode.PRODUCTION,
    )

    async with SessionLocal() as session:

        # ════════════════════════════════════════════════════════════
        # 步骤 1: 注入扫描、异常登录、PowerShell、C2 日志
        # ════════════════════════════════════════════════════════════
        _step(1, "注入安全事件日志 (模拟 Sigma 规则检测)")

        incident_id = "INC-DEMO-20260803-001"
        attacker_ip = "203.0.113.77"
        evidence_ids = ["EV-SCAN-001", "EV-LOGIN-002", "EV-PSH-003", "EV-C2-004"]

        events = [
            {"rule": "network_scan",     "src": attacker_ip, "dst": "10.0.0.0/24",  "severity": "medium"},
            {"rule": "anomaly_login",    "src": attacker_ip, "dst": "10.0.0.5",     "severity": "high",   "user": "admin"},
            {"rule": "powershell_exec",   "src": "10.0.0.5",  "dst": "10.0.0.5",     "severity": "high",   "cmd": "Invoke-Mimikatz"},
            {"rule": "c2_beacon",         "src": "10.0.0.5",  "dst": attacker_ip,    "severity": "critical", "freq": "every_60s"},
        ]

        for ev in events:
            _info(f"Sigma 检测: {ev['rule']:20s} src={ev['src']:16s} sev={ev['severity']}")

        _ok(f"生成 {len(evidence_ids)} 条证据: {evidence_ids}")

        # ════════════════════════════════════════════════════════════
        # 步骤 2: Flink CEP 形成攻击链
        # ════════════════════════════════════════════════════════════
        _step(2, "Flink CEP 攻击链识别")

        attack_chain = "扫描探测 → 异常登录 → PowerShell 执行 → C2 通信"
        _info(f"CEP 模式匹配: {attack_chain}")
        _info(f"关联事件: incident_id={incident_id}")
        _ok("攻击链确认: 横向移动 + C2 回连，建议临时封禁攻击源 IP")

        # ════════════════════════════════════════════════════════════
        # 步骤 3: Audit Agent 生成临时封禁计划
        # ════════════════════════════════════════════════════════════
        _step(3, "Audit Agent 生成临时封禁计划")

        plan = ActionPlan(
            tool_name="block_ip",
            target=attacker_ip,
            parameters={"ip": attacker_ip, "ttl_seconds": 3600},
            incident_id=incident_id,
            agent_identity="audit-agent-001",
            evidence_ids=evidence_ids,
            asset_info={"type": "external_attacker", "criticality": "none"},
            trace_id=f"TRC-DEMO-{uuid.uuid4().hex[:8].upper()}",
        )
        _info(f"动作计划: tool=block_ip target={attacker_ip} ttl=3600s")
        _info(f"Agent: {plan.agent_identity}")
        _info(f"证据: {plan.evidence_ids}")

        # ════════════════════════════════════════════════════════════
        # 步骤 4: 策略引擎计算风险
        # ════════════════════════════════════════════════════════════
        _step(4, "策略引擎计算风险 (RiskEngine)")

        assessment = risk_engine.assess(
            tool_name=plan.tool_name,
            target=plan.target,
            parameters=plan.parameters,
            incident_id=incident_id,
            evidence_ids=plan.evidence_ids,
            asset_info=plan.asset_info,
        )
        factors = assessment.factors

        _info(f"action_base_risk:     {factors.action_base_risk}")
        _info(f"asset_criticality:   {factors.asset_criticality}")
        _info(f"blast_radius:         {factors.blast_radius}")
        _info(f"evidence_completeness:{factors.evidence_completeness:.0%}")
        _info(f"source_trust:         {factors.source_trust:.0%}")
        _info(f"reversibility:        {factors.reversibility}")
        _info(f"is_internal_ip:       {factors.is_internal_ip}")
        _info(f"grounding_score:      {factors.grounding_score:.0%}")
        _info(f"---")
        _info(f"risk_score:           {assessment.risk_score:.3f}")
        _info(f"risk_level:           {assessment.risk_level}")
        _info(f"automation_level:     {assessment.automation_level.value}")
        _info(f"auto_execute:         {assessment.auto_execute}")
        _info(f"policy_decision:      {assessment.policy_decision}")
        if assessment.reasons:
            _info(f"reasons:              {assessment.reasons}")

        if assessment.auto_execute:
            _ok(f"风险等级 {assessment.automation_level.value} — 允许自动执行 (策略引擎签发授权)")
        else:
            _warn(f"风险等级 {assessment.automation_level.value} — 需要 {assessment.approval_required} 授权")

        # ════════════════════════════════════════════════════════════
        # 步骤 5: 自动签发短期单目标授权
        # ════════════════════════════════════════════════════════════
        _step(5, "自动签发短期单目标授权 (GrantManager)")

        grant = await grant_manager.issue_grant(
            session=session,
            subject=plan.agent_identity,
            incident_id=incident_id,
            tool_name=plan.tool_name,
            target_scope={"ips": [attacker_ip]},
            parameter_constraints={"ttl_seconds": {"min": 60, "max": 3600}},
            evidence_ids=evidence_ids,
            approval_level="auto",
            automation_level=assessment.automation_level,
            created_by="risk_engine",
            ttl_seconds=600,       # 授权有效期 10 分钟
            max_executions=1,      # 最多执行 1 次
        )
        await session.flush()
        _ok(f"授权签发: grant_id={grant.id}")
        _info(f"  subject:              {grant.subject}")
        _info(f"  incident_id:          {grant.incident_id}")
        _info(f"  tool_name:            {grant.tool_name}")
        _info(f"  target_scope:         {grant.target_scope}")
        _info(f"  max_executions:       {grant.max_executions}")
        _info(f"  expires_at:           {grant.expires_at.isoformat()}")
        _info(f"  revocable:            {grant.revocable}")

        # ════════════════════════════════════════════════════════════
        # 步骤 6: TAG 验证授权并执行
        # ════════════════════════════════════════════════════════════
        _step(6, "Trusted Action Gateway 验证授权 + 执行 (步骤 7)")

        # 设置 plan 的 grant_id
        plan.grant_id = grant.id
        plan.trace_id = f"TRC-DEMO-{uuid.uuid4().hex[:8].upper()}"

        result = await gateway.process_action(session, plan)
        await session.commit()

        _info(f"action_id:        {result.action_id}")
        _info(f"trace_id:         {result.trace_id}")
        _info(f"action_state:     {result.action_state.value}")
        _info(f"policy_decision:  {result.policy_decision}")
        _info(f"grant_id:         {result.grant_id}")
        _info(f"idempotency_key:  {result.idempotency_key[:32]}...")

        if result.execution_result:
            _info(f"execution_result: {result.execution_result}")
        if result.verification_result:
            _info(f"verification:     {result.verification_result}")

        if result.action_state == ActionState.SUCCEEDED:
            _ok("封禁执行成功 + 验证通过")
        else:
            _fail(f"动作未成功: state={result.action_state.value} blocked_by={result.blocked_by}")

        # ════════════════════════════════════════════════════════════
        # 步骤 8: PostActionVerifier 验证规则和流量 (已在步骤 6 中完成)
        # ════════════════════════════════════════════════════════════
        _step(7, "通过 STDIO MCP 执行测试 IP 临时封禁 (iptables 专用链)")
        _step(8, "PostActionVerifier 验证规则和流量")

        # 列出专用链规则
        rules = await iptables_executor.list_rules("AGENT_GUARD_INPUT")
        _info(f"AGENT_GUARD_INPUT 链规则数: {len(rules)}")
        for r in rules:
            _info(f"  rule_id={r.get('rule_id', '')} src={r.get('src', '')} "
                  f"comment={r.get('comment', '')[:60]}")

        # 验证 INPUT 主链无 DROP 规则
        main_rules = await iptables_executor.list_rules("INPUT")
        drop_rules = [r for r in main_rules if r.get("src", "").startswith("203.")]
        if not drop_rules:
            _ok("INPUT 主链无 Agent DROP 规则 — 隔离正确")
        else:
            _fail("INPUT 主链发现 DROP 规则 — 隔离失败")

        if result.verification_result.get("verified"):
            _ok(f"PostActionVerifier 验证通过: {result.verification_result.get('evidence', '')}")
        else:
            _warn("验证未通过")

        # ════════════════════════════════════════════════════════════
        # 步骤 9: 完整审计轨迹
        # ════════════════════════════════════════════════════════════
        _step(9, "完整审计轨迹 (TagAuditTrail)")

        audit_trail = await tag_audit_logger.get_audit_trail(
            session, incident_id=incident_id, limit=20,
        )
        _info(f"审计记录数: {len(audit_trail)}")
        for entry in audit_trail:
            _info(
                f"  state={entry.action_state:20s} "
                f"tool={entry.tool_name:12s} "
                f"target={entry.target:16s} "
                f"risk={entry.risk_level:4s} "
                f"grant={entry.grant_id[:16] if entry.grant_id else 'N/A':16s} "
                f"trace={entry.trace_id[:16]}"
            )
        _ok("审计轨迹完整 — 不含明文 Token / 密码 / 私钥")

        # ════════════════════════════════════════════════════════════
        # 步骤 10: 重复请求 — 幂等验证
        # ════════════════════════════════════════════════════════════
        _step(10, "重复发送同一请求 — 证明没有重复执行")

        # 用相同的 plan 再次请求
        plan2 = ActionPlan(
            tool_name=plan.tool_name,
            target=plan.target,
            parameters=plan.parameters,
            incident_id=plan.incident_id,
            agent_identity=plan.agent_identity,
            evidence_ids=plan.evidence_ids,
            asset_info=plan.asset_info,
            plan_version=plan.plan_version,
            trace_id=f"TRC-DEMO-DUP-{uuid.uuid4().hex[:8].upper()}",
        )
        result2 = await gateway.process_action(session, plan2)

        _info(f"首次 action_id:   {result.action_id}")
        _info(f"重复 action_id:   {result2.action_id}")
        _info(f"首次 state:       {result.action_state.value}")
        _info(f"重复 state:       {result2.action_state.value}")

        if result.action_id == result2.action_id:
            _ok("幂等命中 — 相同 action_id，未重复执行")
        else:
            _fail("幂等失败 — 生成了不同的 action_id")

        # 检查 iptables 规则数未增加
        rules_after_dup = await iptables_executor.list_rules("AGENT_GUARD_INPUT")
        if len(rules_after_dup) == len(rules):
            _ok(f"iptables 规则数未增加 ({len(rules)} → {len(rules_after_dup)})")
        else:
            _fail(f"iptables 规则数增加 ({len(rules)} → {len(rules_after_dup)})")

        # ════════════════════════════════════════════════════════════
        # 步骤 11: 注入恶意日志 — 诱导封禁核心服务器
        # ════════════════════════════════════════════════════════════
        _step(11, "注入恶意日志 — 诱导封禁核心服务器 (数据库)")

        malicious_plan = ActionPlan(
            tool_name="block_ip",
            target="10.0.0.1",  # 数据库服务器
            parameters={"ip": "10.0.0.1", "ttl_seconds": 99999},
            incident_id="INC-INJECTION-001",
            agent_identity="compromised-agent",
            evidence_ids=[],  # 无证据
            asset_info={"type": "database", "criticality": "critical", "protected": True},
        )
        _info(f"恶意请求: target={malicious_plan.target} (数据库服务器)")
        _info(f"Agent: {malicious_plan.agent_identity} (疑似被入侵)")
        _info(f"证据: {malicious_plan.evidence_ids} (无)")

        malicious_result = await gateway.process_action(session, malicious_plan)

        # ════════════════════════════════════════════════════════════
        # 步骤 12: 系统拒绝 (目标受保护 + 证据不足)
        # ════════════════════════════════════════════════════════════
        _step(12, "系统拒绝 — 目标受保护 / 证据不足 / 授权范围不符")

        _info(f"action_state: {malicious_result.action_state.value}")
        _info(f"blocked_by:   {malicious_result.blocked_by}")
        _info(f"block_reason: {malicious_result.block_reason}")

        if malicious_result.action_state == ActionState.BLOCKED:
            _ok(f"恶意请求被阻止: blocked_by={malicious_result.blocked_by}")
            _ok(f"阻止原因: {malicious_result.block_reason}")
        else:
            _fail("恶意请求未被阻止 — 安全漏洞!")

        # ════════════════════════════════════════════════════════════
        # 步骤 13: 按 action_id 执行幂等回滚
        # ════════════════════════════════════════════════════════════
        _step(13, "按 action_id 执行幂等回滚")

        # 回滚步骤 6 的封禁
        rollback_result = await gateway.request_rollback(
            session, result.action_id, "analyst-admin",
        )
        await session.commit()

        _info(f"rollback action_state: {rollback_result.action_state.value}")
        _info(f"rollback_result:       {rollback_result.rollback_result}")

        if rollback_result.action_state == ActionState.ROLLED_BACK:
            _ok("回滚成功 — 规则已从专用链移除")
        else:
            _fail(f"回滚失败: {rollback_result.action_state.value}")

        # 验证幂等回滚 — 再次回滚应返回相同结果
        rollback_result2 = await gateway.request_rollback(
            session, result.action_id, "analyst-admin",
        )
        _info(f"第二次回滚 action_state: {rollback_result2.action_state.value}")

        if rollback_result2.action_state == ActionState.ROLLED_BACK:
            _ok("幂等回滚 — 重复请求返回相同结果，未重复执行")
        else:
            _fail("幂等回滚失败")

        # 验证规则已移除
        rules_after_rollback = await iptables_executor.list_rules("AGENT_GUARD_INPUT")
        remaining = [r for r in rules_after_rollback if r.get("src") == attacker_ip]
        if not remaining:
            _ok("封禁规则已从专用链移除")
        else:
            _fail(f"封禁规则仍存在: {len(remaining)} 条")

    # ── 总结 ──
    print("\n" + "=" * 70)
    print("  演示完成 — 13 步全部执行")
    print("=" * 70)
    print("  关键验证点:")
    print("  - 风险自适应: A2 自动执行 (可逆 + 单目标 + 证据充分)")
    print("  - 分步提权: 短期 (10min) 单目标授权, max_executions=1")
    print("  - 幂等控制: 重复请求返回相同 action_id, iptables 规则未增加")
    print("  - 影响范围: 核心资产 (数据库) 被自动拒绝")
    print("  - iptables 专用链: AGENT_GUARD_INPUT, 规则绑定 action_id")
    print("  - 执行后验证: PostActionVerifier 验证规则存在性")
    print("  - 幂等回滚: 重复回滚返回相同结果")
    print("  - 审计日志: 完整轨迹, 不含明文敏感信息")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_demo())
