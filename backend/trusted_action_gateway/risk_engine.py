"""
风险自适应自治引擎 — 多维风险评分与策略决策

A4 危险动作检测:
  在 _evaluate 最前置调用 DbSafetyPolicy.check_action()
  若返回 A4 → 直接 deny, 不可通过分步提权绕过
"""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
import logging

from .state_machine import (
    AutomationLevel, ExecutionMode, decide_automation_level,
    LEVEL_APPROVAL_MAP, LEVEL_AUTO_EXECUTE,
)

# A4 危险动作策略 — 延迟导入避免循环依赖
try:
    from response_engine.db_safety import db_safety_policy, A4Decision
except ImportError:
    # 测试环境或独立使用 TAG 时, 使用内置简化版
    db_safety_policy = None
    A4Decision = None

logger = logging.getLogger(__name__)


@dataclass
class RiskFactors:
    """风险因子集合"""
    action_base_risk: str = "MEDIUM"  # LOW/MEDIUM/HIGH/CRITICAL
    asset_criticality: str = "medium"  # low/medium/high/critical
    blast_radius: str = "single"  # single/few/wide
    evidence_completeness: float = 0.5  # 0.0-1.0
    source_trust: float = 0.5  # 0.0-1.0
    reversibility: bool = True
    environment: str = "production"  # shadow/sandbox/production
    execution_mode: str = "live"  # live/dry_run/mock

    # 附加因子
    is_protected_asset: bool = False
    is_internal_ip: bool = False
    has_wildcard_target: bool = False
    grounding_score: float = 1.0  # 证据支撑度

    # A4 检查所需上下文 (DbSafetyPolicy)
    tool_name: str = ""
    parameters: dict = None
    target: str = ""
    asset_type: str = ""


@dataclass
class RiskAssessment:
    """风险评估结果"""
    risk_score: float = 0.0  # 0.0-1.0
    risk_level: str = "A1"
    automation_level: AutomationLevel = AutomationLevel.A1
    approval_required: str = "basic"  # basic/auto/cad/human/denied
    auto_execute: bool = True
    policy_decision: str = "allow"  # allow/deny/require_confirmation/require_human
    reasons: list = field(default_factory=list)
    blocked_by: str = ""
    factors: RiskFactors = None

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "automation_level": self.automation_level.value,
            "approval_required": self.approval_required,
            "auto_execute": self.auto_execute,
            "policy_decision": self.policy_decision,
            "reasons": self.reasons,
            "blocked_by": self.blocked_by,
        }


class RiskEngine:
    """风险自适应自治引擎"""

    def __init__(self):
        self._mode = ExecutionMode.PRODUCTION
        self._protected_asset_types = {
            "database", "domain_controller", "gateway",
            "kafka", "flink", "postgresql", "mcp_server_host",
        }

    def set_mode(self, mode: ExecutionMode):
        self._mode = mode

    @property
    def mode(self) -> ExecutionMode:
        return self._mode

    def assess(
        self,
        tool_name: str,
        target: str,
        parameters: dict,
        incident_id: str = "",
        evidence_ids: list = None,
        asset_info: dict = None,
    ) -> RiskAssessment:
        """评估动作风险"""
        factors = self._collect_factors(
            tool_name, target, parameters, incident_id,
            evidence_ids or [], asset_info or {},
        )
        return self._evaluate(factors)

    def _collect_factors(
        self, tool_name, target, parameters, incident_id,
        evidence_ids, asset_info,
    ) -> RiskFactors:
        """收集风险因子"""
        # 工具基础风险
        tool_risk_map = {
            "block_ip": "HIGH",
            "isolate_host": "CRITICAL",
            "rate_limit": "MEDIUM",
            "terminate_process": "HIGH",
            "alert_only": "LOW",
            "vulnerability_scan": "LOW",
            "event_store.query": "LOW",
            "knowledge.search": "LOW",
        }
        action_base_risk = tool_risk_map.get(tool_name, "MEDIUM")

        # 资产关键性
        asset_criticality = asset_info.get("criticality", "medium")
        asset_type = asset_info.get("type", "")
        is_protected = (
            asset_type in self._protected_asset_types
            or asset_info.get("protected", False)
        )

        # 影响范围
        targets = parameters.get("targets", [])
        if isinstance(targets, list):
            blast_radius = "wide" if len(targets) > 10 else ("few" if len(targets) > 1 else "single")
        else:
            blast_radius = "single"

        # 证据完整度
        evidence_completeness = min(1.0, len(evidence_ids) / 3.0) if evidence_ids else 0.2

        # 来源可信度（简化：有 incident_id 则信任度高）
        source_trust = 0.8 if incident_id else 0.3

        # 可逆性
        reversible_map = {
            "block_ip": True, "isolate_host": True, "rate_limit": True,
            "terminate_process": False, "alert_only": False,
            "vulnerability_scan": False,
        }
        reversibility = reversible_map.get(tool_name, False)

        # 内网 IP 检测 — 使用明确 CIDR (RFC 1918 + 100.64.0.0/10)
        # 不使用 ip.is_private, 因为它将 TEST-NET (203.0.113.0/24 等) 也判为私有
        import ipaddress
        is_internal = False
        if target:
            try:
                ip = ipaddress.ip_address(target)
                if ip.is_loopback:
                    is_internal = True
                else:
                    for cidr in (
                        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                        "100.64.0.0/10",  # CGNAT
                    ):
                        if ip in ipaddress.ip_network(cidr, strict=False):
                            is_internal = True
                            break
            except ValueError:
                pass

        # 通配符目标检测
        has_wildcard = target in ("*", "0.0.0.0/0", "::/0", "any", "ALL")

        # Grounding score
        grounding_score = parameters.get("grounding_score", 1.0)

        return RiskFactors(
            action_base_risk=action_base_risk,
            asset_criticality=asset_criticality,
            blast_radius=blast_radius,
            evidence_completeness=evidence_completeness,
            source_trust=source_trust,
            reversibility=reversibility,
            environment=self._mode.value,
            execution_mode=parameters.get("execution_mode", "live"),
            is_protected_asset=is_protected,
            is_internal_ip=is_internal,
            has_wildcard_target=has_wildcard,
            grounding_score=grounding_score,
            # A4 检查上下文
            tool_name=tool_name,
            parameters=parameters,
            target=target,
            asset_type=asset_type,
        )

    def _evaluate(self, factors: RiskFactors) -> RiskAssessment:
        """评估风险因子并生成决策"""
        reasons = []
        blocked_by = ""

        # A4 危险动作前置检查 (DbSafetyPolicy)
        # 不可通过分步提权绕过
        if db_safety_policy is not None and factors.tool_name:
            a4_decision = db_safety_policy.check_action(
                tool_name=factors.tool_name,
                parameters=factors.parameters or {},
                target=factors.target or "",
                asset_type=factors.asset_type or "",
            )
            if a4_decision.should_block:
                blocked_by = a4_decision.blocked_by or "a4_policy"
                reasons.append(a4_decision.reason)
                if a4_decision.recommendations:
                    reasons.extend(f"建议: {r}" for r in a4_decision.recommendations[:2])
                logger.warning(
                    f"[RiskEngine] A4 blocked: tool={factors.tool_name} "
                    f"blocked_by={blocked_by} reason={a4_decision.reason}"
                )
                return RiskAssessment(
                    risk_score=1.0, risk_level="A4",
                    automation_level=AutomationLevel.A4,
                    approval_required="denied",
                    auto_execute=False,
                    policy_decision="deny",
                    reasons=reasons, blocked_by=blocked_by,
                    factors=factors,
                )

        # 硬性阻断规则
        if factors.has_wildcard_target:
            blocked_by = "wildcard_target"
            reasons.append("通配符目标被禁止")
            return RiskAssessment(
                risk_score=1.0, risk_level="A4",
                automation_level=AutomationLevel.A4,
                approval_required="denied",
                auto_execute=False,
                policy_decision="deny",
                reasons=reasons, blocked_by=blocked_by,
                factors=factors,
            )

        if factors.is_protected_asset and factors.environment == "production":
            blocked_by = "protected_asset"
            reasons.append(f"核心资产({factors.asset_criticality})禁止自动处置")
            return RiskAssessment(
                risk_score=0.95, risk_level="A4",
                automation_level=AutomationLevel.A4,
                approval_required="denied",
                auto_execute=False,
                policy_decision="deny",
                reasons=reasons, blocked_by=blocked_by,
                factors=factors,
            )

        if factors.grounding_score < 0.4:
            blocked_by = "grounding_gate"
            reasons.append(f"Grounding 验证未通过 (score={factors.grounding_score:.2f}<0.4)")
            return RiskAssessment(
                risk_score=0.9, risk_level="A3",
                automation_level=AutomationLevel.A3,
                approval_required="human",
                auto_execute=False,
                policy_decision="require_human",
                reasons=reasons, blocked_by=blocked_by,
                factors=factors,
            )

        # shadow 模式：只生成计划不执行
        if factors.environment == "shadow":
            level = decide_automation_level(**{
                k: v for k, v in {
                    "action_base_risk": factors.action_base_risk,
                    "asset_criticality": factors.asset_criticality,
                    "blast_radius": factors.blast_radius,
                    "evidence_completeness": factors.evidence_completeness,
                    "source_trust": factors.source_trust,
                    "reversibility": factors.reversibility,
                    "environment": factors.environment,
                    "execution_mode": factors.execution_mode,
                }.items()
            })
            reasons.append("shadow 模式：只生成动作计划不执行")
            return RiskAssessment(
                risk_score=0.3, risk_level=level.value,
                automation_level=level,
                approval_required=LEVEL_APPROVAL_MAP[level],
                auto_execute=False,
                policy_decision="require_human",
                reasons=reasons, factors=factors,
            )

        # 计算自动化等级
        level = decide_automation_level(
            factors.action_base_risk,
            factors.asset_criticality,
            factors.blast_radius,
            factors.evidence_completeness,
            factors.source_trust,
            factors.reversibility,
            factors.environment,
            factors.execution_mode,
        )

        # 计算风险分数
        risk_score = self._calculate_score(factors)

        # 内网 IP 加成
        if factors.is_internal_ip and factors.action_base_risk in ("HIGH", "CRITICAL"):
            if level == AutomationLevel.A2:
                level = AutomationLevel.A3
                reasons.append("内网 IP 高风险操作升级为 A3")

        # 证据不足加成
        if factors.evidence_completeness < 0.3 and level in (AutomationLevel.A0, AutomationLevel.A1, AutomationLevel.A2):
            level = AutomationLevel.A3
            reasons.append("证据不足升级为 A3")

        approval = LEVEL_APPROVAL_MAP[level]
        auto_exec = LEVEL_AUTO_EXECUTE[level] and factors.environment != "shadow"

        if approval == "denied":
            decision = "deny"
        elif approval in ("cad", "human"):
            decision = "require_confirmation" if approval == "cad" else "require_human"
        else:
            decision = "allow"

        if not auto_exec and decision == "allow":
            decision = "require_confirmation"

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=level.value,
            automation_level=level,
            approval_required=approval,
            auto_execute=auto_exec,
            policy_decision=decision,
            reasons=reasons,
            factors=factors,
        )

    def _calculate_score(self, factors: RiskFactors) -> float:
        """计算 0.0-1.0 风险分数"""
        risk_weight = {"LOW": 0.2, "MEDIUM": 0.4, "HIGH": 0.7, "CRITICAL": 0.9}
        crit_weight = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.9}
        radius_weight = {"single": 0.1, "few": 0.3, "wide": 0.7}

        score = (
            risk_weight.get(factors.action_base_risk, 0.4) * 0.35
            + crit_weight.get(factors.asset_criticality, 0.3) * 0.25
            + radius_weight.get(factors.blast_radius, 0.1) * 0.15
            + (1.0 - factors.evidence_completeness) * 0.15
            + (1.0 - factors.source_trust) * 0.10
        )

        if not factors.reversibility:
            score += 0.15
        if factors.is_internal_ip:
            score += 0.05
        if factors.is_protected_asset:
            score += 0.20

        return min(1.0, score)


# 全局单例
risk_engine = RiskEngine()
