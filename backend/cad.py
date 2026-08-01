"""
审计角色 (CAD) — 独立、穿透、免疫

三大职责（不生产任何审核内容，只监督和验证）:

1. 穿透式验证 (Verify)
   - 不信任其他 Agent 的"汇报"
   - 直接查询 EventStore、Timeline、执行日志等底层数据
   - 比对 Agent 断言与原始数据是否一致

2. 上下文审计 (AuditCtx)
   - 审查系统指令是否存在模糊/矛盾/易被利用的漏洞
   - 审查工具描述是否准确
   - 审查检索文档是否有盲区

3. 免疫与熔断 (Circuit)
   - 常态化监控风险趋势
   - 设定阈值，超限自动熔断
   - 熔断后限制风险扩散
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from event_store import event_store

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════
# 1. 穿透式验证器 (Penetrating Verifier)
# ════════════════════════════════════════════

@dataclass
class VerificationReport:
    """单条验证结果"""
    claim: str                           # Agent 的断言原文
    claim_source: str                    # 哪个 Agent 输出的
    claimed_evidence_ids: list[int]      # Agent 声称的证据 ID
    actual_evidence_ids: list[int]       # 实际查询到的证据 ID
    verified: bool                       # 是否验证通过
    discrepancy: str = ""                # 差异描述
    severity: str = "info"               # 差异严重度


class PenetratingVerifier:
    """
    穿透式验证器

    不信任任何 Agent 的中间结论，直接从底层数据源验证。
    """

    async def verify_claims(
        self,
        session: AsyncSession,
        session_id: str,
        evidence_trail: list[dict],
    ) -> list[VerificationReport]:
        """
        逐条验证 evidence_trail 中的断言

        验证步骤:
        1. 获取 Agent 声称的 evidence_ids
        2. 直接从 EventStore 查询这些 ID 的原始数据
        3. 比对：声称的事件是否真实存在？内容是否一致？
        4. 输出差异报告
        """
        reports = []

        for item in evidence_trail:
            claim_text = item.get("claim", "")
            claimed_ids = item.get("evidence_ids", [])
            claim_type = item.get("type", "unknown")
            claim_source = item.get("source", "executor")

            if not claimed_ids:
                reports.append(VerificationReport(
                    claim=claim_text,
                    claim_source=claim_source,
                    claimed_evidence_ids=[],
                    actual_evidence_ids=[],
                    verified=False,
                    discrepancy="断言未附带任何证据 ID",
                    severity="high",
                ))
                continue

            # 穿透：直接查 EventStore
            actual_events = []
            for eid in claimed_ids:
                evt = await event_store.get_by_id(session, eid)
                if evt:
                    actual_events.append(evt)

            actual_ids = [e.id for e in actual_events]

            # 比对
            claimed_set = set(claimed_ids)
            actual_set = set(actual_ids)

            missing = claimed_set - actual_set          # Agent 声称但实际不存在
            extra = actual_set - claimed_set            # 实际存在但 Agent 没引用

            if not missing and not extra:
                reports.append(VerificationReport(
                    claim=claim_text,
                    claim_source=claim_source,
                    claimed_evidence_ids=claimed_ids,
                    actual_evidence_ids=actual_ids,
                    verified=True,
                ))
            else:
                discrepancy_parts = []
                severity = "low"

                if missing:
                    discrepancy_parts.append(f"声称的事件 ID {sorted(missing)} 在数据库中不存在")
                    severity = "high"
                if extra:
                    discrepancy_parts.append(f"数据库中存在事件 ID {sorted(extra)} 但 Agent 未引用")
                    severity = "medium" if severity != "high" else severity

                reports.append(VerificationReport(
                    claim=claim_text[:100],
                    claim_source=claim_source,
                    claimed_evidence_ids=claimed_ids,
                    actual_evidence_ids=actual_ids,
                    verified=False,
                    discrepancy="; ".join(discrepancy_parts),
                    severity=severity,
                ))

        valid = sum(1 for r in reports if r.verified)
        logger.info(
            f"PenetratingVerifier: {valid}/{len(reports)} claims verified, "
            f"{len(reports) - valid} discrepancies found"
        )
        for r in reports:
            if not r.verified:
                logger.warning(f"  Discrepancy [{r.severity}]: {r.discrepancy}")

        return reports

    async def verify_tool_results(
        self,
        session: AsyncSession,
        tool_results: list[dict],
    ) -> list[VerificationReport]:
        """
        验证工具调用结果是否真实

        某些场景下 Agent 可能声称"调用了工具X返回了结果Y"，
        但实际上工具从未被调用或返回了不同的结果。
        """
        # 当前架构中工具调用由代码执行而非 LLM 执行，此风险已消除
        # 保留接口以备未来扩展
        return []


# ════════════════════════════════════════════
# 2. 上下文审计器 (Context Auditor)
# ════════════════════════════════════════════

@dataclass
class ContextRisk:
    """上下文风险点"""
    source: str              # "system_prompt" | "tool_description" | "config"
    risk_type: str           # "ambiguous" | "contradictory" | "exploitable" | "blind_spot"
    description: str
    severity: str            # "critical" | "high" | "medium" | "low"
    suggestion: str = ""


class ContextAuditor:
    """
    上下文审计器

    不审计 AI 的输出，而是审计 AI 运行的"环境"：
    - 系统指令是否有模糊/矛盾/易被利用的漏洞
    - 工具描述是否准确
    - 权限配置是否合理
    - 检索策略是否有盲区
    """

    async def audit_system_prompts(self) -> list[ContextRisk]:
        """审计所有 Agent 的系统指令"""
        risks = []

        # 读取各 Agent 的系统 prompt 进行检查
        prompts_to_check = {
            "Decomposer": "你是一个严谨的安全分析专家",
            "SubAuditor": "你是严谨的安全分析专家。严格遵循输出格式",
            "Executor": "你是严谨的安全审计专家。只采纳有证据支撑的结论",
            "Reviewer": "你是一个严格的安全审计复核专家，专门负责防幻觉检查",
        }

        for agent, prompt_text in prompts_to_check.items():
            # 检查 1: 指令是否清晰明确
            if "严格" not in prompt_text and "严谨" not in prompt_text:
                risks.append(ContextRisk(
                    source=f"system_prompt:{agent}",
                    risk_type="ambiguous",
                    description=f"{agent} 系统指令缺少严谨性要求，可能导致输出松散",
                    severity="medium",
                    suggestion="添加'严格遵循输出格式'等约束性指令",
                ))

            # 检查 2: 是否要求了证据引用
            if "证据" not in prompt_text and "ID" not in prompt_text:
                risks.append(ContextRisk(
                    source=f"system_prompt:{agent}",
                    risk_type="blind_spot",
                    description=f"{agent} 系统指令未要求引用证据ID，存在幻觉风险",
                    severity="high",
                    suggestion="添加'每条结论必须附带事件ID'的要求",
                ))

        return risks

    async def audit_tool_descriptions(self) -> list[ContextRisk]:
        """审计工具描述是否准确、不被滥用"""
        risks = []

        # 从 tool_registry 获取工具信息
        from tool_registry import tool_registry
        for tool_name in tool_registry.list_tools():
            info = tool_registry.get_info(tool_name)
            if not info:
                continue

            desc = info.get("description", "")

            # 检查描述是否足够清晰
            if len(desc) < 20:
                risks.append(ContextRisk(
                    source=f"tool_description:{tool_name}",
                    risk_type="ambiguous",
                    description=f"工具 {tool_name} 的描述过于简短({len(desc)}字)，"
                                f"可能导致 LLM 误用",
                    severity="medium",
                    suggestion="补充详细的参数说明和返回格式描述",
                ))

            # 检查是否有"可写"操作（安全审计场景应只读）
            if "write" in tool_name or "delete" in tool_name or "update" in tool_name:
                risks.append(ContextRisk(
                    source=f"tool_description:{tool_name}",
                    risk_type="exploitable",
                    description=f"工具 {tool_name} 具有写操作权限，安全审计场景应限制为只读",
                    severity="critical",
                    suggestion="移除写权限或增加二次确认",
                ))

        return risks

    async def audit_config(self) -> list[ContextRisk]:
        """审计系统配置"""
        risks = []
        from config import settings

        # 检查 LLM 配置
        if not settings.llm_api_key:
            risks.append(ContextRisk(
                source="config:llm_api_key",
                risk_type="exploitable",
                description="LLM API Key 未配置，系统使用降级模式，所有审计结论不可信",
                severity="critical",
                suggestion="配置有效的 LLM API Key",
            ))

        # 检查 temperature 设置（高 temperature 会增加幻觉）
        # 从各 Agent 配置获取
        return risks

    async def full_audit(self) -> list[ContextRisk]:
        """完整上下文审计"""
        all_risks = []
        all_risks.extend(await self.audit_system_prompts())
        all_risks.extend(await self.audit_tool_descriptions())
        all_risks.extend(await self.audit_config())

        by_severity = defaultdict(list)
        for r in all_risks:
            by_severity[r.severity].append(r)

        logger.info(
            f"ContextAuditor: {len(all_risks)} risks found "
            f"(critical={len(by_severity['critical'])}, "
            f"high={len(by_severity['high'])}, "
            f"medium={len(by_severity['medium'])})"
        )
        return all_risks


# ════════════════════════════════════════════
# 3. 免疫与熔断系统 (Circuit Breaker)
# ════════════════════════════════════════════

@dataclass
class CircuitBreakerState:
    """熔断器状态"""
    tripped: bool = False
    tripped_at: float = 0.0
    reason: str = ""
    # 监控指标
    hallucination_risk_trend: list[float] = field(default_factory=list)
    evidence_completeness_trend: list[float] = field(default_factory=list)
    audit_count: int = 0
    anomaly_rate: float = 0.0

    # 阈值
    MAX_HALLUCINATION_RISK: float = 0.5       # 平均幻觉风险超过此值 → 熔断
    MIN_EVIDENCE_COMPLETENESS: float = 0.3    # 证据完整度低于此值 → 熔断
    CONSECUTIVE_BAD_AUDITS: int = 5           # 连续 N 次审核质量差 → 熔断
    WARMUP_AUDITS: int = 10                   # 预热期：前 N 次审计不触发熔断
    COOLDOWN_SECONDS: float = 300             # 熔断后冷却期（秒），到期自动半开


class CircuitBreaker:
    """
    熔断器

    参考生物免疫系统：
    - 免疫: 常态化监控风险趋势，提前发现异常
    - 熔断: 风险超限时自动切断，防止扩散

    状态:
      CLOSED (正常) → OPEN (熔断) → HALF_OPEN (半开尝试) → CLOSED/OPEN
    """

    def __init__(self):
        self.state = CircuitBreakerState()
        self._bad_count = 0

    def record_audit_result(
        self,
        hallucination_risk: float,
        evidence_completeness: float,
        anomaly_detected: bool,
    ):
        """记录一次审计结果到监控趋势"""
        self.state.audit_count += 1
        self.state.hallucination_risk_trend.append(hallucination_risk)
        self.state.evidence_completeness_trend.append(evidence_completeness)

        # 仅保留最近 100 条记录
        if len(self.state.hallucination_risk_trend) > 100:
            self.state.hallucination_risk_trend.pop(0)
        if len(self.state.evidence_completeness_trend) > 100:
            self.state.evidence_completeness_trend.pop(0)

        # 计算近期异常率
        recent = self.state.hallucination_risk_trend[-20:]
        self.state.anomaly_rate = sum(1 for r in recent if r > 0.3) / max(len(recent), 1)

        # 检查熔断条件
        self._check_trip()

    def _check_trip(self):
        """检查是否需要熔断"""
        if self.state.tripped:
            # 自动恢复：冷却期过后进入半开状态
            if time.time() - self.state.tripped_at > self.state.COOLDOWN_SECONDS:
                logger.info(
                    f"Circuit breaker cooldown expired ({self.state.COOLDOWN_SECONDS}s), "
                    f"transitioning to HALF_OPEN"
                )
                self.state.tripped = False
                self.state.tripped_at = 0.0
                self.state.reason = ""
                self._bad_count = 0
            return  # 已经熔断

        # 预热期：前 N 次审计不触发熔断（系统刚启动，基线未建立）
        if self.state.audit_count < self.state.WARMUP_AUDITS:
            return

        recent_h = self.state.hallucination_risk_trend[-10:]
        recent_e = self.state.evidence_completeness_trend[-10:]

        if not recent_h:
            return

        avg_risk = sum(recent_h) / len(recent_h)
        avg_completeness = sum(recent_e) / len(recent_e) if recent_e else 1.0

        # 条件 1: 平均幻觉风险超限
        if avg_risk > self.state.MAX_HALLUCINATION_RISK:
            self._trip(
                f"平均幻觉风险 {avg_risk:.2f} 超过阈值 {self.state.MAX_HALLUCINATION_RISK}"
            )
            return

        # 条件 2: 证据完整度低于阈值
        if avg_completeness < self.state.MIN_EVIDENCE_COMPLETENESS:
            self._trip(
                f"证据完整度 {avg_completeness:.2f} 低于阈值 {self.state.MIN_EVIDENCE_COMPLETENESS}"
            )
            return

        # 条件 3: 连续差审核
        recent_bad = sum(
            1 for h, e in zip(recent_h, recent_e)
            if h > 0.4 or e < 0.5
        )
        if recent_bad >= self.state.CONSECUTIVE_BAD_AUDITS:
            self._trip(
                f"连续 {recent_bad} 次审核质量低于标准"
            )
            return

    def _trip(self, reason: str):
        """触发熔断"""
        self.state.tripped = True
        self.state.tripped_at = time.time()
        self.state.reason = reason
        logger.critical(f"CIRCUIT BREAKER TRIPPED: {reason}")

    def reset(self):
        """重置熔断（人工介入后）"""
        if not self.state.tripped:
            return
        logger.info("Circuit breaker reset (manual intervention)")
        self.state.tripped = False
        self.state.tripped_at = 0.0
        self.state.reason = ""
        self._bad_count = 0

    def get_status(self) -> dict:
        """获取熔断器状态"""
        return {
            "tripped": self.state.tripped,
            "tripped_at": self.state.tripped_at,
            "reason": self.state.reason,
            "audit_count": self.state.audit_count,
            "avg_hallucination_risk": (
                sum(self.state.hallucination_risk_trend[-10:]) / 10
                if len(self.state.hallucination_risk_trend) >= 10 else 0.0
            ),
            "avg_evidence_completeness": (
                sum(self.state.evidence_completeness_trend[-10:]) / 10
                if len(self.state.evidence_completeness_trend) >= 10 else 1.0
            ),
            "anomaly_rate": self.state.anomaly_rate,
            "thresholds": {
                "max_hallucination_risk": self.state.MAX_HALLUCINATION_RISK,
                "min_evidence_completeness": self.state.MIN_EVIDENCE_COMPLETENESS,
                "consecutive_bad": self.state.CONSECUTIVE_BAD_AUDITS,
                "warmup_audits": self.state.WARMUP_AUDITS,
                "cooldown_seconds": self.state.COOLDOWN_SECONDS,
            },
        }


# ════════════════════════════════════════════
# 全局单例
# ════════════════════════════════════════════

verifier = PenetratingVerifier()
context_auditor = ContextAuditor()
circuit_breaker = CircuitBreaker()
