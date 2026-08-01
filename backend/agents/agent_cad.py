"""
审计角色 (CAD Agent) — 独立监督者

核心原则:
  - 独立性: 不参与任何内容生产，唯一职责是监督和审计
  - 穿透式: 不信任其他 Agent 的汇报，直接从底层验证
  - 免疫性: 常态化监控 + 自动熔断

运行方式:
  后台周期性任务（每 N 秒/每次流水线完成后触发）

与 Reviewer 的区别:
  Reviewer: 审核流水线内部，检查 Executor 结论是否遗漏威胁
  CAD:     独立于流水线运行，验证所有 Agent 的断言是否真实，
           审计系统本身的配置风险，触发熔断

触发时机:
  1. 每次 Audit-LLM 流水线完成后（验证该次审计的断言）
  2. 定时运行（上下文审计）
  3. 人工触发
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from cad import verifier, context_auditor, circuit_breaker, VerificationReport, ContextRisk
from event_store import event_store, EventFilter

logger = logging.getLogger(__name__)


class CADAgent:
    """
    审计角色 (CAD)

    audit_pipeline() — 流水线完成后验证断言
    audit_context()  — 上下文审计（定时）
    get_status()     — 熔断器状态查询
    """

    def __init__(self):
        self._audit_count = 0
        self._last_context_audit = 0
        self._context_audit_interval = 3600  # 每小时审计一次上下文

    async def audit_pipeline(
        self,
        session: AsyncSession,
        event_id: int,
        audit_llm_data: dict,
    ) -> dict:
        """
        审计一次完整的 Audit-LLM 流水线结果

        Args:
            session: DB session
            event_id: 被审计的事件 ID
            audit_llm_data: _audit_llm 字段的完整内容（含 evidence_trail）

        Returns:
            CAD 审计报告（含穿透验证结果 + 熔断状态）
        """
        self._audit_count += 1
        t_start = time.time()
        logger.info(f"CAD auditing pipeline result for event #{event_id}")

        # ── 1. 穿透式验证 ──
        evidence_trail = audit_llm_data.get("evidence_trail", [])
        verification_reports = await verifier.verify_claims(
            session, "", evidence_trail
        )

        # ── 2. 计算验证指标 ──
        total_claims = len(verification_reports)
        verified_claims = sum(1 for r in verification_reports if r.verified)
        hallucination_count = total_claims - verified_claims

        # 寻找高危差异
        high_sev_discrepancies = [
            r for r in verification_reports
            if not r.verified and r.severity in ("high", "critical")
        ]

        hallucination_risk = hallucination_count / max(total_claims, 1)
        evidence_completeness = verified_claims / max(total_claims, 1)

        # ── 3. 更新熔断器 ──
        circuit_breaker.record_audit_result(
            hallucination_risk=hallucination_risk,
            evidence_completeness=evidence_completeness,
            anomaly_detected=hallucination_count > 0,
        )

        # ── 4. 生成 CAD 审计报告 ──
        cad_report = {
            "event_id": event_id,
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "penetrating_verification": {
                "total_claims": total_claims,
                "verified": verified_claims,
                "hallucination_count": hallucination_count,
                "hallucination_risk": round(hallucination_risk, 4),
                "evidence_completeness": round(evidence_completeness, 4),
                "high_severity_discrepancies": [
                    {
                        "claim": r.claim[:80],
                        "discrepancy": r.discrepancy,
                        "claimed_ids": r.claimed_evidence_ids,
                        "actual_ids": r.actual_evidence_ids,
                    }
                    for r in high_sev_discrepancies
                ],
            },
            "circuit_breaker": circuit_breaker.get_status(),
            "duration_ms": round((time.time() - t_start) * 1000, 1),
        }

        # 如果熔断器被触发，记录日志
        if circuit_breaker.state.tripped:
            logger.critical(
                f"CAD CIRCUIT BREAKER: event #{event_id} - "
                f"{circuit_breaker.state.reason}"
            )

        logger.info(
            f"CAD audit complete for event #{event_id}: "
            f"{verified_claims}/{total_claims} verified, "
            f"risk={hallucination_risk:.2f}, "
            f"tripped={circuit_breaker.state.tripped}"
        )

        return cad_report

    async def audit_context(self) -> dict:
        """
        上下文审计（独立于审核流水线运行）

        定期检查系统配置、prompt、工具描述是否存在风险。
        """
        logger.info("CAD running context audit")

        risks = await context_auditor.full_audit()

        # 按严重度分类
        critical = [r for r in risks if r.severity == "critical"]
        high = [r for r in risks if r.severity == "high"]

        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_risks": len(risks),
            "critical_count": len(critical),
            "high_count": len(high),
            "risks": [
                {
                    "source": r.source,
                    "risk_type": r.risk_type,
                    "description": r.description,
                    "severity": r.severity,
                    "suggestion": r.suggestion,
                }
                for r in risks
            ],
        }

        if critical:
            logger.warning(
                f"CAD context audit: {len(critical)} critical risks found"
            )
            for r in critical:
                logger.warning(f"  CRITICAL: {r.description}")

        return report

    async def check_circuit_breaker(self) -> dict:
        """查询熔断器状态"""
        return circuit_breaker.get_status()

    async def reset_circuit_breaker(self) -> dict:
        """人工重置熔断器"""
        circuit_breaker.reset()
        return circuit_breaker.get_status()


cad_agent = CADAgent()
