"""
证据验证器 — 用知识库验证 LLM 断言的准确性

这是减少幻觉的核心机制:
  1. 提取 LLM 输出中的断言（claim）
  2. 从知识库检索相关证据
  3. LLM 判断断言是否被证据支撑
  4. 标记无依据断言为"疑似幻觉"
  5. 返回验证报告供下游降权

集成点:
  - 在 ChunkVerdict.validate_evidence() 之后调用
  - 在 Executor._synthesize_from_chunks() 中注入
  - CAD 的穿透验证中作为补充
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .retriever import Retriever, RetrievalResult
from .context_builder import rag_context_builder
from summary_compression import summary

logger = logging.getLogger(__name__)


@dataclass
class VerifierReport:
    """单条断言验证报告"""
    claim: str
    verdict: str              # "supported" | "contradicted" | "unsupported"
    confidence: float         # 验证置信度
    supporting_evidence: list[str] = field(default_factory=list)
    contradiction_detail: str = ""
    suggestion: str = ""


@dataclass
class BatchVerifierReport:
    """批量验证报告"""
    reports: list[VerifierReport] = field(default_factory=list)
    supported_count: int = 0
    unsupported_count: int = 0
    hallucination_risk: float = 0.0  # 未支撑比例


class EvidenceVerifier:
    """证据验证器"""

    def __init__(self):
        self.retriever = Retriever()

    async def verify_claim(
        self,
        session: AsyncSession,
        claim: str,
        threat_type: str = "",
        severity: str = "",
        query_embedding: Optional[list[float]] = None,
    ) -> VerifierReport:
        """
        验证单条断言

        Args:
            session: DB session
            claim: LLM 输出的断言文本
            threat_type: 关联威胁类型
            severity: 严重度
            query_embedding: 查询向量

        Returns:
            VerifierReport
        """
        # 1. 检索知识库
        result = await self.retriever.retrieve(
            session,
            query=claim,
            query_embedding=query_embedding,
            threat_type=threat_type,
            severity=severity,
            top_k=3,
            min_score=0.5,
        )

        if not result.chunks:
            return VerifierReport(
                claim=claim[:200],
                verdict="unsupported",
                confidence=0.0,
                suggestion="知识库中无相关证据，请核实该断言",
            )

        # 2. 构建验证 prompt
        prompt = rag_context_builder.build_verification_prompt(claim, result)

        # 3. LLM 验证
        try:
            from trace_hook import set_trace_context
            set_trace_context(caller="evidence_verifier", operation="verify", event_id=0)
            from prompts import render
            resp = await summary.llm.chat([
                {"role": "system", "content": render("rag/evidence_verify_system")},
                {"role": "user", "content": prompt},
            ])
            parsed = json.loads(resp)
            return VerifierReport(
                claim=claim[:200],
                verdict=parsed.get("verdict", "unsupported"),
                confidence=parsed.get("confidence", 0.0),
                supporting_evidence=parsed.get("supporting_evidence", []),
                contradiction_detail=parsed.get("contradiction_detail", ""),
                suggestion=parsed.get("suggestion", ""),
            )
        except Exception as e:
            logger.warning(f"Claim verification failed: {e}")
            return VerifierReport(
                claim=claim[:200],
                verdict="unsupported",
                confidence=0.0,
                suggestion=f"验证过程出错: {e}",
            )

    async def verify_batch(
        self,
        session: AsyncSession,
        claims: list[str],
        threat_type: str = "",
        severity: str = "",
        query_embedding: Optional[list[float]] = None,
    ) -> BatchVerifierReport:
        """批量验证断言"""
        reports = []
        for claim in claims:
            report = await self.verify_claim(
                session, claim, threat_type, severity, query_embedding
            )
            reports.append(report)

        supported = sum(1 for r in reports if r.verdict == "supported")
        unsupported = sum(1 for r in reports if r.verdict == "unsupported")
        total = len(reports)
        risk = unsupported / max(total, 1)

        logger.info(
            f"Batch verify: {supported}/{total} supported, "
            f"{unsupported} unsupported, risk={risk:.2f}"
        )

        return BatchVerifierReport(
            reports=reports,
            supported_count=supported,
            unsupported_count=unsupported,
            hallucination_risk=risk,
        )


evidence_verifier = EvidenceVerifier()
