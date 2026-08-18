"""
执行者 (Executor) — Audit-LLM 第三层（分块审核版）

核心变更：
  1. 工具返回大量事件后，不再全部塞给一个 LLM
  2. 改为：Chunker 分块 → SubAuditor 并行子审核 → LLM 汇总

流水线:
  tool_calls → 并行执行 → 收集结果
    → 提取事件数据
    → Chunker 分块（按IP/时间窗/攻击链）
    → SubAuditor 并行审核每块
    → LLM 汇总所有块结论 → AuditResult
    → Reviewer（可选）
"""
import asyncio
import json
import logging
import time
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from tool_registry import tool_registry
from audit_types import ToolCall, ToolResult, AuditResult
from summary_compression import summary
from agents.chunker import chunker, AuditChunk
from agents.sub_auditor import sub_auditor, ChunkVerdict

logger = logging.getLogger(__name__)


class Executor:
    """
    执行者（分块审核版）
    """

    def __init__(self):
        pass

    async def execute(
        self,
        tool_calls: list[ToolCall],
        session: AsyncSession,
        session_id: str,
        raw_event: dict = None,
        depth: str = "",
    ) -> AuditResult:
        start_time = time.time()
        all_results: list[ToolResult] = []

        # 1. 分离工具调用（data 工具 vs LLM 工具）
        data_calls = [tc for tc in tool_calls
                      if tc.tool not in ("llm.deep_analyze", "llm.recheck")]
        deep_calls = [tc for tc in tool_calls if tc.tool == "llm.deep_analyze"]
        recheck_calls = [tc for tc in tool_calls if tc.tool == "llm.recheck"]

        # 2. 并行执行 data 工具
        if data_calls:
            logger.info(f"Executor: executing {len(data_calls)} tools in parallel")
            data_results = await self._execute_parallel(data_calls, session)
            all_results.extend(data_results)

        # 3. 从工具结果中提取事件数据 + 攻击链 ID
        events, chain_ids = self._extract_events(all_results)

        # 4. Chunker 分块
        audit_chunks = chunker.chunk(events, chain_event_ids=chain_ids)
        logger.info(f"Executor: split into {len(audit_chunks)} chunks for audit")

        # 4b. 提取 RAG 知识片段，下发到 SubAuditor 用于 Layer 4 校验
        knowledge_chunks = self._extract_knowledge_chunks(all_results)
        if knowledge_chunks:
            logger.info(
                f"Executor: passing {len(knowledge_chunks)} kb chunks to SubAuditor "
                f"for Layer-4 grounding verification"
            )

        # 5. SubAuditor 并行审核每块（携带知识库片段）
        chunk_verdicts = await self._audit_chunks_parallel(
            audit_chunks, knowledge_chunks=knowledge_chunks
        )

        # 5b. EvidenceVerifier 知识库交叉验证（Layer 2 校验）
        kb_verification = await self._verify_claims_with_knowledge(
            session, chunk_verdicts, raw_event
        )

        # 6. 收集攻击链信息（如有）
        chain_info = self._extract_chain_info(all_results)

        # 6b. 收集知识库检索结果 (RAG)
        rag_context = self._extract_rag_context(all_results)

        # 6c. 深度分析 — 前置合成模式：在 synthesize 之前执行，
        # 让其结论作为额外 section 注入 synthesize prompt，深度分析回流 audit_result
        # （旧实现把 deep_text 仅塞入 tool_results 展示用，对最终结论无影响）
        deep_text = ""
        if deep_calls:
            deep_text = await self._llm_deep_analyze(
                raw_event, audit_chunks, chunk_verdicts, depth
            )
            for dc in deep_calls:
                all_results.append(ToolResult(
                    call_id=dc.call_id, task_id=dc.task_id,
                    tool="llm.deep_analyze", success=True,
                    data=deep_text, duration_ms=0,
                ))

        # 7. LLM 汇总所有块结论 → AuditResult（深度分析作为额外上下文注入）
        audit_result = await self._synthesize_from_chunks(
            raw_event, audit_chunks, chunk_verdicts,
            chain_info, depth, rag_context, kb_verification,
            deep_analysis=deep_text,
        )
        audit_result.deep_analysis = deep_text

        # 8. recheck
        if recheck_calls:
            recheck = await self._llm_recheck(
                raw_event, audit_result, chunk_verdicts
            )
            audit_result.needs_human_review = bool(recheck.get("needs_human", False))
            for rc in recheck_calls:
                all_results.append(ToolResult(
                    call_id=rc.call_id, task_id=rc.task_id,
                    tool="llm.recheck", success=True,
                    data=recheck, duration_ms=0,
                ))

        audit_result.tool_results = all_results

        duration = time.time() - start_time
        logger.info(
            f"Executor done in {duration:.1f}s: "
            f"{len(audit_chunks)} chunks, {len(chunk_verdicts)} verdicts, "
            f"threat={audit_result.threat_detected} "
            f"confidence={audit_result.confidence:.2f}"
        )
        return audit_result

    async def _execute_parallel(
        self, tool_calls: list[ToolCall], session: AsyncSession
    ) -> list[ToolResult]:
        """并行执行工具调用（每个工具独立 session，避免 AsyncSession 并发冲突）"""
        from models import async_session as db_session

        async def execute_one(tc: ToolCall) -> ToolResult:
            t_start = time.time()
            try:
                async with db_session() as s:
                    args = dict(tc.args)
                    args["session"] = s
                    data = await tool_registry.execute(tc.tool, **args)
                duration = (time.time() - t_start) * 1000
                return ToolResult(
                    call_id=tc.call_id, task_id=tc.task_id,
                    tool=tc.tool, success=True, data=data,
                    duration_ms=round(duration, 1),
                )
            except Exception as e:
                duration = (time.time() - t_start) * 1000
                logger.warning(f"Tool {tc.tool} ({tc.call_id}) failed: {e}")
                return ToolResult(
                    call_id=tc.call_id, task_id=tc.task_id,
                    tool=tc.tool, success=False, error=str(e),
                    duration_ms=round(duration, 1),
                )

        return await asyncio.gather(*[execute_one(tc) for tc in tool_calls])

    def _extract_events(
        self, results: list[ToolResult]
    ) -> tuple[list[dict], set[int]]:
        """
        从工具返回中提取事件列表和攻击链事件 ID
        """
        events: list[dict] = []
        chain_ids: set[int] = set()

        for r in results:
            if not r.success or not r.data:
                continue

            # event_store.query 返回 list[dict]
            if r.tool == "event_store.query" and isinstance(r.data, list):
                for item in r.data:
                    if isinstance(item, dict):
                        events.append(item)

            # correlation.chains 返回的攻击链
            if r.tool == "correlation.chains" and isinstance(r.data, list):
                for chain in r.data:
                    eids = chain.get("event_ids", [])
                    chain_ids.update(eids)

            # 注: correlation.temporal 仅是同 IP 时间窗分组，不应作为攻击链依据，
            # 不再注入 chain_ids，避免污染 chunker 的 attack_chain 策略分类

        logger.info(
            f"Extracted {len(events)} events, {len(chain_ids)} in chains"
        )
        return events, chain_ids

    def _extract_chain_info(self, results: list[ToolResult]) -> str:
        """提取攻击链信息文本"""
        parts = []
        for r in results:
            if r.tool == "correlation.chains" and r.success and r.data:
                for chain in r.data:
                    parts.append(
                        f"- [{chain.get('pattern_name','?')}] "
                        f"confidence={chain.get('confidence',0)} "
                        f"{chain.get('alert','')}"
                    )
        return "\n".join(parts)

    def _extract_rag_context(self, results: list[ToolResult]) -> str:
        """
        从 knowledge.search 工具结果中提取 RAG 上下文

        将安全知识库的检索结果格式化为 LLM 可参考的文本，
        注入到汇总 prompt 中，使审计结论有知识库支撑。
        """
        from rag.context_builder import rag_context_builder
        from rag.retriever import RetrievalResult

        chunks = []
        for r in results:
            if r.tool == "knowledge.search" and r.success and r.data:
                if isinstance(r.data, list):
                    chunks.extend(r.data)

        if not chunks:
            return ""

        result = RetrievalResult(
            chunks=chunks,
            total_found=len(chunks),
            strategy_used="tool_extract",
        )
        context = rag_context_builder.build_context(result, max_tokens=2000)
        if context:
            logger.info(f"RAG context injected into synthesis: {len(chunks)} chunks")
        return context

    def _extract_knowledge_chunks(self, results: list[ToolResult]) -> list[dict]:
        """
        从 knowledge.search 工具结果中提取原始知识库片段列表

        与 _extract_rag_context 不同：本方法返回 list[dict] 原始片段
        （含 threat_types 字段），直接供 GroundingVerifier 的 Layer 4
        知识库一致性校验消费，不进行 prompt 上下文化包装。

        必须在 SubAuditor 并行审核前调用，以便把知识库片段下发到每块审核。
        """
        chunks: list[dict] = []
        for r in results:
            if r.tool == "knowledge.search" and r.success and r.data:
                if isinstance(r.data, list):
                    # 过滤缺威胁类型标注的条目（无 threat_types 无法做 Layer 4 校验）
                    for c in r.data:
                        if not isinstance(c, dict):
                            continue
                        if c.get("threat_types"):
                            chunks.append(c)
                        else:
                            logger.debug(
                                f"Skipping kb chunk w/o threat_types: id={c.get('id', '?')}"
                            )
        return chunks

    async def _verify_claims_with_knowledge(
        self,
        session: AsyncSession,
        verdicts: list[ChunkVerdict],
        raw_event: dict,
    ) -> dict:
        """
        Layer 2 校验：用 EvidenceVerifier 对威胁断言做知识库交叉验证

        改进：每条断言携带自身的 threat_type / severity 上下文进行验证，
        避免不同威胁类型混用首个 chunk 的单一上下文导致偏差。
        """
        from rag.evidence_verifier import evidence_verifier

        # 收集所有威胁断言 (claim_text, threat_type, severity)
        # 每条断言用其自身的 threat_type / severity 进行知识库比对，
        # 避免单一 chunk 上下文污染跨类型断言的验证
        claims_to_verify: list[dict] = []
        for v in verdicts:
            if not v.threat_detected:
                continue
            for claim in v.threat_claims:
                summary_text = claim.get("summary", "")
                if not summary_text:
                    continue
                claims_to_verify.append({
                    "summary": summary_text[:200],
                    "threat_type": claim.get("type", "") or v.severity,
                    "severity": claim.get("severity", v.severity),
                })

        if not claims_to_verify:
            return {"verified": True, "supported": 0, "unsupported": 0, "risk": 0.0}

        # 限制验证数量（避免过多 LLM 调用），优先取前 5 条
        # 按威胁严重度排序，高风险断言优先验证
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        claims_to_verify.sort(key=lambda c: sev_order.get(c["severity"], 5))
        claims_to_verify = claims_to_verify[:5]

        # 独立 session 执行验证，避免 SQL 失败污染流水线主事务
        from models import async_session as db_session

        try:
            async with db_session() as s:
                # 按 threat_type 分批验证，每批用各自的 threat_type/severity 上下文
                # 同时保留每条断言与验证结果的对应关系
                reports = []
                for c in claims_to_verify:
                    batch = await evidence_verifier.verify_batch(
                        s,
                        claims=[c["summary"]],
                        threat_type=c["threat_type"],
                        severity=c["severity"],
                    )
                    reports.extend(batch.reports)

            supported = sum(1 for r in reports if r.verdict == "supported")
            unsupported = sum(1 for r in reports if r.verdict == "unsupported")
            total = len(reports)
            risk = unsupported / max(total, 1)

            logger.info(
                f"Knowledge verification: {supported}/{total} supported, "
                f"risk={risk:.2f}"
            )
            return {
                "verified": True,
                "supported": supported,
                "unsupported": unsupported,
                "risk": risk,
                "details": [
                    {"claim": r.claim[:80], "verdict": r.verdict}
                    for r in reports[:3]
                ],
            }
        except Exception as e:
            logger.warning(f"Knowledge verification failed: {e}")
            return {"verified": False, "supported": 0, "unsupported": 0, "risk": 0.0}

    async def _audit_chunks_parallel(
        self,
        chunks: list[AuditChunk],
        knowledge_chunks: list[dict] | None = None,
    ) -> list[ChunkVerdict]:
        """并行审核所有事件块

        异常 chunk 不会被中断丢弃，而是包装为保守的 ChunkVerdict，
        标记为疑似威胁 + 100% 幻觉风险 + 强制人工复核，
        避免单个 LLM 调用失败导致整批流水线坍缩。

        Args:
            chunks: 待审核的 AuditChunk 列表
            knowledge_chunks: 可选的安全知识库片段，下发到每个 SubAuditor
                              用于启用 GroundingVerifier Layer 4 知识库一致性校验
        """
        if not chunks:
            return []

        kb = knowledge_chunks or []
        tasks = [
            sub_auditor.audit(chunk, knowledge_chunks=kb) for chunk in chunks
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        verdicts: list[ChunkVerdict] = []
        for chunk, result in zip(chunks, results):
            if isinstance(result, Exception):
                logger.warning(
                    f"Chunk {chunk.chunk_id} audit failed: "
                    f"{type(result).__name__}: {result}"
                )
                verdicts.append(ChunkVerdict(
                    chunk_id=chunk.chunk_id,
                    threat_detected=True,
                    confidence=0.0,
                    severity="high",
                    summary=f"审核异常: {type(result).__name__}",
                    alert="chunk 审核异常，需人工复核",
                    unsubstantiated=True,
                    hallucination_risk=1.0,
                    all_event_ids_in_chunk=[
                        e.get("id", e.get("event_id")) for e in chunk.events if e.get("id")
                    ],
                    schema_valid=False,
                    schema_errors=[f"chunk audit raised: {type(result).__name__}"],
                ))
            else:
                verdicts.append(result)

        threat_count = sum(1 for v in verdicts if v.threat_detected)
        fail_count = sum(1 for v in verdicts if not v.schema_valid)
        logger.info(
            f"SubAuditor: {len(verdicts)} chunks, "
            f"{threat_count} with threats, {fail_count} failed"
        )
        return verdicts

    async def _synthesize_from_chunks(
        self, raw_event: dict,
        chunks: list[AuditChunk],
        verdicts: list[ChunkVerdict],
        chain_info: str,
        depth: str,
        rag_context: str = "",
        kb_verification: dict = None,
        deep_analysis: str = "",
    ) -> AuditResult:
        """汇总所有块级结论 → AuditResult（含交叉验证）

        Args:
            deep_analysis: 深度分析初步研判文本（来自 _llm_deep_analyze），
                           作为额外 section 注入 synthesize prompt，
                           让 LLM 在汇总阶段直接参考深度研判结论。
        """
        if not chunks or not verdicts:
            return AuditResult(
                threat_detected=False,
                summary="无事件可审核",
                severity="info",
            )

        # ── 交叉验证：检查每条断言是否有真实事件支撑 ──
        hallucination_risks = []
        total_claims = 0
        valid_claims = 0
        invalid_claims = 0
        all_validation_issues = []

        for verdict in verdicts:
            validation = verdict.validate_evidence()
            total_claims += validation["total_claims"]
            valid_claims += validation["valid_claims"]
            invalid_claims += validation["invalid_claims"]
            hallucination_risks.append(verdict.hallucination_risk)
            all_validation_issues.extend(validation["issues"])

        # 综合幻觉风险分数
        avg_hallucination_risk = (
            sum(hallucination_risks) / len(hallucination_risks)
            if hallucination_risks else 0.0
        )

        # 证据完整度 = 有效断言比例
        evidence_completeness = (
            valid_claims / total_claims if total_claims > 0 else 1.0
        )

        # 自动调整：证据完整度低的块，整体置信度打折（惩罚上限 30%）
        confidence_penalty = 1.0 - (avg_hallucination_risk * 0.3)

        logger.info(
            f"Cross-verification: {valid_claims}/{total_claims} claims valid, "
            f"hallucination_risk={avg_hallucination_risk:.2f}, "
            f"completeness={evidence_completeness:.2f}, "
            f"penalty={confidence_penalty:.2f}"
        )
        if all_validation_issues:
            for issue in all_validation_issues[:5]:
                logger.warning(f"  Evidence issue: {issue}")

        # 构建汇总 prompt（含 Grounding 报告）
        block_summaries = []
        for chunk, verdict in zip(chunks, verdicts):
            status = "🚨" if verdict.threat_detected else "✅"
            risk_tag = f" [幻觉风险={verdict.hallucination_risk:.2f}]" if verdict.unsubstantiated else ""
            grounding_tag = f" [Grounding={verdict.grounding_score:.2f}]" if verdict.grounding_score < 0.8 else ""
            claims_detail = ""
            for claim in verdict.threat_claims:
                eids = claim.get("evidence_ids", [])
                quotes = claim.get("evidence_quotes", [])
                claims_detail += (
                    f"      - {claim.get('type','?')} conf={claim.get('confidence',0):.2f} "
                    f"evidence_ids={eids} quotes={len(quotes)}条\n"
                )
            block_summaries.append(
                f"{status} 块 [{chunk.chunk_id}] ({chunk.label}){risk_tag}{grounding_tag}\n"
                f"   威胁={verdict.threat_detected} "
                f"置信度={verdict.confidence:.2f} 严重度={verdict.severity}\n"
                f"   摘要={verdict.summary[:150]}\n"
                f"   告警={verdict.alert[:100] if verdict.alert else '无'}\n"
                f"{claims_detail}"
            )

        summary_text = "\n".join(block_summaries)
        event_json = json.dumps(raw_event, ensure_ascii=False)[:500] if raw_event else ""

        # 注入验证结果到 prompt
        verification_section = (
            f"## 交叉验证结果\n"
            f"证据完整度: {evidence_completeness:.1%} "
            f"({valid_claims}/{total_claims} 条断言有事件ID支撑)\n"
            f"平均幻觉风险: {avg_hallucination_risk:.2f}\n"
        )
        if all_validation_issues:
            verification_section += "证据问题:\n" + "\n".join(
                f"  ⚠️ {issue}" for issue in all_validation_issues[:5]
            )
        verification_section += (
            "\n注意: 无证据支撑的断言在汇总时应被忽略或降权。\n"
        )

        # 知识库交叉验证结果
        kb_section = ""
        if kb_verification and kb_verification.get("verified"):
            kb_section = (
                f"## 知识库交叉验证 (EvidenceVerifier)\n"
                f"已验证断言: {kb_verification['supported']} 条知识库支撑, "
                f"{kb_verification['unsupported']} 条无支撑\n"
                f"知识库幻觉风险: {kb_verification['risk']:.2f}\n"
            )
            for d in kb_verification.get("details", []):
                kb_section += f"  - [{d['verdict']}] {d['claim']}\n"

        # 深度分析初步研判（仅 deep 模式生成，作为 synthesize 的额外上下文）
        # 前置合成模式：deep_analyze 在 synthesize 之前执行，
        # 让 LLM 汇总时直接参考深度分析结论，避免深度分析沦为孤立工具结果
        deep_section = ""
        if deep_analysis:
            deep_section = (
                f"## 深度分析初步研判 (来自 deep_analyze)\n"
                f"{deep_analysis[:1500]}\n"
                f"注意: 该深度研判已经过跨块关联分析，请在汇总时纳入或显式反驳。\n"
            )

        prompt = f"""你是安全审计结论综合专家。汇总以下所有审核块的结论，输出最终审计结论。

## 原始事件
{event_json}

## 审核深度
{depth}

## 攻击链信息
{chain_info if chain_info else '（无）'}

## 安全知识库参考 (RAG)
{rag_context if rag_context else '（未检索到相关知识）'}

{deep_section}

## 交叉验证
{verification_section}

{kb_section}

## 各审核块结论（共 {len(verdicts)} 块）
{summary_text}

## 输出要求（严格遵循）
1. 只采纳有事件证据支撑的断言（即有 evidence_ids 的）
2. 无证据的断言应被忽略
3. 最终置信度应参考交叉验证结果
4. 如果安全知识库有相关参考，在 summary 中引用知识库条目

{{
    "threat_detected": true/false,
    "threat_type": "C2/DDoS/数据外泄/横向移动/勒索软件/端口扫描/暴力破解/其他/混合",
    "confidence": 0.0-1.0,
    "severity": "critical/high/medium/low/info",
    "summary": "最终审计结论摘要（引用具体事件ID）",
    "affected_entities": {{"src_ip": "", "dst_ip": ""}},
    "suggested_actions": [],
    "needs_human_review": true/false,
    "evidence_summary": "支撑最终结论的关键证据ID列表"
}}"""

        from trace_hook import set_trace_context
        set_trace_context(operation="execute")
        result = await summary.llm.chat([
            {
                "role": "system",
                "content": "你是严谨的安全审计专家。只采纳有证据支撑的结论，输出JSON。",
            },
            {"role": "user", "content": prompt},
        ])

        # 结构化验证（Pydantic）
        from audit_schemas import validate_synthesis_output
        parsed, schema_errors = validate_synthesis_output(result)
        if schema_errors:
            logger.warning(f"Synthesis schema validation issues: {schema_errors}")

        if parsed is None:
            logger.warning("Synthesis parse failed completely")
            return AuditResult(
                threat_detected=any(v.threat_detected for v in verdicts),
                summary="汇总解析失败",
                needs_human_review=True,
            )

        try:

            # 应用证据完整度调整（设最低置信度下限 0.1，防止坍缩到 0）
            raw_confidence = parsed.get("confidence", 0.0)

            # 三层校验综合惩罚
            # Layer 1: Grounding 验证（程序化）
            avg_grounding = (
                sum(v.grounding_score for v in verdicts) / len(verdicts)
                if verdicts else 1.0
            )
            grounding_penalty = 1.0 - ((1.0 - avg_grounding) * 0.4)

            # Layer 2: 知识库交叉验证
            kb_risk = kb_verification.get("risk", 0.0) if kb_verification else 0.0
            kb_penalty = 1.0 - (kb_risk * 0.2)

            # 综合惩罚（原有 hallucination_risk 惩罚 + grounding + kb）
            combined_penalty = confidence_penalty * grounding_penalty * kb_penalty
            adjusted_confidence = min(1.0, max(0.1, raw_confidence * combined_penalty))

            logger.info(
                f"Confidence adjustment: raw={raw_confidence:.2f} "
                f"× evidence={confidence_penalty:.2f} "
                f"× grounding={grounding_penalty:.2f} "
                f"× kb={kb_penalty:.2f} "
                f"= {adjusted_confidence:.2f}"
            )

            needs_human = (
                parsed.get("needs_human_review", False)
                or avg_hallucination_risk > 0.6
                or evidence_completeness < 0.3
                or avg_grounding < 0.4
                or kb_risk > 0.7
            )

            return AuditResult(
                threat_detected=parsed.get("threat_detected", False),
                threat_type=parsed.get("threat_type", ""),
                confidence=round(adjusted_confidence, 4),
                severity=parsed.get("severity", "info"),
                summary=(
                    f"{parsed.get('summary','')} "
                    f"[证据完整度={evidence_completeness:.0%}]"
                ),
                evidence=[v.to_dict() if hasattr(v, 'to_dict') else {"summary": v.summary}
                          for v in verdicts],
                affected_entities=parsed.get("affected_entities", {}),
                suggested_actions=parsed.get("suggested_actions", []),
                needs_human_review=needs_human,
            )
        except Exception as e:
            logger.warning(f"Synthesis parse failed: {e}")
            return AuditResult(
                threat_detected=any(v.threat_detected for v in verdicts),
                summary=f"汇总解析失败",
                needs_human_review=True,
            )

    async def _llm_deep_analyze(
        self, raw_event: dict,
        chunks: list[AuditChunk],
        verdicts: list[ChunkVerdict],
        depth: str,
    ) -> str:
        """深度 LLM 分析（基于所有块结论）"""
        v_text = "\n".join(
            f"[{v.chunk_id}] threat={v.threat_detected} conf={v.confidence:.2f} "
            f"types={','.join(c.get('type', '') for c in v.threat_claims[:5])} alert={v.alert[:80]}"
            for v in verdicts
        )
        prompt = f"""你是深度安全分析专家。基于所有审核块的结论，进行深度综合研判。

## 各块结论
{v_text}

## 深度分析要求
1. 是否存在多个块之间的关联威胁？
2. 是否存在跨时间窗口的攻击模式？
3. 当前的置信度是否合理？

{{"深度研判":"...","跨块关联":[],"置信度评估":"...","补充建议":[]}}"""
        from trace_hook import set_trace_context
        set_trace_context(operation="execute_deep")
        return await summary.llm.chat([
            {"role": "system", "content": "输出JSON格式的深度分析。"},
            {"role": "user", "content": prompt},
        ])

    async def _llm_recheck(
        self, raw_event: dict,
        audit: AuditResult,
        verdicts: list[ChunkVerdict],
    ) -> dict:
        """复核"""
        v_text = "\n".join(
            f"[{v.chunk_id}] threat={v.threat_detected} conf={v.confidence:.2f}"
            for v in verdicts
        )
        prompt = f"""复核以下审计结论是否完整。

## 各块结论
{v_text}

## 汇总结论
威胁={audit.threat_detected} 类型={audit.threat_type} 置信度={audit.confidence}

## 复核
{{"is_complete":true/false,"missed_threats":[],"needs_human":true/false,"review_notes":"..."}}"""
        from trace_hook import set_trace_context
        set_trace_context(operation="execute_recheck")
        result = await summary.llm.chat([
            {"role": "system", "content": "输出JSON。"},
            {"role": "user", "content": prompt},
        ])
        try:
            from audit_schemas import extract_json
            parsed = extract_json(result)
            if not parsed:
                return {"needs_human": True, "review_notes": result[:200]}

            # 强制布尔化 — LLM 可能输出 "true"(字符串) / 1(数字) / "yes" 等非 bool 值
            # 解析失败时一律保守认为需要人工复核
            def _as_bool(v) -> bool:
                if isinstance(v, bool):
                    return v
                if isinstance(v, (int, float)):
                    return bool(v)
                if isinstance(v, str):
                    return v.strip().lower() in ("true", "yes", "1", "y", "needs")
                # 其他类型 / None — 保守设为 True
                return True

            parsed["needs_human"] = _as_bool(parsed.get("needs_human", False))
            # is_complete 用于完整性说明，不强转；保留分析用途
            if "is_complete" in parsed:
                parsed["is_complete"] = _as_bool(parsed["is_complete"])
            # missed_threats 强制列表
            if not isinstance(parsed.get("missed_threats"), list):
                parsed["missed_threats"] = []
            # review_notes 强制字符串
            parsed["review_notes"] = str(parsed.get("review_notes", ""))[:500]
            return parsed
        except Exception:
            return {"needs_human": True, "review_notes": result[:200]}


executor = Executor()
