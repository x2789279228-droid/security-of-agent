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
        session: Optional[AsyncSession] = None,
        session_id: str = "",
        raw_event: dict = None,
        depth: str = "",
    ) -> AuditResult:
        start_time = time.time()
        all_results: list[ToolResult] = []
        raw_event = raw_event or {}
        triage = raw_event.get("_audit_triage") or {}
        skip_llm = bool(triage.get("skip_llm")) or str(triage.get("lane") or "") in (
            "tools_only", "rule_close",
        )

        # 1. 分离工具调用（data 工具 vs LLM 工具）
        data_calls = [tc for tc in tool_calls
                      if tc.tool not in ("llm.deep_analyze", "llm.recheck")]
        deep_calls = [tc for tc in tool_calls if tc.tool == "llm.deep_analyze"]
        recheck_calls = [tc for tc in tool_calls if tc.tool == "llm.recheck"]
        if skip_llm:
            deep_calls, recheck_calls = [], []

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

        # tools_only: 跳过 SubAuditor/synthesize,用非 LLM 信号确定性收口
        # (真正释放 LLM 通道给 P0/P1)
        if skip_llm:
            logger.info(
                f"Executor: tools_only/skip_llm tier={triage.get('tier')} "
                f"— deterministic verdict, no SubAuditor"
            )
            return self._deterministic_from_non_llm(
                raw_event, all_results, depth=depth,
            )

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

        from veto_gates import (
            hop_stats_from_verdicts,
            should_run_deep_llm_hops,
            extract_non_llm_signals,
        )
        hop_stats = hop_stats_from_verdicts(chunk_verdicts)
        skip_reasoning = hop_stats.skip_reasoning
        run_deep_hops = should_run_deep_llm_hops(depth, skip_reasoning)
        if skip_reasoning:
            logger.warning(
                f"Executor hop-budget early-stop: risk={hop_stats.avg_hallucination_risk:.2f} "
                f"grounding={hop_stats.avg_grounding:.2f} "
                f"completeness={hop_stats.evidence_completeness:.2f}"
            )

        # 5b. EvidenceVerifier 知识库交叉验证 — 仅 deep 且未早停（控制 LLM hop）
        kb_verification = {"verified": False, "supported": 0, "unsupported": 0, "risk": 0.0}
        if run_deep_hops:
            kb_verification = await self._verify_claims_with_knowledge(
                session, chunk_verdicts, raw_event
            )

        # 6. 收集攻击链信息（如有）
        chain_info = self._extract_chain_info(all_results)

        # 6b. 收集知识库检索结果 (RAG)
        rag_context = self._extract_rag_context(all_results)

        signals = extract_non_llm_signals(
            raw_event, tool_results=all_results, chain_info=chain_info,
        )

        # 6c. 深度分析 — 前置合成模式：在 synthesize 之前执行。
        # PR1: 仅 deep 且未触发早停时运行，禁止用推理 hop 填补无证据。
        deep_text = ""
        if deep_calls and run_deep_hops:
            deep_text = await self._llm_deep_analyze(
                raw_event, audit_chunks, chunk_verdicts, depth
            )
            for dc in deep_calls:
                all_results.append(ToolResult(
                    call_id=dc.call_id, task_id=dc.task_id,
                    tool="llm.deep_analyze", success=True,
                    data=deep_text, duration_ms=0,
                ))
        elif deep_calls:
            logger.info("Executor: skipped llm.deep_analyze (non-deep or hop budget)")

        # 7. LLM 汇总所有块结论 → AuditResult（深度分析作为额外上下文注入）
        audit_result = await self._synthesize_from_chunks(
            raw_event, audit_chunks, chunk_verdicts,
            chain_info, depth, rag_context, kb_verification,
            deep_analysis=deep_text,
            signals=signals,
            hop_stats=hop_stats,
        )
        audit_result.deep_analysis = deep_text

        # 8. recheck — 只允许抬升 needs_human，不允许升级威胁
        if recheck_calls and run_deep_hops:
            recheck = await self._llm_recheck(
                raw_event, audit_result, chunk_verdicts
            )
            audit_result.needs_human_review = bool(
                audit_result.needs_human_review or recheck.get("needs_human", False)
            )
            if recheck.get("abstain"):
                audit_result.needs_human_review = True
                if audit_result.verdict == "confirmed" or audit_result.threat_detected:
                    audit_result.threat_detected = False
                    audit_result.verdict = "insufficient_evidence"
            for rc in recheck_calls:
                all_results.append(ToolResult(
                    call_id=rc.call_id, task_id=rc.task_id,
                    tool="llm.recheck", success=True,
                    data=recheck, duration_ms=0,
                ))
        elif recheck_calls:
            logger.info("Executor: skipped llm.recheck (non-deep or hop budget)")

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
            log_args = {
                k: v for k, v in dict(tc.args or {}).items()
                if k != "session" and not str(k).startswith("_")
            }
            try:
                async with db_session() as s:
                    args = dict(tc.args)
                    args["session"] = s
                    data = await tool_registry.execute(tc.tool, **args)
                duration = (time.time() - t_start) * 1000
                result = ToolResult(
                    call_id=tc.call_id, task_id=tc.task_id,
                    tool=tc.tool, success=True, data=data,
                    duration_ms=round(duration, 1),
                )
            except Exception as e:
                duration = (time.time() - t_start) * 1000
                logger.warning(f"Tool {tc.tool} ({tc.call_id}) failed: {e}")
                result = ToolResult(
                    call_id=tc.call_id, task_id=tc.task_id,
                    tool=tc.tool, success=False, error=str(e),
                    duration_ms=round(duration, 1),
                )
            self._emit_tool_telemetry(tc, result, log_args)
            return result

        # return_exceptions=True：任何意外异常都不拖垮整批工具调用，
        # 与 _audit_chunks_parallel 的写法保持一致
        raw_results = await asyncio.gather(
            *[execute_one(tc) for tc in tool_calls], return_exceptions=True
        )
        finalized: list[ToolResult] = []
        for tc, r in zip(tool_calls, raw_results):
            if isinstance(r, Exception):
                logger.warning(f"Tool {tc.tool} ({tc.call_id}) crashed: {r}")
                crashed = ToolResult(
                    call_id=tc.call_id, task_id=tc.task_id,
                    tool=tc.tool, success=False, error=str(r),
                )
                self._emit_tool_telemetry(tc, crashed, {
                    k: v for k, v in dict(tc.args or {}).items()
                    if k != "session" and not str(k).startswith("_")
                })
                finalized.append(crashed)
            else:
                finalized.append(r)
        return finalized

    @staticmethod
    def _emit_tool_telemetry(tc: ToolCall, result: ToolResult, log_args: dict) -> None:
        """链 C：调查工具调用打进 MCP Guard logger/检测器。失败不阻断执行。"""
        try:
            from mcp_guard.telemetry import ingest_tool_call
            ingest_tool_call(
                tool_name=tc.tool,
                arguments=log_args,
                caller="agent_executor",
                source="audit_llm",
                caller_role="system",
                decision="allow",
                reason=tc.task_id or "",
                exec_status="success" if result.success else "error",
                exec_result={"error": result.error} if (not result.success and result.error) else None,
                duration_ms=result.duration_ms,
            )
        except Exception as e:
            logger.warning("executor telemetry failed: %s", e)

    @staticmethod
    def _normalize_event(item: dict) -> dict | None:
        """
        规整单条事件, 确保落入 chunker/SubAuditor 的每条事件都携带可在
        evidence_ids 中引用的规范 `id`(并补 `event_id` 别名)及分块所需元数据。

        - 优先采用已有 int 主键 `id`; 无可信主键时尝试回填 `event_id`/`_id` 为 int。
        - 无任何 id 的事件本身不可被 CAD 穿透引用 → 静默喂进审计块会落到 0-0/1.0
          误判, 故返回 None 交由上层日志暴露。
        """
        if not isinstance(item, dict):
            return None
        event = dict(item)
        raw_id = event.get("id", event.get("event_id", event.get("_id")))
        try:
            int_id = int(raw_id)
        except (TypeError, ValueError):
            int_id = None
        if int_id is None:
            logger.warning(
                "Executor: 跳过无可用 id 的事件(无法被 CAD 穿透验证/引用) type="
                f"{event.get('type', event.get('event_type', '?'))} raw_id={raw_id!r}"
            )
            return None
        event["id"] = int_id
        event["event_id"] = event.get("event_id", int_id)
        # 分块提示与 Grounding 所需的规范字段(缺省补齐)
        event.setdefault("event_type", event.get("type", "?"))
        event.setdefault("severity", "info")
        event.setdefault("created_at", "")
        return event

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
                        norm = self._normalize_event(item)
                        if norm is not None:
                            events.append(norm)

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

    def _deterministic_from_non_llm(
        self,
        raw_event: dict,
        tool_results: list,
        depth: str = "",
    ) -> AuditResult:
        """tools_only 车道: 不调 LLM,用 Sigma/异常/类型信号生成确定性结论。"""
        from veto_gates import extract_non_llm_signals, apply_confirmation_gate

        signals = extract_non_llm_signals(
            raw_event, tool_results=tool_results,
            anomaly_score=float(
                (raw_event.get("_anomaly") or {}).get("score")
                or raw_event.get("anomaly_score")
                or 0
            ),
        )
        sigma = raw_event.get("_sigma") or {}
        threat = bool(signals.has_signal or sigma.get("detected"))
        conf = 0.0
        if signals.anomaly_score:
            conf = max(conf, float(signals.anomaly_score))
        if sigma.get("detected"):
            conf = max(conf, 0.55)
            if str(sigma.get("max_severity") or "").lower() == "critical":
                conf = max(conf, 0.75)
        if signals.type_signal:
            conf = max(conf, 0.5)
        decision = apply_confirmation_gate(
            llm_threat_detected=threat,
            llm_abstain=not threat,
            signals=signals,
            has_admitted_claims=threat,
            extra_human=False,
        )
        et = str(
            raw_event.get("threat_type")
            or raw_event.get("event")
            or raw_event.get("type")
            or ""
        )
        return AuditResult(
            threat_detected=decision.threat_detected,
            threat_type=et if decision.threat_detected else "",
            confidence=round(min(1.0, conf), 4),
            severity=str(raw_event.get("severity") or "info"),
            summary=(
                f"tools_only 确定性结论: signals={signals.reasons[:3]} "
                f"verdict={decision.verdict}"
            ),
            needs_human_review=decision.needs_human_review,
            verdict=decision.verdict,
            tool_results=list(tool_results or []),
            non_llm_signals=signals.to_dict(),
            hop_trace=[{"hop": "tools_only", "skip_llm": True}],
            schema_valid=True,
        )

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
                    threat_detected=False,
                    confidence=0.0,
                    severity="info",
                    summary=f"审核异常: {type(result).__name__}",
                    alert="chunk 审核异常，需人工复核（不计入威胁投票）",
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
        signals=None,
        hop_stats=None,
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
                verdict="insufficient_evidence",
                summary="无事件可审核",
                severity="info",
                needs_human_review=True,
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

        # 构建汇总 prompt：只列出 admitted（grounded/partial）主张，ungrounded 单独列出禁止采纳
        block_summaries = []
        discarded_for_prompt = []
        for chunk, verdict in zip(chunks, verdicts):
            status = "🚨" if verdict.threat_detected else "✅"
            risk_tag = f" [幻觉风险={verdict.hallucination_risk:.2f}]" if verdict.unsubstantiated else ""
            grounding_tag = f" [Grounding={verdict.grounding_score:.2f}]" if verdict.grounding_score < 0.8 else ""
            claims_detail = ""
            for claim in verdict.threat_claims:
                eids = claim.get("evidence_ids", [])
                quotes = claim.get("evidence_quotes", [])
                gv = claim.get("grounding_verdict", "admitted")
                claims_detail += (
                    f"      - [{gv}] {claim.get('type','?')} conf={claim.get('confidence',0):.2f} "
                    f"evidence_ids={eids} quotes={len(quotes)}条\n"
                )
            for dc in getattr(verdict, "discarded_claims", None) or []:
                discarded_for_prompt.append(
                    f"  - [{chunk.chunk_id}] {dc.get('type','?')}: {str(dc.get('summary',''))[:80]}"
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
        from memory_guard import sanitize_event_for_llm
        event_json = json.dumps(sanitize_event_for_llm(raw_event), ensure_ascii=False)[:500] if raw_event else ""

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
            "\n硬约束: ungrounded 断言已剥离，禁止写进 threat_detected；"
            "不得发明新的 evidence_ids / TTP / 实体。证据不足须 abstain=true。\n"
        )
        if discarded_for_prompt:
            verification_section += "已剥离（禁止采纳）:\n" + "\n".join(
                discarded_for_prompt[:8]
            ) + "\n"

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

        from prompts import render
        prompt = render(
            "audit/executor_synthesize",
            event_json=event_json,
            depth=depth,
            chain_info=chain_info,
            rag_context=rag_context,
            deep_section=deep_section,
            verification_section=verification_section,
            kb_section=kb_section,
            summary_text=summary_text,
            verdicts=verdicts,
        )

        from trace_hook import set_trace_context
        set_trace_context(operation="execute")
        result = await summary.llm.chat([
            {
                "role": "system",
                "content": render("audit/executor_synthesize_system"),
            },
            {"role": "user", "content": prompt},
        ])

        from agents.llm_fallback import is_llm_fallback
        is_fb, fb_reason = is_llm_fallback(result)
        if is_fb:
            logger.warning(f"Synthesis LLM fallback (no retry): {fb_reason}")
            any_threat = any(getattr(v, "threat_detected", False) for v in (verdicts or []))
            return AuditResult(
                threat_detected=any_threat,
                verdict="insufficient_evidence",
                summary=f"汇总降级: {fb_reason}",
                needs_human_review=True,
                confidence=0.2 if any_threat else 0.0,
            )

        # 结构化验证（Pydantic）
        from audit_schemas import validate_synthesis_output
        parsed, schema_errors = validate_synthesis_output(result)
        if schema_errors:
            logger.warning(f"Synthesis schema validation issues: {schema_errors}")

        if parsed is None:
            logger.warning("Synthesis parse failed completely")
            return AuditResult(
                threat_detected=False,
                verdict="insufficient_evidence",
                summary="汇总解析失败",
                needs_human_review=True,
            )

        try:
            from veto_gates import apply_confirmation_gate, extract_non_llm_signals

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

            admitted_count = sum(len(v.threat_claims) for v in verdicts)
            discarded_all = []
            for v in verdicts:
                discarded_all.extend(getattr(v, "discarded_claims", None) or [])

            gate_signals = signals or extract_non_llm_signals(
                raw_event, chain_info=chain_info,
            )
            extra_human = (
                parsed.get("needs_human_review", False)
                or avg_hallucination_risk > 0.3
                or evidence_completeness < 0.3
                or avg_grounding < 0.5
                or kb_risk > 0.7
                or bool(parsed.get("abstain"))
            )
            decision = apply_confirmation_gate(
                llm_threat_detected=bool(parsed.get("threat_detected", False)),
                llm_abstain=bool(parsed.get("abstain")),
                signals=gate_signals,
                has_admitted_claims=admitted_count > 0,
                extra_human=extra_human,
            )

            logger.info(
                f"Confirmation gate: llm_threat={parsed.get('threat_detected')} "
                f"→ {decision.verdict} threat={decision.threat_detected} "
                f"signal={gate_signals.has_signal} admitted={admitted_count} "
                f"reason={decision.reason}"
            )

            hop_trace = []
            if hop_stats is not None:
                hop_trace.append({
                    "hop": "sub_auditor",
                    "avg_hallucination_risk": round(hop_stats.avg_hallucination_risk, 4),
                    "avg_grounding": round(hop_stats.avg_grounding, 4),
                    "skip_reasoning": hop_stats.skip_reasoning,
                })
            hop_trace.append({
                "hop": "synthesize",
                "verdict": decision.verdict,
                "reason": decision.reason,
            })

            return AuditResult(
                threat_detected=decision.threat_detected,
                threat_type=parsed.get("threat_type", "") if decision.threat_detected else "",
                confidence=round(adjusted_confidence, 4),
                severity=parsed.get("severity", "info") if decision.threat_detected else "info",
                summary=(
                    f"{parsed.get('summary','')} "
                    f"[证据完整度={evidence_completeness:.0%} "
                    f"verdict={decision.verdict}]"
                ),
                evidence=[v.to_dict() if hasattr(v, 'to_dict') else {"summary": v.summary}
                          for v in verdicts],
                affected_entities=parsed.get("affected_entities", {}),
                suggested_actions=parsed.get("suggested_actions", []) if decision.threat_detected else [],
                needs_human_review=decision.needs_human_review,
                verdict=decision.verdict,
                discarded_claims=discarded_all,
                hop_trace=hop_trace,
                non_llm_signals=gate_signals.to_dict(),
                grounding_score=avg_grounding,
                kb_verification=kb_verification or {},
            )
        except Exception as e:
            logger.warning(f"Synthesis parse failed: {e}")
            return AuditResult(
                threat_detected=False,
                verdict="insufficient_evidence",
                summary="汇总解析失败",
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
        from prompts import render
        prompt = render("audit/executor_deep", v_text=v_text)
        from trace_hook import set_trace_context
        set_trace_context(operation="execute_deep")
        return await summary.llm.chat([
            {"role": "system", "content": render("audit/executor_deep_system")},
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
        from prompts import render
        prompt = render(
            "audit/executor_recheck",
            v_text=v_text,
            threat_detected=audit.threat_detected,
            threat_type=audit.threat_type,
            confidence=audit.confidence,
        )
        from trace_hook import set_trace_context
        set_trace_context(operation="execute_recheck")
        result = await summary.llm.chat([
            {"role": "system", "content": render("audit/executor_recheck_system")},
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
            parsed["abstain"] = _as_bool(parsed.get("abstain", False))
            if parsed["abstain"]:
                parsed["needs_human"] = True
                parsed["missed_threats"] = []
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
