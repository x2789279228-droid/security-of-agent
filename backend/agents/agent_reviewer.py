"""
复核者 (Reviewer) — Audit-LLM 第四层

职责：
  对照 Decomposer 的子任务清单，检查 Executor 的输出：
  1. 是否覆盖了所有要求
  2. 证据是否充分
  3. 结论是否自洽
  4. 是否有遗漏的威胁

与旧版 Agent-D 的区别：
  - Agent-D 是事后补查（独立于流水线）
  - Reviewer 是流水线的最后一步，是 Decomposer 主动分配的审核环节

输入：
  - 原始事件
  - Decomposer 的输出（子任务列表 + 审核深度）
  - Executor 的输出（AuditResult + 所有 ToolResult）
  - 全部工具返回的原始数据

输出：FinalVerdict
"""
import json
import logging
from typing import Optional

from summary_compression import summary
from audit_types import (
    AuditResult, FinalVerdict,
    AUDIT_DEPTH_STANDARD,
)

logger = logging.getLogger(__name__)


class Reviewer:
    """
    复核者

    review(event, decomposer_output, audit_result, tool_data) → FinalVerdict
    """

    async def review(
        self,
        raw_event: dict,
        decomposer_output: dict,
        audit_result: AuditResult,
        tool_data_raw: str,
    ) -> FinalVerdict:
        """
        复核审计结论

        Args:
            raw_event: 原始事件
            decomposer_output: Decomposer 的输出
            audit_result: Executor 生成的审计结果
            tool_data_raw: 工具返回的原始数据文本

        Returns:
            FinalVerdict
        """
        depth = decomposer_output.get("audit_depth", AUDIT_DEPTH_STANDARD)
        sub_tasks = decomposer_output.get("sub_tasks", [])
        llm_analysis = decomposer_output.get("llm_analysis", "")

        from veto_gates import (
            should_run_llm_reviewer,
            executor_conclusion_floor,
            clamp_reviewer_conclusion,
            filter_missed_threats,
        )
        executor_level = executor_conclusion_floor(
            threat_detected=audit_result.threat_detected,
            verdict=getattr(audit_result, "verdict", "") or "",
            needs_human_review=audit_result.needs_human_review,
        )

        # P0-9: 仅 deep 走 LLM 复核；quick/standard 确定性映射，不增加 hop
        if not should_run_llm_reviewer(depth):
            return FinalVerdict(
                conclusion=executor_level,
                confidence=audit_result.confidence,
                human_intervention=audit_result.needs_human_review
                or executor_level in ("suspicious", "insufficient_evidence"),
                final_summary=audit_result.summary,
                reviewer_notes=f"{depth} audit, no LLM review (hop budget); floor={executor_level}",
            )

        verdict = await self._llm_review(
            raw_event, decomposer_output, audit_result, tool_data_raw
        )
        if verdict.abstain:
            executor_level = "insufficient_evidence"
        verdict.conclusion = clamp_reviewer_conclusion(executor_level, verdict.conclusion)
        verdict.missed_threats = filter_missed_threats(verdict.missed_threats)
        if verdict.abstain:
            verdict.conclusion = "insufficient_evidence"
            verdict.missed_threats = []
            verdict.human_intervention = True
        if verdict.conclusion in ("suspicious", "insufficient_evidence"):
            verdict.human_intervention = True
        return verdict

    def _extract_rag_for_review(self, audit_result: AuditResult) -> str:
        """
        从 audit_result.tool_results 中提取 knowledge.search 工具返回的知识库片段

        为什么单独提取：原实现中 RAG 片段只在 tool_data_raw[:3000] 中体现，
        经常被截断 — 而 prompt 第 6 条防幻觉检查（知识库一致性）依赖完整
        知识库描述。本方法把 RAG 检索结果格式化为独立 section，
        让 Reviewer LLM 能完整看到知识库内容并真正执行一致性比对。

        格式化策略：
          - 仅取 knowledge.search 工具的成功结果
          - 每个片段输出 title / threat_types / severity / content（截断到 400 字符）
          - 总长度上限 2500 字符，避免 prompt 膨胀
        """
        if not audit_result or not audit_result.tool_results:
            return ""

        sections: list[str] = []
        budget = 2500
        for tr in audit_result.tool_results:
            if tr.tool != "knowledge.search" or not tr.success or not tr.data:
                continue
            if not isinstance(tr.data, list):
                continue
            for chunk in tr.data:
                if not isinstance(chunk, dict):
                    continue
                title = chunk.get("title", "") or "(无标题)"
                threat_types = chunk.get("threat_types", []) or []
                severity = chunk.get("severity", "") or ""
                content = (chunk.get("content", "") or "")[:400]
                entry = (
                    f"- **{title}**\n"
                    f"  威胁类型: {threat_types if threat_types else '(未标注)'}\n"
                    f"  严重度: {severity}\n"
                    f"  内容: {content}\n"
                )
                if len("\n".join(sections)) + len(entry) > budget:
                    sections.append("... (达到展示上限，已截断)")
                    break
                sections.append(entry)
            if any("达到展示上限" in s for s in sections):
                break
        return "\n".join(sections).strip()

    async def _llm_review(
        self,
        raw_event: dict,
        decomposer_output: dict,
        audit_result: AuditResult,
        tool_data_raw: str,
    ) -> FinalVerdict:
        """LLM 复核 — 含专门的事实核查"""
        event_json = json.dumps(raw_event, ensure_ascii=False, indent=2)[:1000]
        depth = decomposer_output.get("audit_depth", "standard")
        sub_tasks = decomposer_output.get("sub_tasks", [])
        llm_analysis = decomposer_output.get("llm_analysis", "")

        sub_tasks_text = "\n".join(
            f"  - [{st['type']}] {st.get('description', '')}"
            for st in sub_tasks
        )

        audit_json = json.dumps(audit_result.to_dict(), ensure_ascii=False, indent=2)

        # D1 修复：单独提取 RAG 知识库片段注入到 prompt
        # 原实现中 RAG 检索结果只在 tool_data_raw[:3000] 中体现，经常被截断，
        # 导致 prompt 第 6 条防幻觉检查（知识库一致性）实际无法执行。
        # 现从 audit_result.tool_results 中完整提取 knowledge.search 返回的 chunk，
        # 注入到独立 prompt section。
        rag_section = self._extract_rag_for_review(audit_result)

        from prompts import render
        prompt = render(
            "audit/reviewer_review",
            event_json=event_json,
            depth=depth,
            sub_tasks_text=sub_tasks_text,
            llm_analysis=llm_analysis,
            audit_json=audit_json,
            rag_section=rag_section,
            tool_data_raw=tool_data_raw,
        )

        from trace_hook import set_trace_context
        set_trace_context(operation="review")
        result = await summary.llm.chat([
            {"role": "system", "content": render("audit/reviewer_review_system")},
            {"role": "user", "content": prompt},
        ])

        try:
            from agents.llm_fallback import is_llm_fallback
            is_fb, fb_reason = is_llm_fallback(result)
            if is_fb:
                logger.warning(f"Reviewer LLM fallback (no retry): {fb_reason}")
                base_conclusion = (
                    "threat_confirmed" if getattr(audit_result, "threat_detected", False)
                    else "suspicious"
                )
                return FinalVerdict(
                    conclusion=base_conclusion,
                    confidence=float(getattr(audit_result, "confidence", 0) or 0) * 0.8,
                    human_intervention=True,
                    final_summary=str(getattr(audit_result, "summary", "") or "")[:500],
                    reviewer_notes=f"llm_fallback:{fb_reason}",
                    abstain=True,
                )

            # 结构化验证（Pydantic）
            from audit_schemas import validate_reviewer_output
            parsed, schema_errors = validate_reviewer_output(result)
            if schema_errors:
                logger.warning(f"Reviewer schema issues: {schema_errors}")
            if parsed is None:
                raise ValueError("JSON 解析完全失败")

            abstain = bool(parsed.get("abstain"))
            conclusion = parsed.get("conclusion", "suspicious")
            if abstain:
                conclusion = "insufficient_evidence"
            return FinalVerdict(
                conclusion=conclusion,
                confidence=parsed.get("confidence", audit_result.confidence),
                missed_threats=parsed.get("missed_threats", []),
                evidence_chain=parsed.get("evidence_chain", []),
                human_intervention=bool(parsed.get("human_intervention", False) or abstain),
                final_summary=parsed.get("final_summary", ""),
                reviewer_notes=parsed.get("reviewer_notes", ""),
                abstain=abstain,
            )
        except Exception as e:
            logger.warning(f"Failed to parse review result: {e}")
            # 解析失败时保留 Executor 结论，标记 degraded，避免整轮结论蒸发
            base_conclusion = (
                "threat_confirmed" if getattr(audit_result, "threat_detected", False)
                else "suspicious"
            )
            return FinalVerdict(
                conclusion=base_conclusion,
                confidence=audit_result.confidence * 0.8,
                human_intervention=True,
                final_summary=audit_result.summary,
                reviewer_notes=f"复核结果解析失败(degraded): {str(result)[:200]}",
                abstain=False,
            )


reviewer = Reviewer()
