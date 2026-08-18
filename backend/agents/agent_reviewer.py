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
    AUDIT_DEPTH_QUICK, AUDIT_DEPTH_STANDARD, AUDIT_DEPTH_DEEP,
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

        # quick 模式不需要 LLM 复核（风险低）
        if depth == AUDIT_DEPTH_QUICK:
            return FinalVerdict(
                conclusion="threat_confirmed" if audit_result.threat_detected else "false_positive",
                confidence=audit_result.confidence,
                human_intervention=audit_result.needs_human_review,
                final_summary=audit_result.summary,
                reviewer_notes="Quick audit, no deep review needed",
            )

        # standard / deep 模式走 LLM 复核
        verdict = await self._llm_review(
            raw_event, decomposer_output, audit_result, tool_data_raw
        )
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

        prompt = f"""你是安全审计复核专家。请复核以下审计结论的完整性和准确性。

## 原始事件
{event_json}

## 审核深度
{depth}

## 要求执行的子任务
{sub_tasks_text}

## LLM 初步分析
{llm_analysis[:500] if llm_analysis else '（无）'}

## Executor 生成的审计结论
{audit_json}

## 安全知识库检索结果 (RAG — 完整片段，未截断)
{rag_section if rag_section else '（未检索到相关知识）'}

## 工具返回的原始数据（截断预览）
{tool_data_raw[:3000]}

## 复核要求
请严格检查，特别注意以下防幻觉检查项：

### 防幻觉专项检查（优先级最高）
1. **事实核查** — Executor 结论中的每一条断言，是否都有工具返回数据支撑？
2. **数字核查** — 结论中提到的数量（IP数、事件数、时间）是否与工具返回一致？
3. **证据来源** — 每条威胁判定是否标注了具体的事件ID或数据来源？
4. **虚假关联** — 是否存在把两个无关事件强行关联成攻击链的情况？
5. **置信度通胀** — 证据不充分时是否给出了过高的置信度？
6. **知识库一致性** — 结论是否与上方"安全知识库检索结果"section 中的 MITRE ATT&CK / CAPEC 描述一致？逐条对照威胁类型、严重度、攻击手法，偏离则标记幻觉风险

### 其他检查项
7. **完整性** — Executor 是否覆盖了所有子任务？
8. **遗漏检查** — 原始数据中是否存在 Executor 未提及的可疑信号？
9. **是否需要人工介入** — 是否存在 AI 难以判断的复杂情况？

## 输出格式（严格 JSON）
{{
    "conclusion": "threat_confirmed/false_positive/suspicious",
    "confidence": 0.0-1.0,

    "hallucination_check": {{
        "has_unsubstantiated_claims": true/false,
        "unsubstantiated_details": ["具体哪些断言缺少证据"],
        "data_consistency": "consistent/partially_consistent/inconsistent",
        "confidence_overinflation": true/false
    }},

    "missed_threats": [{{"description":"...","evidence":"...","severity":"..."}}],
    "evidence_chain": ["证据1","证据2",...],
    "human_intervention": true/false,
    "final_summary": "最终判断摘要",
    "reviewer_notes": "复核过程中的关键发现（特别是幻觉风险相关）"
}}"""

        from trace_hook import set_trace_context
        set_trace_context(operation="review")
        result = await summary.llm.chat([
            {
                "role": "system",
                "content": (
                    "你是一个严格的安全审计复核专家，专门负责防幻觉检查。"
                    "你的核心职责是：找出前序 LLM 的输出中那些有数据支撑的断言和没有数据支撑的断言。"
                    "没有数据支撑的断言必须标记为幻觉风险。"
                    "宁可误报不可漏报。严格遵循 JSON 格式输出。"
                ),
            },
            {"role": "user", "content": prompt},
        ])

        try:
            # 结构化验证（Pydantic）
            from audit_schemas import validate_reviewer_output
            parsed, schema_errors = validate_reviewer_output(result)
            if schema_errors:
                logger.warning(f"Reviewer schema issues: {schema_errors}")
            if parsed is None:
                raise ValueError("JSON 解析完全失败")

            return FinalVerdict(
                conclusion=parsed.get("conclusion", "suspicious"),
                confidence=parsed.get("confidence", audit_result.confidence),
                missed_threats=parsed.get("missed_threats", []),
                evidence_chain=parsed.get("evidence_chain", []),
                human_intervention=parsed.get("human_intervention", False),
                final_summary=parsed.get("final_summary", ""),
                reviewer_notes=parsed.get("reviewer_notes", ""),
            )
        except Exception as e:
            logger.warning(f"Failed to parse review result: {e}")
            return FinalVerdict(
                conclusion="suspicious",
                confidence=audit_result.confidence * 0.8,
                human_intervention=True,
                final_summary=audit_result.summary,
                reviewer_notes=f"复核结果解析失败: {result[:200]}",
            )


reviewer = Reviewer()
