"""
RAG 上下文构建器 — 将检索结果格式化为 LLM 可用的上下文

功能:
  1. 格式化检索块为结构化文本
  2. 添加来源引用（减少幻觉的关键）
  3. 按相关性排序
  4. 控制在 token 预算内

集成到审计流水线:
  - SubAuditor: 审核前注入相关知识
  - Executor: 综合阶段作为参考
  - Reviewer: 验证结论
"""
import logging
from typing import Optional

from .retriever import RetrievalResult

logger = logging.getLogger(__name__)


class RAGContextBuilder:
    """RAG 上下文构建器"""

    def __init__(self, max_tokens: int = 2000):
        self.max_tokens = max_tokens

    def build_context(
        self,
        result: RetrievalResult,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        构建 RAG 上下文文本

        Args:
            result: 检索结果
            max_tokens: token 上限

        Returns:
            格式化的上下文文本
        """
        limit = max_tokens or self.max_tokens
        if not result.chunks:
            return ""

        parts = ["## 安全知识参考（检索增强）\n"]
        parts.append("> 以下知识来自安全知识库，请基于这些信息进行判断。\n")

        tokens_used = 0
        added = 0

        for chunk in result.chunks:
            score = chunk.get("score", 0)
            title = chunk.get("title", "")
            source = chunk.get("source", "")
            content = chunk.get("content", "")
            threat_types = chunk.get("threat_types", [])
            severity = chunk.get("severity", "")
            chunk_id = chunk.get("id", "")

            # 格式化
            header = f"### 知识条目 (score={score:.2f})"
            if title:
                header += f" — {title}"
            source_info = f"来源: {source}" if source else ""
            type_info = f"威胁类型: {', '.join(threat_types)}" if threat_types else ""

            block = f"\n{header}\n"
            if source_info:
                block += f"{source_info}"
            if type_info:
                block += f" | {type_info}"
            if severity:
                block += f" | 严重度: {severity}"
            block += f"\n> ID: {chunk_id}\n\n{content}\n"

            estimated = len(block) // 2
            if tokens_used + estimated > limit:
                logger.info(f"RAG context truncated at {added} chunks ({tokens_used} tokens)")
                parts.append(f"\n[上下文截断: 已达 {limit} token 上限]\n")
                break

            parts.append(block)
            tokens_used += estimated
            added += 1

        result_text = "\n".join(parts)
        logger.info(f"RAG context built: {added} chunks, ~{tokens_used} tokens")
        return result_text

    def build_verification_prompt(
        self,
        claim: str,
        result: RetrievalResult,
    ) -> str:
        """构建断言验证 prompt"""
        context = self.build_context(result, max_tokens=1500)
        if not context:
            return ""

        from prompts import render
        prompt = render("rag/evidence_verify", context=context, claim=claim)
        return prompt


rag_context_builder = RAGContextBuilder()
