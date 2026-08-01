"""
质量评估服务 — RAG 检索质量 + 忠实度（参考 studyagentplus evaluation/service）

指标说明:
- 检索质量: context_precision / context_recall / hit_rate_at_k / top1_relevance
- 忠实度: faithfulness / citation_coverage / answer_relevance / unsupported_claim_ratio
"""
import logging
from typing import Any, Optional

from eval_metrics import (
    lexical_overlap_score,
    split_claims,
    term_frequency_score,
    tokenize,
    context_text,
    embedding_faithfulness_score,
)
from eval_repository import save_evaluation_run

logger = logging.getLogger(__name__)


def _score(metric: str, score: float, threshold: float, reason: str) -> dict:
    normalized = max(0.0, min(1.0, round(float(score), 4)))
    return {
        "metric": metric,
        "score": normalized,
        "threshold": threshold,
        "passed": normalized >= threshold,
        "reason": reason,
    }


async def evaluate_rag_retrieval(
    *,
    query: str,
    contexts: list[dict],
    ground_truth: str = "",
    subject_id: str = "",
    retrieval_strategy: str = "",
    answer_embedding: Optional[list[float]] = None,
    context_embeddings: Optional[list[list[float]]] = None,
    persist: bool = True,
) -> dict:
    """评估一次 RAG 检索质量"""
    context_scores = [lexical_overlap_score(query, context_text(c)) for c in contexts]
    relevant = [s for s in context_scores if s >= 0.08]
    context_precision = round(len(relevant) / len(contexts), 4) if contexts else 0.0
    top1_relevance = round(context_scores[0], 4) if context_scores else 0.0
    hit_rate = 1.0 if relevant else 0.0
    context_recall = (
        max(lexical_overlap_score(ground_truth, context_text(c)) for c in contexts)
        if ground_truth and contexts
        else hit_rate
    )
    context_recall = round(context_recall, 4)

    # 语义补充指标（提供 embedding 时）
    semantic = 0.0
    if answer_embedding is not None and context_embeddings:
        semantic = embedding_faithfulness_score(answer_embedding, context_embeddings)

    scores = [
        _score("context_precision", context_precision, 0.7,
               f"{len(relevant)}/{len(contexts)} 个上下文与查询词法重叠"),
        _score("context_recall", context_recall, 0.7,
               "基于标准答案覆盖率" if ground_truth else "基于查询命中率的召回代理"),
        _score("hit_rate_at_k", hit_rate, 0.8,
               "至少一个检索上下文相关" if hit_rate else "没有检索到相关上下文"),
        _score("top1_relevance", top1_relevance, 0.1, "Top-1 上下文与查询的词法重叠"),
        _score("semantic_relevance", semantic, 0.4, "基于 embedding 的语义相关度"),
    ]

    output = {
        "context_scores": context_scores,
        "relevant_count": len(relevant),
        "top1_relevance": top1_relevance,
    }
    if persist:
        return await save_evaluation_run(
            run_type="rag",
            subject_id=subject_id,
            scores=scores,
            query=query,
            ground_truth=ground_truth,
            contexts=contexts,
            retrieval_strategy=retrieval_strategy,
            input_payload={"query": query, "ground_truth": ground_truth},
            output_payload=output,
        )
    return {"id": "not-persisted", "run_type": "rag", "scores": scores, "saved": False}


async def evaluate_faithfulness(
    *,
    answer: str,
    contexts: list[dict],
    query: str = "",
    subject_id: str = "",
    prompt_version: str = "",
    answer_embedding: Optional[list[float]] = None,
    context_embeddings: Optional[list[list[float]]] = None,
    persist: bool = True,
) -> dict:
    """评估回答对上下文的忠实度（防幻觉）"""
    claims = split_claims(answer)
    support_scores = [
        max(lexical_overlap_score(claim, context_text(c)) for c in contexts)
        if contexts else 0.0
        for claim in claims
    ]
    supported = [s for s in support_scores if s >= 0.18]
    unsupported_count = max(0, len(claims) - len(supported))
    faithfulness = round(len(supported) / len(claims), 4) if claims else 0.0
    citation_coverage = min(1.0, round(len(contexts) / max(1, len(claims)), 4)) if contexts else 0.0
    answer_relevance = (
        lexical_overlap_score(query, answer)
        if query
        else term_frequency_score(answer, tokenize("\n".join(context_text(c) for c in contexts))[:20])
    )

    semantic = 0.0
    if answer_embedding is not None and context_embeddings:
        semantic = embedding_faithfulness_score(answer_embedding, context_embeddings)

    scores = [
        _score("faithfulness", faithfulness, 0.75,
               f"{len(supported)}/{len(claims)} 条断言有上下文支撑"),
        _score("citation_coverage", citation_coverage, 0.6,
               f"{len(contexts)} 个上下文覆盖 {len(claims)} 条断言"),
        _score("answer_relevance", round(answer_relevance, 4), 0.15, "回答与查询的重叠度"),
        _score("unsupported_claim_ratio", 1 - (unsupported_count / max(1, len(claims))), 0.75,
               f"检测到 {unsupported_count} 条无支撑断言"),
        _score("semantic_faithfulness", semantic, 0.4, "基于 embedding 的语义忠实度"),
    ]

    output = {
        "claim_count": len(claims),
        "unsupported_claim_count": unsupported_count,
        "support_scores": support_scores,
    }
    if persist:
        return await save_evaluation_run(
            run_type="faithfulness",
            subject_id=subject_id,
            scores=scores,
            query=query,
            answer=answer,
            contexts=contexts,
            prompt_version=prompt_version,
            input_payload={"query": query, "answer": answer},
            output_payload=output,
        )
    return {"id": "not-persisted", "run_type": "faithfulness", "scores": scores, "saved": False}
