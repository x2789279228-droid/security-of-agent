"""
质量评估指标（移植自 studyagentplus evaluation/metrics）

指标均为启发式（heuristic），不依赖 LLM：
- 词法重叠（中文按字 + 相邻二元组，英文按 token）
- 断言切分（忠实度评估用）
- 词频覆盖
- 语义相似度（基于预计算 embedding 的余弦）
"""
import math
import re
from collections import Counter
from typing import Any

ASCII_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+", re.UNICODE)


def _is_cjk(char: str) -> bool:
    codepoint = ord(char)
    return 0x4E00 <= codepoint <= 0x9FFF


def tokenize(text: str) -> list[str]:
    """中英混合 tokenize：中文单字 + 相邻二元组 + 英文小写 token"""
    tokens: list[str] = []
    cjk_chars = [char for char in text or "" if _is_cjk(char)]
    tokens.extend(cjk_chars)
    tokens.extend("".join(cjk_chars[i:i + 2]) for i in range(0, max(0, len(cjk_chars) - 1)))
    tokens.extend(t.lower() for t in ASCII_TOKEN_RE.findall(text or "") if t.strip())
    return tokens


def lexical_overlap_score(left: str, right: str) -> float:
    """Jaccard 式重叠：重叠 token 数 / 左侧 token 数"""
    left_tokens = set(tokenize(left))
    right_tokens = set(tokenize(right))
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens)


def split_claims(answer: str) -> list[str]:
    """将回答按句切分为断言（短于 8 字符的丢弃）"""
    raw_claims = re.split(r"[。！？\n]+", answer or "")
    return [c.strip() for c in raw_claims if len(c.strip()) >= 8]


def term_frequency_score(text: str, terms: list[str]) -> float:
    """目标术语在文本中的覆盖率"""
    tokens = Counter(tokenize(text))
    normalized = [t.lower() for t in terms if t.strip()]
    if not normalized:
        return 0.0
    matched = sum(1 for t in normalized if t in tokens or t in text.lower())
    return round(matched / len(normalized), 4)


def context_text(context: dict[str, Any]) -> str:
    return str(context.get("content") or context.get("text") or "")


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return round(dot / (norm_a * norm_b), 6)


def semantic_similarity_score(
    answer_embedding: list[float] | None,
    reference_embedding: list[float] | None,
) -> float:
    if answer_embedding is None or reference_embedding is None:
        return 0.0
    return cosine_similarity(answer_embedding, reference_embedding)


def context_coverage_score(
    answer_embedding: list[float] | None,
    context_embeddings: list[list[float]],
) -> float:
    """回答 embedding 与各上下文 embedding 的最大余弦均值"""
    if answer_embedding is None or not context_embeddings:
        return 0.0
    best = [cosine_similarity(answer_embedding, ctx) for ctx in context_embeddings]
    return round(sum(best) / len(best), 4) if best else 0.0


def embedding_faithfulness_score(
    answer_embedding: list[float] | None,
    context_embeddings: list[list[float]],
    reference_embedding: list[float] | None = None,
    coverage_weight: float = 0.6,
) -> float:
    """基于 embedding 的忠实度：上下文覆盖度 + 参考答案一致性加权"""
    if answer_embedding is None or not context_embeddings:
        return 0.0
    coverage = context_coverage_score(answer_embedding, context_embeddings)
    if reference_embedding is not None:
        reference = semantic_similarity_score(answer_embedding, reference_embedding)
        return round(coverage_weight * coverage + (1 - coverage_weight) * reference, 4)
    return round(coverage, 4)
