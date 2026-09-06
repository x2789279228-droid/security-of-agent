"""
检索重排 — Cross-encoder HTTP（优先）→ 词法特征分 → LLM list-rerank（最后）

对接 docker-compose 里 soc-bge-rerank (Infinity, /rerank 与 /v1/rerank)。
CPU 上 BGE-reranker-v2-m3 单次 20 条可达数秒，超时必须远大于 1s。
"""
from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# CPU reranker：冷启动/20 文档常见 2–8s，0.8s 会 100% 超时
CE_TIMEOUT = 15.0


def _settings():
    from config import settings
    return settings


def resolve_rerank_url(s=None) -> str:
    """仅使用 rag_rerank_url。空则不用 HTTP CE（不回落 LLM 网关）。"""
    if s is None:
        s = _settings()
    return (getattr(s, "rag_rerank_url", "") or "").strip()


def rerank_candidate_urls(base: str) -> list[str]:
    """从配置 URL 派生候选路径，禁止拼出 /rerank/v1/rerank。"""
    raw = (base or "").strip().rstrip("/")
    if not raw:
        return []
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")
    urls: list[str] = []
    if path and path not in ("", "/"):
        urls.append(origin + path)
    for suffix in ("/rerank", "/v1/rerank"):
        u = origin + suffix
        if u not in urls:
            urls.append(u)
    return urls


def _local_rerank_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"soc-bge-rerank", "localhost", "127.0.0.1", "rerank", "infinity"} or host.endswith(".internal")


def _parse_rerank_results(body: object) -> list[dict]:
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        rows = body.get("results") or body.get("data") or body.get("rankings") or []
    else:
        rows = []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        idx = row.get("index")
        if idx is None:
            continue
        try:
            idx = int(idx)
        except (TypeError, ValueError):
            continue
        score = row.get("relevance_score", row.get("score", row.get("relevanceScore")))
        out.append({"index": idx, "score": score})
    return out


def feature_rerank(query: str, chunks: list[dict], top_k: int) -> list[dict]:
    """RRF/向量分 + 词法重叠 + 标题命中，无需模型。"""
    from .lexical import lexical_overlap_rank

    from .lexical import extract_security_terms
    terms = extract_security_terms(query)
    scored = []
    for i, c in enumerate(chunks):
        base = float(c.get("rrf_score") or c.get("score") or 0.0)
        overlap = lexical_overlap_rank(query, f"{c.get('title','')} {c.get('content','')}")
        title = (c.get("title") or "").lower()
        qlow = (query or "").lower()
        title_hit = 1.0 if qlow and qlow in title else 0.0
        blob = f"{c.get('title','')} {c.get('content','')}".lower()
        exact = 0.0
        for term in terms:
            if term.lower() in blob:
                exact += 0.5
        final = base * 8.0 + overlap * 0.7 + title_hit * 0.2 + exact
        item = dict(c)
        item["rerank_score"] = round(final, 4)
        item["reranked"] = False
        item["rerank_backend"] = "feature"
        item["_order"] = i
        scored.append(item)
    scored.sort(key=lambda x: (-x["rerank_score"], x["_order"]))
    for it in scored:
        it.pop("_order", None)
        it["score"] = it["rerank_score"]
    return scored[:top_k]


async def http_cross_encoder_rerank(query: str, chunks: list[dict], top_k: int) -> Optional[list[dict]]:
    s = _settings()
    if not getattr(s, "rag_rerank_enabled", True):
        return None
    # 只打显式配置的 rerank 服务。禁止回落到 llm_base_url/v1/rerank：
    # MiniMax 等对话网关没有该端点，空 URL 时应立刻走特征重排，而不是 15s 超时。
    configured = resolve_rerank_url(s)
    if not configured:
        return None
    model = getattr(s, "rag_rerank_model", "") or "BAAI/bge-reranker-v2-m3"
    documents = [
        f"{c.get('title','')}\n{(c.get('content') or '')[:800]}" for c in chunks
    ]
    payloads = [
        {"model": model, "query": query, "documents": documents, "top_n": min(top_k, len(documents))},
        {"query": query, "documents": documents},
    ]
    last_err = ""
    try:
        async with httpx.AsyncClient(timeout=CE_TIMEOUT) as client:
            for url in rerank_candidate_urls(configured):
                headers = {"Content-Type": "application/json"}
                api_key = (getattr(s, "rag_rerank_api_key", None) or "")
                if not api_key and not _local_rerank_host(url):
                    api_key = getattr(s, "llm_api_key", "") or getattr(s, "embedding_api_key", "")
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                for payload in payloads:
                    try:
                        r = await client.post(url, json=payload, headers=headers)
                    except httpx.TimeoutException as e:
                        last_err = f"timeout {CE_TIMEOUT}s url={url}"
                        logger.warning(f"[reranker] HTTP cross-encoder 超时: {last_err}")
                        return None
                    except Exception as e:
                        last_err = str(e)
                        logger.info(f"[reranker] {url} 连接失败: {e}")
                        break
                    if r.status_code in (404, 405):
                        break
                    if r.status_code == 422:
                        continue
                    if r.status_code >= 400:
                        last_err = f"{r.status_code} {r.text[:180]}"
                        logger.warning(f"[reranker] {url} -> {last_err}")
                        continue
                    try:
                        body = r.json()
                    except Exception:
                        last_err = "non-json response"
                        continue
                    parsed = _parse_rerank_results(body)
                    if not parsed:
                        last_err = f"empty results keys={list(body)[:8] if isinstance(body, dict) else type(body)}"
                        continue
                    ordered: list[dict] = []
                    seen: set[int] = set()
                    for row in parsed:
                        idx = row["index"]
                        if idx < 0 or idx >= len(chunks) or idx in seen:
                            continue
                        seen.add(idx)
                        item = dict(chunks[idx])
                        try:
                            item["rerank_score"] = round(float(row["score"] or 0), 4)
                        except (TypeError, ValueError):
                            item["rerank_score"] = 0.0
                        item["reranked"] = True
                        item["rerank_backend"] = "cross_encoder"
                        item["score"] = item["rerank_score"]
                        ordered.append(item)
                    if not ordered:
                        continue
                    for i, c in enumerate(chunks):
                        if i not in seen and len(ordered) < top_k:
                            item = dict(c)
                            item.setdefault("reranked", False)
                            item.setdefault("rerank_backend", "cross_encoder")
                            ordered.append(item)
                    logger.info(f"[reranker] cross-encoder ok url={url} n={len(ordered)}")
                    return ordered[:top_k]
    except Exception as e:
        last_err = str(e)
        logger.warning(f"[reranker] HTTP cross-encoder 不可用: {e}")
    if last_err:
        logger.warning(f"[reranker] HTTP cross-encoder 放弃: {last_err}")
    return None


async def rerank_chunks(
    query: str,
    chunks: list[dict],
    top_k: int = 5,
    *,
    skip_llm: bool = False,
) -> tuple[list[dict], str]:
    """返回 (chunks, backend)。backend=cross_encoder|feature|llm|none。"""
    if len(chunks) <= 1:
        return chunks[:top_k], "none"
    ce = await http_cross_encoder_rerank(query, chunks, top_k)
    if ce:
        return ce, "cross_encoder"
    featured = feature_rerank(query, chunks, top_k)
    if skip_llm:
        return featured, "feature"
    # 生成式 LLM 会打乱精确词排序，仅在特征分完全无区分时才用
    try:
        from rag.retriever import retriever
        llm_out = await retriever.rerank(query, chunks, top_k=top_k)
        if llm_out and any(c.get("reranked") for c in llm_out):
            # 若特征分已把精确词抬到 top1，保留特征分
            feat_blob = f"{featured[0].get('title','')} {featured[0].get('content','')}".lower() if featured else ""
            from .lexical import extract_security_terms
            terms = extract_security_terms(query)
            if terms and any(t.lower() in feat_blob for t in terms):
                return featured, "feature"
            for c in llm_out:
                c["rerank_backend"] = "llm"
                c.setdefault("rerank_score", c.get("score"))
            return llm_out, "llm"
    except Exception as e:
        logger.debug(f"[reranker] LLM rerank skipped: {e}")
    return featured, "feature"
