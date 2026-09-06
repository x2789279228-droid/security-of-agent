"""
检索器 — 混合检索安全知识库

检索策略（参考旅游助手多通道检索）:
  1. 向量检索: 语义相似度搜索 (pgvector cosine)
  2. 标签过滤: 按威胁类型/严重度/来源过滤
  3. 混合检索: 向量 + 标签 + 元数据

输出: RetrievalResult (含检索块列表 + 来源元数据)
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select, and_, or_, func as sql_func, text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class RetrievalResult:
    """检索结果"""
    chunks: list[dict] = field(default_factory=list)
    total_found: int = 0
    strategy_used: str = ""  # "vector" | "bm25" | "rrf" | "rrf_rerank" | "filter"
    transform: dict = field(default_factory=dict)
    rerank_backend: str = ""  # cross_encoder | feature | llm | none


class Retriever:
    """安全知识检索器"""

    def __init__(self):
        pass

    async def retrieve(
        self,
        session: AsyncSession,
        query: str = "",
        query_embedding: Optional[list[float]] = None,
        threat_type: str = "",
        severity: str = "",
        source: str = "",
        top_k: int = 5,
        min_score: float = 0.6,
        skip_llm: bool = False,
        rewrite: Optional[str] = None,
        hyde: Optional[str] = None,
        rerank: Optional[bool] = None,
    ) -> RetrievalResult:
        """
        混合检索: 规则扩展 → dense + BM25 → RRF → 可选 cross-encoder。

        rag_hybrid_enabled=false 时退回原 dense / ILIKE 路径。
        """
        from rag.query_transform import transform_query
        from summary_compression import embedder

        do_rerank = settings.rag_rerank_enabled if rerank is None else bool(rerank)
        hybrid = bool(getattr(settings, "rag_hybrid_enabled", False))
        prefetch = int(getattr(settings, "rag_prefetch", 20) or 20)
        transform = await transform_query(
            query, rewrite=rewrite, hyde=hyde, skip_llm=skip_llm, empty_hits=False,
        ) if query else {
            "original": "", "expanded": "", "lexical_query": "",
            "keywords": [], "lexical_first": False, "hyde_text": "",
            "rewritten": "", "step_back": "",
        }

        dense_text = (transform.get("hyde_text") or transform.get("expanded")
                      or transform.get("rewritten") or query)
        if query_embedding is None and dense_text:
            try:
                query_embedding = await embedder.embed(dense_text, type_="query")
            except Exception as e:
                logger.warning(f"query embed failed: {e}")
                query_embedding = None

        result = RetrievalResult(transform=transform)
        if hybrid and (query or query_embedding):
            result = await self._hybrid_search(
                session,
                query=query,
                transform=transform,
                query_embedding=query_embedding,
                threat_type=threat_type,
                severity=severity,
                source=source,
                top_k=max(top_k, prefetch),
                min_score=min_score,
            )
            result.transform = transform
            if not result.chunks and transform.get("hyde_text") == "" and not skip_llm:
                # empty_only HyDE：双路为空再生成假设文档重试 dense
                retry = await transform_query(
                    query, rewrite="off", hyde="always", skip_llm=skip_llm, empty_hits=True,
                )
                if retry.get("hyde_text"):
                    try:
                        hyde_emb = await embedder.embed(retry["hyde_text"], type_="query")
                    except Exception:
                        hyde_emb = None
                    if hyde_emb:
                        result = await self._hybrid_search(
                            session, query=query, transform=retry,
                            query_embedding=hyde_emb, threat_type=threat_type,
                            severity=severity, source=source,
                            top_k=max(top_k, prefetch), min_score=min_score,
                        )
                        result.transform = retry
        elif query_embedding:
            result = await self._vector_search(
                session, query_embedding, threat_type, severity, source,
                top_k, min_score, query,
            )
            result.transform = transform
        elif query or threat_type or severity or source:
            result = await self._filter_search(
                session, query, threat_type, severity, source, top_k,
            )
            result.transform = transform

        result = await self._drop_unapproved(session, result)

        if do_rerank and query and len(result.chunks) > 2:
            try:
                from rag.reranker import rerank_chunks
                n = min(int(getattr(settings, "rag_rerank_top_n", 20) or 20), len(result.chunks))
                ranked, backend = await rerank_chunks(
                    query, result.chunks[:n], top_k=top_k, skip_llm=skip_llm,
                )
                result.chunks = ranked
                result.rerank_backend = backend
                if backend == "cross_encoder" and result.strategy_used in ("rrf", "hybrid", ""):
                    result.strategy_used = "rrf_rerank"
            except Exception as e:
                logger.warning(f"rerank skipped: {e}")
                result.chunks = result.chunks[:top_k]
                result.rerank_backend = "none"
        else:
            result.chunks = result.chunks[:top_k]
            result.rerank_backend = result.rerank_backend or "none"
        result.total_found = len(result.chunks)
        return result

    async def _hydrate_chunks(
        self, session: AsyncSession, hits: list[dict],
    ) -> list[dict]:
        from models import KnowledgeChunk
        chunk_ids = [h.get("chunk_id") for h in hits if h.get("chunk_id")]
        if not chunk_ids:
            return []
        rows = (await session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.chunk_id.in_(chunk_ids))
        )).scalars().all()
        row_map = {r.chunk_id: r for r in rows}
        out = []
        for h in hits:
            cid = h.get("chunk_id")
            r = row_map.get(cid)
            pl = h.get("payload") or {}
            out.append({
                "id": r.id if r else 0,
                "doc_id": h.get("doc_id") or (r.doc_id if r else 0),
                "chunk_id": cid or (r.chunk_id if r else ""),
                "content": (r.content if r else pl.get("content", "") or "")[:1500],
                "title": (r.title if r else pl.get("title", "")),
                "source": (r.source if r else pl.get("source", "")),
                "threat_types": list(r.threat_types or []) if r else list(pl.get("threat_types") or []),
                "severity": (r.severity if r else pl.get("severity", "")),
                "tags": list(r.tags or []) if r else list(pl.get("tags") or []),
                "score": h.get("score", 0.0),
                "rrf_score": h.get("rrf_score") if h.get("rrf_score") is not None else h.get("score"),
                "dense_rank": h.get("dense_rank"),
                "bm25_rank": h.get("bm25_rank"),
                "strategy": h.get("strategy") or "rrf",
            })
        return out

    async def _inject_exact_terms(
        self, session: AsyncSession, query: str, chunks: list[dict],
        threat_type: str, severity: str, source: str, top_k: int,
    ) -> list[dict]:
        """把 CVE/T-ID 等精确命中插到候选最前，避免 Qdrant dense 短路丢掉词法结果。"""
        exact = await self._exact_term_search(
            session, query, threat_type, severity, source, top_k,
        )
        if not exact.chunks:
            return chunks
        seen: set[str] = set()
        merged: list[dict] = []

        def _key(c: dict) -> str:
            return str(c.get("chunk_id") or c.get("id") or "")

        for c in exact.chunks:
            k = _key(c)
            if not k or k in seen:
                continue
            seen.add(k)
            item = dict(c)
            item.setdefault("strategy", "bm25")
            merged.append(item)
        for c in chunks:
            k = _key(c)
            if k and k in seen:
                continue
            if k:
                seen.add(k)
            merged.append(c)
        return merged[: max(top_k, len(chunks))]

    async def _exact_term_search(
        self, session: AsyncSession,
        query: str, threat_type: str, severity: str, source: str, top_k: int,
    ) -> RetrievalResult:
        from models import KnowledgeChunk
        from rag.lexical import lexical_needles

        needles = lexical_needles(query)
        if not needles:
            return RetrievalResult(strategy_used="bm25")
        ors = []
        for i, n in enumerate(needles):
            pat = f"%{n}%"
            ors.append(KnowledgeChunk.content.ilike(pat))
            ors.append(KnowledgeChunk.title.ilike(pat))
            ors.append(KnowledgeChunk.search_lex.ilike(pat))
        conditions = [or_(*ors)]
        if threat_type:
            conditions.append(
                text("threat_types @> CAST(:threat_type AS jsonb)").bindparams(
                    threat_type=json.dumps([threat_type])
                )
            )
        if severity:
            conditions.append(KnowledgeChunk.severity == severity)
        if source:
            conditions.append(KnowledgeChunk.source == source)
        stmt = select(KnowledgeChunk).where(and_(*conditions)).limit(top_k)
        try:
            rows = (await session.execute(stmt)).scalars().all()
        except Exception as e:
            logger.debug(f"exact-term search failed: {e}")
            return RetrievalResult(strategy_used="bm25")
        chunks = []
        for i, r in enumerate(rows):
            blob = f"{r.title or ''} {r.content or ''}".lower()
            hit = sum(1 for n in needles if n.lower() in blob)
            chunks.append({
                "id": r.id, "doc_id": r.doc_id, "chunk_id": r.chunk_id or "",
                "content": (r.content or "")[:1500], "title": r.title or "",
                "source": r.source or "", "threat_types": r.threat_types or [],
                "severity": r.severity or "", "tags": r.tags or [],
                "score": 1.0 if any(n.lower() in blob for n in needles) else 0.5,
                "bm25_rank": i + 1,
                "strategy": "bm25",
                "exact_hits": hit,
            })
        chunks.sort(key=lambda c: (-int(c.get("exact_hits") or 0), c.get("title") or ""))
        return RetrievalResult(chunks=chunks, total_found=len(chunks), strategy_used="bm25")

    async def _hybrid_search(
        self, session: AsyncSession, *,
        query: str, transform: dict,
        query_embedding: Optional[list[float]],
        threat_type: str, severity: str, source: str,
        top_k: int, min_score: float,
    ) -> RetrievalResult:
        from rag.lexical import encode_sparse, rrf_fuse
        from qdrant_store import qdrant_store, hybrid_enabled

        lexical_q = transform.get("lexical_query") or query
        backend = getattr(settings, "rag_bm25_backend", "builtin")
        si, sv = encode_sparse(lexical_q, backend=backend) if lexical_q else ([], [])

        qhits: list[dict] = []
        if hybrid_enabled() and query_embedding:
            try:
                await qdrant_store.ensure_collection()
                qhits = await qdrant_store.query_hybrid(
                    [float(x) for x in query_embedding],
                    si, sv,
                    top_k=top_k,
                    prefetch=int(getattr(settings, "rag_prefetch", 20) or 20),
                    threat_type=threat_type,
                    severity=severity,
                    source=source,
                    min_score=0.0,
                )
            except Exception as e:
                logger.warning(f"[hybrid] Qdrant RRF 失败: {e}")

        if qhits:
            chunks = await self._hydrate_chunks(session, qhits)
            if chunks:
                # Qdrant 命中不能短路：精确 CVE/T-ID 必须并入候选，否则纯 dense 邻居会淹没词法命中
                chunks = await self._inject_exact_terms(
                    session, query, chunks, threat_type, severity, source, top_k,
                )
                logger.info(f"Hybrid RRF (Qdrant): {len(chunks)} chunks query='{(query or '')[:30]}'")
                return RetrievalResult(chunks=chunks, total_found=len(chunks), strategy_used="rrf")

        # PG / 进程内融合兜底
        dense_res = RetrievalResult()
        if query_embedding:
            dense_res = await self._vector_search(
                session, query_embedding, threat_type, severity, source,
                top_k, min_score if min_score else 0.0, query,
            )
        lex_res = await self._lexical_search(
            session, lexical_q, threat_type, severity, source, top_k,
        )
        def _id(c):
            return str(c.get("chunk_id") or c.get("id") or "")
        fused = rrf_fuse(
            {
                "dense": [_id(c) for c in dense_res.chunks],
                "bm25": [_id(c) for c in lex_res.chunks],
            },
            k=int(getattr(settings, "rag_rrf_k", 60) or 60),
        )
        by_id = {}
        for c in dense_res.chunks + lex_res.chunks:
            by_id.setdefault(_id(c), c)
        chunks = []
        for row in fused[:top_k]:
            c = by_id.get(row["id"])
            if not c:
                continue
            item = dict(c)
            item["rrf_score"] = row["rrf_score"]
            item["dense_rank"] = row["ranks"].get("dense")
            item["bm25_rank"] = row["ranks"].get("bm25")
            item["score"] = row["rrf_score"]
            item["strategy"] = "rrf"
            chunks.append(item)
        if not chunks:
            exact_only = await self._inject_exact_terms(
                session, query, [], threat_type, severity, source, top_k,
            )
            if exact_only:
                return RetrievalResult(chunks=exact_only, total_found=len(exact_only), strategy_used="bm25")
            return await self._filter_search(
                session, query, threat_type, severity, source, top_k,
            )
        chunks = await self._inject_exact_terms(
            session, query, chunks, threat_type, severity, source, top_k,
        )
        logger.info(f"Hybrid RRF (in-process): {len(chunks)} chunks")
        return RetrievalResult(chunks=chunks, total_found=len(chunks), strategy_used="rrf")

    async def _lexical_search(
        self, session: AsyncSession,
        query: str, threat_type: str, severity: str, source: str, top_k: int,
    ) -> RetrievalResult:
        """Postgres ts_rank；sqlite / 无 tsv 时用 search_lex + 词法重叠。"""
        from models import KnowledgeChunk
        from rag.lexical import lexical_overlap_rank

        if not query and not threat_type and not severity and not source:
            return RetrievalResult(strategy_used="bm25")

        is_pg = str(getattr(settings, "database_url", "") or "").startswith("postgresql")
        if is_pg and query:
            try:
                clauses = ["search_tsv @@ plainto_tsquery('simple', :q)"]
                params: dict = {"q": query, "limit": top_k}
                if threat_type:
                    clauses.append("threat_types @> CAST(:threat_type AS jsonb)")
                    params["threat_type"] = json.dumps([threat_type])
                if severity:
                    clauses.append("severity = :severity")
                    params["severity"] = severity
                if source:
                    clauses.append("source = :source")
                    params["source"] = source
                sql = text(f"""
                    SELECT id, doc_id, chunk_id, content, title, source,
                           threat_types, severity, tags,
                           ts_rank(search_tsv, plainto_tsquery('simple', :q)) AS rank
                    FROM knowledge_chunks
                    WHERE {' AND '.join(clauses)}
                    ORDER BY rank DESC
                    LIMIT :limit
                """)
                rows = (await session.execute(sql, params)).all()
                chunks = []
                for i, row in enumerate(rows):
                    chunks.append({
                        "id": row[0], "doc_id": row[1], "chunk_id": row[2] or "",
                        "content": (row[3] or "")[:1500], "title": row[4] or "",
                        "source": row[5] or "", "threat_types": row[6] or [],
                        "severity": row[7] or "", "tags": row[8] or [],
                        "score": round(float(row[9] or 0), 4),
                        "bm25_rank": i + 1,
                        "strategy": "bm25",
                    })
                return RetrievalResult(chunks=chunks, total_found=len(chunks), strategy_used="bm25")
            except Exception as e:
                logger.debug(f"ts_rank 不可用, 词法重叠降级: {e}")

        conditions = []
        if threat_type:
            conditions.append(
                text("threat_types @> CAST(:threat_type AS jsonb)").bindparams(
                    threat_type=json.dumps([threat_type])
                )
            )
        if severity:
            conditions.append(KnowledgeChunk.severity == severity)
        if source:
            conditions.append(KnowledgeChunk.source == source)
        stmt = select(KnowledgeChunk)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.limit(max(top_k * 8, 40))
        rows = (await session.execute(stmt)).scalars().all()
        scored = []
        for r in rows:
            blob = f"{r.title or ''} {r.content or ''} {getattr(r, 'search_lex', '') or ''}"
            score = lexical_overlap_rank(query, blob) if query else 1.0
            if query and score <= 0:
                continue
            scored.append((score, r))
        scored.sort(key=lambda x: -x[0])
        chunks = []
        for i, (score, r) in enumerate(scored[:top_k]):
            chunks.append({
                "id": r.id, "doc_id": r.doc_id, "chunk_id": r.chunk_id or "",
                "content": (r.content or "")[:1500], "title": r.title or "",
                "source": r.source or "", "threat_types": r.threat_types or [],
                "severity": r.severity or "", "tags": r.tags or [],
                "score": score, "bm25_rank": i + 1, "strategy": "bm25",
            })
        return RetrievalResult(chunks=chunks, total_found=len(chunks), strategy_used="bm25")

    async def _drop_unapproved(self, session: AsyncSession, result: RetrievalResult) -> RetrievalResult:
        """未审批 / 已拒绝的内部文档不得进入检索（防 RAG 投毒）。"""
        if not result.chunks:
            return result
        from models import KnowledgeDoc
        from memory_guard import kb_is_retrievable

        doc_ids = {c.get("doc_id") for c in result.chunks if c.get("doc_id")}
        if not doc_ids:
            return result
        rows = (await session.execute(
            select(
                KnowledgeDoc.id,
                KnowledgeDoc.approval_status,
                KnowledgeDoc.valid_until,
            ).where(KnowledgeDoc.id.in_(doc_ids))
        )).all()
        from ops_loop import kb_chunk_is_fresh
        allowed = {did for did, st, _vu in rows if kb_is_retrievable(st or "")}
        freshness = {did: vu for did, _st, vu in rows}
        status_map = {did: st for did, st, _vu in rows}
        kept = []
        for c in result.chunks:
            did = c.get("doc_id")
            if did not in allowed:
                continue
            vu = freshness.get(did)
            if vu is not None:
                c = dict(c)
                c["valid_until"] = vu.isoformat() if hasattr(vu, "isoformat") else vu
            if not kb_chunk_is_fresh(c):
                continue
            kept.append(c)
        result.chunks = kept
        result.total_found = len(kept)
        return result

    async def _vector_search(
        self, session: AsyncSession, embedding: list[float],
        threat_type: str, severity: str, source: str,
        top_k: int, min_score: float, query: str,
    ) -> RetrievalResult:
        """向量相似度检索 (现优先走 Qdrant, 不可用时回退 pgvector)"""
        from models import KnowledgeChunk

        # ── 优先: Qdrant 向量检索 + payload 过滤 ──
        # qdrant 不可用/无结果时走下方 pgvector 兜底
        try:
            from qdrant_store import qdrant_store
            if settings.qdrant_enabled and settings.qdrant_url:
                qhits = await qdrant_store.search(
                    query_vector=[float(x) for x in embedding],
                    top_k=top_k,
                    min_score=min_score,
                    threat_type=threat_type,
                    severity=severity,
                    source=source,
                )
                if qhits:
                    # 用 chunk_id 回查 pg 拿完整 chunk 元数据
                    chunk_ids = [h["chunk_id"] for h in qhits if h.get("chunk_id")]
                    by_id = {h["chunk_id"]: h for h in qhits}
                    qchunks = []
                    if chunk_ids:
                        from sqlalchemy import select as _sel
                        rows = (await session.execute(
                            _sel(KnowledgeChunk).where(KnowledgeChunk.chunk_id.in_(chunk_ids))
                        )).scalars().all()
                        row_map = {r.chunk_id: r for r in rows}
                        for cid in chunk_ids:
                            r = row_map.get(cid)
                            h = by_id.get(cid, {})
                            qchunks.append({
                                "id": r.id if r else 0,
                                "doc_id": h.get("doc_id") or (r.doc_id if r else 0),
                                "chunk_id": cid,
                                "content": (r.content if r else (h.get("payload") or {}).get("content", ""))[:1500],
                                "title": (r.title if r else (h.get("payload") or {}).get("title", "")),
                                "source": (r.source if r else (h.get("payload") or {}).get("source", "")),
                                "threat_types": list(r.threat_types or []) if r else list((h.get("payload") or {}).get("threat_types", []) or []),
                                "severity": (r.severity if r else (h.get("payload") or {}).get("severity", "")),
                                "tags": list(r.tags or []) if r else list((h.get("payload") or {}).get("tags", []) or []),
                                "score": h.get("score", 0.0),
                                "strategy": "vector",
                            })
                    if qchunks:
                        logger.info(f"Vector search (Qdrant): {len(qchunks)} chunks (query='{query[:30]}', threat_type={threat_type})")
                        return RetrievalResult(
                            chunks=qchunks,
                            total_found=len(qchunks),
                            strategy_used="vector",
                        )
        except Exception as qe:
            logger.warning(f"[Qdrant] 检索降级 pgvector: {qe}")

        # ── 兜底: pgvector 向量检索 ──
        distance_expr = KnowledgeChunk.embedding.cosine_distance(embedding)
        stmt = select(
            KnowledgeChunk,
            distance_expr.label("distance"),
        ).order_by(distance_expr)

        # pgvector 原生距离算子 `<=>` 做数据库端排序（最高性能）
        from models import KnowledgeChunk
        from sqlalchemy import text as sa_text, bindparam

        # 构造过滤条件
        filter_clauses = ["TRUE"]
        bind_params: dict = {}
        if threat_type:
            filter_clauses.append("threat_types @> CAST(:threat_type AS jsonb)")
            bind_params["threat_type"] = json.dumps([threat_type])
        if severity:
            filter_clauses.append("severity = :severity")
            bind_params["severity"] = severity
        if source:
            filter_clauses.append("source = :source")
            bind_params["source"] = source

        where_sql = " AND ".join(filter_clauses)
        limit = top_k * 2

        # 用 pgvector 的 <=> 算子做数据库端排序（参数化查询）
        vec_str = "[" + ",".join(f"{v:.6f}" for v in embedding) + "]"
        bind_params["vec"] = vec_str
        bind_params["limit"] = limit

        sql = sa_text(f"""
            SELECT id, doc_id, content, title, source,
                   threat_types, severity, tags, chunk_id,
                   (embedding <=> CAST(:vec AS vector)) AS distance
            FROM knowledge_chunks
            WHERE {where_sql}
              AND embedding IS NOT NULL
              AND vector_dims(embedding) = :vdim_guard
            ORDER BY distance ASC
            LIMIT :limit
        """)
        bind_params["vdim_guard"] = len(embedding)

        try:
            result2 = await session.execute(sql, bind_params)
            rows = result2.all()
        except Exception as e:
            logger.warning(f"pgvector query failed: {e}")
            rows = []

        chunks = []
        for row in rows:
            distance = float(row[-1])  # last column = distance
            score = 1.0 - distance
            if score < min_score:
                continue
            chunks.append({
                "id": row[0],
                "doc_id": row[1],
                "content": (row[2] or "")[:1500],
                "title": row[3] or "",
                "source": row[4] or "",
                "threat_types": row[5] or [],
                "severity": row[6] or "",
                "tags": row[7] or [],
                "chunk_id": row[8] or "",
                "score": round(score, 4),
                "strategy": "vector",
            })

        logger.info(f"Vector search: {len(chunks)} chunks from {len(rows)} candidates (query='{query[:30]}', threat_type={threat_type})")

        return RetrievalResult(
            chunks=chunks,
            total_found=len(chunks),
            strategy_used="vector",
        )

    async def _filter_search(
        self, session: AsyncSession,
        query: str, threat_type: str, severity: str, source: str,
        top_k: int,
    ) -> RetrievalResult:
        """按条件过滤 + 文本模糊匹配"""
        from models import KnowledgeChunk

        conditions = []
        if query:
            conditions.append(KnowledgeChunk.content.ilike(f"%{query}%"))
        if threat_type:
            # jsonb 列必须用 @> 运算符（JSON.contains() 会生成不支持的 LIKE）
            conditions.append(
                text("threat_types @> CAST(:threat_type AS jsonb)").bindparams(
                    threat_type=json.dumps([threat_type])
                )
            )
        if severity:
            conditions.append(KnowledgeChunk.severity == severity)
        if source:
            conditions.append(KnowledgeChunk.source == source)

        stmt = select(KnowledgeChunk)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.limit(top_k)

        result = await session.execute(stmt)
        rows = result.scalars().all()

        chunks = [
            {
                "id": r.id,
                "doc_id": r.doc_id,
                "chunk_id": r.chunk_id or "",
                "content": r.content[:1500],
                "title": r.title,
                "source": r.source,
                "threat_types": r.threat_types,
                "severity": r.severity,
                "tags": r.tags,
                "score": 1.0,
                "strategy": "filter",
            }
            for r in rows
        ]

        return RetrievalResult(
            chunks=chunks,
            total_found=len(chunks),
            strategy_used="filter",
        )

    async def retrieve_for_threat(
        self,
        session: AsyncSession,
        threat_type: str,
        severity: str = "",
        src_ip: str = "",
        query: str = "",
        query_embedding: Optional[list[float]] = None,
        top_k: int = 3,
    ) -> RetrievalResult:
        """
        为威胁事件检索相关知识

        自动组合:
          - 按 threat_type 精确匹配
          - 按 severity 级别匹配
          - 向量语义检索（如提供）
        """
        # 先按 threat_type 精确过滤
        result1 = await self.retrieve(
            session,
            threat_type=threat_type,
            severity=severity if severity in ("critical", "high") else "",
            top_k=top_k,
        )

        # 再用向量补充检索
        if query_embedding:
            result2 = await self.retrieve(
                session,
                query_embedding=query_embedding,
                top_k=top_k,
                min_score=0.5,
            )
            # 合并去重
            seen_ids = {c["id"] for c in result1.chunks}
            for c in result2.chunks:
                if c["id"] not in seen_ids and len(result1.chunks) < top_k:
                    result1.chunks.append(c)
                    seen_ids.add(c["id"])

        # 如果还没有结果，用 severity 检索
        if not result1.chunks and severity:
            result1 = await self.retrieve(
                session,
                severity=severity,
                top_k=top_k,
            )

        return result1

    async def rerank(
        self,
        query: str,
        chunks: list[dict],
        top_k: int = 5,
    ) -> list[dict]:
        """
        LLM 重排：用 LLM 对检索结果按相关性重新排序

        比纯向量距离排序更准确，因为 LLM 能理解安全领域语义。
        仅在结果 > 2 条时调用，避免不必要的 LLM 开销。
        """
        if len(chunks) <= 2:
            return chunks[:top_k]

        from summary_compression import summary

        # 构建编号列表供 LLM 评分
        items_text = ""
        for i, c in enumerate(chunks):
            title = c.get("title", "")
            content_preview = c.get("content", "")[:200]
            items_text += f"[{i}] {title}\n{content_preview}\n\n"

        from prompts import render
        prompt = render("rag/rerank", query=query, items_text=items_text, top_k=top_k)

        try:
            from trace_hook import set_trace_context
            set_trace_context(operation="rerank")
            result = await summary.llm.chat([
                {"role": "system", "content": render("rag/rerank_system")},
                {"role": "user", "content": prompt},
            ])
            import json as _json
            order = _json.loads(result.strip())
            if isinstance(order, list) and order:
                reranked = []
                for idx in order[:top_k]:
                    if isinstance(idx, int) and 0 <= idx < len(chunks):
                        c = dict(chunks[idx])
                        c["reranked"] = True
                        reranked.append(c)
                if reranked:
                    logger.info(f"Reranked {len(reranked)} chunks for query '{query[:30]}'")
                    return reranked
        except Exception as e:
            logger.warning(f"Rerank failed, using original order: {e}")

        return chunks[:top_k]


retriever = Retriever()
