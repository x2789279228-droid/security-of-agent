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
    strategy_used: str = ""  # "vector" | "filter" | "hybrid"


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
    ) -> RetrievalResult:
        """
        混合检索

        Args:
            query: 文本查询
            query_embedding: 向量查询（预计算）
            threat_type: 威胁类型过滤
            severity: 严重度过滤
            source: 来源过滤
            top_k: 返回条数
            min_score: 最低相似度

        Returns:
            RetrievalResult
        """
        from models import KnowledgeChunk

        # 策略 1: 向量检索
        if query_embedding:
            result = await self._vector_search(
                session, query_embedding, threat_type, severity, source,
                top_k, min_score, query,
            )
            return await self._drop_unapproved(session, result)

        # 策略 2: 文本查询 + 过滤
        if query or threat_type or severity or source:
            result = await self._filter_search(
                session, query, threat_type, severity, source, top_k,
            )
            return await self._drop_unapproved(session, result)

        return RetrievalResult()

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
                   threat_types, severity, tags,
                   (embedding <=> CAST(:vec AS vector)) AS distance
            FROM knowledge_chunks
            WHERE {where_sql}
              AND embedding IS NOT NULL
            ORDER BY distance ASC
            LIMIT :limit
        """)

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
