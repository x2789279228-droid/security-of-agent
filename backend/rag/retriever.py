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

from sqlalchemy import Numeric, select, and_, or_, func as sql_func, text
from sqlalchemy.ext.asyncio import AsyncSession

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
        cve_id: str = "",
        cvss_min: Optional[float] = None,
        product: str = "",
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
            source: 来源过滤（支持逗号分隔多值，如 "cve,vulnerability"）
            cve_id: CVE-ID 精确过滤（metadata_->>'cve_id' = :x）
            cvss_min: 最低 CVSS 分值过滤（(metadata_->>'cvss_score')::numeric >= :x）
            product: 受影响产品过滤（metadata_->'products' ? :x）
            top_k: 返回条数
            min_score: 最低相似度

        Returns:
            RetrievalResult
        """
        from models import KnowledgeChunk

        # 策略 1: 向量检索
        if query_embedding:
            return await self._vector_search(
                session, query_embedding, threat_type, severity, source,
                top_k, min_score, query,
                cve_id=cve_id, cvss_min=cvss_min, product=product,
            )

        # 策略 2: 文本查询 + 过滤
        if query or threat_type or severity or source or cve_id or cvss_min or product:
            return await self._filter_search(
                session, query, threat_type, severity, source, top_k,
                cve_id=cve_id, cvss_min=cvss_min, product=product,
            )

        return RetrievalResult()

    async def retrieve_cve(
        self,
        session: AsyncSession,
        cve_id: str,
        top_k: int = 3,
    ) -> RetrievalResult:
        """按 CVE-ID 精确检索知识库（验证器 CVE 专项、速查用）"""
        return await self.retrieve(
            session, cve_id=cve_id.strip().upper(), top_k=top_k, min_score=0.0,
        )

    def _split_sources(self, source: str) -> list[str]:
        """逗号分隔的 source 参数 → 列表（空返回空列表）"""
        return [s.strip() for s in source.split(",") if s.strip()] if source else []

    async def _vector_search(
        self, session: AsyncSession, embedding: list[float],
        threat_type: str, severity: str, source: str,
        top_k: int, min_score: float, query: str,
        cve_id: str = "", cvss_min: Optional[float] = None, product: str = "",
    ) -> RetrievalResult:
        """向量相似度检索"""
        from models import KnowledgeChunk

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
            filter_clauses.append("c.threat_types @> CAST(:threat_type AS jsonb)")
            bind_params["threat_type"] = json.dumps([threat_type])
        if severity:
            filter_clauses.append("c.severity = :severity")
            bind_params["severity"] = severity
        sources = self._split_sources(source)
        if len(sources) == 1:
            filter_clauses.append("c.source = :source")
            bind_params["source"] = sources[0]
        elif len(sources) > 1:
            placeholders = ", ".join(f":src{i}" for i in range(len(sources)))
            filter_clauses.append(f"c.source IN ({placeholders})")
            for i, s in enumerate(sources):
                bind_params[f"src{i}"] = s
        if cve_id:
            # metadata 在 knowledge_docs 上，join 后走 d.metadata 过滤
            filter_clauses.append("d.metadata->>'cve_id' = :cve_id")
            bind_params["cve_id"] = cve_id.upper()
        if cvss_min is not None:
            filter_clauses.append("(d.metadata->>'cvss_score')::numeric >= :cvss_min")
            bind_params["cvss_min"] = float(cvss_min)
        if product:
            filter_clauses.append("d.metadata->'products' ? :product")
            bind_params["product"] = product

        where_sql = " AND ".join(filter_clauses)
        limit = top_k * 2

        # 用 pgvector 的 <=> 算子做数据库端排序
        # 向量格式: '[0.1,0.2,...]'::vector
        vec_str = "[" + ",".join(f"{v:.6f}" for v in embedding) + "]"
        vec_literal = f"'{vec_str}'::vector"

        sql = sa_text(f"""
            SELECT c.id, c.doc_id, c.content, c.title, c.source,
                   c.threat_types, c.severity, c.tags, d.metadata,
                   (c.embedding <=> {vec_literal}) AS distance
            FROM knowledge_chunks c
            JOIN knowledge_docs d ON d.id = c.doc_id
            WHERE c.embedding IS NOT NULL
              AND {where_sql}
            ORDER BY distance ASC
            LIMIT {limit}
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
                "metadata": row[8] if row[8] is not None else {},
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
        cve_id: str = "", cvss_min: Optional[float] = None, product: str = "",
    ) -> RetrievalResult:
        """按条件过滤 + 文本模糊匹配"""
        from models import KnowledgeChunk, KnowledgeDoc

        conditions = []
        if query:
            conditions.append(KnowledgeChunk.content.ilike(f"%{query}%"))
        if threat_type:
            # jsonb 列必须用 @> 运算符（JSON.contains() 会生成不支持的 LIKE）
            conditions.append(
                text("knowledge_chunks.threat_types @> CAST(:threat_type AS jsonb)").bindparams(
                    threat_type=json.dumps([threat_type])
                )
            )
        if severity:
            conditions.append(KnowledgeChunk.severity == severity)
        sources = self._split_sources(source)
        if sources:
            conditions.append(KnowledgeChunk.source.in_(sources))
        # cve_id / cvss_min / product 都存于 knowledge_docs.metadata（chunk 无 metadata 列），
        # 通过 doc_id 关联过滤并随结果带回 doc metadata
        if cve_id:
            conditions.append(KnowledgeDoc.metadata_["cve_id"].astext == cve_id.upper())
        if cvss_min is not None:
            conditions.append(
                KnowledgeDoc.metadata_["cvss_score"].astext.cast(Numeric) >= float(cvss_min)
            )
        if product:
            conditions.append(KnowledgeDoc.metadata_["products"].has_key(product))

        stmt = select(KnowledgeChunk, KnowledgeDoc.metadata_).join(
            KnowledgeDoc, KnowledgeDoc.id == KnowledgeChunk.doc_id
        )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.limit(top_k)

        result = await session.execute(stmt)
        rows = result.all()

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
                "metadata": meta if meta is not None else {},
                "score": 1.0,
                "strategy": "filter",
            }
            for r, meta in rows
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

        prompt = f"""你是安全知识检索专家。请对以下检索结果按与查询的相关性排序。

## 查询
{query}

## 检索结果
{items_text}

## 要求
输出与查询最相关的结果编号（从最相关到最不相关），JSON 数组格式:
[编号1, 编号2, ...]

只输出编号数组，不要其他内容。最多输出 {top_k} 个。"""

        try:
            from trace_hook import set_trace_context
            set_trace_context(operation="rerank")
            result = await summary.llm.chat([
                {"role": "system", "content": "输出 JSON 数组，只含编号。"},
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
