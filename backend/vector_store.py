import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pgvector.sqlalchemy import Vector

from models import Memory
from config import settings

logger = logging.getLogger(__name__)


def memory_point_id(memory_id: int) -> str:
    """由 memory 主键派生稳定 UUID point id (幂等 upsert/delete)。"""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"soc-agent-memory:{memory_id}"))


class VectorStore:
    """
    agent 记忆向量存储 — Qdrant 优先 + pgvector 兜底

    与 RAG 知识库 (qdrant_store.py) 同一套降级策略:
    - Qdrant 承担向量检索 (agent_memories collection, agent_id 作 payload 过滤)。
    - pg 的 memories 表仍是主数据 (保留 embedding 列, 兼容旧逻辑/兜底检索)。
    - Qdrant 不可用(未配置/连接失败/查询异常)时静默降级 pgvector, 保证链路不断。
    - 对外接口签名不变, 始终返回 list[Memory], 调用方无需改动。
    """

    def __init__(self):
        self.dim = settings.embedding_dim
        self._client = None
        self._client_lock = asyncio.Lock()

    # ── Qdrant 客户端 (懒加载 + 降级) ──

    async def _client_or_none(self):
        async with self._client_lock:
            if self._client is not None:
                return self._client
            if not settings.qdrant_enabled or not settings.qdrant_url:
                return None
            try:
                from qdrant_client import QdrantClient
                c = QdrantClient(url=settings.qdrant_url, timeout=settings.qdrant_timeout)
                c.get_collections()  # 连通性探测
                self._client = c
                return c
            except Exception as e:
                logger.warning(f"[Memory/Qdrant] 客户端初始化失败, 回退 pgvector: {e}")
                self._client = None
                return None

    async def _qcall(self, sync_fn, *args):
        """在线程池执行同步 qdrant 方法; 失败返回 None(降级)。"""
        client = await self._client_or_none()
        if client is None:
            return None
        try:
            return await asyncio.to_thread(sync_fn, client, *args)
        except Exception as e:
            logger.warning(f"[Memory/Qdrant] 调用失败(降级 pgvector): {e}")
            return None

    async def _ensure_memories_collection(self):
        from qdrant_client.http import models as m

        def _ensure(client):
            if not client.collection_exists(settings.qdrant_memories_collection):
                client.create_collection(
                    collection_name=settings.qdrant_memories_collection,
                    vectors_config=m.VectorParams(
                        size=settings.qdrant_vector_size or settings.embedding_dim,
                        distance=m.Distance.COSINE,
                    ),
                )
            return True

        return await self._qcall(_ensure)

    # ── 写入 ──

    async def store_memory(
        self, session: AsyncSession, content: str, embedding: list[float],
        agent_id: str = "shared", metadata: Optional[dict] = None,
        source_type: str = "agent_output",
        provenance_id: str = "",
        trust: Optional[float] = None,
        signed: bool = False,
    ) -> Memory:
        from memory_guard import content_hash, default_trust, sanitize_untrusted_text, looks_like_injection

        source_type = source_type or "agent_output"
        if trust is None:
            trust = default_trust(source_type)
        # 指令型内容强制降 trust，避免写入即投毒
        if looks_like_injection(content):
            trust = min(float(trust), 0.1)
            content = sanitize_untrusted_text(content, max_len=500)
        else:
            content = sanitize_untrusted_text(content, max_len=2000)

        meta = dict(metadata or {})
        digest = content_hash(content)
        meta.update({
            "source_type": source_type,
            "provenance_id": provenance_id,
            "content_hash": digest,
            "trust": float(trust),
            "signed": bool(signed),
        })
        mem = Memory(
            agent_id=agent_id,
            content=content,
            embedding=embedding,
            metadata_=meta,
            source_type=source_type,
            provenance_id=provenance_id,
            content_hash=digest,
            trust=float(trust),
            signed=bool(signed),
        )
        session.add(mem)
        await session.commit()
        await session.refresh(mem)
        await self._upsert_qdrant(mem)
        logger.info(
            f"Stored memory id={mem.id} agent={agent_id} "
            f"source={source_type} trust={trust:.2f}"
        )
        return mem

    async def _upsert_qdrant(self, mem: Memory):
        client = await self._client_or_none()
        if client is None:
            return
        await self._ensure_memories_collection()
        from qdrant_client.http import models as m

        def _upsert(c):
            c.upsert(
                collection_name=settings.qdrant_memories_collection,
                points=[m.PointStruct(
                    id=memory_point_id(mem.id),
                    vector=list(mem.embedding) if mem.embedding is not None else [],
                    payload={
                        "memory_id": mem.id,
                        "agent_id": mem.agent_id,
                        "content": mem.content[:2000],
                        "created_at": mem.created_at.isoformat() if mem.created_at else "",
                        "source_type": getattr(mem, "source_type", "") or "",
                        "trust": float(getattr(mem, "trust", 0.2) or 0.2),
                        "content_hash": getattr(mem, "content_hash", "") or "",
                    },
                )],
                wait=True,
            )
            return True

        await self._qcall(_upsert)

    # ── 检索 (Qdrant 优先 + pgvector 兜底, 返回 list[Memory]) ──

    async def search_similar(
        self, session: AsyncSession, query_embedding: list[float],
        agent_id: Optional[str] = None, top_k: int = 5,
        min_score: Optional[float] = None,
        min_trust: Optional[float] = None,
        for_llm: bool = False,
    ) -> list[Memory]:
        if min_score is None:
            min_score = settings.vector_search_threshold
        hits = await self._search_qdrant(query_embedding, agent_id, top_k, min_score)
        if hits is not None:
            memories = await self._load_memories_by_ids(session, hits)
            if memories:
                return self._apply_trust_filter(memories, min_trust, for_llm)
            if hits:
                logger.warning(
                    f"[Memory] Qdrant 命中 {len(hits)} 条但 pg 未取到, 回退 pgvector"
                )
        memories = await self._search_pgvector(session, query_embedding, agent_id, top_k, min_score)
        return self._apply_trust_filter(memories, min_trust, for_llm)

    @staticmethod
    def _apply_trust_filter(
        memories: list, min_trust: Optional[float], for_llm: bool,
    ) -> list:
        if for_llm:
            from memory_guard import filter_memories_for_llm, LLM_MIN_TRUST
            floor = LLM_MIN_TRUST if min_trust is None else min_trust
            return filter_memories_for_llm(memories, min_trust=floor)
        if min_trust is None:
            return memories
        from memory_guard import memory_trust_value
        return [m for m in memories if memory_trust_value(m) >= min_trust]

    async def _search_qdrant(
        self, query_embedding: list[float],
        agent_id: Optional[str], top_k: int, min_score: float,
    ):
        client = await self._client_or_none()
        if client is None:
            return None
        from qdrant_client.http import models as m
        await self._ensure_memories_collection()

        def _search(c):
            must = []
            if agent_id:
                must.append(m.FieldCondition(key="agent_id", match=m.MatchValue(value=agent_id)))
            qf = m.Filter(must=must) if must else None
            resp = c.query_points(
                collection_name=settings.qdrant_memories_collection,
                query=query_embedding,
                query_filter=qf,
                limit=top_k,
                score_threshold=min_score,
                with_payload=True,
                with_vectors=False,
            )
            return [p.payload.get("memory_id") for p in resp.points if p and p.payload]

        ids = await self._qcall(_search)
        return ids

    async def _load_memories_by_ids(self, session: AsyncSession, ids: list) -> list[Memory]:
        if not ids:
            return []
        stmt = select(Memory).where(Memory.id.in_(ids))
        result = await session.execute(stmt)
        rows = {m.id: m for m in result.scalars().all()}
        # 按 Qdrant 返回的相似度顺序返回(过滤掉 pg 中已删除的)
        return [rows[i] for i in ids if i in rows]

    async def _search_pgvector(
        self, session: AsyncSession, query_embedding: list[float],
        agent_id: Optional[str], top_k: int, min_score: float,
    ) -> list[Memory]:
        vec = np.array(query_embedding, dtype=np.float32)
        stmt = select(Memory).order_by(Memory.embedding.cosine_distance(vec)).limit(top_k)
        if agent_id:
            stmt = stmt.where(Memory.agent_id == agent_id)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        def cosine_sim(a, b):
            a_norm = np.linalg.norm(a)
            b_norm = np.linalg.norm(b)
            if a_norm == 0 or b_norm == 0:
                return 0.0
            return float(np.dot(a, b) / (a_norm * b_norm))

        filtered = [r for r in rows if r.embedding is not None and
                    cosine_sim(np.array(r.embedding, dtype=np.float32), vec) > min_score]
        logger.info(f"[Memory] pgvector search found {len(rows)} raw, {len(filtered)} after threshold={min_score}")
        return filtered if filtered else rows[:1]

    # ── 删除 ──

    async def delete_memory(self, session: AsyncSession, memory_id: int) -> bool:
        mem = await session.get(Memory, memory_id)
        if mem:
            await session.delete(mem)
            await session.commit()
            # Qdrant 同步删除, 失败静默降级
            await self._delete_qdrant(memory_id)
            return True
        return False

    async def _delete_qdrant(self, memory_id: int):
        def _del(c):
            from qdrant_client.http import models as m
            c.delete(
                collection_name=settings.qdrant_memories_collection,
                points_selector=m.PointIdsList(points=[memory_point_id(memory_id)]),
            )
            return True

        await self._qcall(_del)


vector_store = VectorStore()
