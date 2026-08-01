import logging
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from pgvector.sqlalchemy import Vector

from models import Memory
from config import settings

logger = logging.getLogger(__name__)

class VectorStore:
    def __init__(self):
        self.dim = settings.embedding_dim

    async def store_memory(
        self, session: AsyncSession, content: str, embedding: list[float],
        agent_id: str = "shared", metadata: Optional[dict] = None
    ) -> Memory:
        mem = Memory(
            agent_id=agent_id,
            content=content,
            embedding=embedding,
            metadata_=metadata or {},
        )
        session.add(mem)
        await session.commit()
        await session.refresh(mem)
        logger.info(f"Stored memory id={mem.id} agent={agent_id}")
        return mem

    async def search_similar(
        self, session: AsyncSession, query_embedding: list[float],
        agent_id: Optional[str] = None, top_k: int = 5,
        min_score: Optional[float] = None
    ) -> list[Memory]:
        if min_score is None:
            min_score = settings.vector_search_threshold
        vec = np.array(query_embedding, dtype=np.float32)
        stmt = select(Memory).order_by(Memory.embedding.cosine_distance(vec)).limit(top_k)
        if agent_id:
            stmt = stmt.where(Memory.agent_id == agent_id)
        result = await session.execute(stmt)
        rows = result.scalars().all()
        # cosine_distance ranges 0 (identical) to 2 (opposite).
        # Filter out results below the similarity threshold.
        def cosine_sim(a, b):
            a_norm = np.linalg.norm(a)
            b_norm = np.linalg.norm(b)
            if a_norm == 0 or b_norm == 0:
                return 0.0
            return float(np.dot(a, b) / (a_norm * b_norm))
        filtered = [r for r in rows if r.embedding is not None and
                    cosine_sim(np.array(r.embedding, dtype=np.float32), vec) > min_score]
        logger.info(f"Vector search found {len(rows)} raw, {len(filtered)} after threshold={min_score}")
        return filtered if filtered else rows[:1]

    async def delete_memory(self, session: AsyncSession, memory_id: int) -> bool:
        mem = await session.get(Memory, memory_id)
        if mem:
            await session.delete(mem)
            await session.commit()
            return True
        return False

vector_store = VectorStore()
