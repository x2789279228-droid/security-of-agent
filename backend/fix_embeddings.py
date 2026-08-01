"""修复知识库中维度错误的 embedding（1 维 → 768 维）"""
import asyncio
import logging

from sqlalchemy import select

from models import KnowledgeChunk, async_session
from summary_compression import embedder

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fix-embeddings")

CONCURRENCY = 8


async def fix():
    async with async_session() as session:
        rows = (await session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.embedding.isnot(None))
        )).scalars().all()
        bad = [r for r in rows if len(r.embedding) < 768]
        log.info(f"total={len(rows)} bad={len(bad)}")

        sem = asyncio.Semaphore(CONCURRENCY)

        async def work(chunk):
            async with sem:
                vec = await embedder.embed(chunk.content[:2000] or " ")
                if len(vec) < 100:
                    log.warning(f"chunk#{chunk.id} embed failed dim={len(vec)}")
                    return 0
                chunk.embedding = vec
                return 1

        done = await asyncio.gather(*[work(c) for c in bad])
        await session.commit()
        log.info(f"fixed={sum(done)}")


if __name__ == "__main__":
    asyncio.run(fix())
