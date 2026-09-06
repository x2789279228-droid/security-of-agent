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


        # batch embeddings: 1 HTTP per up-to-100 texts (embed_many chunks internally by EMBED_BATCH_SIZE)
        import os as _os
        bs = max(1, int(_os.environ.get("EMBED_BATCH_SIZE", "100") or "100"))
        fixed = 0
        for i in range(0, len(bad), bs):
            group = bad[i:i+bs]
            vecs = await embedder.embed_many([ (c.content or " ")[:2000] for c in group ])
            for c, vec in zip(group, vecs):
                if vec and len(vec) >= 100:
                    c.embedding = vec
                    fixed += 1
                elif vec:
                    log.warning(f"chunk#{c.id} embed failed dim={len(vec) if vec else 0}")
        await session.commit()
        log.info(f"fixed={fixed}")


if __name__ == "__main__":
    asyncio.run(fix())
