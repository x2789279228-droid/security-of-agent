"""
回填 Qdrant hybrid collection（dense named + BM25 sparse）。

用法（backend 目录）:
  python migrate_qdrant_hybrid.py

会:
  1. ensure soc_knowledge_chunks_v2
  2. 读 knowledge_chunks，编码 sparse，upsert 双写
不删除旧 dense collection，可用 rag_hybrid_enabled=false 回滚。
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migrate_qdrant_hybrid")


async def main():
    from config import settings
    from models import KnowledgeChunk, async_session, init_db
    from qdrant_store import qdrant_store, hybrid_collection_name
    from rag.lexical import encode_sparse, build_search_lex
    from sqlalchemy import select

    await init_db()
    await qdrant_store.ensure_collection()
    logger.info("hybrid collection=%s", hybrid_collection_name())

    backend = getattr(settings, "rag_bm25_backend", "builtin")
    batch = []
    total = 0
    async with async_session() as session:
        rows = (await session.execute(select(KnowledgeChunk))).scalars().all()
        for r in rows:
            lex = r.search_lex or build_search_lex(r.title or "", r.content or "", r.threat_types)
            if not r.search_lex:
                r.search_lex = lex
            si, sv = encode_sparse(f"{r.title or ''} {r.content or ''} {lex}", backend=backend)
            vec = list(r.embedding) if r.embedding is not None else None
            if not vec:
                continue
            batch.append({
                "chunk_id": r.chunk_id,
                "doc_id": r.doc_id,
                "vector": [float(x) for x in vec],
                "sparse_indices": si,
                "sparse_values": sv,
                "payload": {
                    "content": (r.content or "")[:1500],
                    "title": r.title or "",
                    "threat_types": list(r.threat_types or []),
                    "severity": r.severity or "",
                    "source": r.source or "",
                    "tags": list(r.tags or []),
                },
            })
            if len(batch) >= 64:
                await qdrant_store.upsert_chunks_batch(batch)
                total += len(batch)
                logger.info("upserted %s", total)
                batch = []
        await session.commit()
    if batch:
        await qdrant_store.upsert_chunks_batch(batch)
        total += len(batch)
    logger.info("done, upserted %s chunks", total)


if __name__ == "__main__":
    asyncio.run(main())
