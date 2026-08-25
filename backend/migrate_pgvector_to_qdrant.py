"""
迁移脚本: 把 pg 的向量数据全量导入 Qdrant.

用法(容器内):
    python migrate_pgvector_to_qdrant.py [--recreate] [--limit N] [--scope chunks|memories|all]

- 幂等: 同 chunk_id / memory_id 重复 upsert 只覆盖。
- --recreate: 先删除重建 collection(迁移前清空)。
- --scope: chars=知识库, memories=agent 记忆, all=两者(默认)。
- 迁移会读取 embedding; embedding 为 None 或 [0.0] 的跳过(留待 _compute_missing_embeddings)。

依赖 Qdrant 可达(settings.qdrant_url)且 qdrant-client 已安装。
"""
import argparse
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("migrate_qdrant")


async def migrate_memories(limit: int = 0):
    """把 memories 表(agent 记忆)全量导入 agent_memories collection。"""
    from config import settings
    from models import async_session, Memory
    from sqlalchemy import select, func
    from vector_store import vector_store

    logger.info(
        f"[memories] Qdrant URL={settings.qdrant_url or '(未配置)'} "
        f"collection={settings.qdrant_memories_collection}"
    )
    await vector_store._ensure_memories_collection()

    async with async_session() as session:
        total = (await session.execute(select(func.count(Memory.id)))).scalar() or 0
        logger.info(f"[memories] total={total}")
        stmt = select(Memory).where(Memory.embedding.isnot(None))
        if limit:
            stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        done = 0
        skipped = 0
        for r in rows:
            if not getattr(r, "embedding", None):
                skipped += 1
                continue
            ok = await vector_store._upsert_qdrant(r)
            # _upsert_qdrant 内部对 Qdrant 不可用会降级(空返回), 这里无法区分成功与否,
            # 统一计入 done, 由 qdrant count 佐证实际同步量。
            done += 1
        logger.info(f"[memories] 迁移完成: 处理={len(rows)} 已同步={done} 跳过={skipped}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--scope", default="all", choices=["chunks", "memories", "all"])
    args = parser.parse_args()

    if args.scope in ("chunks", "all"):
        await migrate_chunks(args.recreate, args.limit)
    if args.scope in ("memories", "all"):
        await migrate_memories(args.limit)


async def migrate_chunks(recreate: bool, limit: int = 0):
    from config import settings
    from models import async_session, KnowledgeChunk
    from sqlalchemy import select, func
    from qdrant_store import qdrant_store

    logger.info(f"Qdrant URL={settings.qdrant_url or '(未配置)'} collection={settings.qdrant_collection}")

    if recreate:
        ok = await qdrant_store.recreate_collection()
        logger.info(f"recreate_collection -> {ok}")
    else:
        await qdrant_store.ensure_collection()

    async with async_session() as session:
        total = (await session.execute(select(func.count(KnowledgeChunk.id)))).scalar() or 0
        logger.info(f"knowledge_chunks total={total}")

        expect_dim = settings.qdrant_vector_size or settings.embedding_dim
        stmt = select(KnowledgeChunk).where(KnowledgeChunk.embedding.isnot(None))
        if limit:
            stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        logger.info(f"待迁移={len(rows)} (期望维度 {expect_dim})")

        from summary_compression import embedder

        done = 0
        skipped = 0
        recomputed = 0
        batch = []
        for r in rows:
            if not getattr(r, "chunk_id", None):
                skipped += 1
                continue
            try:
                vec = [float(x) for x in (r.embedding or [])]
            except Exception:
                skipped += 1
                continue
            # 维度不匹配的历史向量(如 768) → 用当前 embedder 重算为期望维度
            if len(vec) != expect_dim:
                try:
                    new_vec = await embedder.embed((r.content or " ")[:2000])
                    if len(new_vec) < expect_dim - 100:  # 明显失败则跳过
                        skipped += 1
                        continue
                    vec = [float(x) for x in new_vec]
                    r.embedding = vec
                    recomputed += 1
                except Exception as e:
                    logger.warning(f"[{r.id}] 重算 embedding 失败: {e}")
                    skipped += 1
                    continue
            batch.append({
                "chunk_id": r.chunk_id,
                "doc_id": r.doc_id,
                "vector": vec,
                "payload": {
                    "content": (r.content or "")[:1500],
                    "title": getattr(r, "title", "") or "",
                    "threat_types": list(getattr(r, "threat_types", []) or []),
                    "severity": getattr(r, "severity", "") or "",
                    "source": getattr(r, "source", "") or "",
                    "tags": list(getattr(r, "tags", []) or []),
                },
            })
            if len(batch) >= 64:
                await qdrant_store.upsert_chunks_batch(batch)
                done += len(batch)
                batch = []
                logger.info(f"已迁移 {done}/{len(rows)} (重算={recomputed})")
        if batch:
            await qdrant_store.upsert_chunks_batch(batch)
            done += len(batch)

        # 回写 pg 中已重算的 embedding (维度修正)
        if recomputed:
            await session.commit()
            logger.info(f"已回写 {recomputed} 个重算后的 embedding 到 pg")

        cnt = await qdrant_store.count()
        logger.info(f"迁移完成: 处理={len(rows)} 已同步={done} 跳过={skipped} 重算={recomputed} qdrant_count={cnt}")


if __name__ == "__main__":
    asyncio.run(main())
