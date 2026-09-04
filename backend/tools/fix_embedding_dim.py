"""
清洗与配置不一致的 pgvector 向量，避免 768/1536 混存导致检索崩溃。

用法（在 backend 容器或已配置 DATABASE_URL 的环境）:
  python -m tools.fix_embedding_dim --dry-run
  python -m tools.fix_embedding_dim --apply
  python -m tools.fix_embedding_dim --apply --reembed-knowledge
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fix_embedding_dim")


async def _probe_and_null(session, table: str, expect_dim: int, apply: bool) -> dict:
    from sqlalchemy import text

    # pgvector: vector_dims(embedding)
    rows = (await session.execute(text(
        f"SELECT id, vector_dims(embedding) AS dim FROM {table} "
        f"WHERE embedding IS NOT NULL"
    ))).all()
    bad_ids = [r.id for r in rows if int(r.dim or 0) != expect_dim]
    dims = {}
    for r in rows:
        dims[int(r.dim or 0)] = dims.get(int(r.dim or 0), 0) + 1

    cleared = 0
    if apply and bad_ids:
        # 分批清空
        for i in range(0, len(bad_ids), 200):
            chunk = bad_ids[i:i + 200]
            await session.execute(
                text(f"UPDATE {table} SET embedding = NULL WHERE id = ANY(:ids)"),
                {"ids": chunk},
            )
            cleared += len(chunk)
        await session.commit()

    return {
        "table": table,
        "total_with_embedding": len(rows),
        "dim_histogram": dims,
        "bad_count": len(bad_ids),
        "cleared": cleared,
        "expect_dim": expect_dim,
    }


async def main(apply: bool, reembed_knowledge: bool) -> int:
    from config import settings
    from models import async_session, init_db

    expect = int(settings.embedding_dim)
    logger.info(f"expect embedding_dim={expect} apply={apply}")
    await init_db()

    reports = []
    async with async_session() as session:
        for table in ("memories", "knowledge_chunks"):
            try:
                reports.append(await _probe_and_null(session, table, expect, apply))
            except Exception as e:
                logger.error(f"{table}: {e}")
                reports.append({"table": table, "error": str(e)})

    for r in reports:
        logger.info(r)

    if apply:
        try:
            from qdrant_store import qdrant_store
            ok = await qdrant_store.ensure_collection()
            logger.info(f"qdrant ensure_collection -> {ok}")
        except Exception as e:
            logger.warning(f"qdrant ensure failed: {e}")

    if apply and reembed_knowledge:
        try:
            from rag.seeder import seed_knowledge_base
            from models import async_session as db_session
            async with db_session() as session:
                n = await seed_knowledge_base(session)
            logger.info(f"reseed knowledge -> {n}")
        except Exception as e:
            logger.warning(f"reembed/seed skipped: {e}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="实际清空不兼容向量")
    parser.add_argument("--dry-run", action="store_true", help="仅探测（默认）")
    parser.add_argument("--reembed-knowledge", action="store_true")
    args = parser.parse_args()
    apply = bool(args.apply)
    raise SystemExit(asyncio.run(main(apply=apply, reembed_knowledge=args.reembed_knowledge)))
