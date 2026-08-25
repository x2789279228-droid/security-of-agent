"""
Qdrant 向量数据库读写模块 — RAG 知识库 (knowledge_chunks) 的向量检索后端

设计目标: 在不改动 pg 主数据的前提下列入 Qdrant 作为向量的「检索事实源」。
- 双写过渡: pg 的 embedding 列仍写入(兼容旧逻辑)，Qdrant 承担向量检索。
- 幂等: point id = uuid5(NamespaceDNS, chunk_id)，同 chunk_id 重复 upsert 只覆盖不重复。
- 过滤: payload 冗余存 threat_types / severity / source，检索时用 payload filter 一体化过滤,
        替代 pg 手写 JSON( @> )+ <=> 原生 SQL。
- 降级: Qdrant 不可用(未配置/连接失败)时返回 None, 由调用方回退 pgvector。

依赖: qdrant-client>=1.9,<2 (同步 QdrantClient 包一层 asyncio.to_thread, 规避异步 client 版本差异)
"""
import asyncio
import logging
import uuid
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


def chunk_point_id(chunk_id: str) -> str:
    """由 chunk_id 派生稳定 UUID point id (幂等 upsert/delete)"""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"soc-knowledge-chunk:{chunk_id}"))


class QdrantStore:
    """Qdrant 向量库封装。所有公共方法均为 async; Qdrant 不可用时静默降级(返回 None/空)。"""

    def __init__(self):
        self._client = None
        self._client_lock = asyncio.Lock()

    # ── 客户端 ──

    async def _client_or_none(self):
        """返回同步 QdrantClient; 未启用/连接失败返回 None(降级)。"""
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
                logger.warning(f"[Qdrant] 客户端初始化失败, 回退 pgvector: {e}")
                self._client = None
                return None

    async def _call(self, sync_fn, *args):
        """在线程池安全执行同步 qdrant 方法; 失败返回 None。"""
        client = await self._client_or_none()
        if client is None:
            return None
        try:
            return await asyncio.to_thread(sync_fn, client, *args)
        except Exception as e:
            logger.warning(f"[Qdrant] 调用失败(降级 pgvector): {e}")
            return None

    # ── 集合管理 ──

    async def ensure_collection(self) -> Optional[bool]:
        """确保 collection 存在(不重复创建)。返回 True 就绪 / None 不可用。"""
        from qdrant_client.http import models as m

        def _ensure(client):
            if not client.collection_exists(settings.qdrant_collection):
                client.create_collection(
                    collection_name=settings.qdrant_collection,
                    vectors_config=m.VectorParams(
                        size=settings.qdrant_vector_size or settings.embedding_dim,
                        distance=m.Distance.COSINE,
                    ),
                )
                logger.info(f"[Qdrant] 已创建 collection={settings.qdrant_collection}")
            return True

        return await self._call(_ensure)

    async def recreate_collection(self) -> Optional[bool]:
        """删除并重建 collection (迁移用)。返回 True / None 不可用。"""
        from qdrant_client.http import models as m

        def _recreate(client):
            if client.collection_exists(settings.qdrant_collection):
                client.delete_collection(settings.qdrant_collection)
            client.create_collection(
                collection_name=settings.qdrant_collection,
                vectors_config=m.VectorParams(
                    size=settings.qdrant_vector_size or settings.embedding_dim,
                    distance=m.Distance.COSINE,
                ),
            )
            return True

        return await self._call(_recreate)

    # ── 写入 ──

    async def upsert_chunk(
        self,
        *,
        chunk_id: str,
        doc_id: int,
        vector: list,
        payload: Optional[dict] = None,
    ) -> Optional[bool]:
        """写入/覆盖一个 knowledge chunk 的向量与过滤 payload。"""
        from qdrant_client.http import models as m

        def _upsert(client):
            client.upsert(
                collection_name=settings.qdrant_collection,
                points=[m.PointStruct(
                    id=chunk_point_id(chunk_id),
                    vector=vector,
                    payload={
                        "chunk_id": chunk_id,
                        "doc_id": doc_id,
                        **(payload or {}),
                    },
                )],
                wait=True,
            )
            return True

        return await self._call(_upsert)

    async def upsert_chunks_batch(
        self,
        chunks: list[dict],
    ) -> Optional[bool]:
        """批量写入(迁移用): chunks=[{chunk_id, doc_id, vector, payload}, ...]。"""
        from qdrant_client.http import models as m

        def _batch(client):
            client.upsert(
                collection_name=settings.qdrant_collection,
                points=[
                    m.PointStruct(
                        id=chunk_point_id(c["chunk_id"]),
                        vector=c["vector"],
                        payload={
                            "chunk_id": c["chunk_id"],
                            "doc_id": c["doc_id"],
                            **(c.get("payload") or {}),
                        },
                    )
                    for c in chunks
                ],
                wait=True,
            )
            return True

        return await self._call(_batch)

    # ── 删除 ──

    async def delete_by_chunk_ids(self, chunk_ids: list[str]) -> Optional[bool]:
        if not chunk_ids:
            return True
        from qdrant_client.http import models as m

        def _del(client):
            client.delete(
                collection_name=settings.qdrant_collection,
                points_selector=m.PointIdsList(points=[chunk_point_id(c) for c in chunk_ids]),
            )
            return True

        return await self._call(_del)

    async def delete_by_doc_id(self, doc_id: int) -> Optional[bool]:
        """按 doc_id 删除该文档的全部 chunk 向量。"""
        from qdrant_client.http import models as m

        def _del(client):
            # 先用 payload filter 列出该 doc_id 的所有点 id, 再删除
            points = client.query_points(
                collection_name=settings.qdrant_collection,
                query_filter=m.Filter(must=[m.FieldCondition(
                    key="doc_id", match=m.MatchValue(value=doc_id),
                )]),
                limit=1000,
                with_payload=False,
            ).points
            ids = [p.id for p in points]
            if ids:
                client.delete(
                    collection_name=settings.qdrant_collection,
                    points_selector=m.PointIdsList(points=ids),
                )
            return True

        return await self._call(_del)

    # ── 检索 ──

    async def search(
        self,
        query_vector: list,
        *,
        top_k: int = 5,
        min_score: float = 0.6,
        threat_type: str = "",
        severity: str = "",
        source: str = "",
    ) -> list[dict]:
        """向量检索 + payload 过滤。返回 [{'chunk_id','doc_id','score','payload'}]"""
        from qdrant_client.http import models as m

        def _search(client):
            must = []
            if threat_type:
                # payload.threat_types 是数组; qdrant FieldCondition 默认按数组元素匹配
                must.append(m.FieldCondition(key="threat_types", match=m.MatchValue(value=threat_type)))
            if severity:
                must.append(m.FieldCondition(key="severity", match=m.MatchValue(value=severity)))
            if source:
                must.append(m.FieldCondition(key="source", match=m.MatchValue(value=source)))
            query_filter = m.Filter(must=must) if must else None

            resp = client.query_points(
                collection_name=settings.qdrant_collection,
                query=query_vector,
                query_filter=query_filter,
                limit=top_k,
                score_threshold=min_score,
                with_payload=True,
                with_vectors=False,
            )
            out = []
            for p in resp.points:
                out.append({
                    "chunk_id": (p.payload or {}).get("chunk_id", ""),
                    "doc_id": (p.payload or {}).get("doc_id"),
                    "score": round(float(p.score), 4),
                    "payload": p.payload or {},
                })
            return out

        result = await self._call(_search)
        return result if result is not None else []

    async def count(self) -> Optional[int]:
        def _count(client):
            return client.get_collection(settings.qdrant_collection).points_count
        return await self._call(_count)


qdrant_store = QdrantStore()
