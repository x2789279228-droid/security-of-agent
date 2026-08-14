"""
知识库管理 — 安全知识的增删改查

知识库条目结构:
  - id: 唯一标识
  - title: 标题
  - content: 知识正文
  - source: 来源 (mitre-attack/cve/playbook/internal)
  - threat_types: 关联的威胁类型列表
  - severity: 适用严重度
  - tags: 标签
  - metadata: 额外元数据
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import json
from sqlalchemy import select, desc, and_, or_, delete as sa_delete, text, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class KnowledgeBaseManager:
    """知识库管理"""

    def __init__(self):
        pass

    async def add_document(
        self,
        session: AsyncSession,
        title: str,
        content: str,
        source: str = "internal",
        threat_types: Optional[list[str]] = None,
        severity: str = "medium",
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """添加知识文档"""
        from models import KnowledgeDoc

        doc = KnowledgeDoc(
            title=title,
            content=content,
            source=source,
            threat_types=threat_types or [],
            severity=severity,
            tags=tags or [],
            metadata_=metadata or {},
        )
        session.add(doc)
        await session.commit()
        await session.refresh(doc)
        logger.info(f"KB doc added: {doc.id} - {title[:50]}")
        return self._doc_to_dict(doc)

    async def get_document(self, session: AsyncSession, doc_id: int, full: bool = False) -> Optional[dict]:
        from models import KnowledgeDoc
        doc = await session.get(KnowledgeDoc, doc_id)
        return self._doc_to_dict(doc, full=full) if doc else None

    async def find_doc_by_metadata(
        self,
        session: AsyncSession,
        metadata: dict,
        sources: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """
        按 metadata JSONB 精确匹配查询文档（如 {"cve_id": "CVE-2021-44228"}）。

        用于 CVE/KEV/漏洞的去重、速查与联动标记。命中多条时取最新一条。
        """
        from models import KnowledgeDoc
        if not metadata:
            return None
        stmt = select(KnowledgeDoc).where(
            text("metadata @> CAST(:payload AS jsonb)").bindparams(payload=json.dumps(metadata))
        )
        if sources:
            stmt = stmt.where(KnowledgeDoc.source.in_(sources))
        stmt = stmt.order_by(desc(KnowledgeDoc.created_at)).limit(1)
        result = await session.execute(stmt)
        doc = result.scalars().first()
        return self._doc_to_dict(doc, full=True) if doc else None

    async def update_metadata_by_metadata(
        self,
        session: AsyncSession,
        metadata: dict,
        patch: dict,
        sources: Optional[list[str]] = None,
        commit: bool = True,
    ) -> int:
        """
        按 metadata JSONB 匹配文档，用 JSONB || 合并补丁（只更新 metadata + 严重度提升）。

        返回更新条数。重复执行幂等（|| 合并不会产生重复键）。
        commit=False 用于批量导入时合并提交（调用方统一 commit）。
        """
        from models import KnowledgeDoc
        if not metadata or not patch:
            return 0
        stmt = sa_update(KnowledgeDoc).where(
            text("metadata @> CAST(:match AS jsonb)").bindparams(match=json.dumps(metadata))
        )
        if sources:
            stmt = stmt.where(KnowledgeDoc.source.in_(sources))
        stmt = stmt.values(
            metadata_=text("metadata || CAST(:patch AS jsonb)").bindparams(patch=json.dumps(patch)),
            severity=text(
                "CASE WHEN severity NOT IN ('critical','high') THEN 'high' ELSE severity END"
            ),
        )
        result = await session.execute(stmt)
        if commit:
            await session.commit()
        return result.rowcount or 0

    async def add_tag_by_metadata(
        self,
        session: AsyncSession,
        metadata: dict,
        tag: str,
        sources: Optional[list[str]] = None,
        commit: bool = True,
    ) -> int:
        """
        按 metadata 匹配文档，若 tags 尚未包含该标签则追加（幂等，避免重复标签）。
        commit=False 用于批量导入时合并提交（调用方统一 commit）。
        """
        from models import KnowledgeDoc
        if not metadata or not tag:
            return 0
        stmt = sa_update(KnowledgeDoc).where(
            text("metadata @> CAST(:match AS jsonb)").bindparams(match=json.dumps(metadata)),
            text("NOT (tags @> CAST(:tag AS jsonb))").bindparams(tag=json.dumps([tag])),
        )
        if sources:
            stmt = stmt.where(KnowledgeDoc.source.in_(sources))
        stmt = stmt.values(
            tags=text("tags || CAST(:tag AS jsonb)").bindparams(tag=json.dumps([tag])),
        )
        result = await session.execute(stmt)
        if commit:
            await session.commit()
        return result.rowcount or 0

    async def delete_by_source(self, session: AsyncSession, source: str) -> int:
        """删除某知识库类型的全部文档及分块（窗口滚动清理用），返回删除文档数"""
        from models import KnowledgeDoc, KnowledgeChunk
        doc_ids = (await session.execute(
            select(KnowledgeDoc.id).where(KnowledgeDoc.source == source)
        )).scalars().all()
        if not doc_ids:
            return 0
        await session.execute(
            sa_delete(KnowledgeChunk).where(KnowledgeChunk.doc_id.in_(doc_ids))
        )
        result = await session.execute(
            sa_delete(KnowledgeDoc).where(KnowledgeDoc.source == source)
        )
        await session.commit()
        return result.rowcount or 0

    async def search_documents(
        self,
        session: AsyncSession,
        query: str = "",
        threat_type: str = "",
        source: str = "",
        severity: str = "",
        tags: Optional[list[str]] = None,
        exclude_sources: Optional[set[str]] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """搜索知识文档（文本匹配）"""
        from models import KnowledgeDoc

        conditions = []
        if query:
            conditions.append(KnowledgeDoc.content.ilike(f"%{query}%"))
        if source:
            conditions.append(KnowledgeDoc.source == source)
        else:
            # 未指定 source 时排除大批量源（如 cve/kev），避免文档管理页被淹没
            for excl in (exclude_sources or set()):
                conditions.append(KnowledgeDoc.source != excl)
        if severity:
            conditions.append(KnowledgeDoc.severity == severity)
        if threat_type:
            conditions.append(
                text(f"threat_types @> '{json.dumps([threat_type])}'::jsonb")
            )
        if tags:
            for tag in tags:
                conditions.append(
                    text(f"tags @> '{json.dumps([tag])}'::jsonb")
                )

        stmt = select(KnowledgeDoc)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(KnowledgeDoc.created_at)).limit(limit).offset(offset)

        result = await session.execute(stmt)
        docs = result.scalars().all()
        return [self._doc_to_dict(d) for d in docs]

    async def delete_document(self, session: AsyncSession, doc_id: int) -> bool:
        from models import KnowledgeDoc, KnowledgeChunk
        # 删除文档及其分块
        await session.execute(
            sa_delete(KnowledgeChunk).where(KnowledgeChunk.doc_id == doc_id)
        )
        doc = await session.get(KnowledgeDoc, doc_id)
        if doc:
            await session.delete(doc)
            await session.commit()
            return True
        return False

    async def list_sources(self, session: AsyncSession) -> list[str]:
        from models import KnowledgeDoc
        stmt = select(KnowledgeDoc.source).distinct()
        result = await session.execute(stmt)
        return [row[0] for row in result.all()]

    async def get_stats(self, session: AsyncSession) -> dict:
        from models import KnowledgeDoc, KnowledgeChunk
        from sqlalchemy import func

        doc_count = (await session.execute(
            select(func.count(KnowledgeDoc.id))
        )).scalar() or 0
        chunk_count = (await session.execute(
            select(func.count(KnowledgeChunk.id))
        )).scalar() or 0

        # 按知识库类型统计（docs/chunks）
        by_source: dict[str, dict] = {}
        for source, count in (await session.execute(
            select(KnowledgeDoc.source, func.count(KnowledgeDoc.id))
            .group_by(KnowledgeDoc.source)
        )).all():
            by_source[source] = {"documents": count, "chunks": 0}
        for source, count in (await session.execute(
            select(KnowledgeChunk.source, func.count(KnowledgeChunk.id))
            .group_by(KnowledgeChunk.source)
        )).all():
            by_source.setdefault(source, {"documents": 0, "chunks": 0})["chunks"] = count

        # 按严重度统计
        by_severity = dict((await session.execute(
            select(KnowledgeDoc.severity, func.count(KnowledgeDoc.id))
            .group_by(KnowledgeDoc.severity)
        )).all())

        return {
            "documents": doc_count,
            "chunks": chunk_count,
            "by_source": by_source,
            "by_severity": by_severity,
        }

    def _doc_to_dict(self, doc, full: bool = False) -> dict:
        return {
            "id": doc.id,
            "title": doc.title,
            "content": doc.content if full else (doc.content[:500] if doc.content else ""),
            "source": doc.source,
            "threat_types": doc.threat_types,
            "severity": doc.severity,
            "tags": doc.tags,
            "metadata": doc.metadata_,
            "created_at": doc.created_at.isoformat() if doc.created_at else "",
        }


async def ensure_kb_indexes(session: AsyncSession):
    """
    幂等创建知识库所需索引。

    说明：metadata JSONB 的 GIN 索引加速 @> / ? 过滤（cve_id 精确匹配、产品数组成员过滤）。
    不建 CVE-ID 唯一索引 —— 同一 cve_id 可能跨源出现（先 kev 后 cve），
    唯一约束会因历史数据违反而阻塞启动；"一库一文档/CVE-ID"靠导入器
    应用层 find_doc_by_metadata 去重保证。
    """
    try:
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kb_docs_metadata_gin
            ON knowledge_docs USING gin(metadata)
        """))
        await session.commit()
        logger.info("ensure_kb_indexes: knowledge_docs.metadata GIN index ensured")
    except Exception as e:
        # DB 不可用或权限不足时不阻塞启动（DEGRADED 模式）
        logger.warning(f"ensure_kb_indexes failed (non-fatal): {e}")


kb_manager = KnowledgeBaseManager()
