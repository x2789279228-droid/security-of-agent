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
from sqlalchemy import select, desc, and_, or_, delete as sa_delete, text
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

    async def get_document(self, session: AsyncSession, doc_id: int) -> Optional[dict]:
        from models import KnowledgeDoc
        doc = await session.get(KnowledgeDoc, doc_id)
        return self._doc_to_dict(doc) if doc else None

    async def search_documents(
        self,
        session: AsyncSession,
        query: str = "",
        threat_type: str = "",
        source: str = "",
        severity: str = "",
        tags: Optional[list[str]] = None,
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
        return {"documents": doc_count, "chunks": chunk_count}

    def _doc_to_dict(self, doc) -> dict:
        return {
            "id": doc.id,
            "title": doc.title,
            "content": doc.content[:500] if doc.content else "",
            "source": doc.source,
            "threat_types": doc.threat_types,
            "severity": doc.severity,
            "tags": doc.tags,
            "metadata": doc.metadata_,
            "created_at": doc.created_at.isoformat() if doc.created_at else "",
        }


kb_manager = KnowledgeBaseManager()
