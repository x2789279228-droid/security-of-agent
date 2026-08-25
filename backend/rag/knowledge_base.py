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
        submitted_by: str = "",
        auto_signed: bool = False,
        published_at=None,
        valid_until=None,
        cutoff_policy: str = "strict",
    ) -> dict:
        """添加知识文档。internal 默认 pending；导入器签名源自动 signed_import。"""
        from models import KnowledgeDoc
        from memory_guard import content_hash, kb_source_is_signed

        if auto_signed or kb_source_is_signed(source):
            status = "signed_import"
        else:
            status = "pending"

        digest = content_hash(content or "")
        meta = dict(metadata or {})
        meta["content_hash"] = digest
        doc = KnowledgeDoc(
            title=title,
            content=content,
            source=source,
            threat_types=threat_types or [],
            severity=severity,
            tags=tags or [],
            metadata_=meta,
            content_hash=digest,
            approval_status=status,
            submitted_by=submitted_by or "",
            published_at=published_at,
            valid_until=valid_until,
            cutoff_policy=cutoff_policy or "strict",
        )
        session.add(doc)
        await session.commit()
        await session.refresh(doc)
        logger.info(
            f"KB doc added: {doc.id} - {title[:50]} status={status} hash={digest[:12]}"
        )
        return self._doc_to_dict(doc)

    async def approve_document(
        self,
        session: AsyncSession,
        doc_id: int,
        approved_by: str,
    ) -> dict:
        """第二人审批。提交人不能自己批。"""
        from models import KnowledgeDoc
        doc = await session.get(KnowledgeDoc, doc_id)
        if not doc:
            return {"success": False, "error": "文档不存在"}
        if doc.approval_status in ("approved", "signed_import"):
            return {"success": False, "error": "已审批或导入签名源"}
        if doc.submitted_by and approved_by and doc.submitted_by == approved_by:
            return {"success": False, "error": "须第二人审批"}
        doc.approval_status = "approved"
        doc.approved_by = approved_by
        await session.commit()
        return {"success": True, "doc": self._doc_to_dict(doc)}

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
            # ── Qdrant 同步删除: 按 doc_id 清该文档的向量 (失败仅记日志) ──
            try:
                from qdrant_store import qdrant_store
                await qdrant_store.delete_by_doc_id(doc_id)
            except Exception as qe:
                logger.warning(f"[Qdrant] delete_document 清理失败(降级): {qe}")
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
            "content_hash": getattr(doc, "content_hash", "") or "",
            "approval_status": getattr(doc, "approval_status", "") or "",
            "submitted_by": getattr(doc, "submitted_by", "") or "",
            "approved_by": getattr(doc, "approved_by", "") or "",
            "published_at": doc.published_at.isoformat() if getattr(doc, "published_at", None) else "",
            "valid_until": doc.valid_until.isoformat() if getattr(doc, "valid_until", None) else "",
            "cutoff_policy": getattr(doc, "cutoff_policy", "") or "strict",
        }


kb_manager = KnowledgeBaseManager()
