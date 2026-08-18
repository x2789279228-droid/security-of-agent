"""
资产变更历史 (Asset History) — P0.A

字段级 diff 计算与查询，供：
  - 资产详情页"变更历史"标签
  - 合规取证
"""
import logging
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import AssetChange

logger = logging.getLogger(__name__)


class AssetHistory:
    """资产变更历史查询"""

    async def list_changes(
        self, session: AsyncSession, asset_id: int,
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        stmt = (
            select(AssetChange)
            .where(AssetChange.asset_id == asset_id)
            .order_by(desc(AssetChange.created_at))
            .limit(limit).offset(offset)
        )
        result = await session.execute(stmt)
        return [
            {
                "id": c.id,
                "asset_id": c.asset_id,
                "change_type": c.change_type,
                "diff": c.diff or {},
                "source": c.source,
                "changed_by": c.changed_by,
                "created_at": c.created_at.isoformat() if c.created_at else "",
            }
            for c in result.scalars().all()
        ]

    async def recent_changes(
        self, session: AsyncSession, limit: int = 100
    ) -> list[dict]:
        """最近所有资产变更（dashboard 用）"""
        stmt = (
            select(AssetChange)
            .order_by(desc(AssetChange.created_at))
            .limit(limit)
        )
        result = await session.execute(stmt)
        return [
            {
                "id": c.id,
                "asset_id": c.asset_id,
                "change_type": c.change_type,
                "diff": c.diff or {},
                "source": c.source,
                "changed_by": c.changed_by,
                "created_at": c.created_at.isoformat() if c.created_at else "",
            }
            for c in result.scalars().all()
        ]


asset_history = AssetHistory()