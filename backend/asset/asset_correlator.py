"""
资产关联器 (Asset Correlator) — P0.A

桥接 case_manager / response_engine / correlation_engine：
  - case 创建时由 dst_ip 反查所属资产
  - 反查结果写入案例 metadata_，作为后续响应判断依据
  - 目标资产关键性直接影响 case 优先级
"""
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .asset_manager import asset_manager, ASSET_WEIGHTS

logger = logging.getLogger(__name__)


class AssetCorrelator:
    """资产关联查询"""

    async def enrich_case_target(
        self, session: AsyncSession, dst_ip: str
    ) -> Optional[dict]:
        """
        由 case 的 dst_ip 反查资产，返回关联快照
        - 命中：return {asset_id, asset_key, criticality, business_owner, business_unit, weight}
        - 未命中：return None
        """
        if not dst_ip:
            return None
        asset = await asset_manager.find_by_ip(session, dst_ip)
        if not asset:
            return None
        return {
            "asset_id": asset["id"],
            "asset_key": asset["asset_key"],
            "criticality": asset["criticality"],
            "business_owner": asset["business_owner"],
            "business_unit": asset["business_unit"],
            "weight": ASSET_WEIGHTS.get(asset["criticality"], 1.0),
        }

    async def recommend_case_priority(
        self, session: AsyncSession, dst_ip: str, base_priority: str = "medium"
    ) -> str:
        """
        根据目标资产关键性推荐案例优先级
        - critical 资产上的告警自动升级到 critical
        - high 资产告警升级到 high
        - 其余沿用 base_priority
        """
        info = await self.enrich_case_target(session, dst_ip)
        if not info:
            return base_priority

        crit_order = ["low", "medium", "high", "critical"]
        asset_level = info["criticality"]
        base_idx = crit_order.index(base_priority) if base_priority in crit_order else 1
        asset_idx = crit_order.index(asset_level) if asset_level in crit_order else 1
        # 取较高者
        return crit_order[max(base_idx, asset_idx)]


asset_correlator = AssetCorrelator()