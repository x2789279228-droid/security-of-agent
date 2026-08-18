"""
资产管理器 (Asset Manager) — P0.A 核心

替代 app.py:431 _ASSET_REGISTRY 内存字典,提供:
  - CRUD (持久化到 assets 表)
  - 资产权重查询 (供 anomaly_detector 加权评分)
  - 资产变更审计 (接入 P0.H audit_trail)
"""
import hashlib
import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, or_, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import Asset, AssetChange

logger = logging.getLogger(__name__)


# ── 等级定义 (与 app.py ASSET_LEVELS 对齐,保持兼容) ──
ASSET_LEVELS = {
    "critical": {"weight": 1.5, "label": "核心资产（数据库/AD/防火墙）"},
    "high":     {"weight": 1.3, "label": "重要资产（应用服务器/文件服务器）"},
    "medium":   {"weight": 1.0, "label": "一般资产（工作站/终端）"},
    "low":      {"weight": 0.8, "label": "低优先级（IoT/测试环境）"},
}
ASSET_WEIGHTS = {k: v["weight"] for k, v in ASSET_LEVELS.items()}


def _make_asset_key(ip: str = "", hostname: str = "", asset_key: str = "") -> str:
    """生成资产唯一键：优先用调用方提供的 key，其次 ip，最后 hostname"""
    if asset_key:
        return asset_key
    if ip:
        return f"ip:{ip}"
    if hostname:
        return f"host:{hostname}"
    raise ValueError("资产必须至少提供 ip / hostname / asset_key 之一")


class AssetManager:
    """资产管理器"""

    async def register(
        self,
        session: AsyncSession,
        *,
        ip: str = "",
        hostname: str = "",
        asset_key: str = "",
        asset_type: str = "host",
        criticality: str = "medium",
        business_owner: str = "",
        tech_owner: str = "",
        business_unit: str = "",
        environment: str = "prod",
        exposure: str = "internal",
        os: str = "",
        services: Optional[list] = None,
        tags: Optional[list] = None,
        metadata: Optional[dict] = None,
        source: str = "manual",
        changed_by: str = "admin",
    ) -> dict:
        """
        注册或更新资产（upsert 语义）
        - 资产已存在 → 字段级 diff 进 asset_changes，主表更新
        - 资产不存在 → 创建，change_type=created
        """
        if criticality not in ASSET_LEVELS:
            return {"success": False, "error": f"无效等级: {criticality}，可选: {list(ASSET_LEVELS.keys())}"}

        key = _make_asset_key(ip, hostname, asset_key)

        # 查现有
        stmt = select(Asset).where(Asset.asset_key == key)
        result = await session.execute(stmt)
        existing = result.scalars().first()

        now = datetime.now(timezone.utc)

        if existing:
            # ── 更新 + diff ──
            diff = {}
            for field, new_val in {
                "ip": ip, "hostname": hostname, "asset_type": asset_type,
                "criticality": criticality, "business_owner": business_owner,
                "tech_owner": tech_owner, "business_unit": business_unit,
                "environment": environment, "exposure": exposure, "os": os,
                "services": services or [], "tags": tags or [],
                "metadata": metadata or {},
            }.items():
                old_val = getattr(existing, field, None)
                if old_val != new_val and new_val:
                    diff[field] = {"old": old_val, "new": new_val}
                    setattr(existing, field, new_val)

            if diff:
                existing.updated_at = now
                existing.last_seen = now
                await session.commit()

                # 变更历史
                session.add(AssetChange(
                    asset_id=existing.id, change_type="updated",
                    diff=diff, source=source, changed_by=changed_by,
                ))
                await session.commit()

                # P0.H 操作审计
                try:
                    from audit_trail import log_action
                    await log_action(
                        session, actor=changed_by, action="asset.update",
                        target_type="asset", target_id=str(existing.id),
                        before={k: v["old"] for k, v in diff.items()},
                        after={k: v["new"] for k, v in diff.items()},
                        reason=f"更新资产 {key}",
                    )
                except Exception as e:
                    logger.warning(f"[Asset] audit_trail log failed: {e}")

                logger.info(f"[Asset] Updated: {key} fields={list(diff.keys())}")
                return {"success": True, "asset": self._to_dict(existing), "diff": diff}
            else:
                existing.last_seen = now
                await session.commit()
                return {"success": True, "asset": self._to_dict(existing), "diff": {}}

        # ── 新增 ──
        asset = Asset(
            asset_key=key, asset_type=asset_type, ip=ip, hostname=hostname, os=os,
            services=services or [], business_owner=business_owner,
            tech_owner=tech_owner, business_unit=business_unit,
            criticality=criticality, environment=environment, exposure=exposure,
            tags=tags or [], metadata_=metadata or {}, source=source,
            first_seen=now, last_seen=now, is_active=True,
        )
        session.add(asset)
        await session.flush()

        session.add(AssetChange(
            asset_id=asset.id, change_type="created",
            diff={"asset_key": {"old": None, "new": key}},
            source=source, changed_by=changed_by,
        ))
        await session.commit()

        # P0.H 操作审计
        try:
            from audit_trail import log_action
            await log_action(
                session, actor=changed_by, action="asset.create",
                target_type="asset", target_id=str(asset.id),
                before={}, after={"asset_key": key, "criticality": criticality},
                reason=f"注册新资产 {key}",
            )
        except Exception as e:
            logger.warning(f"[Asset] audit_trail log failed: {e}")

        logger.info(f"[Asset] Created: {key} type={asset_type} criticality={criticality}")
        return {"success": True, "asset": self._to_dict(asset), "diff": None}

    async def remove(
        self, session: AsyncSession, asset_id: int, by: str = "admin"
    ) -> dict:
        """软删除资产 (is_active=False)"""
        asset = await session.get(Asset, asset_id)
        if not asset:
            return {"success": False, "error": "资产不存在"}
        if not asset.is_active:
            return {"success": False, "error": "资产已下线"}

        before = {"is_active": True}
        asset.is_active = False
        asset.updated_at = datetime.now(timezone.utc)
        session.add(AssetChange(
            asset_id=asset.id, change_type="decommissioned",
            diff={"is_active": {"old": True, "new": False}},
            source="manual", changed_by=by,
        ))
        await session.commit()

        try:
            from audit_trail import log_action
            await log_action(
                session, actor=by, action="asset.decommission",
                target_type="asset", target_id=str(asset_id),
                before=before, after={"is_active": False},
                reason=f"下线资产 {asset.asset_key}",
            )
        except Exception as e:
            logger.warning(f"[Asset] audit_trail log failed: {e}")

        return {"success": True}

    async def get_asset(self, session: AsyncSession, asset_id: int) -> Optional[dict]:
        asset = await session.get(Asset, asset_id)
        return self._to_dict(asset) if asset else None

    async def find_by_ip(
        self, session: AsyncSession, ip: str
    ) -> Optional[dict]:
        """通过 IP 精确查找资产"""
        if not ip:
            return None
        stmt = select(Asset).where(Asset.ip == ip, Asset.is_active == True)
        result = await session.execute(stmt)
        asset = result.scalars().first()
        return self._to_dict(asset) if asset else None

    async def list_assets(
        self, session: AsyncSession, *,
        criticality: str = "", business_unit: str = "",
        asset_type: str = "", active_only: bool = True,
        limit: int = 200, offset: int = 0,
    ) -> list[dict]:
        conditions = []
        if active_only:
            conditions.append(Asset.is_active == True)
        if criticality:
            conditions.append(Asset.criticality == criticality)
        if business_unit:
            conditions.append(Asset.business_unit == business_unit)
        if asset_type:
            conditions.append(Asset.asset_type == asset_type)

        stmt = select(Asset)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(Asset.criticality), desc(Asset.updated_at)).limit(limit).offset(offset)

        result = await session.execute(stmt)
        return [self._to_dict(a) for a in result.scalars().all()]

    async def get_asset_weight(
        self, session: AsyncSession, dst_ip: str
    ) -> float:
        """
        查询目标 IP 的资产权重 (供 anomaly_detector / response_engine 使用)

        替代 app.py:464 get_asset_weight 内存版
        - 精确 IP 命中 → 返回该资产权重
        - 未命中 → 1.0 (默认)
        """
        if not dst_ip:
            return 1.0
        asset = await self.find_by_ip(session, dst_ip)
        if asset:
            return ASSET_WEIGHTS.get(asset["criticality"], 1.0)
        return 1.0

    async def get_levels(self) -> dict:
        """供 API 返回等级定义 (兼容 app.py ASSET_LEVELS)"""
        return {
            "levels": ASSET_LEVELS,
        }

    async def import_legacy_registry(
        self, session: AsyncSession, registry: dict, by: str = "migration"
    ) -> int:
        """
        一次性内存 _ASSET_REGISTRY → assets 表迁移
        - registry: dict[ip, {ip, level, label, business, weight}]
        - 返回迁移条数
        """
        n = 0
        for ip, info in registry.items():
            try:
                r = await self.register(
                    session, ip=ip, asset_type="host",
                    criticality=info.get("level", "medium"),
                    business_unit=info.get("business", ""),
                    exposure="internal",
                    tags=[info.get("label", "")],
                    source="legacy_migration", changed_by=by,
                )
                if r.get("success"):
                    n += 1
            except Exception as e:
                logger.warning(f"[Asset] legacy import failed for {ip}: {e}")
        logger.info(f"[Asset] Imported {n} assets from legacy registry")
        return n

    @staticmethod
    def _to_dict(a: Asset) -> dict:
        return {
            "id": a.id,
            "asset_key": a.asset_key,
            "asset_type": a.asset_type,
            "ip": a.ip or "",
            "hostname": a.hostname or "",
            "os": a.os or "",
            "services": a.services or [],
            "business_owner": a.business_owner or "",
            "tech_owner": a.tech_owner or "",
            "business_unit": a.business_unit or "",
            "criticality": a.criticality,
            "environment": a.environment,
            "exposure": a.exposure,
            "tags": a.tags or [],
            "source": a.source,
            "first_seen": a.first_seen.isoformat() if a.first_seen else "",
            "last_seen": a.last_seen.isoformat() if a.last_seen else "",
            "is_active": a.is_active,
            "weight": ASSET_WEIGHTS.get(a.criticality, 1.0),
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "updated_at": a.updated_at.isoformat() if a.updated_at else "",
        }


asset_manager = AssetManager()