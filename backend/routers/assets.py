"""
资产管理路由 — 资产注册/发现/变更历史

端点前缀: /api/assets
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_session
from auth import get_current_user, RequireRole, UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/assets", tags=["assets"])

# ── 共享状态 ──
# 持久化到 assets 表，启动时由 lifespan 从 DB 重建内存缓存 _ASSET_REGISTRY
# 旧调用方 (kafka_consumer 等) 仍走同步 get_asset_weight(dst_ip) 不变

# 内存缓存 (兼容层)：IP → {level, business, weight}
_ASSET_REGISTRY: dict[str, dict] = {}

ASSET_LEVELS = {
    "critical": {"weight": 1.5, "label": "核心资产（数据库/AD/防火墙）"},
    "high":     {"weight": 1.3, "label": "重要资产（应用服务器/文件服务器）"},
    "medium":   {"weight": 1.0, "label": "一般资产（工作站/终端）"},
    "low":      {"weight": 0.8, "label": "低优先级（IoT/测试环境）"},
}


async def refresh_asset_cache():
    """从 DB 重建 _ASSET_REGISTRY 内存缓存（启动时 + 资产变更后调用）"""
    try:
        from asset import asset_manager
        from models import async_session
        async with async_session() as s:
            assets = await asset_manager.list_assets(s, active_only=True, limit=10000)
        _ASSET_REGISTRY.clear()
        for a in assets:
            if a["ip"]:
                _ASSET_REGISTRY[a["ip"]] = {
                    "ip": a["ip"], "level": a["criticality"],
                    "label": a.get("hostname") or a["ip"],
                    "business": a.get("business_unit", ""),
                    "weight": a["weight"],
                }
        logger.info(f"[Assets] Loaded {len(_ASSET_REGISTRY)} assets into cache")
    except Exception as e:
        logger.warning(f"[Assets] cache refresh failed: {e}")


def get_asset_weight(dst_ip: str) -> float:
    """
    查询目标 IP 的资产权重（同步，读内存缓存）
    - 保留签名兼容 kafka_consumer 等现有调用
    - 启动时由 _refresh_asset_cache() 加载，资产变更时刷新
    """
    import ipaddress
    if not dst_ip:
        return 1.0
    for cidr, info in _ASSET_REGISTRY.items():
        try:
            if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(cidr, strict=False):
                return info.get("weight", 1.0)
        except ValueError:
            continue
    return 1.0


# ── 端点 ──

@router.get("")
async def assets_list(
    criticality: str = "", business_unit: str = "",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """列出所有已注册资产 (DB-backed)"""
    from asset import asset_manager
    assets = await asset_manager.list_assets(
        session, criticality=criticality, business_unit=business_unit,
        active_only=True, limit=500,
    )
    return {
        "assets": assets,
        "cache": _ASSET_REGISTRY,
        "levels": ASSET_LEVELS,
    }


@router.post("")
async def assets_register(
    ip: str = "", hostname: str = "", level: str = "medium",
    label: str = "", business: str = "", asset_type: str = "host",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """注册/更新资产 (DB 持久化 + 内存缓存同步)"""
    from asset import asset_manager
    tags = [label] if label else []
    result = await asset_manager.register(
        session, ip=ip, hostname=hostname, asset_type=asset_type,
        criticality=level, business_unit=business,
        tags=tags, source="manual", changed_by=user.username,
    )
    if result.get("success"):
        await refresh_asset_cache()
    return result


@router.delete("/{asset_id}")
async def assets_remove(
    asset_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """下线资产 (软删除)"""
    from asset import asset_manager
    result = await asset_manager.remove(session, asset_id, by=user.username)
    if result.get("success"):
        await refresh_asset_cache()
    return result


@router.get("/{asset_id}/history")
async def asset_history_view(
    asset_id: int, limit: int = 50,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """资产变更历史"""
    from asset import asset_history
    return {"changes": await asset_history.list_changes(session, asset_id, limit=limit)}


@router.post("/discovery")
async def assets_discovery(
    scope: str, scanner: str = "edr",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """启动资产发现任务"""
    from asset import discovery_service
    create = await discovery_service.create_task(session, scope=scope, scanner=scanner)
    if create.get("task_id"):
        run = await discovery_service.run_task(session, create["task_id"])
        await refresh_asset_cache()
        return {**create, **run}
    return create


@router.get("/discovery/tasks")
async def assets_discovery_tasks(
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """资产发现任务列表"""
    from asset import discovery_service
    return {"tasks": await discovery_service.list_tasks(session, limit=limit)}
