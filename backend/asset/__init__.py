"""
Asset 模块 — 资产管理 (P0.A)

职责:
  1. 资产 CRUD + 资产权重查询（替代 app.py 内存 _ASSET_REGISTRY）
  2. 资产变更历史 (diff 计算 + 进 asset_changes 表)
  3. 资产发现 (nmap / EDR / CMDB 三路适配器)
  4. 资产关联 (IP/CIDR → asset，供 case_manager / response_engine 使用)

调用方式:
    from asset import asset_manager
    asset = await asset_manager.register(session, ip="10.0.0.5", criticality="critical")
    weight = await asset_manager.get_asset_weight(session, "10.0.0.5")
"""
from .asset_manager import asset_manager, ASSET_LEVELS, ASSET_WEIGHTS
from .asset_history import asset_history
from .discovery import discovery_service
from .asset_correlator import asset_correlator

__all__ = [
    "asset_manager", "asset_history", "discovery_service", "asset_correlator",
    "ASSET_LEVELS", "ASSET_WEIGHTS",
]