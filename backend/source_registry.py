"""
数据源注册与认证 — 解决"无差别接收"的核心模块

安全审计平台不应急收所有数据。每个日志源必须：
  1. 注册并获取 API Key
  2. 每次上报携带 API Key + Source ID
  3. 未注册来源的日志直接拒绝并告警

用法:
    registry = SourceRegistry()
    registry.load_from_config()
    if registry.authenticate("soc-syslog-2024"):
        # 合法来源，接收
    else:
        # 拒绝，记录告警
"""
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class DataSource:
    """已注册的数据源"""
    api_key: str
    name: str
    source_type: str = "generic"       # "syslog" | "api" | "simulator" | "generic"
    enabled: bool = True
    registered_at: float = field(default_factory=time.time)
    last_seen: float = 0
    total_events: int = 0
    rejected_events: int = 0


class SourceRegistry:
    """
    数据源注册表

    管理合法日志源的 API Key 白名单。
    生产环境应持久化到数据库，此处用内存 + 配置文件。
    """

    def __init__(self):
        self._sources: dict[str, DataSource] = {}
        self._rejection_log: list[dict] = []
        self._rejection_log_max = 500

    def load_from_config(self):
        """从配置文件加载预注册的 API Key"""
        try:
            keys = json.loads(settings.source_api_keys)
            for api_key, name in keys.items():
                self._sources[api_key] = DataSource(
                    api_key=api_key,
                    name=name,
                    source_type=self._infer_type(name),
                )
            logger.info(f"SourceRegistry: loaded {len(self._sources)} registered sources")
        except Exception as e:
            logger.warning(f"SourceRegistry: failed to load config: {e}")

    def _infer_type(self, name: str) -> str:
        if "syslog" in name:
            return "syslog"
        if "simulator" in name:
            return "simulator"
        if "api" in name:
            return "api"
        return "generic"

    def register(self, api_key: str, name: str, source_type: str = "generic") -> DataSource:
        """注册新数据源"""
        source = DataSource(
            api_key=api_key,
            name=name,
            source_type=source_type,
        )
        self._sources[api_key] = source
        logger.info(f"SourceRegistry: registered source '{name}' (type={source_type})")
        return source

    def revoke(self, api_key: str) -> bool:
        """吊销数据源"""
        if api_key in self._sources:
            self._sources[api_key].enabled = False
            logger.warning(f"SourceRegistry: revoked source '{self._sources[api_key].name}'")
            return True
        return False

    def authenticate(self, api_key: str) -> Optional[DataSource]:
        """
        验证数据源 API Key

        Returns:
            DataSource if valid, None if rejected
        """
        source = self._sources.get(api_key)
        if source and source.enabled:
            source.last_seen = time.time()
            source.total_events += 1
            return source

        # 记录拒绝
        self._log_rejection(api_key, "invalid_key" if not source else "revoked")
        return None

    def _log_rejection(self, api_key: str, reason: str):
        """记录未认证访问（安全告警）"""
        entry = {
            "api_key_prefix": api_key[:8] + "..." if len(api_key) > 8 else api_key,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._rejection_log.append(entry)
        if len(self._rejection_log) > self._rejection_log_max:
            self._rejection_log = self._rejection_log[-self._rejection_log_max:]
        logger.warning(
            f"SourceRegistry: REJECTED access from key={entry['api_key_prefix']} reason={reason}"
        )

    def list_sources(self) -> list[dict]:
        """列出所有已注册数据源"""
        return [
            {
                "api_key_prefix": s.api_key[:8] + "...",
                "name": s.name,
                "source_type": s.source_type,
                "enabled": s.enabled,
                "total_events": s.total_events,
                "last_seen": s.last_seen,
            }
            for s in self._sources.values()
        ]

    def get_rejection_log(self, limit: int = 50) -> list[dict]:
        """获取最近的拒绝记录（安全审计用）"""
        return self._rejection_log[-limit:]

    def stats(self) -> dict:
        return {
            "registered_sources": len(self._sources),
            "enabled_sources": sum(1 for s in self._sources.values() if s.enabled),
            "total_events": sum(s.total_events for s in self._sources.values()),
            "recent_rejections": len(self._rejection_log),
        }


source_registry = SourceRegistry()
