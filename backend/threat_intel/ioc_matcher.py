"""
ioc_matcher.py — IOC 实时匹配引擎

将安全事件中的 IP/域名/哈希/URL 与 threat_iocs 表进行实时匹配。
使用内存缓存 + Redis 加速，避免每次查询都命中 PostgreSQL。

匹配策略:
  - 精确匹配: IP / 哈希 / 域名
  - CIDR 匹配: IP 属于已知恶意网段
  - 域名通配: *.evil.com 匹配 sub.evil.com

用法:
    from threat_intel.ioc_matcher import ioc_matcher
    hits = await ioc_matcher.match(ip="1.2.3.4", domain="evil.com")
"""
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class IocHit:
    """IOC 命中结果"""
    ioc_type: str
    ioc_value: str
    threat_type: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    source: str = ""
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "context": self.context,
        }


class IocMatcher:
    """IOC 匹配引擎（内存缓存 + DB 回源）"""

    def __init__(self):
        self.threshold = settings.ioc_match_threshold
        # 内存缓存: {ioc_value: IocHit}
        self._cache: dict[str, IocHit] = {}
        self._cidr_cache: list[tuple[ipaddress.IPv4Network, IocHit]] = []
        self._domain_suffix: dict[str, IocHit] = {}  # .evil.com → hit
        self._last_refresh = 0.0
        self._refresh_interval = 300  # 5 分钟刷新

    async def refresh_cache(self, session=None):
        """从 PostgreSQL 刷新 IOC 缓存"""
        try:
            if session is None:
                from models import async_session
                async with async_session() as s:
                    await self._load_from_db(s)
            else:
                await self._load_from_db(session)
            self._last_refresh = time.time()
            logger.info(
                "IOC 缓存刷新: %d 精确 + %d CIDR + %d 域名后缀",
                len(self._cache), len(self._cidr_cache), len(self._domain_suffix),
            )
        except Exception as e:
            logger.error("IOC 缓存刷新失败: %s", e)

    async def _load_from_db(self, session):
        """从 threat_iocs 表加载活跃 IOC"""
        from sqlalchemy import select
        from models import ThreatIoc

        result = await session.execute(
            select(ThreatIoc).where(ThreatIoc.is_active == True)
        )
        iocs = result.scalars().all()

        cache = {}
        cidr_cache = []
        domain_suffix = {}

        for ioc in iocs:
            hit = IocHit(
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.ioc_value,
                threat_type=ioc.threat_type,
                severity=ioc.severity,
                confidence=ioc.confidence,
                source=ioc.source,
                context=ioc.context or {},
            )

            if ioc.ioc_type == "cidr":
                try:
                    net = ipaddress.ip_network(ioc.ioc_value, strict=False)
                    cidr_cache.append((net, hit))
                except ValueError:
                    pass
            elif ioc.ioc_type == "domain" and ioc.ioc_value.startswith("*."):
                domain_suffix[ioc.ioc_value[1:]] = hit  # .evil.com
            else:
                cache[ioc.ioc_value.lower()] = hit

        self._cache = cache
        self._cidr_cache = cidr_cache
        self._domain_suffix = domain_suffix

    async def match(
        self,
        ip: str = "",
        domain: str = "",
        file_hash: str = "",
        url: str = "",
        session=None,
    ) -> list[IocHit]:
        """
        多字段 IOC 匹配

        返回所有命中的 IOC（可能多条）
        """
        # 自动刷新缓存
        if time.time() - self._last_refresh > self._refresh_interval:
            await self.refresh_cache(session)

        hits = []

        # IP 精确匹配
        if ip:
            hit = self._cache.get(ip.lower())
            if hit:
                hits.append(hit)
            else:
                # CIDR 匹配
                try:
                    addr = ipaddress.ip_address(ip)
                    for net, cidr_hit in self._cidr_cache:
                        if addr in net:
                            hits.append(cidr_hit)
                            break
                except ValueError:
                    pass

        # 域名匹配
        if domain:
            domain_lower = domain.lower()
            hit = self._cache.get(domain_lower)
            if hit:
                hits.append(hit)
            else:
                # 后缀匹配 (*.evil.com)
                for suffix, s_hit in self._domain_suffix.items():
                    if domain_lower.endswith(suffix):
                        hits.append(s_hit)
                        break

        # 哈希匹配
        if file_hash:
            hit = self._cache.get(file_hash.lower())
            if hit:
                hits.append(hit)

        # URL 匹配
        if url:
            hit = self._cache.get(url.lower())
            if hit:
                hits.append(hit)

        if hits:
            try:
                from metrics import inc_ioc_match
                inc_ioc_match()
            except Exception:
                pass
        return hits

    @property
    def cache_size(self) -> int:
        return len(self._cache) + len(self._cidr_cache) + len(self._domain_suffix)


# ── 全局单例 ──
ioc_matcher = IocMatcher()
