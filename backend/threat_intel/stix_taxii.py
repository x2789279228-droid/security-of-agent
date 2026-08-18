"""
stix_taxii.py — TAXII 2.1 客户端与 STIX Bundle 解析

支持:
  - TAXII 2.1 Server 发现与 Collection 枚举
  - 增量拉取 (since 参数)
  - STIX 2.1 Bundle 解析 → IOC 提取
  - MISP REST API 对接 (events/restSearch)
  - CSV / STIX Bundle 文件导入

用法:
    from threat_intel.stix_taxii import taxii_client
    iocs = await taxii_client.poll_feed(feed_config)
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# STIX 2.1 IOC 类型映射
_STIX_IOC_MAP = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "file": "file_hash",
    "email-addr": "email",
}


class TaxiiClient:
    """TAXII 2.1 / MISP 情报拉取客户端"""

    def __init__(self):
        self.misp_url = settings.misp_url
        self.misp_api_key = settings.misp_api_key
        self.misp_verify_ssl = settings.misp_verify_ssl
        self.taxii_url = settings.taxii_url
        self.taxii_user = settings.taxii_user
        self.taxii_password = settings.taxii_password

    async def poll_feed(self, feed_config: dict) -> list[dict]:
        """
        根据 feed 配置拉取 IOC

        feed_config: {feed_type, url, api_key, collection, ...}
        返回: [{ioc_type, ioc_value, threat_type, severity, source, ...}]
        """
        feed_type = feed_config.get("feed_type", "taxii")

        if feed_type == "taxii":
            return await self._poll_taxii(feed_config)
        elif feed_type == "misp":
            return await self._poll_misp(feed_config)
        elif feed_type == "csv":
            return await self._import_csv(feed_config)
        elif feed_type == "stix_bundle":
            return await self._import_stix_bundle(feed_config)
        else:
            logger.warning("不支持的情报源类型: %s", feed_type)
            return []

    async def _poll_taxii(self, config: dict) -> list[dict]:
        """TAXII 2.1 拉取"""
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp 未安装")
            return []

        url = config.get("url", self.taxii_url)
        collection = config.get("collection", "")
        since = config.get("since", "")

        if not url:
            return []

        headers = {"Accept": "application/taxii+json;version=2.1"}
        auth = None
        user = config.get("user", self.taxii_user)
        pwd = config.get("password", self.taxii_password)
        if user and pwd:
            auth = aiohttp.BasicAuth(user, pwd)

        iocs = []
        try:
            async with aiohttp.ClientSession(auth=auth) as session:
                # 获取 objects
                objects_url = f"{url.rstrip('/')}/collections/{collection}/objects/"
                params = {}
                if since:
                    params["added_after"] = since

                async with session.get(
                    objects_url, headers=headers, params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("TAXII 拉取失败: HTTP %d", resp.status)
                        return []
                    data = await resp.json()

                    for obj in data.get("objects", []):
                        parsed = self._parse_stix_object(obj, config.get("name", "taxii"))
                        iocs.extend(parsed)

            logger.info("TAXII 拉取: %d 条 IOC", len(iocs))
        except Exception as e:
            logger.error("TAXII 拉取异常: %s", e)

        return iocs

    async def _poll_misp(self, config: dict) -> list[dict]:
        """MISP REST API 拉取"""
        try:
            import aiohttp
        except ImportError:
            return []

        url = config.get("url", self.misp_url)
        api_key = config.get("api_key", self.misp_api_key)
        if not url or not api_key:
            return []

        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                body = {
                    "returnFormat": "json",
                    "last": "1d",
                    "published": True,
                }
                ssl_ctx = None if not self.misp_verify_ssl else False

                async with session.post(
                    f"{url.rstrip('/')}/attributes/restSearch",
                    headers=headers,
                    json=body,
                    ssl=ssl_ctx,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("MISP 拉取失败: HTTP %d", resp.status)
                        return []
                    data = await resp.json()

                    for attr in data.get("response", []):
                        a = attr.get("Attribute", attr)
                        ioc = self._misp_attr_to_ioc(a, config.get("name", "misp"))
                        if ioc:
                            iocs.append(ioc)

            logger.info("MISP 拉取: %d 条 IOC", len(iocs))
        except Exception as e:
            logger.error("MISP 拉取异常: %s", e)

        return iocs

    async def _import_csv(self, config: dict) -> list[dict]:
        """CSV 文件导入 (每行一个 IOC)"""
        import csv
        from pathlib import Path

        file_path = config.get("url", "")
        if not file_path or not Path(file_path).exists():
            return []

        iocs = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ioc_type = row.get("type", row.get("ioc_type", "ip"))
                    ioc_value = row.get("value", row.get("ioc_value", ""))
                    if ioc_value:
                        iocs.append({
                            "ioc_type": ioc_type,
                            "ioc_value": ioc_value.strip(),
                            "threat_type": row.get("threat_type", ""),
                            "severity": row.get("severity", "medium"),
                            "source": config.get("name", "csv"),
                        })
        except Exception as e:
            logger.error("CSV 导入失败: %s", e)

        return iocs

    async def _import_stix_bundle(self, config: dict) -> list[dict]:
        """STIX Bundle JSON 文件导入"""
        from pathlib import Path

        file_path = config.get("url", "")
        if not file_path or not Path(file_path).exists():
            return []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            iocs = []
            for obj in bundle.get("objects", []):
                parsed = self._parse_stix_object(obj, config.get("name", "stix"))
                iocs.extend(parsed)
            return iocs
        except Exception as e:
            logger.error("STIX Bundle 导入失败: %s", e)
            return []

    def _parse_stix_object(self, obj: dict, source: str) -> list[dict]:
        """解析单个 STIX 对象为 IOC"""
        iocs = []
        obj_type = obj.get("type", "")

        if obj_type == "indicator":
            # STIX Indicator — 从 pattern 中提取
            pattern = obj.get("pattern", "")
            labels = obj.get("labels", [])
            severity = "high" if "malicious-activity" in labels else "medium"

            # 简单 pattern 解析: [ipv4-addr:value = '1.2.3.4']
            import re
            for match in re.finditer(r"(\w[\w-]*):value\s*=\s*'([^']+)'", pattern):
                stix_type, value = match.groups()
                ioc_type = _STIX_IOC_MAP.get(stix_type, stix_type)
                iocs.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "threat_type": labels[0] if labels else "",
                    "severity": severity,
                    "confidence": obj.get("confidence", 50) / 100,
                    "source": source,
                    "stix_id": obj.get("id", ""),
                    "mitre_attack_id": "",
                })

        elif obj_type in _STIX_IOC_MAP:
            # 直接可观察对象
            ioc_type = _STIX_IOC_MAP[obj_type]
            value = obj.get("value", "")
            if obj_type == "file":
                hashes = obj.get("hashes", {})
                value = hashes.get("SHA-256", hashes.get("MD5", ""))
            if value:
                iocs.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "threat_type": "",
                    "severity": "medium",
                    "source": source,
                    "stix_id": obj.get("id", ""),
                })

        return iocs

    def _misp_attr_to_ioc(self, attr: dict, source: str) -> Optional[dict]:
        """MISP Attribute → IOC"""
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        if not value:
            return None

        type_map = {
            "ip-dst": "ip", "ip-src": "ip",
            "domain": "domain", "hostname": "domain",
            "url": "url", "link": "url",
            "md5": "file_hash", "sha1": "file_hash", "sha256": "file_hash",
            "email-src": "email", "email-dst": "email",
        }

        ioc_type = type_map.get(attr_type)
        if not ioc_type:
            return None

        return {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "threat_type": attr.get("category", ""),
            "severity": "high" if attr.get("to_ids") else "medium",
            "confidence": 0.8,
            "source": source,
            "stix_id": "",
        }


# ── 全局单例 ──
taxii_client = TaxiiClient()
