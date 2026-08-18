"""
intel_enricher.py — 事件情报富化

将 IOC 匹配和信誉评分结果附加到安全事件/网络流/TLS 会话上，
实现检测与情报的自动联动。

富化点:
  - SecurityEvent: src_ip / dst_ip 信誉 + IOC 命中
  - NetworkFlow: 五元组 IOC 匹配 + GeoIP
  - TlsSession: SNI 域名信誉 + JA3 情报
  - EdrEvent: 进程哈希 IOC + 外联 IP 信誉

用法:
    from threat_intel.intel_enricher import intel_enricher
    enriched = await intel_enricher.enrich_event(session, event_dict)
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


class IntelEnricher:
    """事件情报富化器"""

    def __init__(self):
        self.enabled = settings.intel_enabled

    async def enrich_event(self, session, event: dict) -> dict:
        """富化安全事件"""
        if not self.enabled:
            return event

        from threat_intel.ioc_matcher import ioc_matcher
        from threat_intel.reputation import reputation_engine

        enrichment = {}

        # IP IOC + 信誉
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")

        if src_ip:
            hits = await ioc_matcher.match(ip=src_ip, session=session)
            if hits:
                enrichment["src_ip_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_ip(src_ip, session=session)
            enrichment["src_ip_reputation"] = rep.to_dict()

        if dst_ip:
            hits = await ioc_matcher.match(ip=dst_ip, session=session)
            if hits:
                enrichment["dst_ip_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_ip(dst_ip, session=session)
            enrichment["dst_ip_reputation"] = rep.to_dict()

        # 域名 IOC
        domain = event.get("host", event.get("sni", ""))
        if domain:
            hits = await ioc_matcher.match(domain=domain, session=session)
            if hits:
                enrichment["domain_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_domain(domain, session=session)
            enrichment["domain_reputation"] = rep.to_dict()

        # 哈希 IOC
        file_hash = event.get("image_hash", event.get("sample_hash", ""))
        if file_hash:
            hits = await ioc_matcher.match(file_hash=file_hash, session=session)
            if hits:
                enrichment["hash_ioc"] = [h.to_dict() for h in hits]

        if enrichment:
            event.setdefault("raw_data", {})
            event["raw_data"]["threat_intel"] = enrichment

            # 提升严重度
            max_score = max(
                (r.get("score", 0) for r in enrichment.values()
                 if isinstance(r, dict) and "score" in r),
                default=0,
            )
            if max_score >= 0.7 and event.get("severity") in ("info", "low"):
                event["severity"] = "high"
                logger.info(
                    "情报富化提升严重度: %s → high (score=%.2f)",
                    event.get("event_type", ""), max_score,
                )

        return event

    async def enrich_flow(self, session, flow: dict) -> dict:
        """富化网络流"""
        if not self.enabled:
            return flow

        from threat_intel.ioc_matcher import ioc_matcher

        hits = await ioc_matcher.match(
            ip=flow.get("dst_ip", ""),
            domain=flow.get("app_protocol", "") if flow.get("app_protocol") == "DNS" else "",
            session=session,
        )
        if hits:
            flow.setdefault("raw_data", {})
            flow["raw_data"]["ioc_hits"] = [h.to_dict() for h in hits]

        return flow


# ── 全局单例 ──
intel_enricher = IntelEnricher()
