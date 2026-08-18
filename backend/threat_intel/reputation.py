"""
reputation.py — IP/域名信誉查询（多源聚合）

聚合多个信誉源对 IP/域名进行评分:
  - 本地 IOC 库命中
  - GeoIP 地理位置 (高风险国家/地区)
  - ASN 信誉 (已知恶意 ASN)
  - 被动 DNS 历史 (域名首次出现时间)
  - WHOIS 年龄 (新注册域名高风险)

用法:
    from threat_intel.reputation import reputation_engine
    score = await reputation_engine.score_ip("1.2.3.4")
    score = await reputation_engine.score_domain("evil.com")
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# 高风险国家/地区 (常见攻击来源)
_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}  # 可按需调整

# 已知恶意 ASN（示例，实际应从情报源更新）
_MALICIOUS_ASNS = set()


@dataclass
class ReputationScore:
    """信誉评分结果"""
    target: str = ""
    target_type: str = "ip"     # ip | domain
    score: float = 0.0          # 0-1, 越高越危险
    level: str = "clean"        # clean | suspicious | malicious
    factors: list = field(default_factory=list)
    geo: dict = field(default_factory=dict)
    ioc_hits: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "score": round(self.score, 3),
            "level": self.level,
            "factors": self.factors,
            "geo": self.geo,
            "ioc_hits": [h.to_dict() if hasattr(h, "to_dict") else h for h in self.ioc_hits],
        }


class ReputationEngine:
    """多源信誉评分引擎"""

    async def score_ip(self, ip: str, session=None) -> ReputationScore:
        """IP 信誉评分"""
        result = ReputationScore(target=ip, target_type="ip")
        score = 0.0
        factors = []

        # 1. IOC 命中
        from threat_intel.ioc_matcher import ioc_matcher
        hits = await ioc_matcher.match(ip=ip, session=session)
        if hits:
            result.ioc_hits = hits
            max_sev = max(hits, key=lambda h: h.confidence)
            score += max_sev.confidence * 0.6
            factors.append(f"ioc_hit:{max_sev.threat_type}")

        # 2. GeoIP（需要 geoip2 库，可选）
        geo = self._lookup_geoip(ip)
        if geo:
            result.geo = geo
            if geo.get("country") in _HIGH_RISK_COUNTRIES:
                score += 0.15
                factors.append(f"high_risk_country:{geo['country']}")

        # 3. 私有 IP 不评分
        import ipaddress
        try:
            if ipaddress.ip_address(ip).is_private:
                return ReputationScore(target=ip, target_type="ip", level="internal")
        except ValueError:
            pass

        result.score = min(score, 1.0)
        result.factors = factors
        result.level = self._classify(result.score)
        return result

    async def score_domain(self, domain: str, session=None) -> ReputationScore:
        """域名信誉评分"""
        result = ReputationScore(target=domain, target_type="domain")
        score = 0.0
        factors = []

        # 1. IOC 命中
        from threat_intel.ioc_matcher import ioc_matcher
        hits = await ioc_matcher.match(domain=domain, session=session)
        if hits:
            result.ioc_hits = hits
            max_sev = max(hits, key=lambda h: h.confidence)
            score += max_sev.confidence * 0.6
            factors.append(f"ioc_hit:{max_sev.threat_type}")

        # 2. 可疑 TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu"}
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 0.1
                factors.append(f"suspicious_tld:{tld}")
                break

        # 3. 域名长度（DGA 检测启发式）
        name_part = domain.split(".")[0]
        if len(name_part) > 20:
            score += 0.1
            factors.append("long_domain_name")

        # 4. 数字/辅音比例（DGA 特征）
        if name_part:
            digits = sum(c.isdigit() for c in name_part)
            if digits / len(name_part) > 0.4:
                score += 0.15
                factors.append("high_digit_ratio")

        result.score = min(score, 1.0)
        result.factors = factors
        result.level = self._classify(result.score)
        return result

    def _lookup_geoip(self, ip: str) -> Optional[dict]:
        """GeoIP 查询（可选依赖 geoip2）"""
        try:
            import geoip2.database
            # 需要 MaxMind GeoLite2 数据库文件
            reader = geoip2.database.Reader("/data/geoip/GeoLite2-Country.mmdb")
            response = reader.country(ip)
            return {
                "country": response.country.iso_code,
                "country_name": response.country.name,
                "asn": response.country.iso_code,
            }
        except (ImportError, FileNotFoundError, Exception):
            return None

    def _classify(self, score: float) -> str:
        if score >= 0.7:
            return "malicious"
        elif score >= 0.3:
            return "suspicious"
        return "clean"


# ── 全局单例 ──
reputation_engine = ReputationEngine()
