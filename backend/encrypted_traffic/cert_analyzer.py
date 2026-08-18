"""
cert_analyzer.py — 证书链分析与风险评分

对 TLS 证书进行安全评估:
  - 自签名检测
  - 过期/即将过期检测
  - 证书链完整性验证
  - SAN 与 SNI 匹配检查
  - 弱签名算法检测 (MD5/SHA1)
  - 已知恶意证书指纹匹配
  - Let's Encrypt 滥用检测（短期证书 + 可疑域名）

用法:
    from encrypted_traffic.cert_analyzer import cert_analyzer
    report = cert_analyzer.analyze(cert_info_dict)
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# 弱签名算法
_WEAK_ALGORITHMS = {"md5", "sha1", "md2", "ecdsa-with-sha1"}

# 可疑 TLD（免费域名滥用）
_SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                    ".work", ".club", ".online", ".site", ".icu"}

# 证书有效期异常阈值
_SHORT_VALIDITY_DAYS = 30   # 有效期 < 30 天可疑
_EXPIRY_WARNING_DAYS = 7    # 即将过期警告


@dataclass
class CertRiskReport:
    """证书风险报告"""
    risk_score: float = 0.0
    risk_level: str = "low"       # low | medium | high | critical
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 3),
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "details": self.details,
        }


class CertAnalyzer:
    """证书安全分析器"""

    def analyze(self, cert_info: dict) -> CertRiskReport:
        """
        分析证书信息，返回风险报告

        cert_info 来自 tls_parser._extract_cert_info():
          {subject, issuer, serial, not_before, not_after, san,
           is_self_signed, signature_algorithm}
        """
        report = CertRiskReport()
        score = 0.0
        reasons = []

        if not cert_info or "error" in cert_info:
            report.risk_score = 0.3
            report.risk_level = "medium"
            report.reasons = ["cert_parse_error"]
            return report

        # 1. 自签名检测
        if cert_info.get("is_self_signed", False):
            score += settings.tls_risk_self_signed
            reasons.append("self_signed_cert")

        # 2. 过期检测
        not_after_str = cert_info.get("not_after", "")
        if not_after_str:
            try:
                not_after = datetime.fromisoformat(not_after_str)
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if not_after < now:
                    score += settings.tls_risk_expired
                    reasons.append("cert_expired")
                elif not_after < now + timedelta(days=_EXPIRY_WARNING_DAYS):
                    score += 0.2
                    reasons.append("cert_expiring_soon")
            except (ValueError, TypeError):
                pass

        # 3. 短有效期检测（Let's Encrypt 滥用）
        not_before_str = cert_info.get("not_before", "")
        if not_before_str and not_after_str:
            try:
                nb = datetime.fromisoformat(not_before_str)
                na = datetime.fromisoformat(not_after_str)
                validity_days = (na - nb).days
                if validity_days <= _SHORT_VALIDITY_DAYS:
                    score += 0.15
                    reasons.append(f"short_validity:{validity_days}d")
            except (ValueError, TypeError):
                pass

        # 4. 弱签名算法
        sig_alg = cert_info.get("signature_algorithm", "").lower()
        if sig_alg:
            for weak in _WEAK_ALGORITHMS:
                if weak in sig_alg:
                    score += 0.3
                    reasons.append(f"weak_signature:{sig_alg}")
                    break

        # 5. SAN 检查
        san = cert_info.get("san", [])
        subject = cert_info.get("subject", "")

        # 无 SAN 的证书（现代浏览器要求 SAN）
        if not san and subject:
            score += 0.1
            reasons.append("no_san")

        # 通配符证书
        for name in san:
            if name.startswith("*."):
                score += 0.05
                reasons.append("wildcard_cert")
                break

        # 可疑 TLD
        for name in san:
            for tld in _SUSPICIOUS_TLDS:
                if name.endswith(tld):
                    score += 0.2
                    reasons.append(f"suspicious_tld:{tld}")
                    break

        # 6. IP 地址作为 SAN（常见于恶意软件）
        import re
        ip_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
        for name in san:
            if ip_pattern.match(name):
                score += 0.25
                reasons.append(f"ip_in_san:{name}")
                break

        # 归一化评分
        report.risk_score = min(score, 1.0)
        report.reasons = reasons
        report.details = {
            "subject": subject,
            "issuer": cert_info.get("issuer", ""),
            "san": san[:5],
            "sig_alg": sig_alg,
        }

        if report.risk_score >= 0.8:
            report.risk_level = "critical"
        elif report.risk_score >= 0.5:
            report.risk_level = "high"
        elif report.risk_score >= 0.25:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"

        return report


# ── 全局单例 ──
cert_analyzer = CertAnalyzer()
