"""
tls_metadata.py — TLS 会话元数据聚合与综合风险评分

将 tls_parser 解析的 ClientHello / ServerHello / Certificate 信息
聚合为完整的 TlsSession 记录，并计算综合风险评分。

风险维度:
  1. JA3 指纹: 未知/已知恶意指纹
  2. 证书风险: cert_analyzer 评分
  3. 协议版本: TLS 1.0/1.1 降级
  4. SNI 异常: IP 直连、空 SNI、与证书不匹配
  5. 密码套件: 弱密码 (RC4/3DES/NULL/EXPORT)

用法:
    from encrypted_traffic.tls_metadata import tls_metadata
    session = tls_metadata.build_session(client_hello_msg, server_hello_msg, cert_msg)
    risk = tls_metadata.score_session(session)
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

from config import settings
from encrypted_traffic.ja3_fingerprint import ja3_engine
from encrypted_traffic.cert_analyzer import cert_analyzer

logger = logging.getLogger(__name__)

# 弱密码套件关键词
_WEAK_CIPHERS = {"RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "anon"}

# 过时协议版本
_DEPRECATED_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}


@dataclass
class TlsSessionData:
    """聚合后的 TLS 会话数据"""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 443
    sni: str = ""
    ja3_hash: str = ""
    ja3s_hash: str = ""
    ja4_hash: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    alpn: str = ""
    # 证书信息
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_san: list = field(default_factory=list)
    cert_is_self_signed: bool = False
    cert_chain_valid: bool = True
    # 风险
    risk_score: float = 0.0
    risk_reasons: list = field(default_factory=list)
    # 原始
    timestamp: float = 0.0
    sensor_id: str = ""

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "sni": self.sni,
            "ja3_hash": self.ja3_hash,
            "ja3s_hash": self.ja3s_hash,
            "ja4_hash": self.ja4_hash,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "alpn": self.alpn,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_san": self.cert_san,
            "cert_is_self_signed": self.cert_is_self_signed,
            "risk_score": round(self.risk_score, 3),
            "risk_reasons": self.risk_reasons,
        }


class TlsMetadataAggregator:
    """TLS 会话元数据聚合器"""

    def build_session(
        self,
        client_hello_msg=None,
        server_hello_msg=None,
        cert_msg=None,
        src_ip: str = "",
        dst_ip: str = "",
        dst_port: int = 443,
        timestamp: float = 0.0,
    ) -> TlsSessionData:
        """从协议消息聚合 TLS 会话"""
        session = TlsSessionData(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            timestamp=timestamp, sensor_id=settings.sensor_id,
        )

        # ClientHello
        if client_hello_msg and client_hello_msg.raw_meta:
            meta = client_hello_msg.raw_meta
            session.sni = meta.get("sni", "")
            session.tls_version = meta.get("client_version", "")
            session.alpn = ",".join(meta.get("alpn", []))

            # JA3 计算
            ja3_fields = meta.get("ja3_fields", {})
            if ja3_fields:
                session.ja3_hash = ja3_engine.compute_ja3(ja3_fields)
                session.ja4_hash = ja3_engine.compute_ja4(ja3_fields)

        # ServerHello
        if server_hello_msg and server_hello_msg.raw_meta:
            meta = server_hello_msg.raw_meta
            session.tls_version = meta.get("server_version", session.tls_version)
            session.cipher_suite = meta.get("cipher_suite", "")
            if not session.alpn:
                session.alpn = ",".join(meta.get("alpn", []))

            # JA3S
            ja3s_fields = {
                "version": 0x0303,  # 简化
                "cipher_suite_id": meta.get("cipher_suite_id", 0),
                "extensions": [],
            }
            session.ja3s_hash = ja3_engine.compute_ja3s(ja3s_fields)

        # Certificate
        if cert_msg and cert_msg.raw_meta:
            cert_info = cert_msg.raw_meta.get("cert_info", {})
            if cert_info and "error" not in cert_info:
                session.cert_subject = cert_info.get("subject", "")
                session.cert_issuer = cert_info.get("issuer", "")
                session.cert_serial = cert_info.get("serial", "")
                session.cert_not_before = cert_info.get("not_before", "")
                session.cert_not_after = cert_info.get("not_after", "")
                session.cert_san = cert_info.get("san", [])
                session.cert_is_self_signed = cert_info.get("is_self_signed", False)

        return session

    def score_session(self, session: TlsSessionData) -> TlsSessionData:
        """计算综合风险评分"""
        score = 0.0
        reasons = []

        # 1. JA3 指纹风险
        if session.ja3_hash:
            match = ja3_engine.lookup(session.ja3_hash)
            if match:
                if match.get("family"):
                    score += 0.6
                    reasons.append(f"known_malware_ja3:{match['family']}")
                else:
                    score += 0.1
                    reasons.append("known_ja3")
            else:
                score += settings.tls_risk_unknown_ja3
                reasons.append("unknown_ja3")

        # 2. 证书风险
        cert_info = {
            "subject": session.cert_subject,
            "issuer": session.cert_issuer,
            "not_before": session.cert_not_before,
            "not_after": session.cert_not_after,
            "san": session.cert_san,
            "is_self_signed": session.cert_is_self_signed,
        }
        cert_report = cert_analyzer.analyze(cert_info)
        if cert_report.risk_score > 0:
            score += cert_report.risk_score * 0.5  # 证书权重 50%
            reasons.extend(cert_report.reasons)

        # 3. 协议版本风险
        if session.tls_version in _DEPRECATED_VERSIONS:
            score += 0.3
            reasons.append(f"deprecated_tls:{session.tls_version}")

        # 4. 弱密码套件
        if session.cipher_suite:
            upper = session.cipher_suite.upper()
            for weak in _WEAK_CIPHERS:
                if weak in upper:
                    score += 0.25
                    reasons.append(f"weak_cipher:{weak}")
                    break

        # 5. SNI 异常
        if not session.sni:
            score += 0.15
            reasons.append("empty_sni")
        else:
            # IP 直连（无域名）
            import re
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", session.sni):
                score += 0.3
                reasons.append("ip_direct_sni")

            # SNI 与证书 SAN 不匹配
            if session.cert_san and session.sni:
                matched = any(
                    session.sni == san or
                    (san.startswith("*.") and session.sni.endswith(san[1:]))
                    for san in session.cert_san
                )
                if not matched:
                    score += 0.2
                    reasons.append("sni_cert_mismatch")

        session.risk_score = min(score, 1.0)
        session.risk_reasons = reasons
        return session


# ── 全局单例 ──
tls_metadata = TlsMetadataAggregator()
