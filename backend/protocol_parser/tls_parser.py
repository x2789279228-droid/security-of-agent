"""
tls_parser.py — TLS 握手解析

从 TCP payload 中解析 TLS 握手报文:
  - ClientHello: 版本、密码套件、扩展（SNI / ALPN / supported_groups）、
                 JA3 指纹原始字段
  - ServerHello: 选定版本、密码套件、ALPN
  - Certificate: 证书链（subject / issuer / SAN / 有效期）

纯字节解析，遵循 RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2)。
JA3 指纹计算委托给 encrypted_traffic.ja3_fingerprint。
"""
import logging
import struct
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# TLS Content Type
_CT_HANDSHAKE = 0x16
_CT_ALERT = 0x15

# Handshake Type
_HT_CLIENT_HELLO = 0x01
_HT_SERVER_HELLO = 0x02
_HT_CERTIFICATE = 0x0B

# TLS 版本映射
_VERSION_MAP = {
    0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}

# 扩展类型
_EXT_SERVER_NAME = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B

# 密码套件名称（常见子集）
_CIPHER_MAP = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}


def _parse_extensions(data: bytes) -> dict:
    """解析 TLS 扩展字段"""
    result = {}
    offset = 0
    while offset + 4 <= len(data):
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        ext_data = data[offset:offset + ext_len]
        offset += ext_len

        if ext_type == _EXT_SERVER_NAME:
            # SNI: list_len(2) → type(1) + name_len(2) + name
            if len(ext_data) >= 5:
                name_len = struct.unpack("!H", ext_data[3:5])[0]
                result["sni"] = ext_data[5:5 + name_len].decode("ascii", errors="replace")

        elif ext_type == _EXT_ALPN:
            # ALPN: list_len(2) → [proto_len(1) + proto]*
            protos = []
            pos = 2
            while pos < len(ext_data):
                plen = ext_data[pos]
                pos += 1
                protos.append(ext_data[pos:pos + plen].decode("ascii", errors="replace"))
                pos += plen
            result["alpn"] = protos

        elif ext_type == _EXT_SUPPORTED_GROUPS:
            if len(ext_data) >= 2:
                glen = struct.unpack("!H", ext_data[:2])[0]
                groups = []
                for i in range(2, min(2 + glen, len(ext_data)), 2):
                    groups.append(struct.unpack("!H", ext_data[i:i + 2])[0])
                result["supported_groups"] = groups

        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            versions = []
            if ext_data and ext_data[0] == len(ext_data) - 1:
                for i in range(1, len(ext_data), 2):
                    if i + 2 <= len(ext_data):
                        versions.append(
                            _VERSION_MAP.get(
                                struct.unpack("!H", ext_data[i:i + 2])[0], ""
                            )
                        )
            result["supported_versions"] = versions

    return result


class TlsParser:
    """TLS 握手解析器"""

    def parse(self, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        payload = pkt.payload
        if not payload or len(payload) < 6:
            return None

        # TLS Record: type(1) version(2) length(2)
        content_type = payload[0]
        if content_type != _CT_HANDSHAKE:
            return None

        record_version = struct.unpack("!H", payload[1:3])[0]
        # record_length = struct.unpack("!H", payload[3:5])[0]

        # Handshake: type(1) length(3)
        offset = 5
        if offset >= len(payload):
            return None
        hs_type = payload[offset]

        if hs_type == _HT_CLIENT_HELLO:
            return self._parse_client_hello(payload, offset, pkt)
        elif hs_type == _HT_SERVER_HELLO:
            return self._parse_server_hello(payload, offset, pkt)
        elif hs_type == _HT_CERTIFICATE:
            return self._parse_certificate(payload, offset, pkt)
        return None

    def _parse_client_hello(self, payload: bytes, offset: int, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            # hs_type(1) + length(3) + client_version(2) + random(32)
            offset += 4  # skip hs header
            client_version = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2 + 32  # skip version + random

            # session_id
            sid_len = payload[offset]
            offset += 1 + sid_len

            # cipher_suites
            cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2
            cipher_suites = []
            for i in range(offset, min(offset + cs_len, len(payload)), 2):
                cs = struct.unpack("!H", payload[i:i + 2])[0]
                cipher_suites.append(cs)
            offset += cs_len

            # compression_methods
            if offset >= len(payload):
                return self._build_client_msg(client_version, cipher_suites, {}, pkt)
            comp_len = payload[offset]
            offset += 1 + comp_len

            # extensions
            extensions = {}
            if offset + 2 <= len(payload):
                ext_total_len = struct.unpack("!H", payload[offset:offset + 2])[0]
                offset += 2
                extensions = _parse_extensions(payload[offset:offset + ext_total_len])

            return self._build_client_msg(client_version, cipher_suites, extensions, pkt)
        except Exception as e:
            logger.debug("ClientHello 解析失败: %s", e)
            return None

    def _build_client_msg(self, version: int, ciphers: list, extensions: dict, pkt) -> "ProtocolMessage":
        from protocol_parser.dissector import ProtocolMessage

        cipher_names = [_CIPHER_MAP.get(c, f"0x{c:04X}") for c in ciphers[:20]]
        sni = extensions.get("sni", "")
        alpn_list = extensions.get("alpn", [])

        return ProtocolMessage(
            protocol="TLS",
            direction="request",
            method="ClientHello",
            host=sni,
            raw_meta={
                "client_version": _VERSION_MAP.get(version, f"0x{version:04X}"),
                "cipher_suites": cipher_names,
                "cipher_suite_ids": ciphers[:20],
                "sni": sni,
                "alpn": alpn_list,
                "supported_groups": extensions.get("supported_groups", []),
                "supported_versions": extensions.get("supported_versions", []),
                # JA3 原始字段（供 ja3_fingerprint 计算）
                "ja3_fields": {
                    "version": version,
                    "ciphers": ciphers,
                    "extensions": list(extensions.keys()) if isinstance(extensions, dict) else [],
                },
            },
        )

    def _parse_server_hello(self, payload: bytes, offset: int, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            offset += 4  # skip hs header
            server_version = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2 + 32  # skip version + random

            sid_len = payload[offset]
            offset += 1 + sid_len

            cipher_suite = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2

            comp_method = payload[offset] if offset < len(payload) else 0
            offset += 1

            extensions = {}
            if offset + 2 <= len(payload):
                ext_total_len = struct.unpack("!H", payload[offset:offset + 2])[0]
                offset += 2
                extensions = _parse_extensions(payload[offset:offset + ext_total_len])

            # TLS 1.3 版本在 supported_versions 扩展中
            actual_version = _VERSION_MAP.get(server_version, f"0x{server_version:04X}")
            sv = extensions.get("supported_versions", [])
            if sv:
                actual_version = sv[0]

            return ProtocolMessage(
                protocol="TLS",
                direction="response",
                method="ServerHello",
                raw_meta={
                    "server_version": actual_version,
                    "cipher_suite": _CIPHER_MAP.get(cipher_suite, f"0x{cipher_suite:04X}"),
                    "cipher_suite_id": cipher_suite,
                    "compression": comp_method,
                    "alpn": extensions.get("alpn", []),
                },
            )
        except Exception as e:
            logger.debug("ServerHello 解析失败: %s", e)
            return None

    def _parse_certificate(self, payload: bytes, offset: int, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            offset += 4  # skip hs header
            # certs_length(3)
            if offset + 3 > len(payload):
                return None
            certs_total = int.from_bytes(payload[offset:offset + 3], "big")
            offset += 3

            certs_raw = []
            end = min(offset + certs_total, len(payload))
            while offset + 3 <= end:
                cert_len = int.from_bytes(payload[offset:offset + 3], "big")
                offset += 3
                cert_der = payload[offset:offset + cert_len]
                offset += cert_len
                certs_raw.append(cert_der)

            # 尝试用 cryptography 解析第一张证书
            cert_info = {}
            if certs_raw:
                cert_info = self._extract_cert_info(certs_raw[0])

            return ProtocolMessage(
                protocol="TLS",
                direction="response",
                method="Certificate",
                raw_meta={
                    "cert_count": len(certs_raw),
                    "cert_info": cert_info,
                },
            )
        except Exception as e:
            logger.debug("Certificate 解析失败: %s", e)
            return None

    def _extract_cert_info(self, der: bytes) -> dict:
        """从 DER 证书中提取关键字段"""
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            san = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "san": san[:10],
                "is_self_signed": cert.subject == cert.issuer,
                "signature_algorithm": cert.signature_algorithm_oid._name,
            }
        except ImportError:
            return {"error": "cryptography library not installed"}
        except Exception as e:
            return {"error": str(e)}


# ── 全局单例 ──
tls_parser = TlsParser()
