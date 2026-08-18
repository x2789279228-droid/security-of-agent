"""
ja3_fingerprint.py — JA3 / JA3S / JA4 TLS 指纹计算

JA3:  客户端指纹 = MD5(Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
JA3S: 服务端指纹 = MD5(Version,Cipher,Extensions)
JA4:  新一代指纹，包含更多字段，抗 GREASE 干扰

输入: tls_parser 解析出的 ClientHello / ServerHello 原始字段
输出: 十六进制 MD5 哈希

已知指纹库: 从 CSV 加载 (hash, description, malware_family)

用法:
    from encrypted_traffic.ja3_fingerprint import ja3_engine
    ja3_hash = ja3_engine.compute_ja3(client_hello_fields)
    match = ja3_engine.lookup(ja3_hash)
"""
import hashlib
import logging
import csv
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# GREASE 值（RFC 8701）— 计算指纹时需排除
_GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE_VALUES]


class JA3Engine:
    """JA3 / JA3S / JA4 指纹计算与查询"""

    def __init__(self):
        self._known_db: dict[str, dict] = {}  # hash → {description, family, source}
        self._load_known_db()

    def _load_known_db(self):
        """加载已知 JA3 指纹库 (CSV: hash,description,family,source)"""
        db_path = settings.ja3_db_path
        if not db_path:
            return
        path = Path(db_path)
        if not path.exists():
            logger.warning("JA3 指纹库不存在: %s", db_path)
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    h = row.get("hash", "").strip().lower()
                    if h:
                        self._known_db[h] = {
                            "description": row.get("description", ""),
                            "family": row.get("family", ""),
                            "source": row.get("source", ""),
                        }
            logger.info("加载 JA3 指纹库: %d 条", len(self._known_db))
        except Exception as e:
            logger.error("加载 JA3 指纹库失败: %s", e)

    def compute_ja3(self, fields: dict) -> str:
        """
        计算 JA3 客户端指纹

        fields 来自 tls_parser 的 ja3_fields:
          {version: int, ciphers: [int], extensions: [int],
           curves: [int], point_formats: [int]}
        """
        version = fields.get("version", 0)
        ciphers = _filter_grease(fields.get("ciphers", []))
        extensions = _filter_grease(fields.get("extensions", []))
        curves = _filter_grease(fields.get("curves", fields.get("supported_groups", [])))
        point_formats = fields.get("point_formats", [0])  # 默认 uncompressed

        # JA3 字符串: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        cipher_str = "-".join(str(c) for c in ciphers)
        ext_str = "-".join(str(e) for e in extensions)
        curve_str = "-".join(str(c) for c in curves)
        pf_str = "-".join(str(p) for p in point_formats)

        ja3_string = f"{version},{cipher_str},{ext_str},{curve_str},{pf_str}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        logger.debug("JA3: %s → %s", ja3_string[:80], ja3_hash)
        return ja3_hash

    def compute_ja3s(self, fields: dict) -> str:
        """
        计算 JA3S 服务端指纹

        fields: {version: int, cipher: int, extensions: [int]}
        """
        version = fields.get("version", 0)
        cipher = fields.get("cipher_suite_id", fields.get("cipher", 0))
        extensions = _filter_grease(fields.get("extensions", []))

        ext_str = "-".join(str(e) for e in extensions)
        ja3s_string = f"{version},{cipher},{ext_str}"
        return hashlib.md5(ja3s_string.encode()).hexdigest()

    def compute_ja4(self, fields: dict) -> str:
        """
        计算 JA4 指纹（简化版）

        JA4 = proto + version + cipher_count + ext_count + ALPN + cipher_hash + ext_hash
        """
        version = fields.get("version", 0x0303)
        ciphers = _filter_grease(fields.get("ciphers", []))
        extensions = _filter_grease(fields.get("extensions", []))
        alpn = fields.get("alpn", [])

        # 协议前缀
        proto = "t"  # TCP
        # 版本编码
        ver_map = {0x0300: "s3", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}
        ver = ver_map.get(version, "00")

        cipher_count = min(len(ciphers), 99)
        ext_count = min(len(extensions), 99)
        alpn_str = (alpn[0] if alpn else "00")[:2]

        # 密码套件哈希（前6个hex）
        cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
        cipher_hash = hashlib.sha256(cipher_bytes).hexdigest()[:12]

        # 扩展哈希
        ext_bytes = b"".join(e.to_bytes(2, "big") for e in sorted(extensions))
        ext_hash = hashlib.sha256(ext_bytes).hexdigest()[:12]

        return f"{proto}{ver}{cipher_count:02d}{ext_count:02d}{alpn_str}_{cipher_hash}_{ext_hash}"

    def lookup(self, ja3_hash: str) -> Optional[dict]:
        """查询已知指纹库"""
        return self._known_db.get(ja3_hash.lower())

    def is_known(self, ja3_hash: str) -> bool:
        return ja3_hash.lower() in self._known_db

    @property
    def db_size(self) -> int:
        return len(self._known_db)


# ── 全局单例 ──
ja3_engine = JA3Engine()
