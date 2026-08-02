"""
敏感字段加密模块 (Field Cipher)

对 Kafka 消息中的敏感字段进行应用层加密/解密。
使用 Fernet (AES-128-CBC + HMAC-SHA256) 对称加密方案。

加密字段:
  - apiKey: 数据源认证密钥
  - srcIp / dstIp: IP 地址（可选，通过配置控制）
  - message: 事件描述（可能含敏感信息）

使用方式:
  from field_cipher import field_cipher

  # 生产端：发送前加密
  encrypted_msg = field_cipher.encrypt_message(msg_dict)

  # 消费端：接收后解密
  decrypted_msg = field_cipher.decrypt_message(msg_dict)

密钥管理:
  环境变量 SHARED_MEMORY_FIELD_ENCRYPTION_KEY（Fernet key, base64url 编码）
  生成: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import base64
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography not installed — field encryption disabled")

# 需要加密的字段列表
ENCRYPT_FIELDS = ("apiKey", "srcIp", "dstIp", "message")

# 加密标记前缀（用于识别已加密的值）
ENC_PREFIX = "ENC:"


class FieldCipher:
    """Kafka 消息敏感字段加密器"""

    def __init__(self):
        self._fernet: Optional[object] = None
        self._enabled = False
        self._init_cipher()

    def _init_cipher(self):
        """从环境变量初始化 Fernet 密钥"""
        if not HAS_CRYPTO:
            return
        key = os.environ.get("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", "")
        if not key:
            logger.info("[FieldCipher] No encryption key set — field encryption disabled")
            return
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
            self._enabled = True
            logger.info("[FieldCipher] Field encryption enabled")
        except Exception as e:
            logger.error(f"[FieldCipher] Invalid encryption key: {e}")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def encrypt_value(self, plaintext: str) -> str:
        """加密单个字段值"""
        if not self._enabled or not plaintext:
            return plaintext
        if plaintext.startswith(ENC_PREFIX):
            return plaintext  # 已加密
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return ENC_PREFIX + token.decode("utf-8")

    def decrypt_value(self, ciphertext: str) -> str:
        """解密单个字段值"""
        if not self._enabled or not ciphertext:
            return ciphertext
        if not ciphertext.startswith(ENC_PREFIX):
            return ciphertext  # 未加密的值
        token = ciphertext[len(ENC_PREFIX):]
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except (InvalidToken, Exception) as e:
            logger.warning(f"[FieldCipher] Decrypt failed: {e}")
            return ciphertext

    def encrypt_message(self, msg: dict) -> dict:
        """加密消息中的敏感字段（生产端调用）"""
        if not self._enabled:
            return msg
        result = dict(msg)
        for field in ENCRYPT_FIELDS:
            if field in result and isinstance(result[field], str) and result[field]:
                result[field] = self.encrypt_value(result[field])
        # rawData 中的敏感字段也加密
        if "rawData" in result and isinstance(result["rawData"], dict):
            raw = dict(result["rawData"])
            for field in ("src_ip", "dst_ip", "message"):
                if field in raw and isinstance(raw[field], str) and raw[field]:
                    raw[field] = self.encrypt_value(raw[field])
            result["rawData"] = raw
        return result

    def decrypt_message(self, msg: dict) -> dict:
        """解密消息中的敏感字段（消费端调用）"""
        if not self._enabled:
            return msg
        result = dict(msg)
        for field in ENCRYPT_FIELDS:
            if field in result and isinstance(result[field], str) and result[field]:
                result[field] = self.decrypt_value(result[field])
        # rawData 中的敏感字段也解密
        if "rawData" in result and isinstance(result["rawData"], dict):
            raw = dict(result["rawData"])
            for field in ("src_ip", "dst_ip", "message"):
                if field in raw and isinstance(raw[field], str) and raw[field]:
                    raw[field] = self.decrypt_value(raw[field])
            result["rawData"] = raw
        return result


field_cipher = FieldCipher()
