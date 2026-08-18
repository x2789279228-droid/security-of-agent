"""
dissector.py — 协议分发器

根据目标端口和 payload 特征自动识别应用层协议，
将 PacketInfo 分发给对应的协议解析器。

识别策略:
  1. 端口映射: 80→HTTP, 53→DNS, 443→TLS, 445→SMB
  2. Payload 特征: GET/POST→HTTP, 0x16 0x03→TLS, 0xFE 'S' 'M' 'B'→SMB
  3. 回退: 未识别 → raw 存储

用法:
    from protocol_parser.dissector import dissector
    capture_engine.register_handler(dissector.on_packet)
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ProtocolMessage:
    """解析后的协议消息"""
    protocol: str              # HTTP | DNS | TLS | SMB | FTP | SSH | UNKNOWN
    direction: str = ""        # request | response
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    timestamp: float = 0.0
    # 通用字段
    method: str = ""           # HTTP method / DNS query type / SMB command
    host: str = ""             # HTTP Host / DNS query name
    uri: str = ""              # HTTP URI
    status_code: int = 0       # HTTP status / DNS rcode
    content_type: str = ""
    user_agent: str = ""
    payload_size: int = 0
    # 协议特定字段
    headers: dict = field(default_factory=dict)
    body_preview: str = ""     # 前 512 字节
    raw_meta: dict = field(default_factory=dict)  # 协议特定元数据

    def to_dict(self) -> dict:
        d = {
            "protocol": self.protocol,
            "direction": self.direction,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "timestamp": self.timestamp,
            "method": self.method,
            "host": self.host,
            "uri": self.uri,
            "status_code": self.status_code,
            "payload_size": self.payload_size,
        }
        if self.headers:
            d["headers"] = self.headers
        if self.body_preview:
            d["body_preview"] = self.body_preview[:512]
        if self.raw_meta:
            d["meta"] = self.raw_meta
        return d


# 端口 → 协议映射
_PORT_PROTOCOL = {
    80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8888: "HTTP", 3000: "HTTP",
    443: "TLS", 8443: "TLS",
    53: "DNS",
    445: "SMB", 139: "SMB",
    21: "FTP",
    22: "SSH",
    25: "SMTP", 587: "SMTP",
    3389: "RDP",
    3306: "MySQL", 5432: "PostgreSQL",
}

# Payload 魔数识别
_PAYLOAD_SIGNATURES = [
    (b"\x16\x03", "TLS"),           # TLS Handshake
    (b"\xfe\x53\x4d\x42", "SMB"),   # SMB2 magic: \xFE S M B
    (b"\xff\x53\x4d\x42", "SMB"),   # SMB1 magic: \xFF S M B
]

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                 b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
_HTTP_RESPONSE = b"HTTP/1."


def identify_protocol(dst_port: int, src_port: int, payload: bytes) -> str:
    """根据端口和 payload 识别应用层协议"""
    # 1. Payload 特征优先
    if payload:
        for sig, proto in _PAYLOAD_SIGNATURES:
            if payload[:len(sig)] == sig:
                return proto
        # HTTP 请求
        for method in _HTTP_METHODS:
            if payload[:len(method)] == method:
                return "HTTP"
        # HTTP 响应
        if payload[:8] == _HTTP_RESPONSE:
            return "HTTP"

    # 2. 端口映射
    proto = _PORT_PROTOCOL.get(dst_port, "")
    if proto:
        return proto
    proto = _PORT_PROTOCOL.get(src_port, "")
    if proto:
        return proto

    return "UNKNOWN"


class ProtocolDissector:
    """
    协议分发器

    注册为 CaptureEngine 的包处理器，
    识别协议后分发给对应的解析器。
    """

    def __init__(self):
        self._parsers = {}  # protocol → parser instance
        self._message_callbacks: list = []
        self._stats = {"total": 0, "parsed": 0, "unknown": 0}

    def register_parser(self, protocol: str, parser):
        """注册协议解析器: parser.parse(pkt) → ProtocolMessage | None"""
        self._parsers[protocol] = parser
        logger.info("注册协议解析器: %s → %s", protocol, parser.__class__.__name__)

    def on_message(self, callback):
        """注册消息回调: async def cb(msg: ProtocolMessage)"""
        self._message_callbacks.append(callback)

    async def on_packet(self, pkt) -> None:
        """包处理入口"""
        self._stats["total"] += 1

        protocol = identify_protocol(pkt.dst_port, pkt.src_port, pkt.payload)
        if protocol == "UNKNOWN":
            self._stats["unknown"] += 1
            return

        parser = self._parsers.get(protocol)
        if parser is None:
            return

        try:
            msg = parser.parse(pkt)
            if msg is None:
                return
            msg.src_ip = pkt.src_ip
            msg.dst_ip = pkt.dst_ip
            msg.src_port = pkt.src_port
            msg.dst_port = pkt.dst_port
            msg.timestamp = pkt.timestamp
            msg.payload_size = len(pkt.payload)

            self._stats["parsed"] += 1
            for cb in self._message_callbacks:
                try:
                    await cb(msg)
                except Exception as e:
                    logger.warning("协议消息回调异常: %s", e)
        except Exception as e:
            logger.debug("协议解析异常 [%s]: %s", protocol, e)

    def get_stats(self) -> dict:
        return dict(self._stats)


# ── 全局单例 ──
dissector = ProtocolDissector()
