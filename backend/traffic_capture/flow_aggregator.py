"""
flow_aggregator.py — 五元组流聚合器

将 CaptureEngine 产出的逐包 PacketInfo 聚合为网络流 (NetworkFlow)。
聚合键: (src_ip, dst_ip, src_port, dst_port, protocol)

超时策略:
  - 空闲超时: 流在 idle_timeout 秒内无新包 → 关闭
  - 最大存活: 流存活超过 active_timeout → 强制关闭（长连接定期刷新）

数据流:
  PacketInfo → FlowAggregator.on_packet()
             → 聚合到 _active_flows
             → 超时检查 → 关闭流 → emit FlowRecord
             → Kafka (ndr-flows) / PostgreSQL (network_flows)

用法:
    from traffic_capture.flow_aggregator import flow_aggregator
    capture_engine.register_handler(flow_aggregator.on_packet)
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class FlowRecord:
    """聚合完成的流记录"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    direction: str = "outbound"
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    duration_ms: float = 0.0
    tcp_flags: str = ""
    app_protocol: str = ""
    sensor_id: str = ""
    flow_start: float = 0.0
    flow_end: float = 0.0
    packet_count: int = 0

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "direction": self.direction,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "duration_ms": round(self.duration_ms, 2),
            "tcp_flags": self.tcp_flags,
            "app_protocol": self.app_protocol,
            "sensor_id": self.sensor_id,
            "flow_start": datetime.fromtimestamp(
                self.flow_start, tz=timezone.utc
            ).isoformat() if self.flow_start else "",
            "flow_end": datetime.fromtimestamp(
                self.flow_end, tz=timezone.utc
            ).isoformat() if self.flow_end else "",
            "packet_count": self.packet_count,
        }


@dataclass
class _ActiveFlow:
    """内部活跃流状态"""
    key: tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    tcp_flags_seen: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0


# 端口 → 应用协议映射（常见服务）
_PORT_APP_MAP = {
    80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8888: "HTTP",
    443: "TLS", 8443: "TLS",
    53: "DNS",
    22: "SSH",
    21: "FTP", 20: "FTP",
    25: "SMTP", 587: "SMTP", 465: "SMTP",
    110: "POP3", 995: "POP3",
    143: "IMAP", 993: "IMAP",
    3389: "RDP",
    445: "SMB", 139: "SMB",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    9200: "Elasticsearch", 9300: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
    5672: "AMQP", 15672: "AMQP",
    9092: "Kafka",
    123: "NTP",
    161: "SNMP", 162: "SNMP",
    514: "Syslog",
    389: "LDAP", 636: "LDAPS",
    88: "Kerberos",
}

# 私有 IP 段（用于判断方向）
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _guess_direction(src_ip: str, dst_ip: str) -> str:
    src_priv, dst_priv = _is_private(src_ip), _is_private(dst_ip)
    if src_priv and not dst_priv:
        return "outbound"
    if not src_priv and dst_priv:
        return "inbound"
    if src_priv and dst_priv:
        return "lateral"
    return "external"


def _guess_app_protocol(dst_port: int, src_port: int) -> str:
    return _PORT_APP_MAP.get(dst_port, "") or _PORT_APP_MAP.get(src_port, "")


class FlowAggregator:
    """
    五元组流聚合器

    注册为 CaptureEngine 的包处理器，将逐包数据聚合为流记录。
    超时流自动关闭并通过回调输出。
    """

    def __init__(self):
        self.idle_timeout = settings.flow_idle_timeout
        self.active_timeout = settings.flow_active_timeout
        self.sensor_id = settings.sensor_id

        self._active: dict[tuple, _ActiveFlow] = {}
        self._lock = asyncio.Lock()
        self._flush_callbacks: list = []  # async def cb(record: FlowRecord)
        self._flush_task: Optional[asyncio.Task] = None
        self._stats_flushed = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._active)

    def on_flow_complete(self, callback):
        """注册流完成回调: async def cb(record: FlowRecord)"""
        self._flush_callbacks.append(callback)

    async def start(self):
        """启动超时检查循环"""
        self._flush_task = asyncio.create_task(self._timeout_loop())
        logger.info(
            "流聚合器启动: idle_timeout=%ds active_timeout=%ds",
            self.idle_timeout, self.active_timeout,
        )

    async def stop(self):
        """停止并刷新所有活跃流"""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # 强制关闭所有活跃流
        async with self._lock:
            keys = list(self._active.keys())
            for key in keys:
                await self._close_flow(key)
        logger.info("流聚合器停止: 共输出 %d 条流记录", self._stats_flushed)

    async def on_packet(self, pkt) -> None:
        """
        包处理入口 — 由 CaptureEngine 调用

        pkt: PacketInfo (from capture_engine)
        """
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        now = pkt.timestamp

        async with self._lock:
            flow = self._active.get(key)
            if flow is None:
                flow = _ActiveFlow(
                    key=key,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    first_seen=now,
                    last_seen=now,
                )
                self._active[key] = flow
                try:
                    from metrics import inc_ndr_flow
                    inc_ndr_flow(pkt.protocol)
                except Exception:
                    pass

            # 更新统计（以 src→dst 方向为 out）
            flow.bytes_out += pkt.length
            flow.packets_out += 1
            flow.packet_count += 1
            flow.last_seen = now

            if pkt.tcp_flags:
                for f in pkt.tcp_flags:
                    if f.isalpha():
                        flow.tcp_flags_seen.add(f.upper())

            # TCP FIN/RST → 立即关闭
            if pkt.protocol == "TCP" and pkt.tcp_flags:
                upper = pkt.tcp_flags.upper()
                if "F" in upper or "R" in upper:
                    await self._close_flow(key)

    async def _timeout_loop(self):
        """定期检查超时流"""
        try:
            while True:
                await asyncio.sleep(10)
                now = time.time()
                to_close = []
                async with self._lock:
                    for key, flow in self._active.items():
                        idle = now - flow.last_seen
                        alive = now - flow.first_seen
                        if idle > self.idle_timeout or alive > self.active_timeout:
                            to_close.append(key)
                    for key in to_close:
                        await self._close_flow(key)
                if to_close:
                    logger.debug("超时关闭 %d 条流", len(to_close))
        except asyncio.CancelledError:
            pass

    async def _close_flow(self, key: tuple):
        """关闭一条流，生成 FlowRecord 并分发"""
        flow = self._active.pop(key, None)
        if flow is None:
            return

        flags_str = ",".join(sorted(flow.tcp_flags_seen)) if flow.tcp_flags_seen else ""
        record = FlowRecord(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            direction=_guess_direction(flow.src_ip, flow.dst_ip),
            bytes_in=flow.bytes_in,
            bytes_out=flow.bytes_out,
            packets_in=flow.packets_in,
            packets_out=flow.packets_out,
            duration_ms=(flow.last_seen - flow.first_seen) * 1000,
            tcp_flags=flags_str,
            app_protocol=_guess_app_protocol(flow.dst_port, flow.src_port),
            sensor_id=self.sensor_id,
            flow_start=flow.first_seen,
            flow_end=flow.last_seen,
            packet_count=flow.packet_count,
        )

        self._stats_flushed += 1
        for cb in self._flush_callbacks:
            try:
                await cb(record)
            except Exception as e:
                logger.warning("流完成回调异常: %s", e)


# ── 全局单例 ──
flow_aggregator = FlowAggregator()
