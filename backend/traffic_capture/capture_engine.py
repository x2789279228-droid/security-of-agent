"""
capture_engine.py — 网络流量采集引擎

支持三种采集后端:
  - libpcap: 通用方案，基于 scapy / python-libpcap，适合 < 1Gbps
  - af_packet: Linux 原生高性能（需 root），适合 1-10Gbps
  - dpdk: 用户态驱动（需 DPDK 环境），适合 > 10Gbps

数据流:
  网卡 → CaptureEngine → FlowAggregator → Kafka (ndr-flows)
                       → PcapStore (PCAP 落盘)
                       → ProtocolDissector (协议解析)

用法:
    from traffic_capture.capture_engine import capture_engine
    await capture_engine.start()
    await capture_engine.stop()
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """解析后的数据包元信息"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str          # TCP | UDP | ICMP
    length: int
    tcp_flags: str = ""    # SYN | ACK | FIN | RST | PSH
    payload: bytes = b""
    raw: bytes = b""


@dataclass
class CaptureStats:
    """采集统计"""
    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    start_time: float = 0.0
    last_packet_time: float = 0.0
    pps: float = 0.0       # packets per second (滑动窗口)
    bps: float = 0.0       # bytes per second
    active_flows: int = 0

    @property
    def uptime(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    def to_dict(self) -> dict:
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "bytes_captured": self.bytes_captured,
            "uptime_sec": round(self.uptime, 1),
            "pps": round(self.pps, 1),
            "bps": round(self.bps, 1),
            "active_flows": self.active_flows,
        }


# 包处理回调类型: async def handler(pkt: PacketInfo) -> None
PacketHandler = Callable[[PacketInfo], Awaitable[None]]


class CaptureEngine:
    """
    网络流量采集引擎

    职责:
      1. 管理抓包生命周期（启动/停止/重启）
      2. 将原始包解析为 PacketInfo
      3. 分发给注册的处理器（流聚合、协议解析、PCAP 写入）
      4. 维护采集统计
    """

    def __init__(self):
        self.interface = settings.capture_interface
        self.bpf_filter = settings.capture_bpf_filter
        self.snap_len = settings.capture_snap_len
        self.method = settings.capture_method
        self.sensor_id = settings.sensor_id

        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._handlers: list[PacketHandler] = []
        self._stats = CaptureStats()
        self._capture = None  # scapy AsyncSniffer 或自定义后端
        self._pps_window: list[float] = []  # 最近 N 秒的包计数

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    @property
    def is_running(self) -> bool:
        return self._running

    def register_handler(self, handler: PacketHandler):
        """注册包处理回调（流聚合器、协议解析器、PCAP 写入器等）"""
        self._handlers.append(handler)
        logger.info("注册包处理器: %s", handler.__qualname__)

    async def start(self):
        """启动采集"""
        if self._running:
            logger.warning("采集引擎已在运行")
            return

        self._running = True
        self._stats.start_time = time.time()
        # 保存主事件循环引用 — scapy sniffer 线程需跨线程调度 handler
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._capture_loop())
        logger.info(
            "采集引擎启动: interface=%s method=%s filter='%s' sensor=%s",
            self.interface, self.method, self.bpf_filter, self.sensor_id,
        )

    async def stop(self):
        """停止采集"""
        if not self._running:
            return
        self._running = False
        if self._capture is not None:
            try:
                if hasattr(self._capture, "stop"):
                    self._capture.stop()
            except Exception as e:
                logger.warning("停止采集器异常: %s", e)
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "采集引擎停止: 共捕获 %d 包 (%.1f MB)",
            self._stats.packets_captured,
            self._stats.bytes_captured / 1048576,
        )

    async def _capture_loop(self):
        """采集主循环 — 根据 method 选择后端"""
        try:
            if self.method == "libpcap":
                await self._capture_libpcap()
            elif self.method == "af_packet":
                await self._capture_af_packet()
            elif self.method == "dpdk":
                await self._capture_dpdk()
            else:
                logger.error("不支持的采集方式: %s", self.method)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("采集循环异常退出: %s", e, exc_info=True)
        finally:
            self._running = False

    async def _capture_libpcap(self):
        """libpcap 后端 — 基于 scapy AsyncSniffer"""
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            logger.error("scapy 未安装，无法使用 libpcap 采集。pip install scapy")
            return

        kwargs = {
            "iface": self.interface,
            "prn": self._on_packet_scapy,
            "store": False,
            "filter": self.bpf_filter or None,
        }
        # AsyncSniffer 在 scapy >= 2.5 支持 started_callback / stopped_callback
        self._capture = AsyncSniffer(**kwargs)
        self._capture.start()
        logger.info("libpcap 采集已启动 (scapy AsyncSniffer)")

        # 保持协程存活，直到 _running = False
        while self._running:
            await asyncio.sleep(0.5)

        if self._capture.running:
            self._capture.stop()

    def _on_packet_scapy(self, pkt):
        """scapy 回调 — 在 sniffer 线程中调用，需线程安全"""
        try:
            info = self._parse_scapy_packet(pkt)
            if info is None:
                return
            self._stats.packets_captured += 1
            self._stats.bytes_captured += info.length
            self._stats.last_packet_time = info.timestamp
            # 跨线程调度到主事件循环。不能在子线程里 get_event_loop()
            # (Python 3.10+ 子线程无循环会抛 RuntimeError, 导致 handler 永不执行)
            loop = self._loop
            if loop is not None and loop.is_running():
                for handler in self._handlers:
                    asyncio.run_coroutine_threadsafe(handler(info), loop)
        except Exception as e:
            logger.debug("包处理异常: %s", e)

    def _parse_scapy_packet(self, pkt) -> Optional[PacketInfo]:
        """将 scapy Packet 转为 PacketInfo"""
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if IP not in pkt:
            return None

        ip_layer = pkt[IP]
        ts = float(pkt.time)

        proto = "OTHER"
        src_port, dst_port = 0, 0
        tcp_flags = ""
        payload = b""

        if TCP in pkt:
            proto = "TCP"
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            flags = tcp.flags
            tcp_flags = str(flags) if flags else ""
            payload = bytes(tcp.payload) if tcp.payload else b""
        elif UDP in pkt:
            proto = "UDP"
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            payload = bytes(udp.payload) if udp.payload else b""
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            return None

        return PacketInfo(
            timestamp=ts,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=len(pkt),
            tcp_flags=tcp_flags,
            payload=payload[:4096],  # 截断 payload 防止内存爆炸
            raw=bytes(pkt)[:self.snap_len],
        )

    async def _capture_af_packet(self):
        """AF_PACKET 后端 — Linux 原生高性能（占位实现）"""
        logger.warning(
            "AF_PACKET 采集需要 Linux 环境和 root 权限。"
            "当前为占位实现，请使用 libpcap 或 dpdk。"
        )
        # 实际实现: 使用 socket(AF_PACKET, SOCK_RAW) + asyncio 事件循环
        # 参考: https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
        while self._running:
            await asyncio.sleep(1)

    async def _capture_dpdk(self):
        """DPDK 后端 — 用户态高速采集（占位实现）"""
        logger.warning(
            "DPDK 采集需要 DPDK 环境和 hugepages 配置。"
            "当前为占位实现，请使用 libpcap 或 af_packet。"
        )
        # 实际实现: 使用 dpdk-python 绑定或 dpdk-testpmd + pipe
        while self._running:
            await asyncio.sleep(1)

    def get_stats(self) -> dict:
        """返回采集统计"""
        self._stats.active_flows = 0  # 由 flow_aggregator 更新
        return self._stats.to_dict()


# ── 全局单例 ──
capture_engine = CaptureEngine()
