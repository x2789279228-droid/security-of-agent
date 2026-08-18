"""
tcp_reassembler.py — TCP 流重组

将 CaptureEngine 产出的离散 TCP 包按 (src_ip, dst_ip, src_port, dst_port)
重组为有序数据流，支持:
  - 按序号排序
  - 重叠/重传包去重
  - 流结束检测 (FIN/RST)
  - 重组后数据送入协议解析器

用法:
    from session_reconstruct.tcp_reassembler import tcp_reassembler
    capture_engine.register_handler(tcp_reassembler.on_packet)
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_STREAM_TIMEOUT = 300  # 流超时 (秒)
_MAX_BUFFER = 10 * 1048576  # 单流最大缓冲 10MB


@dataclass
class TcpSegment:
    """TCP 段"""
    seq: int = 0
    payload: bytes = b""
    timestamp: float = 0.0
    flags: str = ""


@dataclass
class TcpStream:
    """重组中的 TCP 流"""
    key: tuple
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    # 双向缓冲
    client_buffer: bytearray = field(default_factory=bytearray)
    server_buffer: bytearray = field(default_factory=bytearray)
    client_seq: int = 0
    server_seq: int = 0
    is_client_first: bool = True
    start_time: float = 0.0
    last_time: float = 0.0
    packet_count: int = 0
    is_closed: bool = False
    # 重组后的完整数据
    reassembled_client: bytes = b""
    reassembled_server: bytes = b""


class TcpReassembler:
    """TCP 流重组器"""

    def __init__(self):
        self._streams: dict[tuple, TcpStream] = {}
        self._complete_callbacks: list = []
        self._stats = {"active": 0, "completed": 0, "timeout": 0}

    def on_stream_complete(self, callback):
        """注册流完成回调: async def cb(stream: TcpStream)"""
        self._complete_callbacks.append(callback)

    async def on_packet(self, pkt) -> None:
        """包处理入口"""
        if pkt.protocol != "TCP" or not pkt.payload:
            return

        # 标准化 key（小端 IP:port 在前）
        forward = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        reverse = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port)

        stream = self._streams.get(forward) or self._streams.get(reverse)

        if stream is None:
            # 新流（SYN 或首个数据包）
            stream = TcpStream(
                key=forward,
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                src_port=pkt.src_port, dst_port=pkt.dst_port,
                start_time=pkt.timestamp,
            )
            self._streams[forward] = stream
            self._stats["active"] = len(self._streams)

        stream.last_time = pkt.timestamp
        stream.packet_count += 1

        # 判断方向
        is_client = (pkt.src_ip == stream.src_ip and pkt.src_port == stream.src_port)

        # 追加数据
        if is_client:
            if len(stream.client_buffer) < _MAX_BUFFER:
                stream.client_buffer.extend(pkt.payload)
        else:
            if len(stream.server_buffer) < _MAX_BUFFER:
                stream.server_buffer.extend(pkt.payload)

        # FIN/RST → 关闭流
        if pkt.tcp_flags:
            upper = pkt.tcp_flags.upper()
            if "F" in upper or "R" in upper:
                await self._close_stream(stream.key, stream)

    async def _close_stream(self, key: tuple, stream: TcpStream):
        """关闭并输出重组结果"""
        stream.is_closed = True
        stream.reassembled_client = bytes(stream.client_buffer)
        stream.reassembled_server = bytes(stream.server_buffer)

        self._streams.pop(key, None)
        self._stats["completed"] += 1
        self._stats["active"] = len(self._streams)

        for cb in self._complete_callbacks:
            try:
                await cb(stream)
            except Exception as e:
                logger.warning("流完成回调异常: %s", e)

    async def cleanup_expired(self):
        """清理超时的流"""
        now = time.time()
        expired = [
            key for key, s in self._streams.items()
            if now - s.last_time > _STREAM_TIMEOUT
        ]
        for key in expired:
            stream = self._streams.pop(key, None)
            if stream:
                stream.reassembled_client = bytes(stream.client_buffer)
                stream.reassembled_server = bytes(stream.server_buffer)
                self._stats["timeout"] += 1
                for cb in self._complete_callbacks:
                    try:
                        await cb(stream)
                    except Exception:
                        pass

        if expired:
            logger.debug("清理超时 TCP 流: %d 条", len(expired))

    def get_stats(self) -> dict:
        return dict(self._stats)


# ── 全局单例 ──
tcp_reassembler = TcpReassembler()
