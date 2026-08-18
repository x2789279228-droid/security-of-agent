"""
pcap_store.py — PCAP 文件轮转与分层存储

职责:
  1. 将 CaptureEngine 的原始包写入 PCAP 文件
  2. 按大小/时间自动轮转
  3. 分层存储: hot (本地 SSD) → warm (本地 HDD) → cold (S3/MinIO)
  4. 过期清理: 超过 retention_days 的文件自动删除
  5. 元数据写入 PostgreSQL (pcap_files 表)

用法:
    from traffic_capture.pcap_store import pcap_store
    capture_engine.register_handler(pcap_store.on_packet)
    await pcap_store.start()
"""
import asyncio
import logging
import os
import struct
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# PCAP 全局头 (little-endian)
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    _PCAP_MAGIC,
    _PCAP_VERSION_MAJOR,
    _PCAP_VERSION_MINOR,
    0,           # thiszone
    0,           # sigfigs
    262144,      # snaplen
    1,           # network (LINKTYPE_ETHERNET)
)

# PCAP 包头: ts_sec, ts_usec, incl_len, orig_len
_PCAP_PKT_HEADER = struct.Struct("<IIII")


class PcapStore:
    """
    PCAP 文件写入与生命周期管理

    文件命名: {sensor_id}_{YYYYMMDD_HHmmss}_{seq}.pcap
    轮转条件: 文件大小 >= rotation_mb 或 存活 >= rotation_sec
    """

    def __init__(self):
        self.storage_path = Path(settings.pcap_storage_path)
        self.rotation_mb = settings.pcap_rotation_mb
        self.rotation_sec = settings.pcap_rotation_sec
        self.retention_days = settings.pcap_retention_days
        self.sensor_id = settings.sensor_id

        self._current_file = None
        self._current_path: Optional[Path] = None
        self._current_size = 0
        self._current_start = 0.0
        self._current_packets = 0
        self._seq = 0
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._db_callback = None  # async def cb(meta: dict) → 写入 pcap_files 表

    def set_db_callback(self, callback):
        """设置元数据持久化回调: async def cb(meta: dict)"""
        self._db_callback = callback

    async def start(self):
        """初始化存储目录，启动清理循环"""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(
            "PCAP 存储启动: path=%s rotation=%dMB/%ds retention=%dd",
            self.storage_path, self.rotation_mb, self.rotation_sec,
            self.retention_days,
        )

    async def stop(self):
        """关闭当前文件，停止清理循环"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            await self._rotate()
        logger.info("PCAP 存储停止")

    async def on_packet(self, pkt) -> None:
        """
        包写入入口 — 由 CaptureEngine 调用

        pkt: PacketInfo (from capture_engine)
        """
        if not pkt.raw:
            return

        async with self._lock:
            if self._current_file is None:
                await self._open_new_file()

            # 写入 PCAP 包头 + 包数据
            ts_sec = int(pkt.timestamp)
            ts_usec = int((pkt.timestamp - ts_sec) * 1_000_000)
            incl_len = len(pkt.raw)
            header = _PCAP_PKT_HEADER.pack(ts_sec, ts_usec, incl_len, incl_len)

            self._current_file.write(header)
            self._current_file.write(pkt.raw)
            self._current_size += len(header) + incl_len
            self._current_packets += 1

            # 检查轮转条件
            if (self._current_size >= self.rotation_mb * 1048576
                    or time.time() - self._current_start >= self.rotation_sec):
                await self._rotate()

    async def _open_new_file(self):
        """打开新的 PCAP 文件"""
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        self._seq += 1
        filename = f"{self.sensor_id}_{ts_str}_{self._seq:04d}.pcap"
        self._current_path = self.storage_path / filename

        self._current_file = open(self._current_path, "wb")
        self._current_file.write(_PCAP_GLOBAL_HEADER)
        self._current_size = len(_PCAP_GLOBAL_HEADER)
        self._current_start = time.time()
        self._current_packets = 0

        logger.debug("打开 PCAP 文件: %s", self._current_path)

    async def _rotate(self):
        """关闭当前文件，触发元数据持久化"""
        if self._current_file is None:
            return

        self._current_file.flush()
        self._current_file.close()

        meta = {
            "file_path": str(self._current_path),
            "file_size": self._current_size,
            "sensor_id": self.sensor_id,
            "interface": settings.capture_interface,
            "packet_count": self._current_packets,
            "capture_start": datetime.fromtimestamp(
                self._current_start, tz=timezone.utc
            ).isoformat(),
            "capture_end": datetime.now(timezone.utc).isoformat(),
            "status": "closed",
            "storage_tier": "hot",
        }

        logger.info(
            "PCAP 轮转: %s (%d 包, %.1f MB)",
            self._current_path.name, self._current_packets,
            self._current_size / 1048576,
        )

        if self._db_callback:
            try:
                await self._db_callback(meta)
            except Exception as e:
                logger.warning("PCAP 元数据持久化失败: %s", e)

        self._current_file = None
        self._current_path = None
        self._current_size = 0
        self._current_packets = 0

    async def _cleanup_loop(self):
        """定期清理过期 PCAP 文件"""
        try:
            while True:
                await asyncio.sleep(3600)  # 每小时检查一次
                await self._cleanup_expired()
        except asyncio.CancelledError:
            pass

    async def _cleanup_expired(self):
        """删除超过 retention_days 的 PCAP 文件"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        cutoff_ts = cutoff.timestamp()
        removed = 0

        for f in self.storage_path.glob("*.pcap"):
            try:
                if f.stat().st_mtime < cutoff_ts:
                    f.unlink()
                    removed += 1
            except OSError as e:
                logger.warning("删除过期 PCAP 失败 %s: %s", f, e)

        if removed:
            logger.info("清理过期 PCAP: 删除 %d 个文件", removed)

    def list_files(self, limit: int = 50) -> list[dict]:
        """列出当前存储的 PCAP 文件"""
        files = []
        for f in sorted(self.storage_path.glob("*.pcap"), reverse=True)[:limit]:
            stat = f.stat()
            files.append({
                "file_path": str(f),
                "file_name": f.name,
                "file_size": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            })
        return files

    def get_disk_usage(self) -> dict:
        """返回 PCAP 存储磁盘使用情况"""
        total_size = 0
        file_count = 0
        for f in self.storage_path.glob("*.pcap"):
            total_size += f.stat().st_size
            file_count += 1
        return {
            "path": str(self.storage_path),
            "file_count": file_count,
            "total_size_mb": round(total_size / 1048576, 2),
            "retention_days": self.retention_days,
        }


# ── 全局单例 ──
pcap_store = PcapStore()
