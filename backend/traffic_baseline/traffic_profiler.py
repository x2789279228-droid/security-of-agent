"""
traffic_profiler.py — 主机/子网流量画像

为每个 IP 维护多维流量基线:
  - 带宽: 每小时入/出字节数均值与标准差
  - 连接率: 每小时新建连接数
  - 协议分布: TCP/UDP/ICMP 比例
  - 端口分布: 常用目标端口 Top-N
  - 通信对: 常见通信伙伴 IP

偏离检测: 当前值超过 μ + kσ 即标记异常。

用法:
    from traffic_baseline.traffic_profiler import traffic_profiler
    await traffic_profiler.update(flow_record)
    report = traffic_profiler.check_deviation(flow_record)
"""
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field

from config import settings

logger = logging.getLogger(__name__)

_SIGMA_THRESHOLD = 3.0  # 偏离 3σ 视为异常


@dataclass
class HostProfile:
    """主机流量画像"""
    ip: str = ""
    # 带宽 (bytes/hour) — 按小时桶
    hourly_bytes_in: list = field(default_factory=lambda: [0.0] * 24)
    hourly_bytes_out: list = field(default_factory=lambda: [0.0] * 24)
    # 连接率
    hourly_connections: list = field(default_factory=lambda: [0.0] * 24)
    # 协议分布
    protocol_counts: dict = field(default_factory=lambda: defaultdict(int))
    # 端口分布
    port_counts: dict = field(default_factory=lambda: defaultdict(int))
    # 通信对
    peer_counts: dict = field(default_factory=lambda: defaultdict(int))
    # 统计
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    total_connections: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    sample_count: int = 0
    # 在线统计 (Welford)
    _mean_bytes_out: float = 0.0
    _m2_bytes_out: float = 0.0

    def update_welford(self, value: float):
        """Welford 在线方差算法"""
        self.sample_count += 1
        delta = value - self._mean_bytes_out
        self._mean_bytes_out += delta / self.sample_count
        delta2 = value - self._mean_bytes_out
        self._m2_bytes_out += delta * delta2

    @property
    def std_bytes_out(self) -> float:
        if self.sample_count < 2:
            return 0.0
        return math.sqrt(self._m2_bytes_out / (self.sample_count - 1))


class TrafficProfiler:
    """流量画像引擎"""

    def __init__(self):
        self._profiles: dict[str, HostProfile] = {}
        self._last_prune = time.time()

    def _get_profile(self, ip: str) -> HostProfile:
        if ip not in self._profiles:
            self._profiles[ip] = HostProfile(ip=ip, first_seen=time.time())
        return self._profiles[ip]

    async def update(self, flow: dict):
        """用流记录更新画像"""
        src_ip = flow.get("src_ip", "")
        if not src_ip:
            return

        profile = self._get_profile(src_ip)
        now = time.time()
        hour = int(time.strftime("%H", time.localtime(now)))

        bytes_out = flow.get("bytes_out", 0)
        bytes_in = flow.get("bytes_in", 0)
        protocol = flow.get("protocol", "TCP")
        dst_port = flow.get("dst_port", 0)
        dst_ip = flow.get("dst_ip", "")

        profile.hourly_bytes_out[hour] += bytes_out
        profile.hourly_bytes_in[hour] += bytes_in
        profile.hourly_connections[hour] += 1
        profile.protocol_counts[protocol] += 1
        if dst_port:
            profile.port_counts[dst_port] += 1
        if dst_ip:
            profile.peer_counts[dst_ip] += 1

        profile.total_bytes_out += bytes_out
        profile.total_bytes_in += bytes_in
        profile.total_connections += 1
        profile.last_seen = now
        profile.update_welford(float(bytes_out))

    def check_deviation(self, flow: dict) -> dict:
        """检查流记录是否偏离基线"""
        src_ip = flow.get("src_ip", "")
        profile = self._profiles.get(src_ip)
        if not profile or profile.sample_count < 10:
            return {"is_anomaly": False, "reason": "insufficient_baseline"}

        bytes_out = float(flow.get("bytes_out", 0))
        mean = profile._mean_bytes_out
        std = profile.std_bytes_out

        if std == 0:
            return {"is_anomaly": False, "reason": "zero_variance"}

        z_score = (bytes_out - mean) / std
        is_anomaly = abs(z_score) > _SIGMA_THRESHOLD

        reasons = []
        if is_anomaly:
            direction = "above" if z_score > 0 else "below"
            reasons.append(f"bytes_out_{direction}:z={z_score:.1f}")

        # 新通信对检测
        dst_ip = flow.get("dst_ip", "")
        if dst_ip and dst_ip not in profile.peer_counts and profile.total_connections > 50:
            reasons.append(f"new_peer:{dst_ip}")
            if not is_anomaly:
                is_anomaly = True

        # 新端口检测
        dst_port = flow.get("dst_port", 0)
        if dst_port and dst_port not in profile.port_counts and profile.total_connections > 50:
            reasons.append(f"new_port:{dst_port}")

        return {
            "is_anomaly": is_anomaly,
            "z_score": round(z_score, 2),
            "mean": round(mean, 1),
            "std": round(std, 1),
            "reasons": reasons,
        }

    def get_profile(self, ip: str) -> Optional[dict]:
        """获取主机画像"""
        profile = self._profiles.get(ip)
        if not profile:
            return None
        return {
            "ip": ip,
            "total_bytes_in": profile.total_bytes_in,
            "total_bytes_out": profile.total_bytes_out,
            "total_connections": profile.total_connections,
            "sample_count": profile.sample_count,
            "mean_bytes_out": round(profile._mean_bytes_out, 1),
            "std_bytes_out": round(profile.std_bytes_out, 1),
            "top_ports": sorted(
                profile.port_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "top_peers": sorted(
                profile.peer_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "protocol_distribution": dict(profile.protocol_counts),
        }

    @property
    def profile_count(self) -> int:
        return len(self._profiles)


# 需要导入 Optional
from typing import Optional

# ── 全局单例 ──
traffic_profiler = TrafficProfiler()
