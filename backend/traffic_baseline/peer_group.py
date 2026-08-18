"""
peer_group.py — 对等组行为分析

将同角色/同子网主机编组，检测组内偏离:
  - 子网对等组: 同 /24 子网的主机应有相似流量模式
  - 角色对等组: 同类型服务器（Web/DB/DNS）行为应一致
  - 偏离检测: 某主机行为显著偏离组均值 → 可能被攻陷

用法:
    from traffic_baseline.peer_group import peer_group
    peer_group.add_host("10.0.1.5", profile_dict)
    deviations = peer_group.detect_deviations()
"""
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEVIATION_THRESHOLD = 2.5  # 偏离组均值 2.5σ 视为异常


@dataclass
class PeerGroup:
    """对等组"""
    group_id: str
    members: list = field(default_factory=list)
    # 组统计
    mean_bytes_out: float = 0.0
    std_bytes_out: float = 0.0
    mean_connections: float = 0.0
    std_connections: float = 0.0
    mean_ports: float = 0.0
    std_ports: float = 0.0


class PeerGroupAnalyzer:
    """对等组分析引擎"""

    def __init__(self):
        self._groups: dict[str, PeerGroup] = {}
        self._host_groups: dict[str, str] = {}  # ip → group_id
        self._host_metrics: dict[str, dict] = {}  # ip → {bytes_out, connections, unique_ports}

    def add_host(self, ip: str, metrics: dict, group_id: str = ""):
        """
        添加主机到对等组

        metrics: {bytes_out, connections, unique_ports, unique_peers}
        group_id: 空则按 /24 子网自动编组
        """
        if not group_id:
            parts = ip.split(".")
            group_id = f"subnet_{'.'.join(parts[:3])}.0/24" if len(parts) == 4 else "unknown"

        self._host_groups[ip] = group_id
        self._host_metrics[ip] = metrics

        if group_id not in self._groups:
            self._groups[group_id] = PeerGroup(group_id=group_id)
        if ip not in self._groups[group_id].members:
            self._groups[group_id].members.append(ip)

    def detect_deviations(self) -> list[dict]:
        """检测所有组内的偏离主机"""
        results = []

        for gid, group in self._groups.items():
            if len(group.members) < 3:
                continue  # 组太小无统计意义

            # 计算组统计
            values = []
            for ip in group.members:
                m = self._host_metrics.get(ip, {})
                values.append(m.get("bytes_out", 0))

            if not values:
                continue

            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance) if variance > 0 else 0

            if std == 0:
                continue

            # 检测偏离
            for ip in group.members:
                m = self._host_metrics.get(ip, {})
                v = m.get("bytes_out", 0)
                z = (v - mean) / std

                if abs(z) > _DEVIATION_THRESHOLD:
                    results.append({
                        "ip": ip,
                        "group": gid,
                        "metric": "bytes_out",
                        "value": v,
                        "group_mean": round(mean, 1),
                        "group_std": round(std, 1),
                        "z_score": round(z, 2),
                        "direction": "above" if z > 0 else "below",
                        "severity": "high" if abs(z) > 4 else "medium",
                    })

        return results

    def get_group_info(self, group_id: str) -> dict:
        """获取组信息"""
        group = self._groups.get(group_id)
        if not group:
            return {}
        return {
            "group_id": group_id,
            "member_count": len(group.members),
            "members": group.members[:20],
        }

    @property
    def group_count(self) -> int:
        return len(self._groups)


# ── 全局单例 ──
peer_group = PeerGroupAnalyzer()
