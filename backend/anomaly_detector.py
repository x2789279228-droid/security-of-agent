"""
异常检测引擎 — 替代原来的重要性评分

核心区别：
  原来: severity + confidence → 重要性分数(0-1) → 高重要性保留，低重要性丢弃
  现在: 统计偏离度 + 频率分析 + 模式匹配 → 异常分数 → 所有事件保留，异常事件标记

检测维度：
  1. 统计偏离度：某实体的行为偏离其历史基线
  2. 频率异常：单位时间内事件数量异常
  3. 低频事件：罕见事件类型的出现
  4. 组合异常：多个低严重度事件构成的攻击模式
  5. 时序异常：非活跃时段的活动
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AnomalyReport:
    """单条事件的异常检测报告"""
    event_id: int
    anomaly_score: float          # 0-1, >0.6 视为异常
    is_anomaly: bool
    deviation_sigma: float        # 统计偏离度（标准差倍数）
    reasons: list[str]            # 异常原因描述
    dimensions: dict = field(default_factory=dict)  # 各维度分数


@dataclass
class EntityBaseline:
    """实体（IP/用户/事件类型）的统计基线"""
    hourly_counts: list[int] = field(default_factory=lambda: [0] * 24)
    daily_count: int = 0
    weekly_count: int = 0
    last_seen: float = 0
    total_count: int = 0
    event_types: set = field(default_factory=set)
    first_seen: float = 0


class AnomalyDetector:
    """
    统计偏离度异常检测器

    维护每个实体的行为基线，新事件到来时计算其偏离程度。
    基线基于滑动窗口（默认7天）自动更新。

    用法:
        detector = AnomalyDetector()
        report = await detector.analyze(session, event_data)
        if report.is_anomaly:
            # 标记事件、触发深入审核
    """

    def __init__(self, window_days: int = 7):
        self.window_days = window_days
        # 实体基线: {entity_type: {entity_key: EntityBaseline}}
        self.baselines: dict[str, dict[str, EntityBaseline]] = {
            "src_ip": defaultdict(EntityBaseline),
            "event_type": defaultdict(EntityBaseline),
            "dst_ip": defaultdict(EntityBaseline),
        }
        # 全局统计
        self.global_hourly_counts = [0] * 24
        self.global_event_types: dict[str, int] = defaultdict(int)
        self._last_prune = time.time()
        # Redis 持久化
        self.redis = None
        self._redis_prefix = "anomaly:baseline:"
        self._last_save = 0
        self._save_interval = 60  # 每60秒异步保存一次

    def set_redis(self, redis_client):
        """设置 Redis 客户端（用于持久化基线）"""
        self.redis = redis_client
        logger.info("AnomalyDetector: Redis persistence enabled")

    async def load_baselines_from_redis(self):
        """启动时从 Redis 恢复基线"""
        if not self.redis:
            return
        try:
            # 加载全局统计
            hourly = await self.redis.get(f"{self._redis_prefix}global:hourly")
            if hourly:
                import json
                self.global_hourly_counts = json.loads(hourly)
            types_data = await self.redis.get(f"{self._redis_prefix}global:event_types")
            if types_data:
                import json
                self.global_event_types = defaultdict(int, json.loads(types_data))

            # 加载实体基线
            for entity_type in ("src_ip", "dst_ip", "event_type"):
                pattern = f"{self._redis_prefix}{entity_type}:*"
                # SCAN 分批迭代：键空间大时 KEYS 会阻塞 Redis 单线程
                keys = [
                    key async for key in self.redis.scan_iter(match=pattern, count=500)
                ]
                for key in keys:
                    data = await self.redis.get(key)
                    if data:
                        import json
                        bl_dict = json.loads(data)
                        bl = EntityBaseline(
                            hourly_counts=bl_dict.get("hourly_counts", [0]*24),
                            daily_count=bl_dict.get("daily_count", 0),
                            weekly_count=bl_dict.get("weekly_count", 0),
                            last_seen=bl_dict.get("last_seen", 0),
                            total_count=bl_dict.get("total_count", 0),
                            event_types=set(bl_dict.get("event_types", [])),
                            first_seen=bl_dict.get("first_seen", 0),
                        )
                        entity_key = key.decode() if isinstance(key, bytes) else key
                        entity_key = entity_key.replace(f"{self._redis_prefix}{entity_type}:", "")
                        self.baselines[entity_type][entity_key] = bl

            total_entities = sum(len(v) for v in self.baselines.values())
            logger.info(
                f"AnomalyDetector: loaded baselines from Redis: "
                f"{total_entities} entities, {sum(self.global_hourly_counts)} total events"
            )
        except Exception as e:
            logger.warning(f"Failed to load baselines from Redis: {e}")

    async def _save_baselines_to_redis(self, force: bool = False):
        """异步保存基线到 Redis（默认受 _save_interval 节流; force=True 跳过节流）"""
        if not self.redis:
            return
        now = time.time()
        if not force and now - self._last_save < self._save_interval:
            return
        self._last_save = now
        try:
            import json
            pipe = self.redis.pipeline()

            # 全局统计
            pipe.setex(
                f"{self._redis_prefix}global:hourly", 86400 * 7,
                json.dumps(self.global_hourly_counts)
            )
            pipe.setex(
                f"{self._redis_prefix}global:event_types", 86400 * 7,
                json.dumps(dict(self.global_event_types))
            )

            # 实体基线（只保存最近活跃的）
            for entity_type in ("src_ip", "dst_ip", "event_type"):
                cutoff = now - 86400 * self.window_days
                for key, bl in list(self.baselines[entity_type].items()):
                    if bl.last_seen < cutoff:
                        continue
                    redis_key = f"{self._redis_prefix}{entity_type}:{key}"
                    pipe.setex(
                        redis_key, 86400 * 7,
                        json.dumps({
                            "hourly_counts": bl.hourly_counts,
                            "daily_count": bl.daily_count,
                            "weekly_count": bl.weekly_count,
                            "last_seen": bl.last_seen,
                            "total_count": bl.total_count,
                            "event_types": list(bl.event_types),
                            "first_seen": bl.first_seen,
                        })
                    )
            await pipe.execute()
        except Exception as e:
            logger.warning(f"Failed to save baselines to Redis: {e}")

    def _prune_baselines(self):
        """清理过期基线（超过窗口期的实体）"""
        now = time.time()
        cutoff = now - self.window_days * 86400
        for entity_type in self.baselines:
            expired = [
                key for key, bl in self.baselines[entity_type].items()
                if bl.last_seen < cutoff
            ]
            for key in expired:
                del self.baselines[entity_type][key]
            if expired:
                logger.debug(f"Pruned {len(expired)} expired {entity_type} baselines")
        self._last_prune = now

    def _update_baseline(self, entity_type: str, entity_key: str,
                         event_type: str, hour: int):
        """更新实体基线"""
        bl = self.baselines[entity_type][entity_key]
        now = time.time()
        if bl.total_count == 0:
            bl.first_seen = now
        bl.last_seen = now
        bl.total_count += 1
        bl.hourly_counts[hour % 24] += 1
        bl.event_types.add(event_type)

    def decay_entity(self, entity_type: str, entity_key: str, factor: float = 0.5) -> bool:
        """按 factor 衰减实体的计数基线(learn_loop FP 收敛用)。

        只缩放 hourly_counts / daily_count / weekly_count / total_count,
        永不删除实体; 实体不存在返回 False。
        """
        bl = self.baselines.get(entity_type, {}).get(entity_key)
        if bl is None:
            return False
        try:
            factor = max(0.0, min(1.0, float(factor)))
        except (TypeError, ValueError):
            factor = 0.5
        bl.hourly_counts = [int(c * factor) for c in bl.hourly_counts]
        bl.daily_count = int(bl.daily_count * factor)
        bl.weekly_count = int(bl.weekly_count * factor)
        bl.total_count = int(bl.total_count * factor)
        logger.info(
            f"AnomalyDetector: decayed {entity_type}/{entity_key} "
            f"by {factor:.2f} → total_count={bl.total_count}"
        )
        return True

    def _calc_statistical_deviation(self, entity_type: str,
                                     entity_key: str,
                                     hour: int) -> float:
        """
        计算统计偏离度（标准差倍数）
        
        比较该实体在当前小时的活跃度 vs 其在其他小时的平均活跃度。
        返回 sigma 值，越大越异常。
        """
        bl = self.baselines[entity_type].get(entity_key)
        if not bl or bl.total_count < 3:
            return 0.0  # 数据不足，无法判断

        current_hour_count = bl.hourly_counts[hour % 24]
        other_hours_total = bl.total_count - current_hour_count
        other_hours_count = 23  # 剩下的23个小时

        if other_hours_count == 0:
            return 0.0

        mean = other_hours_total / other_hours_count if other_hours_total > 0 else 0
        if mean == 0:
            return float(current_hour_count) if current_hour_count > 0 else 0.0

        # 简化计算：泊松分布近似
        # 标准差 ≈ sqrt(mean)
        std = max(1.0, (mean ** 0.5))

        if current_hour_count <= mean:
            return 0.0  # 低于均值不算异常

        sigma = (current_hour_count - mean) / std

        return min(sigma, 10.0)  # 限制最大值

    def _event_type_share(self, event_type: str) -> float:
        """事件类型在全局统计中的占比（分母与 _calc_event_rarity 同口径）。"""
        total = sum(self.global_hourly_counts)
        if total <= 0:
            return 0.0
        return self.global_event_types.get(event_type, 0) / total

    def _calc_event_rarity(self, event_type: str) -> float:
        """
        计算事件类型的罕见程度

        越罕见 → 分数越高 → 越可能是异常。
        分子是 7 天窗口的累计类型计数，分母必须用同口径的全局总数
        （24 个小时桶合计）。此前误用单个小时桶 global_hourly_counts[0]，
        分母典型缩小约 24 倍 → ratio 放大 → rarity 几乎恒为 0，
        且随 UTC 钟点漂移、冷启动后未经历 0 点段时恒为 0。
        """
        total = sum(self.global_hourly_counts)
        if total < 10:
            return 0.0

        type_count = self.global_event_types.get(event_type, 0)
        ratio = type_count / total

        # 出现比例越低越罕见
        rarity = max(0.0, 1.0 - ratio * 100)

        return min(rarity, 1.0)

    def _calc_temporal_anomaly(self, hour: int) -> float:
        """
        时序异常检测
        
        在非活跃时段（如凌晨）出现的事件更可疑。
        """
        # 凌晨 0-5 点
        if hour in (0, 1, 2, 3, 4, 5):
            return 0.4
        # 深夜 22-23 点
        if hour in (22, 23):
            return 0.2
        return 0.0

    async def analyze(self, event: dict) -> AnomalyReport:
        """
        分析单条事件，返回异常检测报告
        
        Args:
            event: 事件字典，必须包含 event_id, event_type, severity, src_ip 等字段
        
        Returns:
            AnomalyReport
        """
        event_id = event.get("event_id", 0)
        event_type = event.get("event", event.get("type", "UNKNOWN"))
        severity = event.get("severity", "info")
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        now = datetime.now(timezone.utc)
        hour = now.hour

        # 定期清理过期基线
        if time.time() - self._last_prune > 3600:
            self._prune_baselines()

        # 更新全局统计
        self.global_hourly_counts[hour] += 1
        self.global_event_types[event_type] += 1

        reasons = []
        dimensions = {}
        total_score = 0.0
        max_sigma = 0.0

        # 1. 统计偏离度检测（源IP）
        if src_ip:
            dev_sigma = self._calc_statistical_deviation("src_ip", src_ip, hour)
            if dev_sigma > 0:
                anomaly_score = min(1.0, dev_sigma / 5.0)
                dimensions["statistical_deviation"] = anomaly_score
                total_score += anomaly_score * 0.35
                max_sigma = max(max_sigma, dev_sigma)
                if dev_sigma > 3:
                    reasons.append(
                        f"统计异常: {src_ip} 当前活跃度偏离基线 {dev_sigma:.1f}σ"
                    )
                elif dev_sigma > 2:
                    reasons.append(
                        f"轻度偏离: {src_ip} 活跃度偏高 ({dev_sigma:.1f}σ)"
                    )
            self._update_baseline("src_ip", src_ip, event_type, hour)

        # 2. 事件类型罕见度
        rarity = self._calc_event_rarity(event_type)
        if rarity > 0:
            dimensions["rarity"] = rarity
            total_score += rarity * 0.20
            if rarity > 0.8:
                reasons.append(
                    f"罕见事件类型: {event_type} "
                    f"(出现率约 {self._event_type_share(event_type):.2%})"
                )

        # 3. 时序异常
        temporal = self._calc_temporal_anomaly(hour)
        if temporal > 0:
            dimensions["temporal"] = temporal
            total_score += temporal * 0.15
            if temporal >= 0.4:
                reasons.append(f"非活跃时段活动: 凌晨{hour}时")

        # 4. 严重度加权（保留原始严重度信息）
        severity_weight = {
            "critical": 1.0, "high": 0.6, "medium": 0.3,
            "low": 0.0, "info": -0.05,
        }.get(severity, 0.0)
        if severity_weight > 0:
            dimensions["severity"] = severity_weight
            total_score += severity_weight * 0.25

        # 5. 目标IP统计
        if dst_ip:
            self._update_baseline("dst_ip", dst_ip, event_type, hour)

        # 更新事件类型基线
        self._update_baseline("event_type", event_type, event_type, hour)

        # 归一化
        anomaly_score = min(1.0, max(0.0, total_score))
        is_anomaly = anomaly_score > 0.6 or max_sigma > 3

        if not reasons and is_anomaly:
            reasons.append(f"综合异常评分: {anomaly_score:.2f}")

        report = AnomalyReport(
            event_id=event_id,
            anomaly_score=round(anomaly_score, 4),
            is_anomaly=is_anomaly,
            deviation_sigma=round(max_sigma, 2),
            reasons=reasons,
            dimensions=dimensions,
        )

        if is_anomaly:
            logger.info(f"Anomaly detected: event #{event_id} "
                        f"{event_type} score={anomaly_score:.3f} "
                        f"sigma={max_sigma:.1f} reasons={reasons}")

        # 异步持久化到 Redis
        await self._save_baselines_to_redis()

        return report


# 全局单例
anomaly_detector = AnomalyDetector()
