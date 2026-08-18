"""
seasonal.py — 时间序列季节性分解与异常检测

对流量指标进行 STL (Seasonal-Trend decomposition using LOESS) 分解:
  - 趋势分量: 长期增长/下降
  - 季节分量: 每日/每周周期性
  - 残差分量: 去除趋势和季节后的异常波动

当残差超过阈值时触发异常告警。

用法:
    from traffic_baseline.seasonal import seasonal_detector
    seasonal_detector.add_observation("10.0.1.5", "bytes_out", value, timestamp)
    anomalies = seasonal_detector.detect("10.0.1.5", "bytes_out")
"""
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 异常检测参数
_RESIDUAL_THRESHOLD = 3.0   # 残差超过 3σ
_MIN_OBSERVATIONS = 48      # 至少 48 个数据点（2天 × 24小时）
_MAX_HISTORY = 720          # 保留最近 30 天（每小时一个点）


@dataclass
class TimeSeriesState:
    """时间序列状态"""
    values: deque = field(default_factory=lambda: deque(maxlen=_MAX_HISTORY))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=_MAX_HISTORY))
    # 小时桶均值（24 个）用于季节性估计
    hourly_sums: list = field(default_factory=lambda: [0.0] * 24)
    hourly_counts: list = field(default_factory=lambda: [0] * 24)
    # 全局统计
    total_sum: float = 0.0
    total_sq_sum: float = 0.0
    count: int = 0

    @property
    def mean(self) -> float:
        return self.total_sum / self.count if self.count > 0 else 0.0

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        variance = (self.total_sq_sum / self.count) - (self.mean ** 2)
        return math.sqrt(max(variance, 0))

    def seasonal_component(self, hour: int) -> float:
        """估计季节分量（该小时的平均值 - 全局平均值）"""
        if self.hourly_counts[hour] == 0:
            return 0.0
        hourly_mean = self.hourly_sums[hour] / self.hourly_counts[hour]
        return hourly_mean - self.mean


class SeasonalDetector:
    """季节性异常检测器"""

    def __init__(self):
        # key: "{ip}:{metric}" → TimeSeriesState
        self._series: dict[str, TimeSeriesState] = {}

    def add_observation(self, ip: str, metric: str, value: float, timestamp: float = 0.0):
        """添加观测值"""
        key = f"{ip}:{metric}"
        if key not in self._series:
            self._series[key] = TimeSeriesState()

        state = self._series[key]
        ts = timestamp or time.time()
        hour = int(time.strftime("%H", time.localtime(ts)))

        state.values.append(value)
        state.timestamps.append(ts)
        state.hourly_sums[hour] += value
        state.hourly_counts[hour] += 1
        state.total_sum += value
        state.total_sq_sum += value * value
        state.count += 1

    def detect(self, ip: str, metric: str, current_value: float = None) -> dict:
        """
        检测当前值是否异常

        返回: {is_anomaly, residual, z_score, seasonal, trend, reasons}
        """
        key = f"{ip}:{metric}"
        state = self._series.get(key)

        if not state or state.count < _MIN_OBSERVATIONS:
            return {"is_anomaly": False, "reason": "insufficient_data", "count": state.count if state else 0}

        if current_value is None:
            if not state.values:
                return {"is_anomaly": False, "reason": "no_data"}
            current_value = state.values[-1]

        now = time.time()
        hour = int(time.strftime("%H", time.localtime(now)))

        # 季节分量
        seasonal = state.seasonal_component(hour)

        # 去季节后的值
        deseasonalized = current_value - seasonal

        # 残差 = 去季节值 - 全局均值
        residual = deseasonalized - state.mean

        # Z-score
        std = state.std
        z_score = residual / std if std > 0 else 0.0

        is_anomaly = abs(z_score) > _RESIDUAL_THRESHOLD
        reasons = []

        if is_anomaly:
            direction = "spike" if z_score > 0 else "drop"
            reasons.append(f"{direction}:z={z_score:.1f}")

            # 检查是否连续异常（持续性攻击 vs 瞬时波动）
            recent = list(state.values)[-6:]  # 最近 6 个观测
            if len(recent) >= 3:
                recent_anomalies = sum(
                    1 for v in recent[-3:]
                    if abs((v - seasonal - state.mean) / std) > _RESIDUAL_THRESHOLD
                ) if std > 0 else 0
                if recent_anomalies >= 2:
                    reasons.append("sustained_anomaly")

        result = {
            "is_anomaly": is_anomaly,
            "current_value": round(current_value, 1),
            "expected": round(state.mean + seasonal, 1),
            "residual": round(residual, 1),
            "z_score": round(z_score, 2),
            "seasonal_component": round(seasonal, 1),
            "mean": round(state.mean, 1),
            "std": round(std, 1),
            "reasons": reasons,
        }

        # ── P0.S 流量大模型 hook (主路径 0 等待) ──
        # 仅在规则判定异常 + 模块启用时,后台派发 LLM 语义判定
        # LLM 失败/降级不影响本结果 (主路径已 ready)
        try:
            from .llm_anomaly import should_trigger_llm, analyze_and_persist
            from llm_enhancer import safe_dispatch
            if should_trigger_llm(result):
                safe_dispatch(
                    analyze_and_persist(
                        ip=ip, metric=metric, detect_result=result,
                    ),
                    log_label=f"traffic:{ip}:{metric}",
                )
        except Exception:
            pass  # LLM hook 失败绝不影响主路径

        return result

    def get_series_info(self, ip: str, metric: str) -> dict:
        """获取时间序列信息"""
        key = f"{ip}:{metric}"
        state = self._series.get(key)
        if not state:
            return {}
        return {
            "count": state.count,
            "mean": round(state.mean, 1),
            "std": round(state.std, 1),
            "hourly_pattern": [
                round(state.hourly_sums[h] / state.hourly_counts[h], 1)
                if state.hourly_counts[h] > 0 else 0
                for h in range(24)
            ],
        }

    @property
    def series_count(self) -> int:
        return len(self._series)


# ── 全局单例 ──
seasonal_detector = SeasonalDetector()
