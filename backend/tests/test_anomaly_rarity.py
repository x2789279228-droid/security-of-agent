"""
P0 修复回归: anomaly rarity 分母口径 (#9)

修复前: ratio = 7天累计类型数 / global_hourly_counts[0]（UTC 0 点单小时桶），
        分母典型缩小约 24 倍 → ratio 放大 → rarity 几乎恒为 0，
        且随钟点漂移、冷启动未经历 0 点段时恒为 0。
修复后: 分母为 24 个小时桶合计，与分子同口径。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import AnomalyDetector


def _detector_with(total: int, type_count: int) -> AnomalyDetector:
    det = AnomalyDetector()
    # 均匀分布在 24 个小时桶上
    per_hour = total // 24
    det.global_hourly_counts = [per_hour] * 24
    det.global_hourly_counts[0] += total - per_hour * 24  # 余数放到 0 点桶
    det.global_event_types.clear()
    if type_count:
        det.global_event_types["T"] = type_count
    return det


class TestEventRarity:
    def test_common_type_near_zero(self):
        """占比 ~50% 的常见类型 → rarity 应为 0（修复前 24 倍放大也恒 0，但语意错误）。"""
        det = _detector_with(total=24000, type_count=12000)
        assert det._calc_event_rarity("T") == 0.0

    def test_share_below_one_percent_scores(self):
        """占比 0.9% < 1% → rarity ≈ 0.1。

        修复前的分母（单小时桶 ≈ total/24）会把 ratio 放大 24 倍(≈21.6%)，
        rarity 恒为 0 —— 该维度完全失效；修复后正常打分。
        """
        det = _detector_with(total=10000, type_count=90)
        rarity = det._calc_event_rarity("T")
        assert 0.0 < rarity <= 0.2, f"0.9% 占比应得到低但非零的 rarity, 实际 {rarity}"

    def test_unknown_type_max_rarity(self):
        det = _detector_with(total=1000, type_count=0)
        assert det._calc_event_rarity("NEVER_SEEN") == 1.0

    def test_cold_start_guard(self):
        """总计数不足时恒为 0（冷启动守卫）。"""
        det = _detector_with(total=8, type_count=1)
        assert det._calc_event_rarity("T") == 0.0

    def test_independent_of_hour_zero_bucket(self):
        """rarity 不应再依赖 0 点桶：0 点桶为 0 时维度依然有效（修复前恒 0）。"""
        det = AnomalyDetector()
        det.global_hourly_counts = [0] + [417] * 23  # 0 点桶空, 其余均摊
        det.global_event_types.clear()
        det.global_event_types["T"] = 90  # 90 / 9583 ≈ 0.94%
        rarity = det._calc_event_rarity("T")
        assert rarity > 0, "0 点桶为空不应导致 rarity 恒 0"

    def test_event_type_share_helper(self):
        det = _detector_with(total=1000, type_count=100)
        assert abs(det._event_type_share("T") - 0.1) < 1e-9
        assert det._event_type_share("MISSING") == 0.0
