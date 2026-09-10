"""
learn_loop.models_stats — 反馈统计(纯函数, 不依赖 FastAPI / DB)

Wilson 置信区间 / EWMA / 按规则误报率分析。

Shadow 提议的门槛是「Wilson 下界 > 15%」(不是点估计), 样本不足时不做:
  n >= 5 且 lo > 0.15 才允许 shadow_rule 提案。
LLM 结论(llm: 前缀)驱动的统计不得自动降级任何规则。
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# 与 ops_loop / feedback_loop 的 15% 降级阈值对齐
SHADOW_MIN_N = 5
SHADOW_LO_THRESHOLD = 0.15
MISSED_THREAT_THRESHOLD = 3
ANOMAL_ADJUST_FP_RATE = 0.3


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple:
    """Wilson 分数区间(双侧)。n<=0 返回 (0.0, 0.0)。"""
    if n <= 0:
        return (0.0, 0.0)
    p = max(0.0, min(1.0, successes / n))
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    margin = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n) ** 0.5 / denom
    lo = max(0.0, centre - margin)
    hi = min(1.0, centre + margin)
    return (round(lo, 4), round(hi, 4))


def ewma(prev: float, value: float, alpha: float = 0.3) -> float:
    """指数加权移动平均。prev=None 时直接取 value。"""
    if prev is None:
        return float(value)
    return round(alpha * float(value) + (1.0 - alpha) * float(prev), 4)


def _fb_field(item, name, default=""):
    """同时兼容 dict 与 ORM 行(FeedbackRecord)。"""
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def analyze_feedback(feedback_list, fp_stats=None) -> dict:
    """分析反馈列表 → 按规则误报率 + 建议列表。

    Args:
        feedback_list: dict/ORM 列表, 字段含 feedback_type / rule_id /
            original_conclusion(可有 llm: 前缀)。
        fp_stats: 可选 feedback_loop.get_fp_statistics() 结果(仅作上下文, 不阻塞)。

    Returns:
        {by_rule: {rule_id: {n, fp, tp, fp_rate, lo, hi, llm_sourced}},
         global: {n, fp, tp, missed_threat, fp_rate, lo, hi},
         suggestions: [...]}
    """
    by_rule: dict[str, dict] = {}
    global_fp = global_tp = missed = 0
    llm_conclusion: dict[str, str] = {}  # rule -> 首个 llm: 结论
    rule_fb: dict[str, int] = {}         # rule -> llm: 条数标记用

    for rec in (feedback_list or []):
        ftype = str(_fb_field(rec, "feedback_type", ""))
        rule = str(_fb_field(rec, "rule_id", "") or "")
        oc = str(_fb_field(rec, "original_conclusion", "") or "")
        if ftype == "missed_threat":
            missed += 1
            continue
        if ftype not in ("false_positive", "true_positive"):
            continue
        is_tp = ftype == "true_positive"
        if is_tp:
            global_tp += 1
        else:
            global_fp += 1
        if not rule:
            continue
        bucket = by_rule.setdefault(rule, {"n": 0, "fp": 0, "tp": 0})
        bucket["n"] += 1
        bucket["tp" if is_tp else "fp"] += 1
        if oc.startswith("llm:") and rule not in llm_conclusion:
            llm_conclusion[rule] = oc
            rule_fb[rule] = rule_fb.get(rule, 0) + 1

    for rule, bucket in by_rule.items():
        fp = bucket["fp"]
        n = bucket["n"]
        lo, hi = wilson_interval(fp, n)
        bucket["fp_rate"] = round(fp / max(n, 1), 4)
        bucket["lo"] = lo
        bucket["hi"] = hi
        bucket["llm_sourced"] = rule in llm_conclusion
        bucket["original_conclusion"] = llm_conclusion.get(rule, "")

    suggestions: list[dict] = []
    for rule, bucket in by_rule.items():
        rid_low = rule.lower()
        anomaly_channel = "anomal" in rid_low
        fp_rate = bucket["fp_rate"]
        # 异常检测通道的 FP → 阈值调整建议(永不自动 shadow)
        if anomaly_channel:
            if bucket["fp"] >= 1 and fp_rate >= ANOMAL_ADJUST_FP_RATE:
                suggestions.append({
                    "type": "adjust_anomaly_threshold",
                    "rule_id": rule,
                    "fp": bucket["fp"],
                    "tp": bucket["tp"],
                    "fp_rate": fp_rate,
                    "n": bucket["n"],
                    "auto": False,
                    "confidence": round(min(0.9, 0.4 + bucket["lo"]), 3),
                    "suggestion": f"异常检测通道 {rule} 误报率偏高({fp_rate:.0%}),建议复核阈值",
                })
            continue
        # 仅当 Wilson 下界 > 15% 才提议 shadow(不信任点估计)
        if bucket["n"] >= SHADOW_MIN_N and bucket["lo"] > SHADOW_LO_THRESHOLD:
            llm = bucket["llm_sourced"]
            suggestions.append({
                "type": "shadow_rule",
                "rule_id": rule,
                "n": bucket["n"],
                "fp": bucket["fp"],
                "tp": bucket["tp"],
                "fp_rate": fp_rate,
                "lo": bucket["lo"],
                "llm_sourced": llm,
                "original_conclusion": bucket["original_conclusion"],
                "auto": not llm,
                "confidence": round(min(0.95, 0.5 + bucket["lo"]), 3),
                "suggestion": (
                    f"规则 {rule} 误报率 Wilson 下界 {bucket['lo']:.0%} "
                    f"({bucket['fp']}/{bucket['n']}), 建议 shadow 降级"
                ),
            })

    # 漏报 ≥3 → 持久化调优建议(persist_tuning_suggestion 载体)
    if missed >= MISSED_THREAT_THRESHOLD:
        suggestions.append({
            "type": "missed_threat",
            "count": missed,
            "auto": True,
            "confidence": 0.7,
            "suggestion": f"收割窗口内 {missed} 次漏报反馈, 建议新增/增强检测规则",
        })

    gf_n = global_fp + global_tp
    glo = {"n": gf_n, "fp": global_fp, "tp": global_tp,
           "missed_threat": missed,
           "fp_rate": round(global_fp / max(gf_n, 1), 4)}
    if gf_n > 0:
        lo, hi = wilson_interval(global_fp, gf_n)
        glo["lo"], glo["hi"] = lo, hi
    else:
        glo["lo"], glo["hi"] = 0.0, 0.0

    return {
        "by_rule": by_rule,
        "global": glo,
        "missed_threat": missed,
        "suggestions": suggestions,
        "fp_stats": fp_stats or {},
    }
