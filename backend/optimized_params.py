"""
层级化Transformer注意力优化参数
自动生成于 2026-07-26T14:30:50.468660
训练样本数: 4988
"""
import math


# ── 路由映射（数据驱动优化） ──
ROUTE_MAPPING = {
    "critical": "none",
    "high": "light",
    "medium": "light",
    "low": "deep",
    "info": "deep"
}

# ── 额外事件类型覆盖 ──
EVENT_ROUTE_OVERRIDE = {
    "C2_BEACON": "none",
    "DATA_EXFIL": "none",
    "MALWARE_DETECT": "none",
    "LATERAL_MOVE": "none",
    "RANSOMWARE": "none",
}


def optimized_route_event(event: dict) -> str:
    """数据优化后的路由决策"""
    severity = event.get("severity", "info")
    event_type = event.get("event", "")
    # 事件类型覆盖
    override = EVENT_ROUTE_OVERRIDE.get(event_type)
    if override:
        return override
    # 严重度映射
    return ROUTE_MAPPING.get(severity, "light")


def optimized_importance_score(event: dict) -> float:
    """数据优化后的重要性评分"""
    severity = event.get("severity", "info")
    confidence = event.get("confidence", 50)

    severity_map = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1
}
    sev_score = severity_map.get(severity, 0.3)
    conf_norm = confidence / 100.0

    w_sev = 0.6358286834081295
    w_conf = 0.5203074063485912
    w_interact = 0.8411166409582017

    score = (w_sev * sev_score + w_conf * conf_norm +
             w_interact * sev_score * conf_norm)
    return min(1.0, max(0.0, score))


# ── Token预算比例（基于重要性分布） ──
BUDGET_RATIOS = {
    "DOC":  0.195,
    "CHUNK": 0.464,
    "TOKEN": 0.341,
}


# ── 记忆树合并触发 ──
CONSOLIDATE_EVERY = 10


# ── Softmax注意力温度 ──
ATTENTION_TEMPERATURE = 3.2
