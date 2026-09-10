"""
learn_loop.types — 学习闭环共享类型与常量

收割(harvest) → 统计/聚类/序列(models_*) → 提议(propose) → 自动应用(apply)
七大既有非对抗机制的产物统一收敛为 LearningAction 行, 由 run_cycle 驱动。
"""
from __future__ import annotations

# 7 个既有机制 → action.mechanism 取值
MECHANISMS = ("baseline", "reputation", "feedback", "degrade", "tune", "postmortem", "case")

# 自动应用白名单: 只有这些 action_type 允许 auto=True 直接落地
AUTO_APPLY_TYPES = frozenset({
    "draft_post_mortem",        # 已关闭案例缺失复盘 → 自动补复盘草稿
    "shadow_rule",              # 高 FP 规则 → Sigma shadow(仅告警)
    "decay_baseline_entity",    # FP 源 IP → 基线衰减(不删实体)
    "update_reputation_prior",  # TP/FP 反馈 → 有界信誉先验
    "persist_tuning_suggestion",  # 调优建议记账(行即持久化)
    "open_review_work_order",   # 复盘 action_items 未完成 → 开 review 工单
})

# 仅人工落地的动作(学习闭环只提议, 不自动应用)
HUMAN_ONLY_TYPES = frozenset({
    "apply_sigma_change",        # 直接改 Sigma 规则内容
    "adjust_anomaly_threshold",  # 异常检测阈值调整
    "label_cluster",             # 事件聚类人工打标
    "propose_sequence_signature",  # 攻击链序列签名(转 CEP 模式前人工确认)
})

ACTION_TYPES = AUTO_APPLY_TYPES | HUMAN_ONLY_TYPES

# 复盘的 action_items 未完成 → 自动开 review 工单的机制名
REVIEW_MECHANISM = "postmortem"

# 置信度区间常量
LLM_PREFIX = "llm:"

# 提案动作的字段清单(insert_actions 依据)
ACTION_KEYS = ("action_type", "target_type", "target_id", "mechanism", "payload", "confidence", "auto")
