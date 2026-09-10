"""
learn_loop — 后端每日学习闭环(收割 → 统计/聚类/序列 → 提议 → 自动应用)

把 7 个既有非对抗机制(baseline / reputation / feedback / degrade / tune /
postmortem / case)的证据收敛为可审计的 LearningRun / LearningAction,
让误报反馈能自动衰减基线、下调信誉、shadow 规则、补复盘草稿、开跟进工单。

对外入口: run_cycle(session, trigger="daily") — 对调度器 fail-open。
"""
from learn_loop.orchestrator import run_cycle

__all__ = ["run_cycle"]
