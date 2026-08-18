"""
数据安全大模型模块 — P0.S

职责:
  - HTTP 会话命中敏感关键字后,LLM 复核是否真为敏感数据外泄
  - 区分真敏感数据 vs 业务正常字段 (规则只能看关键字)
  - 高置信度命中 → 自动创建审计工单

子模块:
  llm_classifier — LLM 分类器 + 工单触发

性能保障:
  - 触发条件:必需规则先命中 "sensitive_data_leak" (绝不降低)
  - 主路径 0 等待 (走 llm_enhancer.safe_dispatch)
  - 日预算 5¥ → ~50 次/日
"""

from .llm_classifier import classify_session, classify_and_broadcast

__all__ = ["classify_session", "classify_and_broadcast"]