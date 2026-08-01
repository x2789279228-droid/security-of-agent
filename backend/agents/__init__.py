"""
Agent 模块 — Audit-LLM + CAD 架构

审核流水线:
  Decomposer → Tool Builder → Executor → Reviewer

独立监督（CAD — 不参与内容生产，独立于流水线运行）:
  PenetratingVerifier + ContextAuditor + CircuitBreaker
"""
from .agent_decomposer import decomposer
from .agent_tool_builder import tool_builder
from .agent_executor import executor
from .agent_reviewer import reviewer
from .agent_cad import cad_agent

# 旧 Agent（兼容）
from .agent_a import AgentA
from .agent_b import AgentB
from .agent_c import AgentC
from .agent_d import AgentD

__all__ = [
    "decomposer", "tool_builder", "executor", "reviewer", "cad_agent",
    "AgentA", "AgentB", "AgentC", "AgentD",
]
