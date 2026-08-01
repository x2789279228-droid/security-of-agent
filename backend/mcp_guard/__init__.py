"""MCP Guard — 可信工具调用控制网关。

本模块从 security_agent v1.3.0 的 mcp_server 集成而来，
为 shared-memory-platform 提供统一的工具调用安全管控能力。

核心组件：
- McpGuardServer: 4层检查链（Registry → Permission → Validator → Policy）
- GuardDecision:    Guard 决策结果
- ToolCallRequest:  Agent 发起的工具调用请求
"""

import logging

from .guard_server import McpGuardServer, GuardDecision, ToolCallRequest

logger = logging.getLogger(__name__)

# 全局单例
try:
    mcp_guard = McpGuardServer()
    logger.info(f"MCP Guard initialized: {len(mcp_guard.list_tools())} tools registered")
except Exception as e:
    logger.error(f"MCP Guard init failed: {e}")
    mcp_guard = None

__all__ = ["McpGuardServer", "GuardDecision", "ToolCallRequest", "mcp_guard"]
