"""
Trusted Action Gateway — MCP 传输安全抽象层

导出所有传输客户端、安全策略和注册表组件。

安全约束:
  - 不使用 shell=True
  - 不允许任意命令执行
  - 不允许 Agent 自由指定 URL
  - 使用类型标注
  - 使用 Pydantic
  - 异常处理完整
"""
from .base import (
    BaseMcpClient,
    BaseTransportSecurityPolicy,
    CallToolRequest,
    CallToolResult,
    McpToolInfo,
    TransportCircuitOpen,
    TransportError,
    TransportSecurityViolation,
    TransportTimeout,
)
from .server_registry import (
    McpServerRegistry,
    ServerEntry,
    mcp_server_registry,
)
from .stdio_client import (
    StdioMcpClient,
    StdioTransportSecurityPolicy,
)
from .remote_client import (
    RemoteMcpClient,
    RemoteTransportSecurityPolicy,
    TokenProvider,
)

__all__ = [
    # 抽象基类
    "BaseMcpClient",
    "BaseTransportSecurityPolicy",
    # STDIO
    "StdioMcpClient",
    "StdioTransportSecurityPolicy",
    # Remote
    "RemoteMcpClient",
    "RemoteTransportSecurityPolicy",
    "TokenProvider",
    # 注册表
    "McpServerRegistry",
    "ServerEntry",
    "mcp_server_registry",
    # 数据模型
    "McpToolInfo",
    "CallToolRequest",
    "CallToolResult",
    # 异常
    "TransportError",
    "TransportTimeout",
    "TransportSecurityViolation",
    "TransportCircuitOpen",
]
