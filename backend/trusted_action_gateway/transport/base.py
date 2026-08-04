"""
Trusted Action Gateway — MCP 传输安全抽象层 (base)

定义所有 MCP 传输客户端和安全策略的抽象基类、共享数据模型与异常层次。

设计约束:
  - 不使用 shell=True
  - 不允许任意命令执行
  - 不允许 Agent 自由指定 URL
  - 使用类型标注
  - 使用 Pydantic
  - 异常处理完整
"""
from __future__ import annotations

import abc
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ── 异常层次 ──

class TransportError(Exception):
    """传输层基础异常。"""


class TransportTimeout(TransportError):
    """传输超时异常。"""


class TransportSecurityViolation(TransportError):
    """传输安全策略违例异常。"""


class TransportCircuitOpen(TransportError):
    """熔断器处于开启状态，请求被拒绝。"""


# ── Pydantic 数据模型 ──

class McpToolInfo(BaseModel):
    """MCP 工具元信息。"""
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    parameters_schema: dict[str, Any] = Field(default_factory=dict)
    server_id: str
    transport_type: str


class CallToolRequest(BaseModel):
    """工具调用请求。"""
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    request_id: str = ""
    incident_id: str = ""
    grant_id: str = ""
    trace_id: str = ""
    timestamp: float = 0.0
    nonce: str = ""


class CallToolResult(BaseModel):
    """工具调用结果。"""
    model_config = ConfigDict(extra="forbid")

    success: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    latency_ms: float = 0.0
    transport_type: str = ""
    server_identity: str = ""


# ── 抽象基类 ──

class BaseMcpClient(abc.ABC):
    """MCP 传输客户端抽象基类。

    所有具体传输实现 (STDIO / Remote) 必须继承此类并实现全部抽象方法。
    """

    server_id: str
    transport_type: str

    @abc.abstractmethod
    async def list_tools(self) -> list[dict]:
        """列出 MCP Server 暴露的工具。"""
        ...

    @abc.abstractmethod
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """调用指定工具并返回结果。"""
        ...

    @abc.abstractmethod
    async def health_check(self) -> bool:
        """检查 MCP Server 健康状态。"""
        ...

    @abc.abstractmethod
    async def close(self) -> None:
        """释放传输资源。"""
        ...


class BaseTransportSecurityPolicy(abc.ABC):
    """传输安全策略抽象基类。

    每种传输类型必须提供对应的安全策略实现，覆盖启动校验、请求校验、
    环境变量净化和安全配置查询。
    """

    @abc.abstractmethod
    def validate_startup(self, config: dict) -> tuple[bool, str]:
        """启动前校验配置合法性。

        Returns:
            (ok, reason) — ok 为 True 时 reason 为说明，为 False 时为拒绝原因。
        """
        ...

    @abc.abstractmethod
    def validate_request(self, request: dict) -> tuple[bool, str]:
        """校验单次请求合法性。

        Returns:
            (ok, reason)
        """
        ...

    @abc.abstractmethod
    def sanitize_environment(self, env: dict) -> dict:
        """净化环境变量，移除敏感项，只保留白名单中的键。"""
        ...

    @abc.abstractmethod
    def get_security_config(self) -> dict:
        """返回当前安全策略的配置摘要。"""
        ...
