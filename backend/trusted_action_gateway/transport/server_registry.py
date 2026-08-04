"""
Trusted Action Gateway — MCP Server 注册表

管理允许连接的 MCP Server 列表。Agent 不能自由指定 URL 或命令，
只能通过 server_id 引用注册表中预配置的 Server。

安全约束:
  - URL 只能从注册表中解析，禁止 Agent 自由指定
  - 强制 HTTPS (Remote 传输)
  - 命令只能来自注册表 (STDIO 传输)
  - 检查可执行文件路径合法性
"""
from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class ServerEntry(BaseModel):
    """MCP Server 注册条目。"""
    model_config = ConfigDict(extra="forbid")

    server_id: str
    transport: str  # "stdio" | "remote"

    # ── STDIO 字段 ──
    command: str = ""  # 可执行文件路径
    args: list[str] = Field(default_factory=list)
    working_dir: str = ""
    expected_hash: str = ""  # 可执行文件 SHA256 哈希
    allowed_env_keys: list[str] = Field(default_factory=list)  # 环境变量白名单

    # ── Remote 字段 ──
    url: str = ""
    allowed_audiences: list[str] = Field(default_factory=list)
    required_scopes: list[str] = Field(default_factory=list)
    mtls_cert_path: str = ""

    # ── 通用资源限制 ──
    max_execution_time: int = 30
    max_memory_mb: int = 256
    max_cpu_percent: float = 50.0
    max_output_size: int = 1048576  # 1 MB
    max_concurrent: int = 4
    network_allowed: bool = False  # STDIO 默认禁止网络
    enabled: bool = True


class McpServerRegistry:
    """MCP Server 注册表 — 管理允许连接的 MCP Server 列表。

    核心安全原则: Agent 不能自由指定 URL 或命令，只能引用注册表中的 server_id。
    """

    def __init__(self) -> None:
        self._servers: dict[str, ServerEntry] = {}

    def register(self, entry: ServerEntry) -> None:
        """注册一个 MCP Server。"""
        if entry.transport not in ("stdio", "remote"):
            raise ValueError(
                f"不支持的传输类型: {entry.transport} (仅支持 'stdio' / 'remote')"
            )
        self._servers[entry.server_id] = entry
        logger.info(
            f"[McpServerRegistry] Registered server '{entry.server_id}' "
            f"(transport={entry.transport}, enabled={entry.enabled})"
        )

    def get(self, server_id: str) -> Optional[ServerEntry]:
        """按 server_id 获取注册条目。"""
        return self._servers.get(server_id)

    def list_servers(self) -> list[ServerEntry]:
        """列出所有已注册的 Server。"""
        return list(self._servers.values())

    def is_registered(self, server_id: str) -> bool:
        """判断 server_id 是否已注册。"""
        return server_id in self._servers

    def validate_url(self, url: str) -> tuple[bool, str, Optional[str]]:
        """校验 URL 是否来自注册表并强制 HTTPS。

        Agent 不能自由指定 URL — URL 只能匹配注册表中预配置的 Remote Server。

        Returns:
            (ok, reason, server_id) — ok 为 True 时返回匹配的 server_id。
        """
        if not url:
            return False, "URL 为空", None

        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False, f"必须使用 HTTPS (当前 scheme={parsed.scheme})", None

        # 在注册表中查找匹配的 URL
        for sid, entry in self._servers.items():
            if entry.transport != "remote":
                continue
            if not entry.enabled:
                continue
            if entry.url and entry.url == url:
                return True, "URL 匹配已注册 Server", sid

        return False, "URL 不在注册表中 (禁止 Agent 自由指定 URL)", None

    def validate_command(self, command: str) -> tuple[bool, str, Optional[str]]:
        """校验命令是否来自注册表并检查可执行文件路径。

        Agent 不能自由指定命令 — 命令只能匹配注册表中预配置的 STDIO Server。

        Returns:
            (ok, reason, server_id)
        """
        if not command:
            return False, "命令为空", None

        # 在注册表中查找匹配的命令
        for sid, entry in self._servers.items():
            if entry.transport != "stdio":
                continue
            if not entry.enabled:
                continue
            if entry.command and entry.command == command:
                # 检查可执行文件路径是否存在
                if not os.path.isfile(command):
                    return False, f"可执行文件不存在: {command}", None
                return True, "命令匹配已注册 Server", sid

        return False, "命令不在注册表中 (禁止 Agent 自由指定命令)", None

    def load_default(self) -> None:
        """加载默认 MCP Server 配置。"""
        # STDIO 本地工具
        self.register(ServerEntry(
            server_id="local-stdio",
            transport="stdio",
            command="python",
            args=["-m", "mcp_server.local_tools"],
            working_dir="",
            expected_hash="",
            allowed_env_keys=[
                "PATH", "PYTHONPATH", "LANG", "LC_ALL",
                "HOME", "TMP", "TEMP", "SYSTEMROOT",
            ],
            max_execution_time=30,
            max_memory_mb=256,
            max_cpu_percent=50.0,
            max_output_size=1048576,
            max_concurrent=4,
            network_allowed=False,
            enabled=True,
        ))

        # Remote SOC
        self.register(ServerEntry(
            server_id="remote-soc",
            transport="remote",
            url="https://soc.internal/mcp",
            allowed_audiences=["mcp-soc"],
            required_scopes=["tools:call"],
            mtls_cert_path="",
            max_execution_time=30,
            max_memory_mb=256,
            max_cpu_percent=50.0,
            max_output_size=1048576,
            max_concurrent=4,
            network_allowed=True,
            enabled=True,
        ))

        logger.info(
            f"[McpServerRegistry] Default servers loaded "
            f"({len(self._servers)} entries)"
        )


# ── 全局单例 ──
mcp_server_registry = McpServerRegistry()
