"""
Trusted Action Gateway — STDIO MCP 传输客户端

通过子进程 stdin/stdout 与本地 MCP Server 通信
(JSON-RPC 2.0 over newline-delimited JSON)。

安全策略:
  1. 禁止 shell=True (使用 subprocess 不带 shell)
  2. 命令只能来自 MCP Server Registry
  3. 检查可执行文件路径和哈希 (SHA256)
  4. 使用固定 working directory
  5. 使用独立低权限系统用户 (Unix: subprocess user 参数; Windows: 记录 warning)
  6. 子进程环境变量采用白名单 (从 ServerEntry.allowed_env_keys)
  7. 不继承 LLM Key、数据库密码、JWT Secret 和无关凭据
  8. 支持最大执行时间 (max_execution_time)
  9. 支持最大内存、CPU、输出大小和并发数
     (Unix: resource.setrlimit; Windows: 记录 warning)
  10. 默认禁止网络访问 (不传递网络相关环境变量; Windows 无法直接限制网络)
  11. 非法 JSON、超时、输出过大时终止进程
  12. 连续故障触发熔断 (3 次连续失败 → 熔断 60 秒)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Optional

from .base import (
    BaseMcpClient,
    BaseTransportSecurityPolicy,
    CallToolResult,
    McpToolInfo,
    TransportCircuitOpen,
    TransportError,
    TransportSecurityViolation,
    TransportTimeout,
)
from .server_registry import McpServerRegistry, ServerEntry, mcp_server_registry

logger = logging.getLogger(__name__)

# ── 敏感环境变量精确黑名单 ──
SENSITIVE_ENV_VARS: set[str] = {
    "SHARED_MEMORY_LLM_API_KEY",
    "SHARED_MEMORY_EMBEDDING_API_KEY",
    "SHARED_MEMORY_JWT_SECRET",
    "SHARED_MEMORY_ADMIN_PASSWORD",
    "SHARED_MEMORY_DATABASE_URL",
    "SHARED_MEMORY_REDIS_URL",
    "POSTGRES_PASSWORD",
    "SHARED_MEMORY_FIELD_ENCRYPTION_KEY",
    "SHARED_MEMORY_FW_SSH_PASSWORD",
}

# 敏感环境变量模式 (子串匹配，作为白名单之后的二次防线)
SENSITIVE_PATTERNS: list[str] = [
    "LLM_API_KEY",
    "EMBEDDING_API_KEY",
    "JWT_SECRET",
    "ADMIN_PASSWORD",
    "DATABASE_URL",
    "REDIS_URL",
    "POSTGRES_PASSWORD",
    "ENCRYPTION_KEY",
    "SSH_PASSWORD",
    "SSH_KEY",
]

# 网络相关环境变量 (默认禁止透传)
NETWORK_ENV_VARS: set[str] = {
    "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
    "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
    "SOCKS_PROXY", "socks_proxy",
}

# 熔断阈值
_CIRCUIT_FAILURE_THRESHOLD = 3
_CIRCUIT_OPEN_SECONDS = 60.0


class StdioTransportSecurityPolicy(BaseTransportSecurityPolicy):
    """STDIO 传输安全策略。"""

    def __init__(self, server_entry: ServerEntry) -> None:
        self._entry = server_entry

    def validate_startup(self, config: dict) -> tuple[bool, str]:
        """启动前校验: 命令路径存在、哈希匹配、working_dir 存在。"""
        entry = self._entry

        # 命令非空
        if not entry.command:
            return False, "ServerEntry.command 为空"

        # 命令路径存在
        if not os.path.isfile(entry.command):
            return False, f"可执行文件不存在: {entry.command}"

        # 哈希校验 (若配置了 expected_hash)
        if entry.expected_hash:
            try:
                actual_hash = self._compute_sha256(entry.command)
            except OSError as e:
                return False, f"计算可执行文件哈希失败: {e}"
            if actual_hash != entry.expected_hash:
                return False, (
                    f"可执行文件哈希不匹配 (expected={entry.expected_hash}, "
                    f"actual={actual_hash})"
                )

        # working_dir 校验 (若配置了)
        if entry.working_dir and not os.path.isdir(entry.working_dir):
            return False, f"working_dir 不存在: {entry.working_dir}"

        return True, "STDIO 启动校验通过"

    def validate_request(self, request: dict) -> tuple[bool, str]:
        """校验请求格式。"""
        if not isinstance(request, dict):
            return False, "请求必须是 dict"

        tool_name = request.get("tool_name") or request.get("name")
        if not tool_name or not isinstance(tool_name, str):
            return False, "请求缺少 tool_name/name 字段或类型错误"

        arguments = request.get("arguments", {})
        if not isinstance(arguments, dict):
            return False, "arguments 必须是 dict"

        return True, "请求校验通过"

    def sanitize_environment(self, env: dict) -> dict:
        """净化环境变量: 只保留白名单中的键，并移除敏感项和网络相关项。"""
        allowed = set(self._entry.allowed_env_keys)
        result: dict[str, str] = {}

        for key, value in env.items():
            # 白名单检查 — 只保留注册表中声明的环境变量
            if key not in allowed:
                continue

            # 敏感精确匹配检查 (二次防线)
            if key in SENSITIVE_ENV_VARS:
                logger.warning(
                    f"[StdioPolicy] 环境变量 '{key}' 在白名单中但命中敏感黑名单，已移除"
                )
                continue

            # 敏感模式匹配检查 (二次防线)
            if any(pat in key for pat in SENSITIVE_PATTERNS):
                logger.warning(
                    f"[StdioPolicy] 环境变量 '{key}' 命中敏感模式，已移除"
                )
                continue

            # 网络相关环境变量默认禁止透传
            if key in NETWORK_ENV_VARS and not self._entry.network_allowed:
                logger.debug(
                    f"[StdioPolicy] 环境变量 '{key}' 为网络代理配置，"
                    f"当前 server 禁止网络，已移除"
                )
                continue

            result[key] = value

        return result

    def get_security_config(self) -> dict:
        """返回安全配置摘要。"""
        return {
            "transport": "stdio",
            "server_id": self._entry.server_id,
            "command": self._entry.command,
            "working_dir": self._entry.working_dir,
            "expected_hash_configured": bool(self._entry.expected_hash),
            "allowed_env_keys": list(self._entry.allowed_env_keys),
            "max_execution_time": self._entry.max_execution_time,
            "max_memory_mb": self._entry.max_memory_mb,
            "max_cpu_percent": self._entry.max_cpu_percent,
            "max_output_size": self._entry.max_output_size,
            "max_concurrent": self._entry.max_concurrent,
            "network_allowed": self._entry.network_allowed,
            "shell_enabled": False,
            "sensitive_env_blacklist": sorted(SENSITIVE_ENV_VARS),
        }

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """计算文件 SHA256 哈希。"""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


class StdioMcpClient(BaseMcpClient):
    """STDIO MCP 传输客户端。

    通过子进程 stdin/stdout 与本地 MCP Server 通信。
    严格遵守安全策略: 不使用 shell、命令来自注册表、哈希校验、环境白名单、
    资源限制、输出限制、熔断器。
    """

    def __init__(
        self,
        server_id: str,
        policy: StdioTransportSecurityPolicy,
        registry: Optional[McpServerRegistry] = None,
    ) -> None:
        self.server_id = server_id
        self.transport_type = "stdio"
        self._policy = policy
        self._registry = registry or mcp_server_registry

        entry = self._registry.get(server_id)
        if entry is None:
            raise TransportSecurityViolation(
                f"server_id '{server_id}' 未在注册表中注册"
            )
        if entry.transport != "stdio":
            raise TransportSecurityViolation(
                f"server_id '{server_id}' 传输类型为 '{entry.transport}'，不是 'stdio'"
            )
        self._entry: ServerEntry = entry

        # 进程状态
        self._process: Optional[subprocess.Popen] = None
        self._request_id: int = 0
        self._lock = asyncio.Lock()

        # 并发控制
        self._semaphore = asyncio.Semaphore(self._entry.max_concurrent)

        # 熔断器状态
        self._circuit_state: str = "closed"  # closed | open | half_open
        self._circuit_failure_count: int = 0
        self._circuit_open_until: float = 0.0

    # ── 熔断器 ──

    def _check_circuit(self) -> None:
        """检查熔断器状态，若开启则抛出异常。"""
        now = time.time()
        if self._circuit_state == "open":
            if now < self._circuit_open_until:
                raise TransportCircuitOpen(
                    f"STDIO 熔断器开启中，剩余 "
                    f"{self._circuit_open_until - now:.0f}s "
                    f"(server_id={self.server_id})"
                )
            # 熔断超时，进入半开状态
            self._circuit_state = "half_open"
            logger.info(
                f"[StdioMcpClient] Circuit → half_open "
                f"(server_id={self.server_id})"
            )

    def _update_circuit(self, success: bool) -> None:
        """根据调用结果更新熔断器状态。"""
        if success:
            if self._circuit_state != "closed":
                logger.info(
                    f"[StdioMcpClient] Circuit → closed "
                    f"(server_id={self.server_id})"
                )
            self._circuit_state = "closed"
            self._circuit_failure_count = 0
        else:
            self._circuit_failure_count += 1
            if self._circuit_failure_count >= _CIRCUIT_FAILURE_THRESHOLD:
                self._circuit_state = "open"
                self._circuit_open_until = time.time() + _CIRCUIT_OPEN_SECONDS
                logger.warning(
                    f"[StdioMcpClient] Circuit → open "
                    f"(failures={self._circuit_failure_count}, "
                    f"open_for={_CIRCUIT_OPEN_SECONDS}s, "
                    f"server_id={self.server_id})"
                )

    # ── 进程管理 ──

    async def _start_process(self) -> subprocess.Popen:
        """启动 MCP Server 子进程。

        安全措施:
          - shell=False (绝不使用 shell=True)
          - 命令来自注册表
          - 哈希校验
          - 固定 working directory
          - 环境变量白名单 + 敏感黑名单
          - Unix: 资源限制 (RLIMIT_AS / RLIMIT_CPU) + 低权限用户
          - Windows: 资源限制不可用，记录 warning
        """
        entry = self._entry

        # 启动前安全校验
        ok, reason = self._policy.validate_startup({})
        if not ok:
            raise TransportSecurityViolation(f"启动校验失败: {reason}")

        # 命令注册表校验
        cmd_ok, cmd_reason, _ = self._registry.validate_command(entry.command)
        if not cmd_ok:
            raise TransportSecurityViolation(f"命令校验失败: {cmd_reason}")

        # 构建命令列表 (绝不使用 shell)
        cmd_list: list[str] = [entry.command] + list(entry.args)

        # 构建净化后的环境变量
        raw_env = dict(os.environ)
        sanitized_env = self._policy.sanitize_environment(raw_env)

        # working directory
        cwd = entry.working_dir if entry.working_dir else None

        # 构建 subprocess 关键字参数
        popen_kwargs: dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,  # 强制: 绝不使用 shell=True
            "env": sanitized_env,
        }
        if cwd is not None:
            popen_kwargs["cwd"] = cwd

        # Unix: 资源限制 + 低权限用户
        if sys.platform != "win32":
            popen_kwargs["preexec_fn"] = self._build_preexec_fn(entry)
            # 低权限用户 (若环境配置了 MCP_STDIO_RUN_USER)
            run_user = os.environ.get("MCP_STDIO_RUN_USER", "")
            if run_user:
                popen_kwargs["user"] = run_user
                logger.info(
                    f"[StdioMcpClient] Dropping privileges to user='{run_user}' "
                    f"(server_id={self.server_id})"
                )
        else:
            # Windows: 无法通过 subprocess 设置资源限制和用户
            if not entry.network_allowed:
                logger.warning(
                    f"[StdioMcpClient] Windows 平台无法直接限制子进程网络访问 "
                    f"(server_id={self.server_id})，依赖环境变量白名单"
                )
            logger.warning(
                f"[StdioMcpClient] Windows 平台无法设置 RLIMIT_AS/RLIMIT_CPU "
                f"(server_id={self.server_id})"
            )

        logger.info(
            f"[StdioMcpClient] Starting process: {entry.command} "
            f"{' '.join(entry.args)} "
            f"(server_id={self.server_id}, cwd={cwd})"
        )

        try:
            # 使用线程池执行阻塞的 Popen 调用
            proc = await asyncio.to_thread(
                subprocess.Popen, cmd_list, **popen_kwargs
            )
        except FileNotFoundError as e:
            raise TransportSecurityViolation(
                f"可执行文件不存在: {e}"
            ) from e
        except OSError as e:
            raise TransportError(f"启动子进程失败: {e}") from e

        self._process = proc
        return proc

    @staticmethod
    def _build_preexec_fn(entry: ServerEntry):
        """构建 Unix preexec_fn: 设置资源限制 (内存/CPU)。"""
        import resource

        max_mem_bytes = entry.max_memory_mb * 1024 * 1024
        max_cpu_seconds = entry.max_execution_time + 5  # 留 5s 余量

        def _set_limits() -> None:
            try:
                # 内存限制 (虚拟内存)
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (max_mem_bytes, max_mem_bytes),
                )
            except (ValueError, OSError) as e:
                logger.warning(
                    f"[StdioMcpClient] setrlimit RLIMIT_AS failed: {e}"
                )
            try:
                # CPU 时间限制 (秒)
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (max_cpu_seconds, max_cpu_seconds),
                )
            except (ValueError, OSError) as e:
                logger.warning(
                    f"[StdioMcpClient] setrlimit RLIMIT_CPU failed: {e}"
                )

        return _set_limits

    def _ensure_process(self) -> subprocess.Popen:
        """确保子进程已启动且仍在运行。"""
        if self._process is None or self._process.poll() is not None:
            raise TransportError(
                f"子进程未启动或已退出 (server_id={self.server_id})"
            )
        return self._process

    def _kill_process(self, reason: str) -> None:
        """终止子进程。"""
        proc = self._process
        if proc is not None and proc.poll() is None:
            logger.warning(
                f"[StdioMcpClient] Killing process "
                f"(reason={reason}, server_id={self.server_id}, "
                f"pid={proc.pid})"
            )
            try:
                proc.kill()
            except Exception as e:
                logger.error(f"[StdioMcpClient] kill failed: {e}")
        self._process = None

    # ── JSON-RPC 通信 ──

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _send_and_recv(self, message: dict) -> dict:
        """发送 JSON-RPC 请求并读取响应 (newline-delimited JSON)。

        使用 asyncio.to_thread 包装阻塞 I/O，避免阻塞事件循环。
        在超时、输出过大、非法 JSON 时终止进程。
        """
        proc = self._ensure_process()
        if proc.stdin is None or proc.stdout is None:
            raise TransportError("子进程 stdin/stdout 未就绪")

        request_line = json.dumps(message, ensure_ascii=False) + "\n"
        request_bytes = request_line.encode("utf-8")

        # 检查请求大小
        if len(request_bytes) > self._entry.max_output_size:
            raise TransportSecurityViolation(
                f"请求体过大 ({len(request_bytes)} > "
                f"{self._entry.max_output_size})"
            )

        # 同步写入 + 读取 (在线程池中执行，避免阻塞事件循环)
        def _write_and_read() -> bytes:
            assert proc.stdin is not None
            assert proc.stdout is not None
            proc.stdin.write(request_bytes)
            proc.stdin.flush()
            line = proc.stdout.readline()
            return line

        timeout = self._entry.max_execution_time
        try:
            raw_line = await asyncio.wait_for(
                asyncio.to_thread(_write_and_read),
                timeout=timeout,
            )
        except asyncio.TimeoutError as e:
            self._kill_process("timeout")
            raise TransportTimeout(
                f"读取响应超时 ({timeout}s, server_id={self.server_id})"
            ) from e

        if not raw_line:
            self._kill_process("empty_response")
            raise TransportError("子进程返回空响应 (可能已退出)")

        # 输出大小检查
        if len(raw_line) > self._entry.max_output_size:
            self._kill_process("output_too_large")
            raise TransportSecurityViolation(
                f"响应过大 ({len(raw_line)} > "
                f"{self._entry.max_output_size})"
            )

        # 解析 JSON
        try:
            response = json.loads(raw_line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._kill_process("invalid_json")
            raise TransportError(f"非法 JSON 响应: {e}") from e

        if not isinstance(response, dict):
            self._kill_process("invalid_response_type")
            raise TransportError("响应不是 JSON 对象")

        return response

    # ── 公共接口 ──

    async def list_tools(self) -> list[McpToolInfo]:
        """列出 MCP Server 暴露的工具。"""
        # 熔断检查
        self._check_circuit()

        async with self._semaphore:
            async with self._lock:
                if self._process is None or self._process.poll() is not None:
                    await self._start_process()

                message = {
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "id": self._next_request_id(),
                }

                try:
                    response = await self._send_and_recv(message)
                except TransportError:
                    self._update_circuit(False)
                    raise

        # 处理 JSON-RPC 错误
        if "error" in response:
            self._update_circuit(False)
            error_info = response.get("error", {})
            error_msg = (
                error_info.get("message", "unknown")
                if isinstance(error_info, dict)
                else str(error_info)
            )
            raise TransportError(f"tools/list 错误: {error_msg}")

        result = response.get("result", {})
        tools_raw = (
            result.get("tools", []) if isinstance(result, dict) else []
        )

        tools: list[McpToolInfo] = []
        for t in tools_raw:
            if not isinstance(t, dict):
                continue
            tools.append(McpToolInfo(
                name=t.get("name", ""),
                description=t.get("description", ""),
                parameters_schema=t.get(
                    "inputSchema", t.get("parameters_schema", {})
                ),
                server_id=self.server_id,
                transport_type=self.transport_type,
            ))

        self._update_circuit(True)
        return tools

    async def call_tool(self, tool_name: str, arguments: dict) -> CallToolResult:
        """调用指定工具。"""
        start_time = time.time()

        # 请求校验
        ok, reason = self._policy.validate_request({
            "tool_name": tool_name,
            "arguments": arguments,
        })
        if not ok:
            raise TransportSecurityViolation(f"请求校验失败: {reason}")

        # 熔断检查 — 开启时返回失败结果而非抛出异常
        try:
            self._check_circuit()
        except TransportCircuitOpen as e:
            return CallToolResult(
                success=False,
                error=f"熔断器开启: {e}",
                latency_ms=round((time.time() - start_time) * 1000, 1),
                transport_type=self.transport_type,
                server_identity=self.server_id,
            )

        async with self._semaphore:
            async with self._lock:
                if self._process is None or self._process.poll() is not None:
                    try:
                        await self._start_process()
                    except TransportSecurityViolation as e:
                        self._update_circuit(False)
                        return CallToolResult(
                            success=False,
                            error=f"启动校验失败: {e}",
                            latency_ms=round(
                                (time.time() - start_time) * 1000, 1
                            ),
                            transport_type=self.transport_type,
                            server_identity=self.server_id,
                        )
                    except TransportError as e:
                        self._update_circuit(False)
                        return CallToolResult(
                            success=False,
                            error=f"启动子进程失败: {e}",
                            latency_ms=round(
                                (time.time() - start_time) * 1000, 1
                            ),
                            transport_type=self.transport_type,
                            server_identity=self.server_id,
                        )

                message = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments,
                    },
                    "id": self._next_request_id(),
                }

                try:
                    response = await self._send_and_recv(message)
                except TransportTimeout as e:
                    self._update_circuit(False)
                    return CallToolResult(
                        success=False,
                        error=f"传输超时: {e}",
                        latency_ms=round(
                            (time.time() - start_time) * 1000, 1
                        ),
                        transport_type=self.transport_type,
                        server_identity=self.server_id,
                    )
                except TransportSecurityViolation as e:
                    self._update_circuit(False)
                    return CallToolResult(
                        success=False,
                        error=f"安全违例: {e}",
                        latency_ms=round(
                            (time.time() - start_time) * 1000, 1
                        ),
                        transport_type=self.transport_type,
                        server_identity=self.server_id,
                    )
                except TransportError as e:
                    self._update_circuit(False)
                    return CallToolResult(
                        success=False,
                        error=f"传输错误: {e}",
                        latency_ms=round(
                            (time.time() - start_time) * 1000, 1
                        ),
                        transport_type=self.transport_type,
                        server_identity=self.server_id,
                    )

        latency_ms = round((time.time() - start_time) * 1000, 1)

        # 处理 JSON-RPC 错误
        if "error" in response:
            self._update_circuit(False)
            error_info = response.get("error", {})
            error_msg = (
                error_info.get("message", "unknown error")
                if isinstance(error_info, dict)
                else str(error_info)
            )
            return CallToolResult(
                success=False,
                error=error_msg,
                latency_ms=latency_ms,
                transport_type=self.transport_type,
                server_identity=self.server_id,
            )

        result = response.get("result", {})
        self._update_circuit(True)
        return CallToolResult(
            success=True,
            result=result if isinstance(result, dict) else {"value": result},
            latency_ms=latency_ms,
            transport_type=self.transport_type,
            server_identity=self.server_id,
        )

    async def health_check(self) -> bool:
        """检查 MCP Server 健康状态。"""
        try:
            if self._process is None or self._process.poll() is not None:
                async with self._lock:
                    if self._process is None or self._process.poll() is not None:
                        await self._start_process()

            message = {
                "jsonrpc": "2.0",
                "method": "ping",
                "id": self._next_request_id(),
            }
            response = await asyncio.wait_for(
                self._send_and_recv(message),
                timeout=min(self._entry.max_execution_time, 10),
            )
            return "result" in response
        except Exception as e:
            logger.debug(
                f"[StdioMcpClient] health_check failed "
                f"(server_id={self.server_id}): {e}"
            )
            return False

    async def close(self) -> None:
        """释放传输资源，终止子进程。"""
        self._kill_process("close")
