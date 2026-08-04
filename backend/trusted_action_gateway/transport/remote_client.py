"""
Trusted Action Gateway — Remote MCP 传输客户端

通过 HTTPS 与远程 MCP Server 通信 (JSON-RPC 2.0 over HTTP POST)。

安全策略:
  1. URL 只能从 MCP Server Registry 解析
  2. 禁止 Agent 自由指定 URL
  3. 强制 HTTPS
  4. 支持 OAuth2/OIDC (token_provider 接口)
  5. Token 必须包含 audience
  6. Token 必须包含最小 scope
  7. Token 必须短期有效 (exp < 1 小时)
  8. 禁止把用户或上游 Token 直接透传
  9. 支持 request_id、timestamp、nonce
  10. 防止请求重放 (nonce 缓存 5 分钟)
  11. 支持连接超时 (10s)、读取超时 (30s) 和响应大小限制 (1MB)
  12. 支持出站域名白名单
  13. 支持熔断和降级 (3 次连续失败 → 熔断 60s → 降级为建议模式)
  14. 支持可选 mTLS
  15. 远程服务不可用时只生成处置建议，不无限重试 (最多重试 2 次，指数退避)
"""
from __future__ import annotations

import abc
import asyncio
import json
import logging
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

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

# ── 常量 ──
_CONNECT_TIMEOUT = 10.0  # 连接超时 (秒)
_READ_TIMEOUT = 30.0  # 读取超时 (秒)
_MAX_RESPONSE_SIZE = 1048576  # 响应大小限制 (1 MB)
_NONCE_CACHE_TTL = 300.0  # nonce 缓存 5 分钟 (秒)
_MAX_RETRIES = 2  # 最大重试次数
_CIRCUIT_FAILURE_THRESHOLD = 3
_CIRCUIT_OPEN_SECONDS = 60.0


class TokenProvider(abc.ABC):
    """OAuth2/OIDC Token 提供者接口。

    具体实现负责向 IdP 请求短期 Token，确保:
      - Token 包含正确的 audience (aud)
      - Token 包含所需 scope
      - Token 短期有效 (exp < 1 小时)
      - 禁止直接透传用户或上游 Token
    """

    @abc.abstractmethod
    async def get_token(
        self,
        server_id: str,
        scopes: list[str],
        incident_id: str,
    ) -> dict:
        """获取 Token。

        Returns:
            dict 包含:
              - access_token: str — 原始 JWT 字符串 (用于 Authorization 头)
              - claims: dict — 解码后的 claims: {iss, sub, aud, scope,
                incident_id, exp, jti}
        """
        ...


class RemoteTransportSecurityPolicy(BaseTransportSecurityPolicy):
    """Remote 传输安全策略。"""

    def __init__(self, server_entry: ServerEntry) -> None:
        self._entry = server_entry

    def validate_startup(self, config: dict) -> tuple[bool, str]:
        """启动前校验: URL HTTPS、域名白名单。"""
        entry = self._entry

        if not entry.url:
            return False, "ServerEntry.url 为空"

        parsed = urlparse(entry.url)
        if parsed.scheme != "https":
            return False, f"必须使用 HTTPS (当前 scheme={parsed.scheme})"

        # 域名白名单检查 — 域名来自注册表 URL
        allowed_host = parsed.hostname or ""
        if not allowed_host:
            return False, "URL 缺少 hostname"

        # 校验 mTLS 证书路径 (若配置了)
        if entry.mtls_cert_path and not _file_exists(entry.mtls_cert_path):
            return False, f"mTLS 证书路径不存在: {entry.mtls_cert_path}"

        return True, "Remote 启动校验通过"

    def validate_request(self, request: dict) -> tuple[bool, str]:
        """校验请求格式: request_id, timestamp, nonce。"""
        if not isinstance(request, dict):
            return False, "请求必须是 dict"

        request_id = request.get("request_id", "")
        if not request_id:
            return False, "请求缺少 request_id"

        timestamp = request.get("timestamp", 0.0)
        if not timestamp or not isinstance(timestamp, (int, float)):
            return False, "请求缺少 timestamp 或类型错误"

        # 时间戳偏差检查 (允许 ±5 分钟)
        now = time.time()
        if abs(now - float(timestamp)) > 300:
            return False, (
                f"请求时间戳偏差过大 (now={now:.0f}, "
                f"ts={timestamp}, delta={abs(now - float(timestamp)):.0f}s)"
            )

        nonce = request.get("nonce", "")
        if not nonce:
            return False, "请求缺少 nonce"

        return True, "请求校验通过"

    def validate_token(
        self,
        token_claims: dict,
        required_scopes: list[str],
        required_audience: str,
    ) -> tuple[bool, str]:
        """校验 Token claims。

        检查项:
          - aud 包含 required_audience
          - scope 包含所有 required_scopes
          - exp 在未来且不超过 1 小时
          - sub 非空
          - jti 非空
        """
        if not isinstance(token_claims, dict):
            return False, "token_claims 必须是 dict"

        # 检查 aud 包含 required_audience
        aud = token_claims.get("aud", [])
        if isinstance(aud, str):
            aud = [aud]
        if not isinstance(aud, list) or required_audience not in aud:
            return False, f"token audience 不包含 '{required_audience}'"

        # 检查 scope 包含所有 required_scopes
        scope_str = token_claims.get("scope", "")
        if not isinstance(scope_str, str):
            return False, "token scope 必须是字符串"
        token_scopes = set(scope_str.split()) if scope_str else set()
        for s in required_scopes:
            if s not in token_scopes:
                return False, f"token scope 缺少 '{s}'"

        # 检查 exp 在未来且不超过 1 小时
        exp = token_claims.get("exp", 0)
        if not isinstance(exp, (int, float)):
            return False, "token exp 类型错误"
        now = time.time()
        if exp <= now:
            return False, "token 已过期"
        if exp > now + 3600:
            return False, "token 有效期超过 1 小时"

        # 检查 sub 非空
        if not token_claims.get("sub"):
            return False, "token sub 为空"

        # 检查 jti 非空
        if not token_claims.get("jti"):
            return False, "token jti 为空"

        return True, "token 校验通过"

    def sanitize_environment(self, env: dict) -> dict:
        """远程模式不需要环境变量 — 返回空 dict。"""
        logger.debug(
            "[RemotePolicy] Remote 传输不透传环境变量，返回空 dict"
        )
        return {}

    def get_security_config(self) -> dict:
        """返回安全配置摘要。"""
        parsed = urlparse(self._entry.url)
        return {
            "transport": "remote",
            "server_id": self._entry.server_id,
            "url": self._entry.url,
            "host": parsed.hostname or "",
            "scheme": parsed.scheme,
            "allowed_audiences": list(self._entry.allowed_audiences),
            "required_scopes": list(self._entry.required_scopes),
            "mtls_configured": bool(self._entry.mtls_cert_path),
            "connect_timeout": _CONNECT_TIMEOUT,
            "read_timeout": _READ_TIMEOUT,
            "max_response_size": _MAX_RESPONSE_SIZE,
            "max_retries": _MAX_RETRIES,
            "nonce_cache_ttl": _NONCE_CACHE_TTL,
            "circuit_failure_threshold": _CIRCUIT_FAILURE_THRESHOLD,
            "circuit_open_seconds": _CIRCUIT_OPEN_SECONDS,
        }


class RemoteMcpClient(BaseMcpClient):
    """Remote MCP 传输客户端。

    通过 HTTPS 与远程 MCP Server 通信。
    严格遵守安全策略: URL 来自注册表、强制 HTTPS、Token 校验、防重放、
    熔断降级、mTLS、有限重试。
    """

    def __init__(
        self,
        server_id: str,
        policy: RemoteTransportSecurityPolicy,
        token_provider: Optional[TokenProvider] = None,
        registry: Optional[McpServerRegistry] = None,
    ) -> None:
        self.server_id = server_id
        self.transport_type = "remote"
        self._policy = policy
        self._token_provider = token_provider
        self._registry = registry or mcp_server_registry

        entry = self._registry.get(server_id)
        if entry is None:
            raise TransportSecurityViolation(
                f"server_id '{server_id}' 未在注册表中注册"
            )
        if entry.transport != "remote":
            raise TransportSecurityViolation(
                f"server_id '{server_id}' 传输类型为 '{entry.transport}'，"
                f"不是 'remote'"
            )
        self._entry: ServerEntry = entry

        # HTTP 客户端 (懒初始化)
        self._client: Optional[httpx.AsyncClient] = None

        # 并发控制
        self._semaphore = asyncio.Semaphore(self._entry.max_concurrent)

        # nonce 防重放缓存: nonce -> timestamp
        self._nonce_cache: dict[str, float] = {}

        # 熔断器状态
        self._circuit_state: str = "closed"  # closed | open | half_open
        self._circuit_failure_count: int = 0
        self._circuit_open_until: float = 0.0

    # ── HTTP 客户端 ──

    def _get_client(self) -> httpx.AsyncClient:
        """获取或创建 httpx 异步客户端。"""
        if self._client is not None:
            return self._client

        timeout = httpx.Timeout(
            connect=_CONNECT_TIMEOUT,
            read=_READ_TIMEOUT,
            write=_CONNECT_TIMEOUT,
            pool=_CONNECT_TIMEOUT,
        )

        client_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": False,
            "verify": True,  # 强制 TLS 证书验证
        }

        # mTLS 证书
        if self._entry.mtls_cert_path and _file_exists(self._entry.mtls_cert_path):
            client_kwargs["cert"] = self._entry.mtls_cert_path
            logger.info(
                f"[RemoteMcpClient] mTLS enabled "
                f"(server_id={self.server_id}, "
                f"cert={self._entry.mtls_cert_path})"
            )

        self._client = httpx.AsyncClient(**client_kwargs)
        return self._client

    # ── 熔断器 ──

    def _check_circuit(self) -> bool:
        """检查熔断器状态。

        Returns:
            True 表示可以继续请求，False 表示熔断器开启 (降级模式)。
        """
        now = time.time()
        if self._circuit_state == "open":
            if now < self._circuit_open_until:
                return False
            # 熔断超时，进入半开状态
            self._circuit_state = "half_open"
            logger.info(
                f"[RemoteMcpClient] Circuit → half_open "
                f"(server_id={self.server_id})"
            )
        return True

    def _update_circuit(self, success: bool) -> None:
        """根据调用结果更新熔断器状态。"""
        if success:
            if self._circuit_state != "closed":
                logger.info(
                    f"[RemoteMcpClient] Circuit → closed "
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
                    f"[RemoteMcpClient] Circuit → open "
                    f"(failures={self._circuit_failure_count}, "
                    f"open_for={_CIRCUIT_OPEN_SECONDS}s, "
                    f"server_id={self.server_id}, 降级为建议模式)"
                )

    # ── 防重放 ──

    def _check_replay(self, nonce: str) -> bool:
        """检查 nonce 是否被重放。

        Returns:
            True 表示是重放 (nonce 已存在)，False 表示是首次使用。
        """
        now = time.time()

        # 惰性清理过期 nonce
        expired = [
            n for n, ts in self._nonce_cache.items()
            if now - ts > _NONCE_CACHE_TTL
        ]
        for n in expired:
            del self._nonce_cache[n]

        if nonce in self._nonce_cache:
            return True  # 重放

        # 记录 nonce
        self._nonce_cache[nonce] = now
        return False

    # ── Token ──

    async def _get_and_validate_token(
        self,
        incident_id: str,
    ) -> tuple[str, dict]:
        """获取并校验 Token。

        Returns:
            (access_token, claims)
        """
        if self._token_provider is None:
            raise TransportSecurityViolation(
                "未配置 token_provider，无法获取 OAuth2/OIDC Token"
            )

        # 获取 Token — 禁止直接透传用户或上游 Token
        token_data = await self._token_provider.get_token(
            server_id=self.server_id,
            scopes=list(self._entry.required_scopes),
            incident_id=incident_id,
        )

        access_token = token_data.get("access_token", "")
        claims = token_data.get("claims", {})

        if not access_token:
            raise TransportSecurityViolation("Token 缺少 access_token 字段")

        if not claims:
            raise TransportSecurityViolation("Token 缺少 claims 字段")

        # 校验 Token claims
        required_audience = (
            self._entry.allowed_audiences[0]
            if self._entry.allowed_audiences
            else ""
        )
        if not required_audience:
            raise TransportSecurityViolation(
                "ServerEntry.allowed_audiences 为空，无法校验 token audience"
            )

        ok, reason = self._policy.validate_token(
            claims,
            list(self._entry.required_scopes),
            required_audience,
        )
        if not ok:
            raise TransportSecurityViolation(f"Token 校验失败: {reason}")

        return access_token, claims

    # ── 公共接口 ──

    async def list_tools(self) -> list[McpToolInfo]:
        """列出远程 MCP Server 暴露的工具。"""
        # 熔断检查
        if not self._check_circuit():
            raise TransportCircuitOpen(
                f"Remote 熔断器开启中 (server_id={self.server_id})"
            )

        async with self._semaphore:
            tools = await self._do_list_tools()
        return tools

    async def _do_list_tools(self) -> list[McpToolInfo]:
        """实际执行 tools/list 请求。"""
        # 构建请求
        nonce = secrets.token_hex(16)
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
            "request_id": f"list-{nonce}",
            "timestamp": time.time(),
            "nonce": nonce,
        }

        # 校验请求
        ok, reason = self._policy.validate_request(request)
        if not ok:
            raise TransportSecurityViolation(f"请求校验失败: {reason}")

        # 防重放检查
        if self._check_replay(nonce):
            raise TransportSecurityViolation(
                f"nonce 重放检测: {nonce}"
            )

        # 获取并校验 Token
        access_token, _claims = await self._get_and_validate_token("")

        # 发送请求 (带重试)
        response = await self._send_with_retry(
            request, access_token, incident_id="", tool_name="",
        )

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
        """调用指定远程工具。"""
        start_time = time.time()

        # 熔断检查 — 开启时降级为建议模式
        if not self._check_circuit():
            self._update_circuit(False)
            return CallToolResult(
                success=False,
                error=(
                    f"远程服务不可用 (熔断器开启)，已降级为建议模式 "
                    f"(server_id={self.server_id})"
                ),
                result={
                    "mode": "suggestion",
                    "suggestion": (
                        f"远程 MCP Server '{self.server_id}' 暂时不可用，"
                        f"工具 '{tool_name}' 调用已降级。"
                        f"建议: 人工介入核实或稍后重试。"
                    ),
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "server_id": self.server_id,
                },
                latency_ms=round((time.time() - start_time) * 1000, 1),
                transport_type=self.transport_type,
                server_identity=self.server_id,
            )

        # 构建请求
        nonce = secrets.token_hex(16)
        request_id = f"call-{nonce}"
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
            "id": 1,
            "request_id": request_id,
            "timestamp": time.time(),
            "nonce": nonce,
            "incident_id": "",
            "grant_id": "",
            "trace_id": "",
        }

        # 校验请求
        ok, reason = self._policy.validate_request(request)
        if not ok:
            return CallToolResult(
                success=False,
                error=f"请求校验失败: {reason}",
                latency_ms=round((time.time() - start_time) * 1000, 1),
                transport_type=self.transport_type,
                server_identity=self.server_id,
            )

        # 防重放检查
        if self._check_replay(nonce):
            self._update_circuit(False)
            return CallToolResult(
                success=False,
                error=f"nonce 重放检测: {nonce}",
                latency_ms=round((time.time() - start_time) * 1000, 1),
                transport_type=self.transport_type,
                server_identity=self.server_id,
            )

        async with self._semaphore:
            try:
                # 获取并校验 Token
                access_token, _claims = await self._get_and_validate_token("")

                # 发送请求 (带重试)
                response = await self._send_with_retry(
                    request, access_token,
                    incident_id="", tool_name=tool_name,
                )
            except TransportSecurityViolation as e:
                self._update_circuit(False)
                return CallToolResult(
                    success=False,
                    error=f"安全违例: {e}",
                    latency_ms=round((time.time() - start_time) * 1000, 1),
                    transport_type=self.transport_type,
                    server_identity=self.server_id,
                )
            except TransportTimeout as e:
                self._update_circuit(False)
                return CallToolResult(
                    success=False,
                    error=f"传输超时: {e}",
                    latency_ms=round((time.time() - start_time) * 1000, 1),
                    transport_type=self.transport_type,
                    server_identity=self.server_id,
                )
            except TransportError as e:
                self._update_circuit(False)
                return CallToolResult(
                    success=False,
                    error=f"传输错误: {e}",
                    latency_ms=round((time.time() - start_time) * 1000, 1),
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

    async def _send_with_retry(
        self,
        request: dict,
        access_token: str,
        incident_id: str,
        tool_name: str,
    ) -> dict:
        """发送 HTTPS POST 请求，支持有限重试 (指数退避)。

        最多重试 _MAX_RETRIES 次，不无限重试。
        """
        client = self._get_client()
        url = self._entry.url

        # URL 注册表二次校验 — 确保没有被篡改
        url_ok, url_reason, _ = self._registry.validate_url(url)
        if not url_ok:
            raise TransportSecurityViolation(
                f"URL 校验失败: {url_reason}"
            )

        body = json.dumps(request, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "X-Request-Id": request.get("request_id", ""),
            "X-Timestamp": str(request.get("timestamp", "")),
            "X-Nonce": request.get("nonce", ""),
        }

        last_error: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.post(
                    url,
                    content=body,
                    headers=headers,
                )

                # 检查响应大小
                content_length = len(resp.content)
                if content_length > _MAX_RESPONSE_SIZE:
                    raise TransportSecurityViolation(
                        f"响应过大 ({content_length} > "
                        f"{_MAX_RESPONSE_SIZE})"
                    )

                if resp.status_code >= 500:
                    last_error = TransportError(
                        f"远程服务端错误 (HTTP {resp.status_code})"
                    )
                    if attempt < _MAX_RETRIES:
                        backoff = 2 ** attempt  # 1s, 2s
                        logger.warning(
                            f"[RemoteMcpClient] HTTP {resp.status_code}, "
                            f"retrying in {backoff}s "
                            f"(attempt={attempt + 1}/{_MAX_RETRIES}, "
                            f"server_id={self.server_id})"
                        )
                        await asyncio.sleep(backoff)
                        continue
                    break

                if resp.status_code >= 400:
                    raise TransportError(
                        f"HTTP {resp.status_code}: "
                        f"{resp.text[:200]}"
                    )

                # 解析 JSON 响应
                try:
                    response = resp.json()
                except (json.JSONDecodeError, ValueError) as e:
                    raise TransportError(
                        f"非法 JSON 响应: {e}"
                    ) from e

                if not isinstance(response, dict):
                    raise TransportError("响应不是 JSON 对象")

                return response

            except httpx.ConnectTimeout as e:
                last_error = TransportTimeout(
                    f"连接超时 ({_CONNECT_TIMEOUT}s): {e}"
                )
            except httpx.ReadTimeout as e:
                last_error = TransportTimeout(
                    f"读取超时 ({_READ_TIMEOUT}s): {e}"
                )
            except httpx.ConnectError as e:
                last_error = TransportError(f"连接失败: {e}")
            except httpx.HTTPError as e:
                last_error = TransportError(f"HTTP 错误: {e}")

            # 重试
            if attempt < _MAX_RETRIES:
                backoff = 2 ** attempt  # 1s, 2s
                logger.warning(
                    f"[RemoteMcpClient] Request failed, retrying in {backoff}s "
                    f"(attempt={attempt + 1}/{_MAX_RETRIES}, "
                    f"server_id={self.server_id}, error={last_error})"
                )
                await asyncio.sleep(backoff)

        # 所有重试用尽 — 远程服务不可用
        raise TransportError(
            f"远程服务不可用 (重试 {_MAX_RETRIES} 次后仍失败, "
            f"server_id={self.server_id}): {last_error}"
        )

    async def health_check(self) -> bool:
        """检查远程 MCP Server 健康状态。"""
        if not self._check_circuit():
            return False

        try:
            client = self._get_client()
            url = self._entry.url

            # URL 注册表校验
            url_ok, _, _ = self._registry.validate_url(url)
            if not url_ok:
                return False

            resp = await client.get(url, timeout=_CONNECT_TIMEOUT)
            return resp.status_code < 500
        except Exception as e:
            logger.debug(
                f"[RemoteMcpClient] health_check failed "
                f"(server_id={self.server_id}): {e}"
            )
            return False

    async def close(self) -> None:
        """释放传输资源，关闭 HTTP 客户端。"""
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception as e:
                logger.error(
                    f"[RemoteMcpClient] close client failed: {e}"
                )
            self._client = None


# ── 辅助函数 ──

def _file_exists(path: str) -> bool:
    """检查文件是否存在。"""
    import os
    return bool(path) and os.path.isfile(path)
