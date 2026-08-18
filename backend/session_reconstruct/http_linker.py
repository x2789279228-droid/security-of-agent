"""
http_linker.py — HTTP 请求-响应配对与事务链

将重组后的 TCP 流中的 HTTP 请求和响应进行配对:
  - 按顺序配对（HTTP/1.1 管道化）
  - 提取事务元数据（method, url, status, content-type, size）
  - 构建会话级事务链（同一 TCP 连接上的多个请求）
  - 安全检测: 敏感数据泄露、异常 User-Agent、WebShell 特征

用法:
    from session_reconstruct.http_linker import http_linker
    transactions = http_linker.extract_transactions(stream)
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# WebShell 特征
_WEBSHELL_PATTERNS = [
    re.compile(rb"(?i)(eval\s*\(|base64_decode|system\s*\(|exec\s*\(|passthru)",),
    re.compile(rb"(?i)(cmd\.exe|/bin/sh|/bin/bash).*[&|;]",),
    re.compile(rb"(?i)(c99shell|r57shell|b374k|weevely)",),
]

# 敏感数据泄露
_SENSITIVE_RESPONSE = [
    re.compile(rb"(?i)(password|passwd|secret|api_key|token)\s*[=:]\s*\S+",),
    re.compile(rb"-----BEGIN (RSA |EC )?PRIVATE KEY-----",),
]


@dataclass
class HttpTransaction:
    """HTTP 事务（请求-响应对）"""
    seq: int = 0
    method: str = ""
    url: str = ""
    host: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    request_size: int = 0
    response_size: int = 0
    security_flags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "request_size": self.request_size,
            "response_size": self.response_size,
            "security_flags": self.security_flags,
        }


class HttpLinker:
    """HTTP 事务配对器"""

    def extract_transactions(self, stream) -> list[HttpTransaction]:
        """
        从重组后的 TCP 流中提取 HTTP 事务

        stream: TcpStream (from tcp_reassembler)
        """
        transactions = []
        client_data = stream.reassembled_client
        server_data = stream.reassembled_server

        if not client_data:
            return transactions

        # 分割请求
        requests = self._split_http_messages(client_data)
        responses = self._split_http_messages(server_data) if server_data else []

        for i, req_bytes in enumerate(requests):
            tx = HttpTransaction(seq=i)
            tx.src_ip = getattr(stream, "src_ip", "") or ""
            tx.dst_ip = getattr(stream, "dst_ip", "") or ""

            # 解析请求
            self._parse_request(req_bytes, tx)

            # 配对响应
            if i < len(responses):
                self._parse_response(responses[i], tx)

            # 安全检测
            self._detect_threats(tx, req_bytes, responses[i] if i < len(responses) else b"")

            transactions.append(tx)

        return transactions

    def _split_http_messages(self, data: bytes) -> list[bytes]:
        """将原始数据分割为独立的 HTTP 消息"""
        messages = []
        # 按请求行/状态行分割
        parts = re.split(rb"(?=(?:GET |POST |PUT |DELETE |HEAD |OPTIONS |PATCH |HTTP/1\.))", data)
        for part in parts:
            part = part.strip()
            if part:
                messages.append(part)
        return messages

    def _parse_request(self, data: bytes, tx: HttpTransaction):
        """解析 HTTP 请求"""
        try:
            header_end = data.find(b"\r\n\r\n")
            header_block = data[:header_end] if header_end > 0 else data[:2048]
            body = data[header_end + 4:] if header_end > 0 else b""

            lines = header_block.split(b"\r\n")
            if lines:
                parts = lines[0].decode("utf-8", errors="replace").split(" ", 2)
                if len(parts) >= 2:
                    tx.method = parts[0]
                    tx.url = parts[1]

            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    key = k.decode("utf-8", errors="replace").strip().lower()
                    val = v.decode("utf-8", errors="replace").strip()
                    tx.request_headers[key] = val
                    if key == "host":
                        tx.host = val

            tx.request_body = body[:1024].decode("utf-8", errors="replace")
            tx.request_size = len(data)
        except Exception as e:
            logger.debug("HTTP 请求解析失败: %s", e)

    def _parse_response(self, data: bytes, tx: HttpTransaction):
        """解析 HTTP 响应"""
        try:
            header_end = data.find(b"\r\n\r\n")
            header_block = data[:header_end] if header_end > 0 else data[:2048]
            body = data[header_end + 4:] if header_end > 0 else b""

            lines = header_block.split(b"\r\n")
            if lines:
                parts = lines[0].decode("utf-8", errors="replace").split(" ", 2)
                if len(parts) >= 2:
                    tx.status_code = int(parts[1])

            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    tx.response_headers[k.decode("utf-8", errors="replace").strip().lower()] = \
                        v.decode("utf-8", errors="replace").strip()

            tx.response_body = body[:1024].decode("utf-8", errors="replace")
            tx.response_size = len(data)
        except Exception as e:
            logger.debug("HTTP 响应解析失败: %s", e)

    def _detect_threats(self, tx: HttpTransaction, req: bytes, resp: bytes):
        """安全检测"""
        flags = []

        # WebShell 检测
        for pattern in _WEBSHELL_PATTERNS:
            if pattern.search(req) or pattern.search(resp):
                flags.append("webshell_indicator")
                break

        # 敏感数据泄露
        for pattern in _SENSITIVE_RESPONSE:
            if pattern.search(resp):
                flags.append("sensitive_data_leak")
                # ── P0.S 数据安全大模型 hook (主路径 0 等待) ──
                # 仅规则先命中才派 LLM 复核.失败静默,不影响本次响应.
                try:
                    from llm_enhancer import safe_dispatch
                    from data_security import classify_and_broadcast
                    safe_dispatch(
                        classify_and_broadcast(
                            http_summary={
                                "url": tx.url, "method": tx.method,
                                "request_headers": tx.request_headers,
                                "response_content_type": tx.response_headers.get("content-type", ""),
                                "response_size": tx.response_size,
                                "body_snippet": resp[:500].decode("utf-8", errors="ignore"),
                                "rule_hit": "sensitive_data_leak",
                                "src_ip": tx.src_ip, "dst_ip": tx.dst_ip,
                            },
                            sensor_id=getattr(self, "sensor_id", "sensor-01"),
                        ),
                        log_label="data_security",
                    )
                except Exception:
                    pass  # LLM hook 失败绝不影响主路径
                break

        # 异常 User-Agent
        ua = tx.request_headers.get("user-agent", "")
        if ua and ("python" in ua.lower() or "curl" in ua.lower() or "wget" in ua.lower()):
            flags.append("scripted_client")

        # 目录遍历
        if "../" in tx.url or "..%2f" in tx.url.lower():
            flags.append("path_traversal")

        # SQL 注入
        if re.search(r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*')", tx.url):
            flags.append("sqli_attempt")

        tx.security_flags = flags


# ── 全局单例 ──
http_linker = HttpLinker()
