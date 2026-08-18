"""
http_parser.py — HTTP 请求/响应语义解析

从 TCP payload 中提取:
  - 请求: method, URI, Host, User-Agent, Content-Type, 参数
  - 响应: status_code, Content-Type, Content-Length
  - 安全相关: SQL 注入特征、路径遍历、敏感路径访问

纯字节解析，不依赖 scapy HTTP 层。
"""
import logging
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# 安全检测模式
_SQLI_PATTERN = re.compile(
    rb"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|"
    rb"insert\s+into|select\s+.*\s+from|;\s*--|xp_cmdshell)",
)
_PATH_TRAVERSAL = re.compile(rb"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",)
_SENSITIVE_PATHS = (
    b"/etc/passwd", b"/etc/shadow", b"wp-admin", b"phpmyadmin",
    b"/.env", b"/.git/config", b"actuator", b"swagger",
    b"/api/debug", b"elmah.axd", b"trace.axd",
)


class HttpParser:
    """HTTP 协议解析器"""

    def parse(self, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        payload = pkt.payload
        if not payload:
            return None

        # 判断请求 vs 响应
        if payload[:5] in (b"HTTP/",):
            return self._parse_response(payload, pkt)
        for method in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                       b"OPTIONS ", b"PATCH "):
            if payload[:len(method)] == method:
                return self._parse_request(payload, pkt)
        return None

    def _parse_request(self, payload: bytes, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            # 分割请求行和头部
            header_end = payload.find(b"\r\n\r\n")
            header_block = payload[:header_end] if header_end > 0 else payload[:2048]
            body = payload[header_end + 4:] if header_end > 0 else b""

            lines = header_block.split(b"\r\n")
            request_line = lines[0].decode("utf-8", errors="replace")
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return None

            method, uri = parts[0], parts[1]

            # 解析头部
            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    key, _, val = line.partition(b":")
                    headers[key.decode("utf-8", errors="replace").strip().lower()] = \
                        val.decode("utf-8", errors="replace").strip()

            host = headers.get("host", "")
            user_agent = headers.get("user-agent", "")
            content_type = headers.get("content-type", "")

            # 安全特征检测
            security_flags = []
            if _SQLI_PATTERN.search(payload[:4096]):
                security_flags.append("sqli_attempt")
            if _PATH_TRAVERSAL.search(uri.encode()):
                security_flags.append("path_traversal")
            for sp in _SENSITIVE_PATHS:
                if sp in uri.encode().lower():
                    security_flags.append(f"sensitive_path:{sp.decode()}")
                    break

            # URL 参数提取
            parsed = urlparse(uri)
            params = parse_qs(parsed.query)

            msg = ProtocolMessage(
                protocol="HTTP",
                direction="request",
                method=method,
                host=host,
                uri=uri,
                user_agent=user_agent,
                content_type=content_type,
                headers=headers,
                body_preview=body[:512].decode("utf-8", errors="replace") if body else "",
                raw_meta={
                    "path": parsed.path,
                    "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
                    "security_flags": security_flags,
                    "http_version": parts[2] if len(parts) > 2 else "",
                },
            )
            return msg
        except Exception as e:
            logger.debug("HTTP 请求解析失败: %s", e)
            return None

    def _parse_response(self, payload: bytes, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            header_end = payload.find(b"\r\n\r\n")
            header_block = payload[:header_end] if header_end > 0 else payload[:2048]
            body = payload[header_end + 4:] if header_end > 0 else b""

            lines = header_block.split(b"\r\n")
            status_line = lines[0].decode("utf-8", errors="replace")
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                return None

            status_code = int(parts[1])

            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    key, _, val = line.partition(b":")
                    headers[key.decode("utf-8", errors="replace").strip().lower()] = \
                        val.decode("utf-8", errors="replace").strip()

            return ProtocolMessage(
                protocol="HTTP",
                direction="response",
                status_code=status_code,
                content_type=headers.get("content-type", ""),
                headers=headers,
                body_preview=body[:512].decode("utf-8", errors="replace") if body else "",
                raw_meta={
                    "http_version": parts[0],
                    "reason": parts[2] if len(parts) > 2 else "",
                    "content_length": int(headers.get("content-length", 0)),
                },
            )
        except Exception as e:
            logger.debug("HTTP 响应解析失败: %s", e)
            return None


# ── 全局单例 ──
http_parser = HttpParser()
