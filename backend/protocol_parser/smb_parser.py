"""
smb_parser.py — SMB/CIFS 协议解析

支持 SMB1 (0xFF 'S' 'M' 'B') 和 SMB2/3 (0xFE 'S' 'M' 'B')。
提取:
  - 命令类型 (Negotiate / SessionSetup / TreeConnect / Create / Read / Write)
  - 文件路径 / 共享名
  - 状态码
  - 安全检测: 匿名会话、敏感文件访问、横向移动特征

遵循 MS-SMB2 规范。
"""
import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)

# SMB2 命令码
_SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT",
    0x0004: "TREE_DISCONNECT",
    0x0005: "CREATE",
    0x0006: "CLOSE",
    0x0007: "FLUSH",
    0x0008: "READ",
    0x0009: "WRITE",
    0x000A: "LOCK",
    0x000B: "IOCTL",
    0x000C: "CANCEL",
    0x000D: "ECHO",
    0x000E: "QUERY_DIRECTORY",
    0x000F: "CHANGE_NOTIFY",
    0x0010: "QUERY_INFO",
    0x0011: "SET_INFO",
    0x0012: "OPLOCK_BREAK",
}

# SMB1 命令码（常见子集）
_SMB1_COMMANDS = {
    0x72: "NEGOTIATE",
    0x73: "SESSION_SETUP",
    0x74: "LOGOFF",
    0x75: "TREE_CONNECT",
    0x71: "TREE_DISCONNECT",
    0xA2: "NT_CREATE_ANDX",
    0x2E: "READ_ANDX",
    0x2F: "WRITE_ANDX",
    0x32: "TRANSACTION2",
    0x25: "TRANSACTION",
    0x00: "CREATE_DIRECTORY",
    0x01: "DELETE_DIRECTORY",
    0x06: "DELETE",
    0x07: "RENAME",
}

# NTSTATUS 常见码
_NTSTATUS = {
    0x00000000: "SUCCESS",
    0xC000006D: "LOGON_FAILURE",
    0xC0000022: "ACCESS_DENIED",
    0xC0000034: "OBJECT_NAME_NOT_FOUND",
    0xC0000033: "OBJECT_NAME_INVALID",
    0xC0000005: "ACCESS_VIOLATION",
    0xC000015B: "LOGON_TYPE_NOT_GRANTED",
    0x00000103: "NO_MORE_FILES",
}

# 敏感文件/路径（安全检测）
_SENSITIVE_SHARES = ("ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON")
_SENSITIVE_FILES = ("sam", "system", "security", "ntds.dit", "bootkey",
                    ".kdbx", "id_rsa", "shadow", "passwd")


class SmbParser:
    """SMB 协议解析器"""

    def parse(self, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        payload = pkt.payload
        if not payload or len(payload) < 8:
            return None

        # NetBIOS Session Service 头 (4 bytes) 可能存在于 TCP 139
        offset = 0
        if len(payload) > 4 and payload[0] == 0x00:
            # NetBIOS: type(1) + length(3)
            offset = 4

        if offset + 4 > len(payload):
            return None

        magic = payload[offset:offset + 4]

        if magic == b"\xfe\x53\x4d\x42":  # SMB2
            return self._parse_smb2(payload, offset, pkt)
        elif magic == b"\xff\x53\x4d\x42":  # SMB1
            return self._parse_smb1(payload, offset, pkt)
        return None

    def _parse_smb2(self, payload: bytes, offset: int, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            # SMB2 Header: magic(4) + header_len(2) + credit_charge(2) +
            #              status(4) + command(2) + credit_req(2) + flags(4) +
            #              next_command(4) + message_id(8) + ...
            if offset + 64 > len(payload):
                return None

            header_len = struct.unpack("<H", payload[offset + 4:offset + 6])[0]
            status = struct.unpack("<I", payload[offset + 8:offset + 12])[0]
            command = struct.unpack("<H", payload[offset + 12:offset + 14])[0]
            flags = struct.unpack("<I", payload[offset + 16:offset + 20])[0]
            message_id = struct.unpack("<Q", payload[offset + 24:offset + 32])[0]

            is_response = bool(flags & 0x00000001)
            cmd_name = _SMB2_COMMANDS.get(command, f"CMD_0x{command:04X}")
            status_name = _NTSTATUS.get(status, f"0x{status:08X}")

            # 安全检测
            security_flags = []
            body = payload[offset + header_len:] if offset + header_len < len(payload) else b""

            # 匿名/空会话检测
            if command == 0x0001 and is_response:  # SESSION_SETUP response
                if status == 0x00000000:
                    # 检查 Session Flags (在 body 中)
                    if len(body) >= 12:
                        session_flags = body[10] if len(body) > 10 else 0
                        if session_flags & 0x01:  # SMB2_SESSION_FLAG_IS_GUEST
                            security_flags.append("guest_session")
                        if session_flags & 0x02:  # SMB2_SESSION_FLAG_IS_NULL
                            security_flags.append("null_session")

            # 敏感共享访问
            if command == 0x0003 and not is_response:  # TREE_CONNECT request
                # 尝试从 body 中提取路径
                path_str = self._extract_utf16_string(body)
                if path_str:
                    for share in _SENSITIVE_SHARES:
                        if share.lower() in path_str.lower():
                            security_flags.append(f"sensitive_share:{share}")
                            break

            # 敏感文件访问
            if command == 0x0005 and not is_response:  # CREATE request
                path_str = self._extract_utf16_string(body[56:] if len(body) > 56 else body)
                if path_str:
                    for sf in _SENSITIVE_FILES:
                        if sf in path_str.lower():
                            security_flags.append(f"sensitive_file:{sf}")
                            break

            return ProtocolMessage(
                protocol="SMB",
                direction="response" if is_response else "request",
                method=cmd_name,
                status_code=status,
                raw_meta={
                    "smb_version": "SMB2",
                    "command": cmd_name,
                    "command_id": command,
                    "status": status_name,
                    "status_code": status,
                    "message_id": message_id,
                    "security_flags": security_flags,
                },
            )
        except Exception as e:
            logger.debug("SMB2 解析失败: %s", e)
            return None

    def _parse_smb1(self, payload: bytes, offset: int, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        try:
            # SMB1 Header: magic(4) + command(1) + status(4) + flags(1) +
            #              flags2(2) + ... (共 32 bytes)
            if offset + 32 > len(payload):
                return None

            command = payload[offset + 4]
            status = struct.unpack("<I", payload[offset + 5:offset + 9])[0]
            cmd_name = _SMB1_COMMANDS.get(command, f"CMD_0x{command:02X}")
            status_name = _NTSTATUS.get(status, f"0x{status:08X}")

            return ProtocolMessage(
                protocol="SMB",
                direction="response" if status != 0 else "request",
                method=cmd_name,
                status_code=status,
                raw_meta={
                    "smb_version": "SMB1",
                    "command": cmd_name,
                    "command_id": command,
                    "status": status_name,
                    "security_flags": ["smb1_deprecated"],
                },
            )
        except Exception as e:
            logger.debug("SMB1 解析失败: %s", e)
            return None

    def _extract_utf16_string(self, data: bytes, max_len: int = 256) -> str:
        """尝试从 SMB body 中提取 UTF-16LE 字符串"""
        try:
            decoded = data[:max_len].decode("utf-16-le", errors="replace")
            # 清理不可打印字符
            cleaned = "".join(c for c in decoded if c.isprintable() or c in "\\/.")
            return cleaned[:200]
        except Exception:
            return ""


# ── 全局单例 ──
smb_parser = SmbParser()
