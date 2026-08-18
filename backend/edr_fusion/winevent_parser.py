"""
winevent_parser.py — Windows Event Log 解析

解析 Windows Security / System 事件日志（XML 或 JSON 格式）。

重点关注的 Security EventID:
  4624 — 登录成功
  4625 — 登录失败
  4648 — 使用显式凭据的登录
  4672 — 分配特殊权限
  4688 — 进程创建
  4697 — 服务安装
  4698 — 计划任务创建
  4720 — 用户账户创建
  4728 — 安全组成员添加
  4732 — 本地安全组成员添加
  5140 — 网络共享访问
  7045 — 新服务安装 (System)

用法:
    from edr_fusion.winevent_parser import winevent_parser
    event = winevent_parser.parse(xml_string)
    event = winevent_parser.parse_dict(json_dict)
"""
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Security EventID → (名称, MITRE ATT&CK, 默认严重度)
_SECURITY_EVENTS = {
    4624: ("LogonSuccess", "", "info"),
    4625: ("LogonFailure", "T1110", "medium"),
    4648: ("ExplicitCredentialLogon", "T1078", "medium"),
    4672: ("SpecialPrivilegeAssigned", "T1078", "info"),
    4688: ("ProcessCreation", "T1059", "info"),
    4697: ("ServiceInstalled", "T1543.003", "high"),
    4698: ("ScheduledTaskCreated", "T1053.005", "high"),
    4720: ("UserAccountCreated", "T1136.001", "medium"),
    4728: ("SecurityGroupMemberAdded", "T1098", "medium"),
    4732: ("LocalGroupMemberAdded", "T1098", "medium"),
    5140: ("NetworkShareAccess", "T1021.002", "info"),
    5145: ("NetworkShareObjectAccess", "T1021.002", "info"),
}

_SYSTEM_EVENTS = {
    7045: ("NewServiceInstalled", "T1543.003", "high"),
    7036: ("ServiceStateChanged", "", "info"),
    7040: ("ServiceStartTypeChanged", "T1543.003", "medium"),
    104:  ("EventLogCleared", "T1070.001", "critical"),
}

# 登录类型映射
_LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# 可疑登录模式
_SUSPICIOUS_LOGON = {"8": "cleartext_network", "10": "remote_interactive"}


@dataclass
class WinEvent:
    """解析后的 Windows 事件"""
    event_id: int = 0
    event_name: str = ""
    log_name: str = ""          # Security | System
    computer: str = ""
    user: str = ""
    process_name: str = ""
    command_line: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    severity: str = "info"
    mitre_technique: str = ""
    security_flags: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    correlation_key: str = ""

    def to_dict(self) -> dict:
        return {
            "source_type": "winevent",
            "event_id": self.event_id,
            "event_name": self.event_name,
            "log_name": self.log_name,
            "computer_name": self.computer,
            "user_name": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "security_flags": self.security_flags,
            "event_data": self.raw_data,
            "correlation_key": self.correlation_key,
        }


class WinEventParser:
    """Windows Event Log 解析器"""

    def parse(self, xml_string: str) -> Optional[WinEvent]:
        """从 XML 字符串解析"""
        try:
            root = ET.fromstring(xml_string)
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            # System 段
            system = root.find(f".//{ns}System")
            if system is None:
                return None

            event_id_el = system.find(f"{ns}EventID")
            event_id = int(event_id_el.text) if event_id_el is not None else 0

            computer_el = system.find(f"{ns}Computer")
            computer = computer_el.text if computer_el is not None else ""

            # 判断日志类型
            log_name = "Security"
            channel_el = system.find(f"{ns}Channel")
            if channel_el is not None and channel_el.text:
                log_name = channel_el.text.split("/")[-1]

            # EventData 段
            data = {}
            event_data = root.find(f".//{ns}EventData")
            if event_data is not None:
                for d in event_data.findall(f"{ns}Data"):
                    name = d.get("Name", "")
                    data[name] = d.text or ""

            return self._build_event(event_id, log_name, computer, data)
        except ET.ParseError as e:
            logger.debug("WinEvent XML 解析失败: %s", e)
            return None

    def parse_dict(self, d: dict) -> Optional[WinEvent]:
        """从 JSON dict 解析"""
        event_id = d.get("EventID", d.get("event_id", 0))
        if not event_id:
            return None
        log_name = d.get("LogName", d.get("log_name", "Security"))
        computer = d.get("Computer", d.get("computer", ""))
        event_data = d.get("EventData", d.get("event_data", d))
        return self._build_event(int(event_id), log_name, computer, event_data)

    def _build_event(self, event_id: int, log_name: str, computer: str, data: dict) -> WinEvent:
        """构建 WinEvent"""
        # 查找事件定义
        if log_name == "Security" or event_id in _SECURITY_EVENTS:
            name, mitre, severity = _SECURITY_EVENTS.get(event_id, (f"Event_{event_id}", "", "info"))
        else:
            name, mitre, severity = _SYSTEM_EVENTS.get(event_id, (f"Event_{event_id}", "", "info"))

        evt = WinEvent(
            event_id=event_id,
            event_name=name,
            log_name=log_name,
            computer=computer,
            user=data.get("SubjectUserName", data.get("TargetUserName", "")),
            process_name=data.get("ProcessName", data.get("NewProcessName", "")),
            command_line=data.get("CommandLine", data.get("ProcessCommandLine", "")),
            src_ip=data.get("IpAddress", data.get("SourceAddress", "")),
            severity=severity,
            mitre_technique=mitre,
            raw_data=data,
        )

        # 登录事件特殊处理
        if event_id in (4624, 4625):
            self._process_logon(evt, data)

        # 服务安装
        if event_id in (4697, 7045):
            evt.security_flags.append("service_install")
            service_name = data.get("ServiceName", data.get("ServiceFileName", ""))
            if service_name:
                evt.raw_data["service_name"] = service_name

        # 进程创建
        if event_id == 4688:
            parent = data.get("ParentProcessName", "")
            if parent:
                evt.raw_data["parent_process"] = parent
            # 检测可疑命令行
            self._check_command_line(evt)

        # 事件日志清除
        if event_id == 104:
            evt.security_flags.append("log_cleared")
            evt.severity = "critical"

        evt.correlation_key = f"{evt.computer}:{evt.event_id}:{evt.user}"
        return evt

    def _process_logon(self, evt: WinEvent, data: dict):
        """处理登录事件"""
        logon_type = data.get("LogonType", "")
        logon_type_name = _LOGON_TYPES.get(logon_type, f"Type_{logon_type}")
        evt.raw_data["logon_type"] = logon_type_name

        # 失败登录
        if evt.event_id == 4625:
            evt.security_flags.append("logon_failure")
            status = data.get("Status", "")
            sub_status = data.get("SubStatus", "")
            evt.raw_data["failure_status"] = f"{status}/{sub_status}"

        # 可疑登录类型
        if logon_type in _SUSPICIOUS_LOGON:
            evt.security_flags.append(_SUSPICIOUS_LOGON[logon_type])
            if evt.severity == "info":
                evt.severity = "medium"

        # 远程交互登录
        if logon_type == "10":
            evt.security_flags.append("rdp_logon")

        # 空密码登录
        if data.get("Status", "") == "0xC0000064":
            evt.security_flags.append("nonexistent_user")

    def _check_command_line(self, evt: WinEvent):
        """检测可疑命令行"""
        if not evt.command_line:
            return
        patterns = [
            (r"(?i)powershell.*-enc\b", "encoded_powershell"),
            (r"(?i)cmd\s+/c\s+", "cmd_execution"),
            (r"(?i)net\s+user", "user_management"),
            (r"(?i)sc\s+create", "service_creation"),
        ]
        for pattern, flag in patterns:
            if re.search(pattern, evt.command_line):
                evt.security_flags.append(flag)
                if evt.severity == "info":
                    evt.severity = "medium"


# ── 全局单例 ──
winevent_parser = WinEventParser()
