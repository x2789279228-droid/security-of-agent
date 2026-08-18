"""
sysmon_parser.py — Sysmon 事件解析

解析 Sysmon XML/JSON 事件，提取安全相关字段并映射到 MITRE ATT&CK。

支持的 Sysmon EventID:
  1  — ProcessCreate (进程创建)
  2  — FileCreateTime (文件创建时间修改)
  3  — NetworkConnect (网络连接)
  5  — ProcessTerminate (进程终止)
  6  — DriverLoaded (驱动加载)
  7  — ImageLoaded (DLL/模块加载)
  8  — CreateRemoteThread (远程线程注入)
  9  — RawAccessRead (原始磁盘读取)
  10 — ProcessAccess (进程访问)
  11 — FileCreate (文件创建)
  12 — RegistryEvent (注册表操作)
  13 — RegistryEvent (注册表值设置)
  15 — FileCreateStreamHash (文件流哈希)
  17 — PipeEvent (命名管道创建)
  22 — DNSEvent (DNS 查询)
  23 — FileDelete (文件删除)
  25 — ProcessTampering (进程篡改)

用法:
    from edr_fusion.sysmon_parser import sysmon_parser
    event = sysmon_parser.parse(xml_string)
    event = sysmon_parser.parse_dict(json_dict)
"""
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Sysmon EventID → 描述 + MITRE ATT&CK 映射
_EVENT_MAP = {
    1:  ("ProcessCreate", "T1059"),
    2:  ("FileCreateTime", "T1070.006"),
    3:  ("NetworkConnect", "T1071"),
    5:  ("ProcessTerminate", ""),
    6:  ("DriverLoaded", "T1547.006"),
    7:  ("ImageLoaded", "T1574.002"),
    8:  ("CreateRemoteThread", "T1055"),
    9:  ("RawAccessRead", "T1006"),
    10: ("ProcessAccess", "T1055"),
    11: ("FileCreate", "T1105"),
    12: ("RegistryEvent", "T1112"),
    13: ("RegistryEvent", "T1112"),
    15: ("FileCreateStreamHash", "T1564.004"),
    17: ("PipeEvent", "T1021.002"),
    22: ("DNSEvent", "T1071.004"),
    23: ("FileDelete", "T1070.004"),
    25: ("ProcessTampering", "T1562.001"),
}

# 高危命令行模式
_SUSPICIOUS_COMMANDS = [
    (r"(?i)powershell.*-enc\b", "encoded_powershell", "T1059.001"),
    (r"(?i)powershell.*-w\s+hidden", "hidden_powershell", "T1059.001"),
    (r"(?i)powershell.*downloadstring", "powershell_download", "T1059.001"),
    (r"(?i)powershell.*invoke-expression", "powershell_iex", "T1059.001"),
    (r"(?i)certutil.*-urlcache", "certutil_download", "T1105"),
    (r"(?i)mshta\s+vbscript", "mshta_execution", "T1218.005"),
    (r"(?i)regsvr32.*/i:http", "regsvr32_remote", "T1218.010"),
    (r"(?i)rundll32.*javascript", "rundll32_js", "T1218.011"),
    (r"(?i)wmic.*process\s+call\s+create", "wmic_exec", "T1047"),
    (r"(?i)vssadmin.*delete\s+shadows", "shadow_delete", "T1490"),
    (r"(?i)net\s+user\s+/add", "user_creation", "T1136.001"),
    (r"(?i)net\s+localgroup\s+administrators", "admin_group_add", "T1098"),
    (r"(?i)schtasks.*/create", "scheduled_task", "T1053.005"),
    (r"(?i)whoami\s+/priv", "privilege_check", "T1033"),
    (r"(?i)mimikatz|sekurlsa|lsadump", "credential_dump", "T1003"),
]

# 可疑进程父子关系
_SUSPICIOUS_PARENTS = {
    "winword.exe": "office_macro_exec",
    "excel.exe": "office_macro_exec",
    "outlook.exe": "email_client_exec",
    "wscript.exe": "script_host",
    "cscript.exe": "script_host",
    "mshta.exe": "html_application",
}


@dataclass
class SysmonEvent:
    """解析后的 Sysmon 事件"""
    event_id: int = 0
    event_name: str = ""
    computer: str = ""
    user: str = ""
    process_name: str = ""
    process_id: int = 0
    parent_process: str = ""
    command_line: str = ""
    image_hash: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    file_path: str = ""
    registry_key: str = ""
    severity: str = "info"
    mitre_technique: str = ""
    security_flags: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    correlation_key: str = ""

    def to_dict(self) -> dict:
        return {
            "source_type": "sysmon",
            "event_id": self.event_id,
            "event_name": self.event_name,
            "computer_name": self.computer,
            "user_name": self.user,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process": self.parent_process,
            "command_line": self.command_line,
            "image_hash": self.image_hash,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "file_path": self.file_path,
            "registry_key": self.registry_key,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "security_flags": self.security_flags,
            "event_data": self.raw_data,
            "correlation_key": self.correlation_key,
        }


class SysmonParser:
    """Sysmon 事件解析器"""

    def parse(self, xml_string: str) -> Optional[SysmonEvent]:
        """从 XML 字符串解析 Sysmon 事件"""
        try:
            root = ET.fromstring(xml_string)
            # 处理命名空间
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            event_id_el = root.find(f".//{ns}EventID")
            if event_id_el is None:
                return None
            event_id = int(event_id_el.text)

            # 提取 EventData 字段
            data = {}
            event_data = root.find(f".//{ns}EventData")
            if event_data is not None:
                for d in event_data.findall(f"{ns}Data"):
                    name = d.get("Name", "")
                    data[name] = d.text or ""

            return self._build_event(event_id, data, root, ns)
        except ET.ParseError as e:
            logger.debug("Sysmon XML 解析失败: %s", e)
            return None

    def parse_dict(self, d: dict) -> Optional[SysmonEvent]:
        """从 JSON dict 解析（Kafka 消费场景）"""
        event_id = d.get("EventID", d.get("event_id", 0))
        if not event_id:
            return None
        event_data = d.get("EventData", d.get("event_data", d))
        return self._build_event(int(event_id), event_data, None, "")

    def _build_event(self, event_id: int, data: dict, root, ns: str) -> SysmonEvent:
        """构建 SysmonEvent"""
        name, mitre = _EVENT_MAP.get(event_id, (f"Event_{event_id}", ""))

        evt = SysmonEvent(
            event_id=event_id,
            event_name=name,
            computer=data.get("Computer", data.get("computer", "")),
            user=data.get("User", data.get("user", "")),
            process_name=data.get("Image", data.get("image", "")),
            parent_process=data.get("ParentImage", data.get("parent_image", "")),
            command_line=data.get("CommandLine", data.get("command_line", "")),
            image_hash=data.get("Hashes", data.get("hashes", "")),
            src_ip=data.get("SourceIp", data.get("source_ip", "")),
            dst_ip=data.get("DestinationIp", data.get("destination_ip", "")),
            file_path=data.get("TargetFilename", data.get("target_filename", "")),
            registry_key=data.get("TargetObject", data.get("target_object", "")),
            mitre_technique=mitre,
            raw_data=data,
        )

        # 端口
        port_str = data.get("DestinationPort", data.get("destination_port", "0"))
        try:
            evt.dst_port = int(port_str)
        except (ValueError, TypeError):
            pass

        # 进程 ID
        pid_str = data.get("ProcessId", data.get("process_id", "0"))
        try:
            evt.process_id = int(pid_str.replace("0x", ""), 16 if "0x" in str(pid_str) else 10)
        except (ValueError, TypeError):
            pass

        # SHA256 提取
        hashes = data.get("Hashes", data.get("hashes", ""))
        sha_match = re.search(r"SHA256=([A-Fa-f0-9]{64})", hashes)
        if sha_match:
            evt.image_hash = sha_match.group(1)

        # 安全检测
        self._detect_threats(evt)

        # 关联键: computer + process + 时间窗口
        evt.correlation_key = f"{evt.computer}:{evt.process_name}:{evt.event_id}"

        return evt

    def _detect_threats(self, evt: SysmonEvent):
        """威胁检测"""
        flags = []
        severity = "info"

        # 命令行检测
        if evt.command_line:
            for pattern, flag_name, technique in _SUSPICIOUS_COMMANDS:
                if re.search(pattern, evt.command_line):
                    flags.append(flag_name)
                    if not evt.mitre_technique:
                        evt.mitre_technique = technique
                    severity = "high"

        # 可疑父子进程
        parent_lower = evt.parent_process.lower().split("\\")[-1] if evt.parent_process else ""
        if parent_lower in _SUSPICIOUS_PARENTS:
            flags.append(f"suspicious_parent:{parent_lower}")
            if severity == "info":
                severity = "medium"

        # 远程线程注入
        if evt.event_id == 8:
            flags.append("remote_thread_injection")
            severity = "critical"

        # 进程篡改
        if evt.event_id == 25:
            flags.append("process_tampering")
            severity = "critical"

        # 驱动加载
        if evt.event_id == 6:
            flags.append("driver_loaded")
            if severity == "info":
                severity = "medium"

        # 网络连接（非标准端口）
        if evt.event_id == 3 and evt.dst_port:
            if evt.dst_port not in (80, 443, 53, 22, 25, 587, 993, 995, 3389):
                flags.append(f"nonstandard_port:{evt.dst_port}")

        evt.security_flags = flags
        evt.severity = severity


# ── 全局单例 ──
sysmon_parser = SysmonParser()
