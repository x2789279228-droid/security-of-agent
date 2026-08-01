"""MCP Guard 工具注册中心。

职责：
1. 维护平台所有可调用工具的元数据（名称/描述/风险等级/参数schema）
2. 提供工具查询接口：Agent 不能直接调用工具，必须通过 Registry 查询
3. 维护 tool_name -> 执行器 的映射，供 GuardServer 分发执行

设计要点：注册表是 Agent 与工具之间的唯一桥梁，未注册的工具一律不可调用（防幻觉）。
所有工具定义内联在代码中，无外部文件依赖。
"""

from typing import Optional


class ToolInfo:
    """工具元数据。"""

    def __init__(self, name: str, description: str, risk_level: str,
                 required_permission: list, parameters: dict):
        self.name = name
        self.description = description
        self.risk_level = risk_level          # LOW / MEDIUM / HIGH / CRITICAL
        self.required_permission = required_permission
        self.parameters = parameters          # 参数 schema

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "required_permission": self.required_permission,
            "parameters": self.parameters,
        }


# ============================================================
# 平台工具定义（内联，无外部 JSON 依赖）
# ============================================================
_PLATFORM_TOOLS = [
    {
        "name": "block_ip",
        "description": "封禁指定IP地址，通过防火墙规则阻断其网络访问",
        "risk_level": "HIGH",
        "required_permission": ["admin", "security_operator"],
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "要封禁的IPv4地址"},
                "duration": {"type": "integer", "description": "封禁时长(秒)", "default": 3600},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "isolate_host",
        "description": "隔离指定主机，切断其网络连接或完全隔离",
        "risk_level": "CRITICAL",
        "required_permission": ["admin", "security_operator"],
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "主机名或标识"},
                "isolation_type": {
                    "type": "string",
                    "enum": ["network", "full"],
                    "description": "隔离类型: network=网络隔离, full=完全隔离",
                    "default": "network",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "rate_limit",
        "description": "对指定IP实施速率限制，防止DDoS或暴力破解",
        "risk_level": "MEDIUM",
        "required_permission": ["admin", "security_operator"],
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "目标IP地址"},
                "rate": {"type": "integer", "description": "允许的速率(请求/秒)"},
            },
            "required": ["ip", "rate"],
        },
    },
    {
        "name": "terminate_process",
        "description": "终止指定进程，用于清除恶意进程或失控服务",
        "risk_level": "HIGH",
        "required_permission": ["admin", "security_operator"],
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "要终止的进程ID"},
            },
            "required": ["pid"],
        },
    },
    {
        "name": "alert_only",
        "description": "仅发送安全告警通知，不执行任何阻断操作",
        "risk_level": "LOW",
        "required_permission": ["admin", "security_operator", "analyst"],
        "parameters": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "告警消息内容"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "vulnerability_scan",
        "description": "对目标执行漏洞扫描，发现潜在安全风险",
        "risk_level": "LOW",
        "required_permission": ["admin", "security_operator", "analyst"],
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "扫描目标(主机/IP/网段)"},
                "scan_type": {
                    "type": "string",
                    "enum": ["fast", "full"],
                    "description": "扫描类型: fast=快速扫描, full=全面扫描",
                    "default": "fast",
                },
            },
            "required": ["target"],
        },
    },
]


# ============================================================
# Mock 执行器（模拟工具执行，返回结构化结果）
# ============================================================
def _exec_block_ip(ip: str, duration: int = 3600, **kw) -> dict:
    """模拟防火墙封禁IP。"""
    return {
        "status": "success",
        "action": "block_ip",
        "detail": f"已封禁 {ip}，时长 {duration} 秒",
        "device": "firewall",
    }


def _exec_isolate_host(host: str, isolation_type: str = "network", **kw) -> dict:
    """模拟EDR主机隔离。"""
    return {
        "status": "success",
        "action": "isolate_host",
        "detail": f"已隔离主机 {host}，隔离类型={isolation_type}",
        "device": "edr",
    }


def _exec_rate_limit(ip: str, rate: int = 100, **kw) -> dict:
    """模拟速率限制。"""
    return {
        "status": "success",
        "action": "rate_limit",
        "detail": f"已对 {ip} 设置速率限制: {rate} req/s",
        "device": "firewall",
    }


def _exec_terminate_process(pid: int = 0, **kw) -> dict:
    """模拟终止进程。"""
    return {
        "status": "success",
        "action": "terminate_process",
        "detail": f"已终止进程 PID={pid}",
        "device": "edr",
    }


def _exec_alert_only(message: str = "", **kw) -> dict:
    """模拟发送告警。"""
    return {
        "status": "success",
        "action": "alert_only",
        "detail": f"告警已发送: {message}",
        "device": "siem",
    }


def _exec_vulnerability_scan(target: str = "", scan_type: str = "fast", **kw) -> dict:
    """模拟漏洞扫描。"""
    return {
        "status": "success",
        "action": "vulnerability_scan",
        "detail": f"扫描完成: 目标={target}, 类型={scan_type}, 发现0个漏洞",
        "device": "scanner",
    }


# 工具名 -> 执行函数 映射
_EXECUTORS = {
    "block_ip": _exec_block_ip,
    "isolate_host": _exec_isolate_host,
    "rate_limit": _exec_rate_limit,
    "terminate_process": _exec_terminate_process,
    "alert_only": _exec_alert_only,
    "vulnerability_scan": _exec_vulnerability_scan,
}


class ToolRegistry:
    """工具注册中心。

    所有平台工具在初始化时自动注册，无外部文件依赖。
    """

    def __init__(self):
        self._tools: dict = {}       # name -> ToolInfo
        self._executors: dict = {}   # name -> callable
        self._load()

    def _load(self):
        """从内联定义加载工具元数据并绑定执行器。"""
        for t in _PLATFORM_TOOLS:
            info = ToolInfo(
                name=t["name"],
                description=t["description"],
                risk_level=t["risk_level"],
                required_permission=t["required_permission"],
                parameters=t["parameters"],
            )
            self._tools[info.name] = info
            self._executors[info.name] = _EXECUTORS[info.name]

    def list_tools(self) -> list:
        """列出所有已注册工具（Agent 查询用）。"""
        return [t.to_dict() for t in self._tools.values()]

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """查询工具元数据。"""
        return self._tools.get(name)

    def is_registered(self, name: str) -> bool:
        """检查工具是否已注册。"""
        return name in self._tools

    def execute(self, name: str, arguments: dict) -> dict:
        """执行工具（由 GuardServer 在 Guard 放行后调用）。"""
        executor = self._executors.get(name)
        if executor is None:
            return {"status": "error", "error": f"工具 '{name}' 未注册执行器"}
        try:
            return executor(**arguments)
        except Exception as e:
            return {"status": "error", "error": str(e)}
