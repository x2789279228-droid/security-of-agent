"""MCP Guard 参数校验模块（基于 Pydantic）。

职责：使用 Pydantic 模型对工具参数做强类型校验。
- 参数是否存在（必填）
- 参数类型是否正确
- 参数格式是否合法（IPv4 / 长度 / 范围 / 枚举）

每个工具对应一个 Pydantic Model，校验失败返回详细错误信息。
校验通过后返回规范化参数（自动补默认值）。
"""

import ipaddress
from typing import Optional, Literal

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ============================================================
# 工具参数模型
# ============================================================

class BlockIpArgs(BaseModel):
    """block_ip 参数模型：封禁指定IP。"""
    model_config = ConfigDict(extra="forbid")  # 禁止多余字段

    ip: str = Field(..., description="要封禁的IPv4地址")
    duration: int = Field(default=3600, ge=60, le=86400, description="封禁时长(秒)")

    @field_validator("ip")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        """校验 IPv4 格式合法性。"""
        try:
            # 使用 ipaddress 模块严格校验
            addr = ipaddress.ip_address(v)
            if not isinstance(addr, ipaddress.IPv4Address):
                raise ValueError("不是合法IPv4地址")
            return v
        except ValueError as e:
            raise ValueError(f"不是合法IPv4: {v} ({e})")


class IsolateHostArgs(BaseModel):
    """isolate_host 参数模型：隔离指定主机。"""
    model_config = ConfigDict(extra="forbid")

    host: str = Field(..., min_length=1, max_length=64, description="主机名或标识")
    isolation_type: Literal["network", "full"] = Field(
        default="network", description="隔离类型: network=网络隔离, full=完全隔离"
    )


class VulnerabilityScanArgs(BaseModel):
    """vulnerability_scan 参数模型：漏洞扫描。"""
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., min_length=1, max_length=128, description="扫描目标")
    scan_type: Literal["fast", "full"] = Field(
        default="fast", description="扫描类型: fast=快速, full=全面"
    )


class RateLimitArgs(BaseModel):
    """rate_limit 参数模型：速率限制。"""
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(..., description="目标IP地址")
    rate: int = Field(..., ge=1, le=100000, description="允许的速率(请求/秒)")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """校验IP地址格式。"""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"不是合法IP地址: {v}")


class TerminateProcessArgs(BaseModel):
    """terminate_process 参数模型：终止进程。"""
    model_config = ConfigDict(extra="forbid")

    pid: int = Field(..., ge=1, description="要终止的进程ID")


class AlertOnlyArgs(BaseModel):
    """alert_only 参数模型：发送告警。"""
    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., min_length=1, max_length=1024, description="告警消息内容")


# ============================================================
# 工具名 -> Pydantic Model 映射
# ============================================================
TOOL_ARG_MODELS = {
    "block_ip": BlockIpArgs,
    "isolate_host": IsolateHostArgs,
    "vulnerability_scan": VulnerabilityScanArgs,
    "rate_limit": RateLimitArgs,
    "terminate_process": TerminateProcessArgs,
    "alert_only": AlertOnlyArgs,
}


class ParamValidator:
    """参数校验器。

    根据工具名查找对应的 Pydantic Model，执行强类型校验。
    校验通过后返回规范化参数（含默认值）。
    """

    def validate(self, tool_name: str, arguments: dict) -> tuple:
        """校验工具参数。

        Returns:
            (passed: bool, message: str, normalized_args: dict)
        """
        if tool_name not in TOOL_ARG_MODELS:
            return False, f"工具 '{tool_name}' 无参数模型", arguments

        model_cls = TOOL_ARG_MODELS[tool_name]
        try:
            instance = model_cls(**arguments)
            # 返回规范化后的参数（补默认值）
            return True, "参数校验通过", instance.model_dump()
        except Exception as e:
            # 提取 Pydantic 错误详情
            errors = []
            if hasattr(e, "errors"):
                for err in e.errors():
                    loc = ".".join(str(x) for x in err.get("loc", []))
                    msg = err.get("msg", "")
                    errors.append(f"{loc}: {msg}")
            else:
                errors.append(str(e))
            return False, "; ".join(errors), arguments
