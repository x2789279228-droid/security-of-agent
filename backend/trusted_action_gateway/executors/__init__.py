"""
Trusted Action Gateway — 执行器层 (Executors)

专用链 iptables 执行器与执行后验证器扩展。

安全约束:
  - 不使用 shell=True
  - 不允许任意命令执行（固定模板 + 受控命令适配器）
  - 所有规则写入专用链 AGENT_GUARD_INPUT / AGENT_GUARD_OUTPUT
  - 完整类型标注与异常处理
"""
from .iptables_executor import IptablesChainExecutor
from .post_verifier import TagPostActionVerifier

__all__ = ["IptablesChainExecutor", "TagPostActionVerifier"]
