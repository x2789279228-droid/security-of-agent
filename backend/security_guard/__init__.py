"""SecurityGuard 模块：安全动作执行前的多维度安全审查。

在响应引擎执行安全动作（block_ip, isolate_host 等）之前，
通过意图审查、序列管控、频率控制、上下文感知四项检查确保动作安全。

Usage:
    from backend.security_guard import SecurityGuard, CheckResult

    guard = SecurityGuard()
    result = guard.inspect("block_ip", {"threat_level": "high", "reason": "恶意扫描", "src_ip": "1.2.3.4"})
    if result["allowed"]:
        # 执行动作...
        guard.record("block_ip", threat_info, exec_result)
"""
from .check_result import CheckResult
from .security_guard import SecurityGuard, security_guard

__all__ = ["SecurityGuard", "CheckResult", "security_guard"]
