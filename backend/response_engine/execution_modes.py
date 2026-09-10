"""
执行模式路由 (Execution Mode Router)

支持三种全局执行模式:
  - live:    真实 SSH 执行（默认，当前行为）
  - dry_run: 走完全部校验链，生成完整命令，但不执行，返回预览
  - mock:    走完校验链，不执行 SSH，返回仿真结果（集成测试用）

配置: config.py → execution_mode = "live" | "dry_run" | "mock"

调用方式:
    from response_engine.execution_modes import execution_router
    result = await execution_router.route(
        action_name="block_ip",
        command="iptables -I INPUT ...",
        params={"src_ip": "1.2.3.4"},
        live_fn=actual_ssh_exec_coroutine,
    )
"""
import logging
import time
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)

# 模式常量
MODE_LIVE = "live"
MODE_DRY_RUN = "dry_run"
MODE_MOCK = "mock"

VALID_MODES = {MODE_LIVE, MODE_DRY_RUN, MODE_MOCK}


# ── Mock 仿真结果模板 ──

_MOCK_TEMPLATES: dict[str, dict] = {
    "block_ip": {
        "success": True,
        "stdout": "Ok.",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] IP 封禁规则已添加",
    },
    "unblock_ip": {
        "success": True,
        "stdout": "Ok.",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] IP 封禁规则已删除",
    },
    "isolate_host": {
        "success": True,
        "stdout": "Ok.",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] 主机隔离规则已添加 (INPUT+OUTPUT)",
    },
    "restore_host": {
        "success": True,
        "stdout": "Ok.",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] 主机隔离规则已删除",
    },
    "rate_limit": {
        "success": True,
        "stdout": "QoS policy created",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] QoS 限速策略已创建",
    },
    "remove_rate_limit": {
        "success": True,
        "stdout": "QoS policy removed",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] QoS 限速策略已删除",
    },
    "kill_session": {
        "success": True,
        "stdout": "Session logged off",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] 会话已终止",
    },
    "kill_process": {
        "success": True,
        "stdout": "KILLED",
        "stderr": "",
        "returncode": 0,
        "message": "[MOCK] 进程已终止",
    },
    "quarantine_file": {
        "success": True,
        "message": "[MOCK] 文件已隔离",
    },
    "clean_persistence": {
        "success": True,
        "message": "[MOCK] 持久化项已清理",
    },
    "forensic_snapshot": {
        "success": True,
        "snapshot_status": "ok",
        "message": "[MOCK] 取证快照已采集",
    },
    "disable_account": {
        "success": True,
        "message": "[MOCK] 账户已禁用",
    },
    "recall_email": {
        "success": True,
        "message": "[MOCK] 邮件已撤回",
    },
    "dns_sinkhole": {
        "success": True,
        "message": "[MOCK] DNS sinkhole 已写入",
    },
    "send_alert": {
        "success": True,
        "message": "[MOCK] 告警已发送",
    },
    "vulnerability_scan": {
        "success": True,
        "stdout": "Nmap scan report for target\n22/tcp open ssh\n80/tcp open http",
        "stderr": "",
        "returncode": 0,
        "open_ports": ["22/tcp open ssh", "80/tcp open http"],
        "message": "[MOCK] nmap 扫描完成，发现 2 个开放端口",
    },
}

_DEFAULT_MOCK = {
    "success": True,
    "stdout": "[MOCK] Command executed successfully",
    "stderr": "",
    "returncode": 0,
    "message": "[MOCK] 操作成功",
}


class ExecutionModeRouter:
    """执行模式路由器"""

    def __init__(self, mode: str = MODE_LIVE):
        self._mode = mode if mode in VALID_MODES else MODE_LIVE

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str):
        if value not in VALID_MODES:
            raise ValueError(f"Invalid execution mode: {value}, must be one of {VALID_MODES}")
        old = self._mode
        self._mode = value
        logger.info(f"[ExecutionMode] Changed: {old} → {value}")

    async def route(
        self,
        action_name: str,
        command: str,
        params: dict,
        live_fn: Callable[..., Coroutine],
        platform: str = "linux",
    ) -> dict:
        """
        根据当前模式路由执行

        Args:
            action_name: 动作名称
            command: 将要执行的完整命令
            params: 动作参数
            live_fn: 真实执行的异步函数 (接受 command 参数)
            platform: 平台 (linux/windows)

        Returns:
            执行结果 dict
        """
        if self._mode == MODE_DRY_RUN:
            return self._dry_run(action_name, command, params, platform)

        if self._mode == MODE_MOCK:
            return self._mock(action_name, params)

        # live 模式
        return await live_fn(command)

    def _dry_run(
        self, action_name: str, command: str, params: dict, platform: str
    ) -> dict:
        """Dry Run: 返回预览，不执行"""
        logger.info(
            f"[DRY_RUN] {action_name} would execute on {platform}: {command[:200]}"
        )
        return {
            "success": True,
            "mode": "dry_run",
            "action": action_name,
            "command": command,
            "platform": platform,
            "params": params,
            "would_execute": True,
            "message": f"[DRY_RUN] 命令已生成但未执行: {command[:100]}",
            "timestamp": time.time(),
        }

    def _mock(self, action_name: str, params: dict) -> dict:
        """Mock: 返回仿真结果"""
        template = _MOCK_TEMPLATES.get(action_name, _DEFAULT_MOCK)
        result = dict(template)
        result["mode"] = "mock"
        result["action"] = action_name
        result["params"] = params
        result["timestamp"] = time.time()
        logger.info(f"[MOCK] {action_name}: simulated success")
        return result


execution_router = ExecutionModeRouter()
