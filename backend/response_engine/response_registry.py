"""
响应动作注册表 (Response Registry)

管理所有可用的响应动作及其定义。
每个动作是一个异步函数，支持回滚。

注册的动作:
  - block_ip        封禁源IP (通过 Windows 防火墙)
  - unblock_ip      解封IP (回滚)
  - isolate_host    隔离主机 (防火墙全阻断)
  - restore_host    恢复主机 (回滚)
  - rate_limit      对IP限速 (通过 QoS 策略)
  - remove_rate_limit 取消限速 (回滚)
  - kill_session    终止用户会话 (RDP/本地)
  - send_alert      发送告警通知

执行模式:
  - stub:  模拟执行，只打日志
  - ssh:   通过 SSH 在 Windows 宿主机执行真实命令
  - auto:  优先 SSH，失败回退 stub

配置 (config.py):
  RESPONSE_TRANSPORT_MODE=auto|stub|ssh
  RESPONSE_SSH_HOST=192.168.1.1
  RESPONSE_SSH_USER=administrator
  RESPONSE_SSH_KEY_FILE=/root/.ssh/id_rsa
"""
import asyncio
import base64
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

from config import settings
from .transport import ssh_transport

logger = logging.getLogger(__name__)


# ── 危险等级 ──

ACTION_SEVERITY_LOW = "low"
ACTION_SEVERITY_MEDIUM = "medium"
ACTION_SEVERITY_HIGH = "high"
ACTION_SEVERITY_CRITICAL = "critical"

# 自动执行阈值：低于此等级的可自动执行，高于此等级需审批
AUTO_EXECUTE_THRESHOLD = {
    ACTION_SEVERITY_LOW: True,
    ACTION_SEVERITY_MEDIUM: True,
    ACTION_SEVERITY_HIGH: False,      # high 需审批
    ACTION_SEVERITY_CRITICAL: False,  # critical 需审批
}

# 是否需要审批的危险等级集合
APPROVAL_REQUIRED = {ACTION_SEVERITY_HIGH, ACTION_SEVERITY_CRITICAL}


@dataclass
class ResponseActionDef:
    """响应动作定义"""
    name: str
    description: str
    severity: str                     # 危险等级
    category: str                     # "network" | "host" | "session" | "notification"
    reversible: bool                  # 是否可回滚
    timeout_ms: int = 30000           # 执行超时
    rollback_fn: Optional[Callable] = None  # 回滚函数
    params_schema: dict = field(default_factory=dict)  # 参数JSON Schema


class ResponseRegistry:
    """响应动作注册表"""

    def __init__(self):
        self._actions: dict[str, ResponseActionDef] = {}
        self._exec_fns: dict[str, Callable[..., Coroutine]] = {}
        self._rollback_fns: dict[str, Callable[..., Coroutine]] = {}
        # 幂等性缓存: action_name:param_key → rollback_token
        self._idempotent_cache: dict[str, str] = {}

    def register(
        self,
        name: str,
        exec_fn: Callable[..., Coroutine],
        description: str,
        severity: str = ACTION_SEVERITY_MEDIUM,
        category: str = "network",
        reversible: bool = True,
        timeout_ms: int = 30000,
        rollback_fn: Optional[Callable[..., Coroutine]] = None,
        params_schema: Optional[dict] = None,
    ):
        """注册一个响应动作"""
        self._actions[name] = ResponseActionDef(
            name=name,
            description=description,
            severity=severity,
            category=category,
            reversible=reversible,
            timeout_ms=timeout_ms,
            rollback_fn=rollback_fn,
            params_schema=params_schema or {},
        )
        self._exec_fns[name] = exec_fn
        if rollback_fn:
            self._rollback_fns[name] = rollback_fn
        logger.info(
            f"Registered response action: {name} "
            f"(severity={severity}, category={category}, "
            f"reversible={reversible})"
        )

    def get_action(self, name: str) -> Optional[ResponseActionDef]:
        return self._actions.get(name)

    def list_actions(self, category: str = "") -> list[ResponseActionDef]:
        if category:
            return [a for a in self._actions.values() if a.category == category]
        return list(self._actions.values())

    async def execute(self, name: str, **kwargs) -> dict:
        """执行动作，返回 {success, result, rollback_token}"""
        action = self._actions.get(name)
        if not action:
            raise ValueError(f"Unknown action: {name}")

        # 幂等性检查
        param_key = f"{name}:{hash(frozenset(kwargs.items()))}"
        if param_key in self._idempotent_cache:
            token = self._idempotent_cache[param_key]
            logger.info(f"Idempotent check: {param_key} already executed, token={token}")
            return {"success": True, "idempotent": True, "rollback_token": token}

        fn = self._exec_fns.get(name)
        if not fn:
            raise ValueError(f"No executor for action: {name}")

        try:
            import asyncio
            result = await asyncio.wait_for(fn(**kwargs), timeout=action.timeout_ms / 1000)
            rollback_token = f"rb_{name}_{kwargs.get('src_ip', kwargs.get('target', 'unknown'))}_{int(__import__('time').time())}"
            self._idempotent_cache[param_key] = rollback_token
            logger.info(f"Action {name} executed: {str(result)[:100]}")
            return {
                "success": True,
                "result": result,
                "rollback_token": rollback_token,
            }
        except Exception as e:
            logger.error(f"Action {name} failed: {e}")
            return {"success": False, "error": str(e)}

    async def rollback(self, name: str, **kwargs) -> dict:
        """回滚动作"""
        fn = self._rollback_fns.get(name)
        if not fn:
            return {"success": False, "error": f"No rollback for action: {name}"}
        try:
            result = await fn(**kwargs)
            logger.info(f"Rollback {name}: {str(result)[:100]}")
            return {"success": True, "result": result}
        except Exception as e:
            logger.error(f"Rollback {name} failed: {e}")
            return {"success": False, "error": str(e)}

    def needs_approval(self, name: str) -> bool:
        """该动作是否需要审批"""
        action = self._actions.get(name)
        if not action:
            return True  # 未知动作，保守处理
        return action.severity in APPROVAL_REQUIRED


response_registry = ResponseRegistry()


# ════════════════════════════════════════════
# 输入验证工具函数
# ════════════════════════════════════════════

def _validate_ip(value: str) -> str:
    """验证并规范化 IP 地址，防止命令注入"""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")

def _validate_alphanumeric(value: str, max_len: int = 128) -> str:
    """仅允许字母数字和有限安全字符"""
    if not value:
        return value
    sanitized = re.sub(r'[^a-zA-Z0-9_\.\-\:\/\ ]', '', value)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]
    return sanitized

def _sanitize_powershell_string(value: str) -> str:
    """转义 PowerShell 字符串中的危险字符"""
    if not value:
        return value
    return value.replace('`', '``').replace('"', '`"').replace('$', '`$').replace('\n', ' ').replace('\r', ' ')

def _validate_positive_int(value: int, name: str = "value") -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a positive integer, got {value}")
    return value

# ════════════════════════════════════════════
# 响应动作实现 (真实执行 + 桩回退)
# ════════════════════════════════════════════

def _mode() -> str:
    """获取当前执行模式"""
    return getattr(settings, "response_transport_mode", "auto")


async def _stub_fallback(action: str, **fields) -> dict:
    """SSH 不可用时的桩回退"""
    logger.warning(
        f"[STUB] {action} would execute: {fields}"
        f" (SSH transport requires RESPONSE_SSH_HOST config)"
    )
    return {"action": action, "mode": "stub", **fields, "_stub": True}


def _ps_cmd(script: str) -> str:
    """将 PowerShell 脚本编码为 Base64 单行命令，避免引号转义问题"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


async def _exec(cmd: str, action: str, **fields) -> dict:
    """
    统一执行入口:
      - ssh 模式 → 通过 SSH 在宿主机执行
      - stub 模式 → 只打日志
      - auto 模式 → 尝试 SSH，失败回退 stub
    """
    mode = _mode()
    if mode == "ssh" or (mode == "auto" and ssh_transport.enabled):
        result = await ssh_transport.run(cmd, powershell=False)
        if result["success"]:
            logger.info(f"[SSH] {action} OK: {result['stdout'][:100]}")
            return {"action": action, "mode": "ssh", **fields, **result}
        elif mode == "ssh":
            logger.error(f"[SSH] {action} FAILED: {result['stderr'][:200]}")
            return {"action": action, "mode": "ssh", "success": False, **fields, **result}
        else:
            logger.warning(f"[SSH] {action} failed, fallback to stub: {result['stderr'][:100]}")
    return await _stub_fallback(action, **fields)


# ── 1. block_ip / unblock_ip (Windows 防火墙) ──

async def _block_ip(src_ip: str, reason: str = "", duration_minutes: int = 60, **kwargs) -> dict:
    """
    封禁源IP — Windows 防火墙入站规则
    命令: netsh advfirewall firewall add rule ...
    支持自动解封: 创建计划任务在 duration 后删除规则
    """
    src_ip = _validate_ip(src_ip)
    duration_minutes = _validate_positive_int(duration_minutes, "duration_minutes")
    safe_reason = _sanitize_powershell_string(reason[:200])
    rule_name = f"RE_Block_{src_ip.replace('.','_')}"
    safe_reason = _sanitize_powershell_string(reason[:200])
    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" '
        f'direction=in action=block '
        f'remoteip="{src_ip}" '
        f'description="ResponseEngine auto-block: {safe_reason}"'
    )
    result = await _exec(cmd, "block_ip", src_ip=src_ip, duration_minutes=duration_minutes, rule_name=rule_name)

    # SSH 成功后创建自动解封任务
    if result.get("success") and duration_minutes > 0 and result.get("mode") == "ssh":
        unblock_script = (
            f'Start-Sleep -Seconds {duration_minutes * 60}\n'
            f'netsh advfirewall firewall delete rule name="{rule_name}"'
        )
        asyncio.create_task(ssh_transport.run(_ps_cmd(unblock_script), powershell=False))
        logger.info(f"[SSH] Auto-unblock scheduled for {src_ip} in {duration_minutes}min")

    return result


async def _unblock_ip(src_ip: str, reason: str = "", **kwargs) -> dict:
    """解封IP — 删除防火墙规则"""
    rule_name = f"RE_Block_{src_ip.replace('.','_')}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    return await _exec(cmd, "unblock_ip", src_ip=src_ip, rule_name=rule_name)


# ── 2. isolate_host / restore_host (防火墙全阻断) ──

async def _isolate_host(host_ip: str, reason: str = "", **kwargs) -> dict:
    """
    隔离主机 — 添加入站+出站全阻断规则
    相当于把该主机从网络中彻底断开
    """
    host_ip = _validate_ip(host_ip)
    rule_name_in = f"RE_Isolate_In_{host_ip.replace('.','_')}"
    rule_name_out = f"RE_Isolate_Out_{host_ip.replace('.','_')}"
    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name_in}" direction=in action=block '
        f'remoteip="{host_ip}" description="ISOLATE: {reason}" && '
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name_out}" direction=out action=block '
        f'remoteip="{host_ip}" description="ISOLATE: {reason}"'
    )
    return await _exec(cmd, "isolate_host", host_ip=host_ip, rule_names=[rule_name_in, rule_name_out])


async def _restore_host(host_ip: str, reason: str = "", **kwargs) -> dict:
    """恢复主机 — 删除隔离规则"""
    safe_ip = host_ip.replace('.', '_')
    cmd = (
        f'netsh advfirewall firewall delete rule name="RE_Isolate_In_{safe_ip}" && '
        f'netsh advfirewall firewall delete rule name="RE_Isolate_Out_{safe_ip}"'
    )
    return await _exec(cmd, "restore_host", host_ip=host_ip)


# ── 3. rate_limit / remove_rate_limit (通过 QoS 策略) ──

async def _rate_limit(src_ip: str, bandwidth_kbps: int = 1000, reason: str = "", **kwargs) -> dict:
    """
    对IP限速 — Windows QoS 策略 (通过 PowerShell)
    创建基于源 IP 的流量限制策略
    """
    src_ip = _validate_ip(src_ip)
    bandwidth_kbps = _validate_positive_int(bandwidth_kbps, "bandwidth_kbps")
    safe_reason = _sanitize_powershell_string(reason[:200])
    policy_name = f"RE_RateLimit_{src_ip.replace('.','_')}"
    safe_src = _sanitize_powershell_string(src_ip)
    safe_policy = _sanitize_powershell_string(policy_name)
    band_bits = bandwidth_kbps * 1024
    ps_script = (
        f'$name = "{safe_policy}"\n'
        f'$ip = "{safe_src}"\n'
        f'$rate = {band_bits}\n'
        f'New-NetQosPolicy -Name $name -IPSourceAddress $ip '
        f'-IPProtocol TCP -ThrottleRateInBits $rate '
        f'-Description "ResponseEngine rate-limit: {safe_reason}" '
        f'-ErrorAction Stop\n'
        f'Write-Output "QoS policy $name created"'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "rate_limit", src_ip=src_ip, bandwidth_kbps=bandwidth_kbps, policy_name=policy_name)


async def _remove_rate_limit(src_ip: str, reason: str = "", **kwargs) -> dict:
    """取消限速 — 删除 QoS 策略"""
    policy_name = f"RE_RateLimit_{src_ip.replace('.','_')}"
    ps_script = (
        f'$name = "{policy_name}"\n'
        f'Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue\n'
        f'Write-Output "QoS policy $name removed"'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "remove_rate_limit", src_ip=src_ip)


# ── 4. kill_session (终止用户会话) ──

async def _kill_session(session_id: str, user: str = "", reason: str = "", **kwargs) -> dict:
    """
    终止用户会话:
      - 如果 session_id 是 RDP 会话ID → logoff
      - 如果 user 提供 → 终止该用户所有进程
      - 否则当作进程名 → taskkill
    """
    if session_id and session_id.isdigit():
        safe_sid = _validate_alphanumeric(session_id, max_len=10)
        ps_script = f'logoff {safe_sid} /server:localhost 2>$null\nWrite-Output "Session {safe_sid} logged off"'
    elif user:
        safe_user = _sanitize_powershell_string(user[:64])
        ps_script = (
            f'Get-Process -IncludeUserName | '
            f'Where-Object {{$_.UserName -match "{safe_user}"}} | '
            f'Stop-Process -Force\n'
            f'Write-Output "Processes for {safe_user} terminated"'
        )
    else:
        safe_name = _validate_alphanumeric(session_id[:64], max_len=64)
        ps_script = (
            f'Stop-Process -Name "{safe_name}" -Force -ErrorAction SilentlyContinue\n'
            f'taskkill /F /IM "{safe_name}" /T 2>$null\n'
            f'Write-Output "Process {safe_name} terminated"'
        )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "kill_session", session_id=session_id, user=user)


# ── 5. send_alert (发送告警通知) ──

async def _send_alert(
    title: str = "", message: str = "", severity: str = "high",
    channel: str = "webhook", webhook_url: str = "", **kwargs
) -> dict:
    """
    发送告警通知:
      - webhook:     POST JSON 到指定 URL (默认)
      - eventlog:    Windows 事件日志
      - dingtalk:    钉钉机器人
      - wework:      企业微信机器人

    channel 参数决定发送方式。
    webhook_url 可以自定义，否则使用默认值。
    """
    if not channel or channel == "webhook":
        if webhook_url:
            title = title or "安全告警"
            message = message or f"威胁告警 (严重度={severity})"
            return await _send_webhook(title, message, severity, webhook_url)
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_webhook_default(title, message, severity)

    elif channel == "eventlog":
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_eventlog(title, message, severity)

    elif channel == "display":
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_display_notification(title, message)

    else:
        logger.warning(f"[ALERT] Unknown channel={channel}, falling back to log")
        return {"action": "send_alert", "mode": "stub", "title": title, "message": message, "_stub": True}


async def _send_webhook(title: str, message: str, severity: str, webhook_url: str) -> dict:
    """通过通用 Webhook 发送告警"""
    try:
        import httpx
        payload = {
            "title": title,
            "message": message,
            "severity": severity,
            "source": "shared-memory-response-engine",
            "timestamp": __import__("time").time(),
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            logger.info(f"[ALERT] Webhook sent to {webhook_url}: {resp.status_code}")
            return {"action": "send_alert", "mode": "webhook", "success": True, "status_code": resp.status_code}
    except Exception as e:
        logger.warning(f"[ALERT] Webhook failed: {e}")
        return {"action": "send_alert", "mode": "webhook", "success": False, "error": str(e)}


async def _send_webhook_default(title: str, message: str, severity: str) -> dict:
    """使用默认渠道记录告警（写日志）"""
    logger.warning(f"[ALERT] [{severity.upper()}] {title}: {message[:200]}")
    return {
        "action": "send_alert", "mode": "log",
        "title": title, "message": message, "severity": severity,
        "success": True,
    }


async def _send_eventlog(title: str, message: str, severity: str) -> dict:
    """写入 Windows 事件日志（通过 SSH）"""
    level = "ERROR" if severity in ("critical", "high") else "WARNING"
    safe_title = _sanitize_powershell_string(title[:200])
    safe_msg = _sanitize_powershell_string(message[:500])
    ps_script = (
        f'Write-EventLog -LogName Application -Source "ResponseEngine" '
        f'-EntryType {level} -EventId 1000 -Message "{safe_title}: {safe_msg}" '
        f'-ErrorAction SilentlyContinue'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "send_alert", title=title, message=message, severity=severity)


async def _send_display_notification(title: str, message: str) -> dict:
    """在宿主机桌面弹出通知（通过 PowerShell）"""
    safe_title = _sanitize_powershell_string(title[:200])
    safe_msg = _sanitize_powershell_string(message[:500])
    ps_script = (
        '[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null\n'
        '$n = New-Object System.Windows.Forms.NotifyIcon\n'
        '$n.Icon = [System.Drawing.SystemIcons]::Warning\n'
        f'$n.BalloonTipTitle = "{safe_title}"\n'
        f'$n.BalloonTipText = "{safe_msg}"\n'
        '$n.Visible = $true\n'
        '$n.ShowBalloonTip(10000)'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "send_alert", title=title, message=message, mode="notification")


# ── 注册所有动作 ──

def _init_registry():
    response_registry.register(
        "block_ip", _block_ip,
        description="封禁源IP (通过防火墙/WAF ACL)",
        severity=ACTION_SEVERITY_HIGH,
        category="network",
        reversible=True,
        rollback_fn=_unblock_ip,
        params_schema={
            "src_ip": "str (required) 源IP",
            "reason": "str 封禁原因",
            "duration_minutes": "int 封禁时长(默认60)",
        },
    )
    response_registry.register(
        "isolate_host", _isolate_host,
        description="将主机隔离到隔离VLAN",
        severity=ACTION_SEVERITY_CRITICAL,
        category="host",
        reversible=True,
        rollback_fn=_restore_host,
        params_schema={
            "host_ip": "str (required) 主机IP",
            "reason": "str 隔离原因",
        },
    )
    response_registry.register(
        "rate_limit", _rate_limit,
        description="对源IP进行带宽限速",
        severity=ACTION_SEVERITY_MEDIUM,
        category="network",
        reversible=True,
        rollback_fn=_remove_rate_limit,
        params_schema={
            "src_ip": "str (required) 源IP",
            "bandwidth_kbps": "int 限制带宽(Kbps,默认1000)",
            "reason": "str 限速原因",
        },
    )
    response_registry.register(
        "kill_session", _kill_session,
        description="强制终止用户登录会话",
        severity=ACTION_SEVERITY_HIGH,
        category="session",
        reversible=False,
        params_schema={
            "session_id": "str (required) 会话ID",
            "user": "str 用户名",
            "reason": "str 终止原因",
        },
    )
    response_registry.register(
        "send_alert", _send_alert,
        description="发送告警通知到指定渠道",
        severity=ACTION_SEVERITY_LOW,
        category="notification",
        reversible=False,
        params_schema={
            "title": "str (required) 告警标题",
            "message": "str (required) 告警内容",
            "severity": "str 告警级别",
            "channel": "str 通知渠道(webhook/dingtalk/wechat)",
        },
    )
    logger.info(f"Response registry initialized with {len(response_registry._actions)} actions")


_init_registry()
