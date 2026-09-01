"""
响应传输层 (Response Transport)

负责将响应动作通过 SSH 分发到真实执行环境。
支持三种模式:
  - stub:  模拟执行（开发/测试用，只打日志）
  - ssh:   通过系统 ssh 命令连接到远程主机执行
  - auto:  优先 ssh，失败则回退 stub

运行模式由 config 中的 RESPONSE_TRANSPORT_MODE 控制。
SSH 连接信息由以下环境变量配置:
  RESPONSE_SSH_HOST       Windows 宿主机 IP
  RESPONSE_SSH_PORT       SSH 端口 (默认 22)
  RESPONSE_SSH_USER       SSH 用户名
  RESPONSE_SSH_KEY_FILE   SSH 私钥路径 (容器内路径)
"""
import asyncio
import json
import logging
import os
import socket
import tempfile
import time

logger = logging.getLogger(__name__)


class SSHTransport:
    """SSH 传输层 — 通过系统 ssh 命令执行远程命令"""

    def __init__(self):
        self._enabled = False
        self._host = ""
        self._port = 22
        self._user = ""
        self._key_file = ""
        # v4 修复(2026-09-01):延迟重试标记
        # Docker 9p bind mount 在容器启动时存在 race condition,entrypoint 跑得比 mount 早
        # 导致 ssh_transport 第一次 configure 走 stub,即使 mount 之后文件就在
        # 通过延迟 retry 机制 + 已有 configure 参数再次调用解决
        self._last_configure_kwargs = None  # (host, port, user, key_file)

    def configure(
        self,
        host: str = "",
        port: int = 22,
        user: str = "",
        key_file: str = "",
    ):
        """配置 SSH 连接"""
        # v4 修复(2026-09-01):记录参数,供后台 retry 任务使用
        self._last_configure_kwargs = {
            "host": host, "port": port, "user": user, "key_file": key_file,
        }
        self._host = host
        self._port = port or 22
        self._user = user
        # 按优先级查找密钥: /tmp/ssh (entrypoint复制) > 配置路径 > 默认路径
        import os as _os
        for candidate in ["/tmp/ssh/id_rsa", key_file, "/tmp/ssh-keys/id_rsa"]:
            if candidate and _os.path.exists(candidate):
                self._key_file = candidate
                logger.info(f"SSH key found: {candidate}")
                break
        else:
            self._key_file = key_file
            if key_file:
                logger.warning(f"SSH key not found at any candidate path, using config: {key_file}")
        key_ok = bool(self._key_file and _os.path.isfile(self._key_file))
        # sshd 可达性探测 (低开销 TCP 握手, 不做 SSH 协议层)
        sshd_ok = False
        sshd_reason = "host_unset"
        if host:
            sshd_ok, sshd_reason = _probe_sshd(host, port or 22, timeout=3.0)
        self._enabled = bool(host and user and key_ok and sshd_ok)
        if self._enabled:
            logger.info(
                f"SSH transport live: {user}@{host}:{port} "
                f"key={self._key_file} sshd={sshd_reason}"
            )
        else:
            # 汇总所有失败原因 — 诚实地告诉调用方为什么走 stub
            reasons = []
            if not host:
                reasons.append("no_host")
            if not user:
                reasons.append("no_user")
            if host and user and not key_ok:
                reasons.append(f"key_missing({self._key_file or 'unset'})")
            if host and not sshd_ok:
                reasons.append(f"sshd_unreachable({sshd_reason})")
            logger.warning(
                f"SSH transport stub (mode=stub): {', '.join(reasons)}; "
                f"response actions will be honestly marked as stub — "
                f"no firewall/host changes will be claimed until "
                f"key is mounted at /tmp/ssh-keys/id_rsa AND sshd is reachable."
            )
        # v4 修复(2026-09-01):如果首次配置是 stub 且参数记录了,后台延迟重试一次
        # 解决 Docker 9p mount race condition: entrypoint 跑时 mount 未就绪
        if not self._enabled and host:
            self._schedule_retry_reconfigure()

    def _schedule_retry_reconfigure(self):
        """v4 修复:后台延迟重试 configure, 解决 9p mount race condition"""
        import asyncio
        import time as _t
        kwargs = self._last_configure_kwargs
        if not kwargs or not kwargs.get("host"):
            return
        # 只调度一次(去重)
        if getattr(self, "_retry_task", None) is not None and not self._retry_task.done():
            return
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return  # 没 event loop, 跳过
        async def _retry():
            for delay in (2.0, 5.0, 10.0):
                await asyncio.sleep(delay)
                if self._enabled:
                    return
                self.configure(**kwargs)
                if self._enabled:
                    logger.info(f"SSH transport: retry succeeded after {delay}s")
                    return
            logger.warning(f"SSH transport: still stub after retries, giving up")
        try:
            self._retry_task = loop.create_task(_retry())
        except Exception as e:
            logger.debug(f"SSH transport: could not schedule retry task: {e}")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def run(
        self,
        command: str,
        timeout: int = 30,
        powershell: bool = True,
        platform: str = "linux",  # v4 修复(2026-09-01):默认改 linux,匹配 soc-firewall
    ) -> dict:
        """
        通过 SSH 在远程主机上执行命令

        Args:
            command: 要执行的命令
            timeout: 超时秒数
            powershell: 是否用 PowerShell 执行 (Windows)
            platform: 白名单校验平台 (linux / windows),默认 linux

        Returns:
            {"success": bool, "stdout": str, "stderr": str, "returncode": int}
        """
        if not self._enabled:
            return {
                "success": False,
                "error": "SSH not configured",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
            }

        # 命令白名单检查(平台参数化,默认 linux 匹配 soc-firewall)
        # v4 修复:之前硬编码 platform="windows",导致 iptables 命令全被拒
        from .command_whitelist import command_whitelist
        allowed, rule_id, reason = command_whitelist.check(command, platform=platform)
        if not allowed:
            logger.warning(f"[SSH] Command whitelist REJECTED ({platform}): {reason}")
            return {
                "success": False,
                "error": f"命令白名单拒绝: {reason}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "blocked_by": "command_whitelist",
            }

        # 构造 SSH 命令
        # 使用 /tmp/ssh/known_hosts 或 /dev/null 避免 appuser 无 home 目录问题
        known_hosts_candidates = ["/tmp/ssh/known_hosts", "/dev/null"]
        known_hosts = None
        for kh in known_hosts_candidates:
            kh_dir = os.path.dirname(kh)
            if kh == "/dev/null" or os.path.isdir(kh_dir):
                known_hosts = kh
                break
        if not known_hosts:
            known_hosts = "/dev/null"

        ssh_args = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5",
            "-o", "BatchMode=yes",
            "-p", str(self._port),
        ]
        if self._key_file:
            ssh_args.extend(["-i", self._key_file])

        # Windows 命令用 PowerShell 包装以获取更好的错误信息
        if powershell:
            # 用 Base64 编码避免转义问题
            encoded = _powershell_base64(command)
            remote_cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        else:
            remote_cmd = command

        ssh_args.extend([f"{self._user}@{self._host}", remote_cmd])

        logger.info(f"SSH: {self._user}@{self._host} (cmd len={len(command)})")

        start = time.time()
        proc = await asyncio.create_subprocess_exec(
            *ssh_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()
            success = proc.returncode == 0
            elapsed = time.time() - start

            if success:
                logger.info(f"SSH OK ({elapsed:.1f}s): {stdout_str[:100]}")
            else:
                logger.warning(
                    f"SSH FAIL (rc={proc.returncode}, {elapsed:.1f}s): "
                    f"{stderr_str[:200]}"
                )

            return {
                "success": success,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": proc.returncode,
                "elapsed_s": round(elapsed, 2),
            }

        except asyncio.TimeoutError:
            proc.kill()
            elapsed = time.time() - start
            logger.warning(f"SSH TIMEOUT after {elapsed:.1f}s: {command[:80]}")
            return {
                "success": False,
                "error": f"SSH command timed out after {timeout}s",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "elapsed_s": round(elapsed, 2),
            }
        except Exception as e:
            elapsed = time.time() - start
            logger.error(f"SSH ERROR ({elapsed:.1f}s): {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "elapsed_s": round(elapsed, 2),
            }

    async def run_script(
        self,
        script_content: str,
        timeout: int = 60,
    ) -> dict:
        """
        在远程主机上执行一段 PowerShell 脚本

        将脚本写入远程临时文件后执行，适合较长脚本。
        """
        # 用 Base64 编码直接传递
        return await self.run(script_content, timeout=timeout, powershell=True)


def _powershell_base64(command: str) -> str:
    """将 PowerShell 命令编码为 Base64 (UTF-16LE)"""
    import base64
    encoded = base64.b64encode(
        command.encode("utf-16-le")
    ).decode("ascii")
    return encoded


def _probe_sshd(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """TCP 探测 sshd 是否监听 host:port (低开销, 不做 SSH 协议握手)

    启动时调用, 验证"sshd 真实可达"而不仅"key 文件存在"。
    返回 (ok, reason):
      - (True, "tcp_ok") — 端口连通
      - (False, "TypeError: msg") — 超时/拒绝/不可达
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp_ok"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return False, f"{type(e).__name__}: {e}"


# ── 全局传输层实例 ──

ssh_transport = SSHTransport()
