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

    def configure(
        self,
        host: str = "",
        port: int = 22,
        user: str = "",
        key_file: str = "",
    ):
        """配置 SSH 连接"""
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
        self._enabled = bool(host and user)
        if self._enabled:
            logger.info(
                f"SSH transport enabled: {user}@{host}:{port} key={self._key_file}"
            )
        else:
            logger.info("SSH transport disabled (no config)")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def run(
        self,
        command: str,
        timeout: int = 30,
        powershell: bool = True,
    ) -> dict:
        """
        通过 SSH 在远程主机上执行命令

        Args:
            command: 要执行的命令
            timeout: 超时秒数
            powershell: 是否用 PowerShell 执行 (Windows)

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

        # 命令白名单检查（Windows 平台）
        from .command_whitelist import command_whitelist
        allowed, rule_id, reason = command_whitelist.check(command, platform="windows")
        if not allowed:
            logger.warning(f"[SSH] Command whitelist REJECTED: {reason}")
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


# ── 全局传输层实例 ──

ssh_transport = SSHTransport()
