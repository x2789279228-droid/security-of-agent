"""
mitm_proxy.py — TLS 解密代理（内网场景可选）

基于 mitmproxy 的透明/显式代理，用于内网 SSL 检查:
  - 使用自签 CA 动态签发目标域名证书
  - 解密后的明文 HTTP 流量送入 protocol_parser 解析
  - 仅在内网授权场景启用（需部署 CA 证书到终端信任链）

依赖: mitmproxy (pip install mitmproxy)

用法:
    from encrypted_traffic.mitm_proxy import mitm_proxy
    await mitm_proxy.start()   # 启动代理
    await mitm_proxy.stop()

配置:
    SHARED_MEMORY_MITM_ENABLED=true
    SHARED_MEMORY_MITM_LISTEN_PORT=8443
    SHARED_MEMORY_MITM_CA_CERT=/certs/ca.crt
    SHARED_MEMORY_MITM_CA_KEY=/certs/ca.key
"""
import asyncio
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


class MitmProxy:
    """
    TLS 解密代理管理器

    封装 mitmproxy 的启动/停止生命周期，
    将解密后的流量转发给协议解析器。
    """

    def __init__(self):
        self.enabled = settings.mitm_enabled
        self.listen_port = settings.mitm_listen_port
        self.ca_cert = settings.mitm_ca_cert
        self.ca_key = settings.mitm_ca_key

        self._running = False
        self._process: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._decrypted_callbacks: list = []

    @property
    def is_running(self) -> bool:
        return self._running

    def on_decrypted(self, callback):
        """注册解密流量回调: async def cb(flow_data: dict)"""
        self._decrypted_callbacks.append(callback)

    async def start(self):
        """启动 TLS 解密代理"""
        if not self.enabled:
            logger.info("MITM 代理未启用 (mitm_enabled=false)")
            return

        if not self.ca_cert or not self.ca_key:
            logger.error("MITM 代理需要配置 CA 证书和私钥 (mitm_ca_cert / mitm_ca_key)")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_proxy())
        logger.info(
            "MITM 代理启动: port=%d ca_cert=%s",
            self.listen_port, self.ca_cert,
        )

    async def stop(self):
        """停止代理"""
        if not self._running:
            return
        self._running = False

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("MITM 代理已停止")

    async def _run_proxy(self):
        """启动 mitmdump 子进程"""
        try:
            cmd = [
                "mitmdump",
                "--listen-port", str(self.listen_port),
                "--set", f"confdir={self._get_confdir()}",
                "--set", "ssl_insecure=true",  # 不验证上游证书（内网场景）
                "--mode", "regular",
                "--set", "flow_detail=2",
                "-q",  # 静默模式
            ]

            # 自定义脚本：将解密流量转发给平台
            addon_script = self._generate_addon_script()
            if addon_script:
                cmd.extend(["-s", addon_script])

            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            logger.info("mitmdump 进程启动: PID=%d", self._process.pid)

            # 读取输出
            while self._running:
                if self._process.stdout:
                    line = await self._process.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").strip()
                    if decoded:
                        logger.debug("mitmdump: %s", decoded)

            await self._process.wait()

        except FileNotFoundError:
            logger.error(
                "mitmdump 未安装。请执行: pip install mitmproxy"
            )
            self._running = False
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("MITM 代理异常: %s", e, exc_info=True)
            self._running = False

    def _get_confdir(self) -> str:
        """获取 mitmproxy 配置目录（存放 CA 证书）"""
        import os
        confdir = os.path.join(os.path.dirname(self.ca_cert), ".mitmproxy")
        os.makedirs(confdir, exist_ok=True)
        return confdir

    def _generate_addon_script(self) -> str:
        """生成 mitmproxy addon 脚本，将解密流量 POST 到平台"""
        import os
        import json

        script_content = f'''
"""mitmproxy addon: 将解密流量转发到 SOC 平台"""
import json
import urllib.request
from mitmproxy import http

PLATFORM_URL = "http://localhost:8001/api/v1/mitm/flow"

def response(flow: http.HTTPFlow):
    """HTTP 响应完成后触发"""
    try:
        data = {{
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "",
            "dst_ip": flow.server_conn.peername[0] if flow.server_conn.peername else "",
            "dst_port": flow.server_conn.peername[1] if flow.server_conn.peername else 443,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "request_headers": dict(flow.request.headers),
            "response_status": flow.response.status_code if flow.response else 0,
            "response_headers": dict(flow.response.headers) if flow.response else {{}},
            "request_body": flow.request.get_text()[:2048] if flow.request.content else "",
            "response_body": flow.response.get_text()[:2048] if flow.response and flow.response.content else "",
            "sni": flow.server_conn.sni or "",
        }}
        payload = json.dumps(data).encode()
        req = urllib.request.Request(
            PLATFORM_URL,
            data=payload,
            headers={{"Content-Type": "application/json"}},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
'''
        script_path = os.path.join(
            os.path.dirname(self.ca_cert) if self.ca_cert else "/tmp",
            "mitm_addon.py",
        )
        try:
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            return script_path
        except Exception as e:
            logger.warning("生成 MITM addon 脚本失败: %s", e)
            return ""

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "running": self._running,
            "listen_port": self.listen_port,
            "pid": self._process.pid if self._process else None,
        }


# ── 全局单例 ──
mitm_proxy = MitmProxy()
