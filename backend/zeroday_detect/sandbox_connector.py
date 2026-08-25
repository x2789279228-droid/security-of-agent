"""
sandbox_connector.py — CAPE / Cuckoo 沙箱 REST API 对接

支持:
  - 文件/URL 提交分析
  - 任务状态轮询
  - 报告获取与解析
  - 高危告警自动提交

用法:
    from zeroday_detect.sandbox_connector import sandbox
    task_id = await sandbox.submit_file(file_bytes, filename="malware.exe")
    status = await sandbox.get_task_status(task_id)
    report = await sandbox.get_report(task_id)
"""
import asyncio
import hashlib
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


class SandboxConnector:
    """CAPE / Cuckoo 沙箱连接器"""

    def __init__(self):
        self.enabled = settings.sandbox_enabled
        self.api_url = settings.sandbox_api_url.rstrip("/")
        self.api_key = settings.sandbox_api_key
        self.timeout = settings.sandbox_timeout
        self.auto_submit = settings.sandbox_auto_submit
        self.auto_threshold = settings.sandbox_auto_threshold
        self.sandbox_type = settings.sandbox_type

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str = "sample.bin",
        package: str = "",
        priority: int = 1,
    ) -> Optional[str]:
        """提交文件到沙箱分析，返回 task_id"""
        if not self.enabled:
            logger.info("沙箱未启用")
            return None

        try:
            import aiohttp

            sha256 = hashlib.sha256(file_bytes).hexdigest()
            url = f"{self.api_url}/tasks/create/file"

            data = aiohttp.FormData()
            data.add_field(
                "file", file_bytes,
                filename=filename,
                content_type="application/octet-stream",
            )
            if package:
                data.add_field("package", package)
            data.add_field("priority", str(priority))
            data.add_field("timeout", str(self.timeout))

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data=data, headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        task_id = str(result.get("task_id", result.get("task_ids", [""])[0]))
                        logger.info("沙箱提交成功: %s → task_id=%s", filename, task_id)
                        try:
                            from metrics import inc_sandbox_submission
                            inc_sandbox_submission("file")
                        except Exception:
                            pass
                        return task_id
                    else:
                        body = await resp.text()
                        logger.error("沙箱提交失败: HTTP %d %s", resp.status, body[:200])
                        return None
        except ImportError:
            logger.error("aiohttp 未安装")
            return None
        except Exception as e:
            logger.error("沙箱提交异常: %s", e)
            return None

    async def submit_url(self, url_to_analyze: str, priority: int = 1) -> Optional[str]:
        """提交 URL 到沙箱分析"""
        if not self.enabled:
            return None

        try:
            import aiohttp

            url = f"{self.api_url}/tasks/create/url"
            data = aiohttp.FormData()
            data.add_field("url", url_to_analyze)
            data.add_field("priority", str(priority))
            data.add_field("timeout", str(self.timeout))

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data=data, headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        task_id = str(result.get("task_id", ""))
                        logger.info("URL 沙箱提交: %s → task_id=%s", url_to_analyze, task_id)
                        return task_id
                    return None
        except Exception as e:
            logger.error("URL 沙箱提交异常: %s", e)
            return None

    async def get_task_status(self, task_id: str) -> Optional[dict]:
        """查询任务状态"""
        try:
            import aiohttp

            url = f"{self.api_url}/tasks/view/{task_id}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        task = data.get("task", data)
                        return {
                            "task_id": task_id,
                            "status": task.get("status", "unknown"),
                            "completed_on": task.get("completed_on", ""),
                        }
                    return None
        except Exception as e:
            logger.debug("任务状态查询失败: %s", e)
            return None

    async def get_report(self, task_id: str) -> Optional[dict]:
        """获取分析报告"""
        try:
            import aiohttp

            url = f"{self.api_url}/tasks/report/{task_id}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
        except Exception as e:
            logger.error("报告获取失败: %s", e)
            return None

    async def wait_for_completion(self, task_id: str, poll_interval: int = 10) -> Optional[dict]:
        """等待任务完成并返回报告"""
        elapsed = 0
        while elapsed < self.timeout + 60:
            status = await self.get_task_status(task_id)
            if status is None:
                return None
            if status["status"] == "reported":
                return await self.get_report(task_id)
            if status["status"] in ("failed_analysis", "failed_processing"):
                logger.warning("沙箱任务失败: %s status=%s", task_id, status["status"])
                return None
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        logger.warning("沙箱任务超时: %s", task_id)
        return None

    async def auto_submit_check(
        self,
        event: dict,
        file_bytes: Optional[bytes] = None,
    ) -> Optional[str]:
        """
        自动提交检查 — 高危告警触发沙箱分析

        条件: sandbox_auto_submit=true 且 事件置信度 >= threshold
        """
        if not self.auto_submit or not self.enabled:
            return None

        confidence = event.get("confidence", 0)
        severity = event.get("severity", "info")

        if confidence >= self.auto_threshold or severity == "critical":
            if file_bytes:
                return await self.submit_file(
                    file_bytes,
                    filename=event.get("sample_name", "auto_sample.bin"),
                    priority=2,
                )
            url = event.get("url", "")
            if url:
                return await self.submit_url(url, priority=2)

        return None

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "type": self.sandbox_type,
            "api_url": self.api_url,
            "auto_submit": self.auto_submit,
        }


# ── 全局单例 ──
sandbox = SandboxConnector()
