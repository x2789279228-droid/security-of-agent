"""
test_inc_zeroday — 0day 检测 / 沙箱联动单元测试(离线)

使用 inc_mock_servers 模拟 CAPE/Cuckoo 沙箱 API, 验证 sandbox_connector 提交/状态/报告/等待。
"""
import asyncio

from zeroday_detect.sandbox_connector import SandboxConnector
from tests.inc_mock_servers import MockExternalServers
from tests.inc_testcases import SAMBOX_REPORT


def _run(coro):
    return asyncio.run(coro)


def _make(server):
    """用 mock CAPE URL 构造沙箱连接器(局部实例, 不动全局单例)。"""
    from config import settings
    settings.sandbox_enabled = True
    settings.sandbox_api_url = server.cape_url
    settings.sandbox_api_key = ""
    return SandboxConnector()


def test_submit_file_returns_task_id():
    """submit_file 提交到 mock CAPE 并返回 task_id。"""
    async def scenario():
        m = await MockExternalServers().start()
        try:
            sb = _make(m)
            tid = await sb.submit_file(b"MZ...", filename="malware.exe")
            assert tid and tid.startswith("task-mock-")
            return tid
        finally:
            await m.stop()
    assert _run(scenario())


def test_submit_url_returns_task_id():
    """submit_url 提交并返回 task_id。"""
    async def scenario():
        m = await MockExternalServers().start()
        try:
            sb = _make(m)
            tid = await sb.submit_url("http://5.6.7.8/evil")
            assert tid and tid.startswith("task-mock-")
            return tid
        finally:
            await m.stop()
    assert _run(scenario())


def test_get_status_reported():
    """get_task_status 返回 reported。"""
    async def scenario():
        m = await MockExternalServers().start()
        try:
            sb = _make(m)
            status = await sb.get_task_status("task-1")
            assert status is not None and status.get("status") == "reported"
        finally:
            await m.stop()
    _run(scenario())


def test_get_report_parses():
    """get_report 解析 mock 报告(含 score/网络行为)。"""
    async def scenario():
        m = await MockExternalServers().start()
        try:
            sb = _make(m)
            report = await sb.get_report("task-1")
            assert report is not None
            assert report.get("info", {}).get("score") == 8.0
            assert report.get("network", {}).get("hosts")
        finally:
            await m.stop()
    _run(scenario())


def test_wait_for_completion_returns_report():
    """wait_for_completion 轮询(报告 status=reported 后返回报告)。"""
    async def scenario():
        m = await MockExternalServers().start()
        try:
            sb = _make(m)
            # mock 立即返回 reported, 应拿到报告
            report = await sb.wait_for_completion("task-1", poll_interval=1)
            assert report is not None
        finally:
            await m.stop()
    _run(scenario())


def test_status_disabled_returns_none():
    """沙箱未启用时 submit 返回 None。"""
    from config import settings
    settings.sandbox_enabled = False
    sb = SandboxConnector()
    async def scenario():
        assert await sb.submit_file(b"x") is None
    _run(scenario())
