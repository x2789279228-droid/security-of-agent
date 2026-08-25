"""
inc_mock_servers — 五项能力外部数据源的轻量 aiohttp mock 服务器(离线验证用)

提供:
  - CAPE/Cuckoo 沙箱 API (sandbox_connector):  /tasks/create/file|url, /tasks/view/{id}, /tasks/report/{id}
  - TAXII 2.1 objects (stix_taxii):            /collections/{coll}/objects/
  - MISP REST (stix_taxii):                    /attributes/restSearch

用途: 使 NDR/EDR 之外依赖外部服务的四项能力可在无真实数据源下被单元测试。
用法(测试中):
    from tests.inc_mock_servers import MockExternalServers
    m = await MockExternalServers.start()
    try:
        # 用 m.cape_url / m.taxii_url / m.misp_url 指向连接
    finally:
        await m.stop()
"""
import json

from aiohttp import web

__all__ = ["MockExternalServers"]


class MockExternalServers:
    """起一个 aiohttp web server, 模拟 CAPE/TAXII/MISP 端点。"""

    def __init__(self, port: int = 0):
        self._port = port
        self._runner = None
        self.host = None
        self.cape_url = None
        self.taxii_url = None
        self.misp_url = None
        # 记录被访问次数(供断言)
        self.cape_submits = 0
        self.cape_views = 0
        self.cape_reports = 0
        self.taxii_objects = 0
        self.misp_searches = 0

    # ── handlers ──

    async def _cape_create(self, request):
        self.cape_submits += 1
        data = await request.post()
        fn = ""
        try:
            fn = data.get("file", None) and getattr(data["file"], "filename", "") or ""
        except Exception:
            pass
        tid = f"task-mock-{self.cape_submits}"
        body = {"task_id": tid, "task_ids": [tid], "filename": fn}
        return web.json_response(body)

    async def _cape_view(self, request):
        self.cape_views += 1
        return web.json_response({"task_id": request.match_info["task_id"],
                                  "status": "reported"})

    async def _cape_report(self, request):
        self.cape_reports += 1
        return web.json_response({
            "task_id": request.match_info["task_id"],
            "info": {"score": 8.0},
            "signatures": [{"name": "network:http_request", "description": "HTTP 请求"}],
            "network": {"hosts": [{"ip": "1.2.3.4", "hostname": "evil.example.com"}]},
            "behavior": {"summary": {"files": ["malware.exe"]}},
        })

    async def _taxii_objects(self, request):
        self.taxii_objects += 1
        return web.json_response({"objects": [
            {"type": "indicator", "id": "indicator--1",
             "name": "malicious ip", "pattern": "[ipv4-addr:value = '5.6.7.8' or "
             "domain-name:value = 'evil.com']"},
        ]})

    async def _misp_restsearch(self, request):
        self.misp_searches += 1
        return web.json_response({"response": [
            {"Attribute": {"type": "ip-src", "value": "5.6.7.8", "category": "Network activity",
                           "to_ids": True}},
            {"Attribute": {"type": "domain", "value": "evil.com", "category": "Network activity"}},
        ]})

    # ── 生命周期 ──

    async def start(self):
        app = web.Application()
        app.router.add_post("/tasks/create/file", self._cape_create)
        app.router.add_post("/tasks/create/url", self._cape_create)
        app.router.add_get("/tasks/view/{task_id}", self._cape_view)
        app.router.add_get("/tasks/report/{task_id}", self._cape_report)
        app.router.add_get("/collections/{collection}/objects/", self._taxii_objects)
        app.router.add_post("/attributes/restSearch", self._misp_restsearch)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self._port)
        await site.start()
        base = f"http://{site._server.sockets[0].getsockname()}"
        # TCPSite 无直接地址; 从 runner 的 sockets 解析
        sock = self._runner.addresses[0] if hasattr(self._runner, "addresses") else None
        host, port = sock[:2] if sock else ("127.0.0.1", self._port)
        base = f"http://{host}:{port}"
        self.host, self.port = host, port
        self.cape_url = base
        self.taxii_url = base
        self.misp_url = base
        return self

    async def stop(self):
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None


async def start_mock() -> MockExternalServers:
    return await MockExternalServers().start()
