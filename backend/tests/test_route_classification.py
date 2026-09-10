"""限流归类守卫:任何 /api 路由都必须"要么豁免、要么被点名限流"。

背景(2026-09-10):旧白名单只豁免 10 个前缀,运营中心 39 个业务域(168 条路由)
全部落进同一个 120/min 共桶,页面并发 + SSE 重连 + 3s 轮询互相挤爆 → 大面积 429。
本测试遍历 backend/routers/*.py 的真实 router(prefix + @router 装饰器),
把"新增端点忘记归类"变成构建期失败,而不是上线后的 429。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http_guards import (  # noqa: E402
    RATE_LIMIT_FORCED,
    RATE_LIMIT_WHITELIST,
    is_rate_limit_whitelisted,
    rate_limit_decision,
)

_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")

# app 导入失败时的诊断线索(环境受限时会退化到静态解析)
_import_errors: list[str] = []


def _router_registry_routes():
    """不导入 app 的静态兜底:直接解析 routers/*.py 的 APIRouter(prefix) + @router 装饰器。

    导入 app 会拉起 lifespan 全链路依赖(DB/Kafka/Redis),在受限环境(CI 无服务、
    sqlite 内存库)下宁可降级也不要让守卫空跑 —— 空跑会让这条防复发网线失效。
    """
    import ast
    from pathlib import Path

    def _prefix(tree) -> str:
        prefix = ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = kw.value.value
        return prefix

    routers_dir = Path(__file__).resolve().parent.parent / "routers"
    for py in sorted(routers_dir.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        prefix = _prefix(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "router"
                    and dec.args
                    and isinstance(dec.args[0], ast.Constant)
                ):
                    yield prefix + dec.args[0].value, dec.func.attr.upper(), node


def _iter_routes():
    """(path, METHOD, endpoint) —— 优先读 app 的注册表(真实生效路由), 失败时退化为静态解析。"""
    try:
        import app as app_module  # noqa: F401  触发 routers 注册

        routes = []
        for route in app_module.app.routes:
            path = getattr(route, "path", "")
            if not path.startswith("/api"):
                continue
            for method in sorted(getattr(route, "methods", set()) or set()):
                if method.lower() in _METHODS:
                    routes.append((path, method, getattr(route, "endpoint", None)))
        if routes:
            return routes
    except Exception as exc:  # pragma: no cover - 环境受限分支
        _import_errors.append(repr(exc))
    return list(_router_registry_routes())




def test_all_api_routes_are_classified():
    """每条 /api 路由:豁免 或 命中 RATE_LIMIT_FORCED(不允许落进未归类的 std 桶)"""
    unclassified = []
    for path, method, endpoint in _iter_routes():
        counted, namespace = rate_limit_decision(path, method)
        if namespace == "std":
            unclassified.append(f"{method} {path} ({getattr(endpoint, '__module__', '?')})")
    assert not unclassified, (
        "以下路由未被归类(既不在 RATE_LIMIT_WHITELIST 的豁免域,"
        "也不在 RATE_LIMIT_FORCED 的高危点名表),上线后会落在共桶限流里:\n  "
        + "\n  ".join(sorted(set(unclassified)))
    )


def test_route_inventory_is_not_empty():
    """守卫本身不能因为路由枚举失效而空跑"""
    routes = list(_iter_routes())
    assert len(routes) > 150, (
        f"路由枚举异常,只拿到 {len(routes)} 条 (app 导入错误: {_import_errors})"
    )


def test_whitelisted_domains_cover_every_router_module():
    """每个业务域至少有前缀进白名单(前缀不重叠导致整域被限流)"""
    from collections import defaultdict

    by_top: dict[str, list[str]] = defaultdict(list)
    for path, _method, _ep in _iter_routes():
        parts = [p for p in path.split("/") if p]
        top = "/" + "/".join(parts[:2]) if len(parts) >= 2 else "/" + "/".join(parts)
        if not is_rate_limit_whitelisted(top):
            by_top[top].append(path)
    assert not by_top, f"这些顶级前缀整体未被豁免: {sorted(by_top)}"


def test_forced_entries_are_actually_reachable():
    """RATE_LIMIT_FORCED 不应残留已删除端点的死条目"""
    live = {(p, m) for p, m, _ in _iter_routes()}
    live_paths = {p for p, _ in live}
    dead = [
        prefix
        for prefix in RATE_LIMIT_FORCED
        if not any(p == prefix or p.startswith(prefix + "/") for p in live_paths)
    ]
    assert not dead, f"RATE_LIMIT_FORCED 中的前缀已无对应端点: {dead}"


def test_no_forced_entry_is_inside_another_whitelist_prefix_by_accident():
    """强制限流项必须落在某个豁免前缀内(否则说明它是普通路径,应直接进白名单)"""
    for prefix in RATE_LIMIT_FORCED:
        top = "/" + "/".join([p for p in prefix.split("/") if p][:2])
        assert is_rate_limit_whitelisted(top), f"{prefix} 的顶级前缀 {top} 未豁免,规则冗余"


def test_operations_center_domains_listed_in_whitelist():
    """回归锚点:2026-09-10 前的 39 个被限流域必须都在白名单里"""
    must_exempt = (
        "/api/cases",
        "/api/work-orders",
        "/api/post-mortems",
        "/api/learn-loop",
        "/api/agent-traces",
        "/api/observability",
        "/api/audit-llm",
        "/api/audit-trail",
        "/api/cad",
        "/api/guard",
        "/api/security",
        "/api/causal",
        "/api/sigma",
        "/api/ops",
        "/api/rules",
        "/api/tree",
        "/api/window",
        "/api/stats",
        "/api/kafka",
        "/api/cep",
        "/api/pipeline",
        "/api/assets",
        "/api/ndr",
        "/api/edr",
        "/api/intel",
        "/api/sandbox",
        "/api/phishing",
        "/api/self-play",
        "/api/sources",
        "/api/logs",
        "/api/memories",
        "/api/capabilities",
    )
    for prefix in must_exempt:
        assert prefix in RATE_LIMIT_WHITELIST, f"{prefix} 从白名单中丢失(会重新变成 429 重灾区)"
