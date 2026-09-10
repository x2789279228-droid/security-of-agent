"""
Dry-run 预览 (Preview Mode)

用 contextvars.ContextVar 实现"当前协程"作用域的预览模式，
不是全局 execution_mode — 预览请求只影响本次调用链，
不改变进程级执行路由（execution_router.mode 保持 live 不动）。

用法:
    results = await preview_actions(ticket.actions, ticket.threat_info)

预览期间 response_registry._execution_mode() 返回 'dry_run'，
直连 ssh_firewall 的动作 (block_ip / isolate_host / dns_sinkhole)
只返回模拟结果，不建立 SSH、不写真实规则。
"""
import contextvars
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 预览模式标记（协程局部；默认 False = 正常执行）
preview_mode = contextvars.ContextVar("soc_preview", default=False)


async def preview_actions(actions: list, threat_info: Optional[dict] = None) -> list[dict]:
    """对动作列表做 dry-run 预览，返回逐动作的模拟结果。

    不做 SecurityGuard 审查、不写 ResponseLog/audit — 预览无副作用
    （唯一"副作用"是 registry 内 mock 分支的日志行）。
    """
    token = preview_mode.set(True)
    try:
        results: list[dict] = []
        from response_engine.response_registry import response_registry
        for a in actions or []:
            name = a.get("name")
            params = dict(a.get("params") or {})
            try:
                r = await response_registry.execute(name, **params)
                inner = r.get("result", r) if isinstance(r, dict) else {}
                results.append({
                    "name": name,
                    "success": True,
                    "preview": inner,
                    "would_execute": True,
                    "mode": "dry_run",
                })
            except Exception as e:
                logger.warning(f"[preview] {name} failed: {e}")
                results.append({"name": name, "success": False, "error": str(e)})
        return results
    finally:
        preview_mode.reset(token)
