"""
temporal.client — Temporal client 封装

lazy 连接 Temporal, 提供 start_audit_workflow 供触发边界调用(替换 asyncio.create_task 兜底)。
若 Temporal 未启用/连接失败, 由调用方回退原有 async 编排。
"""
import logging
from typing import Any, Dict, Optional

from config import settings

logger = logging.getLogger(__name__)

_client = None
_client_lock = None  # 惰性 asyncio.Lock


async def get_client():
    """惰性构造并缓存 temporalio Client。未启用/失败返回 None(触发方降级)。"""
    global _client, _client_lock
    if not settings.temporal_enabled or not settings.temporal_host:
        return None
    if _client is not None:
        return _client
    if _client_lock is None:
        import asyncio
        _client_lock = asyncio.Lock()
    async with _client_lock:
        if _client is not None:
            return _client
        try:
            from temporalio.client import Client
            c = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
            _client = c
            logger.info(f"[Temporal] connected {settings.temporal_host} ns={settings.temporal_namespace} q={settings.temporal_task_queue}")
            return c
        except Exception as e:
            logger.warning(f"[Temporal] connect failed (fallback async): {e}")
            _client = None
            return None


async def start_audit_workflow(
    *,
    session_id: str,
    event_id: int,
    log_data: dict,
    anomaly_score: float,
    anomaly_reasons: list,
    max_rounds: int = 3,
) -> bool:
    """启动 4 层 Agent 编排 Workflow。成功返回 True; 不可用/失败返回 False(触发方回退 async)。

    同一 event 唯一 workflow id(audit-{event_id}), 避免重复编排。
    """
    client = await get_client()
    if client is None:
        return False
    try:
        from temporal.workflows import AuditWorkflowInput
        inp = AuditWorkflowInput(
            session_id=session_id,
            event_id=event_id,
            log_data=log_data,
            anomaly_score=float(anomaly_score or 0.0),
            anomaly_reasons=list(anomaly_reasons or []),
            max_rounds=int(max_rounds or 3),
        )
        await client.start_workflow(
            "AuditPipelineWorkflow",
            args=[inp],
            id=f"audit-{event_id}",
            task_queue=settings.temporal_task_queue,
        )
        logger.info(f"[Temporal] started workflow audit-{event_id} (rounds<={max_rounds})")
        return True
    except Exception as e:
        logger.warning(f"[Temporal] start_workflow failed (fallback async): {e}")
        return False
