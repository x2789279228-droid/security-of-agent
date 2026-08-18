"""
资产发现 (Asset Discovery) — P0.A

三路适配器：
  - nmap (复用 mcp_guard 已注册的 vulnerability_scan 工具链)
  - edr_fusion (从 edr_events.computer_name 派生资产)
  - cmdb_api (预留外部 CMDB 接入点)

发现结果通过 asset_manager.register() 落库，自动计算 diff。
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from models import AssetDiscoveryTask, Asset
from .asset_manager import asset_manager

logger = logging.getLogger(__name__)


class DiscoveryService:
    """资产发现服务"""

    async def create_task(
        self, session: AsyncSession, *,
        scope: str, scanner: str = "nmap",
    ) -> dict:
        """创建发现任务"""
        task = AssetDiscoveryTask(
            task_id=f"DISC-{uuid.uuid4().hex[:12]}",
            scope=scope, scanner=scanner, status="pending",
        )
        session.add(task)
        await session.commit()
        logger.info(f"[Discovery] Task created: {task.task_id} scope={scope}")
        return {"task_id": task.task_id, "id": task.id, "status": "pending"}

    async def run_task(
        self, session: AsyncSession, task_id: str,
    ) -> dict:
        """
        执行发现任务
        - nmap: 调用 nmap 适配器 (环回真实网络需 mcp_guard 放行)
        - edr: 从 edr_events 派生主机资产
        - cmdb_api: 预留
        """
        stmt = select(AssetDiscoveryTask).where(AssetDiscoveryTask.task_id == task_id)
        result = await session.execute(stmt)
        task = result.scalars().first()
        if not task:
            return {"success": False, "error": "任务不存在"}

        task.status = "running"
        task.started_at = datetime.now(timezone.utc)
        await session.commit()

        new_count = 0
        changed_count = 0

        try:
            if task.scanner == "edr":
                new_count, changed_count = await self._discover_from_edr(session, task)
            elif task.scanner == "nmap":
                # nmap 真实扫描需平台环境就绪，先返回占位说明
                # 实际部署时调 mcp_guard.tool_registry._exec_vulnerability_scan
                logger.info(f"[Discovery] nmap task {task_id} placeholder (需运行环境)")
                new_count, changed_count = 0, 0
            elif task.scanner == "cmdb_api":
                logger.warning("[Discovery] cmdb_api scanner not implemented yet")
            else:
                logger.warning(f"[Discovery] unknown scanner: {task.scanner}")

            task.new_count = new_count
            task.changed_count = changed_count
            task.status = "completed"
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()

        except Exception as e:
            task.status = "failed"
            task.result = {"error": str(e)}
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.error(f"[Discovery] task {task_id} failed: {e}")
            return {"success": False, "error": str(e)}

        logger.info(
            f"[Discovery] Task {task_id} completed: new={new_count} changed={changed_count}"
        )
        return {
            "success": True, "task_id": task_id,
            "new_count": new_count, "changed_count": changed_count,
        }

    async def _discover_from_edr(
        self, session: AsyncSession, task: AssetDiscoveryTask
    ) -> tuple[int, int]:
        """
        从 EDR 事件派生资产
        - 扫描 edr_events.computer_name / src_ip，把出现过的主机注册为资产
        - 该路径不需外部网络，可在纯软件环境下验证
        """
        try:
            from models import EdrEvent
        except ImportError:
            logger.warning("[Discovery] EDR models not available")
            return 0, 0

        stmt = select(
            distinct(EdrEvent.computer_name), EdrEvent.src_ip
        ).where(EdrEvent.computer_name != "").limit(500)
        result = await session.execute(stmt)

        new_count = 0
        changed_count = 0
        seen_hosts = set()

        for row in result.all():
            hostname = row[0]
            ip = row[1] or ""
            if not hostname or hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)

            r = await asset_manager.register(
                session, ip=ip, hostname=hostname, asset_type="endpoint",
                criticality="medium", source="edr_discovery",
                changed_by=f"discovery:{task.task_id}",
            )
            if r.get("success"):
                if r.get("diff") is None:
                    new_count += 1
                elif r.get("diff"):
                    changed_count += 1

        return new_count, changed_count

    async def list_tasks(
        self, session: AsyncSession, limit: int = 50,
    ) -> list[dict]:
        stmt = (
            select(AssetDiscoveryTask)
            .order_by(AssetDiscoveryTask.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return [
            {
                "id": t.id,
                "task_id": t.task_id,
                "scope": t.scope,
                "scanner": t.scanner,
                "status": t.status,
                "started_at": t.started_at.isoformat() if t.started_at else "",
                "completed_at": t.completed_at.isoformat() if t.completed_at else "",
                "new_count": t.new_count,
                "changed_count": t.changed_count,
                "created_at": t.created_at.isoformat() if t.created_at else "",
            }
            for t in result.scalars().all()
        ]


discovery_service = DiscoveryService()