"""
响应执行器 (Response Executor)

职责:
  1. 接收策略匹配后的动作列表
  2. 按优先级顺序执行动作
  3. 记录每个动作的结果和回滚令牌
  4. 支持批量执行和部分失败处理
  5. 支持通过回滚令牌撤销已执行的动作

执行流程:
  execute_actions(actions, threat_info)
      → 按优先级排序
      → 逐个执行（并行执行可并行动作）
      → 记录结果 + 回滚令牌
      → 返回 ActionResult

  rollback(rollback_token)
      → 根据令牌查找已执行的动作
      → 逆向逐个回滚
      → 返回回滚结果
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .response_registry import response_registry

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """单次动作执行结果"""
    action_name: str
    success: bool
    result: dict = field(default_factory=dict)
    error: str = ""
    rollback_token: str = ""
    duration_ms: float = 0.0
    idempotent: bool = False


@dataclass
class BatchActionResult:
    """批量执行结果"""
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[ActionResult] = field(default_factory=list)
    batch_rollback_token: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    error: str = ""

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000


class RollbackStore:
    """回滚令牌存储（内存+Redis双写）"""

    def __init__(self):
        self._store: dict[str, list[dict]] = {}  # token → [action_records]
        self._redis = None

    def set_redis(self, redis_client):
        self._redis = redis_client

    def record(self, token: str, action_records: list[dict]):
        self._store[token] = action_records
        logger.info(f"RollbackStore: recorded {len(action_records)} actions under token {token[:16]}...")

    def get(self, token: str) -> Optional[list[dict]]:
        records = self._store.get(token)
        if records:
            return records
        # TODO: 从Redis读取
        return None

    def remove(self, token: str):
        self._store.pop(token, None)


rollback_store = RollbackStore()


class ResponseExecutor:
    """响应执行器"""

    def __init__(self):
        pass

    async def execute_actions(
        self,
        actions: list[dict],
        threat_info: Optional[dict] = None,
        parallel: bool = False,
    ) -> BatchActionResult:
        """
        执行一组响应动作

        Args:
            actions: [{"name": "block_ip", "params": {...}}, ...]
            threat_info: 威胁上下文（用于日志）
            parallel: 是否并行执行（可并行动作之间）

        Returns:
            BatchActionResult
        """
        batch_result = BatchActionResult(
            total=len(actions),
            start_time=time.time(),
        )

        if not actions:
            batch_result.end_time = time.time()
            return batch_result

        # 生成批次回滚令牌（使用 crypto 随机数）
        import secrets
        batch_token = f"batch_{secrets.token_hex(16)}"
        batch_result.batch_rollback_token = batch_token
        action_records = []

        if parallel:
            # 并行执行
            tasks = [self._execute_one(action, threat_info) for action in actions]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    batch_result.results.append(ActionResult(
                        action_name=actions[i].get("name", "?"),
                        success=False,
                        error=str(r),
                    ))
                    batch_result.failed += 1
                else:
                    batch_result.results.append(r)
                    if r.success:
                        batch_result.succeeded += 1
                    else:
                        batch_result.failed += 1
                    action_records.append({
                        "action": r.action_name,
                        "success": r.success,
                        "rollback_token": r.rollback_token,
                        "params": actions[i].get("params", {}),
                    })
        else:
            # 串行执行（按优先级）
            for action in actions:
                result = await self._execute_one(action, threat_info)
                batch_result.results.append(result)
                if result.success:
                    batch_result.succeeded += 1
                else:
                    batch_result.failed += 1
                action_records.append({
                    "action": result.action_name,
                    "success": result.success,
                    "rollback_token": result.rollback_token,
                    "params": action.get("params", {}),
                })

        batch_result.end_time = time.time()

        # 存储回滚记录
        rollback_store.record(batch_token, action_records)

        logger.info(
            f"Batch execute: {batch_result.succeeded}/{batch_result.total} actions OK "
            f"in {batch_result.duration_ms:.0f}ms, "
            f"rollback_token={batch_token[:16]}..."
        )

        return batch_result

    async def _execute_one(self, action: dict, threat_info: Optional[dict] = None) -> ActionResult:
        """执行单个动作"""
        name = action.get("name", "")
        params = dict(action.get("params", {}))

        # 注入威胁上下文参数（仅注入该动作接受的参数）
        if threat_info:
            action_def = response_registry.get_action(name)
            accepted_params = list((action_def.params_schema if action_def else {}).keys()) if action_def else []

            # 根据动作类型注入合适的IP参数
            if name in ("block_ip", "rate_limit", "unblock_ip", "remove_rate_limit"):
                if "src_ip" not in params and threat_info.get("src_ip"):
                    params["src_ip"] = threat_info["src_ip"]
            elif name in ("isolate_host", "restore_host"):
                if "host_ip" not in params and threat_info.get("src_ip"):
                    params["host_ip"] = threat_info["src_ip"]
            elif name == "kill_session":
                if "session_id" not in params and threat_info.get("session_id"):
                    params["session_id"] = threat_info["session_id"]

            if "reason" not in params:
                params["reason"] = (
                    f"威胁类型={threat_info.get('threat_type','?')} "
                    f"置信度={threat_info.get('confidence',0):.2f}"
                )

        t_start = time.time()
        try:
            result = await response_registry.execute(name, **params)
            duration = (time.time() - t_start) * 1000
            return ActionResult(
                action_name=name,
                success=result.get("success", False),
                result=result.get("result", result),
                rollback_token=result.get("rollback_token", ""),
                duration_ms=round(duration, 1),
                idempotent=result.get("idempotent", False),
            )
        except Exception as e:
            duration = (time.time() - t_start) * 1000
            logger.error(f"Execute action {name} failed: {e}")
            return ActionResult(
                action_name=name,
                success=False,
                error=str(e),
                duration_ms=round(duration, 1),
            )

    async def rollback_batch(self, batch_token: str) -> BatchActionResult:
        """
        回滚一批动作（逆向执行）

        Args:
            batch_token: 批次回滚令牌

        Returns:
            BatchActionResult
        """
        records = rollback_store.get(batch_token)
        if not records:
            return BatchActionResult(
                total=0,
                succeeded=0,
                failed=0,
                error=f"Rollback token not found: {batch_token}",
            )

        logger.info(f"Rolling back {len(records)} actions from token {batch_token[:16]}...")

        # 逆向回滚（最后执行的先回滚）
        results = []
        succeeded = 0
        failed = 0

        for record in reversed(records):
            action_name = record["action"]
            params = record["params"]

            try:
                result = await response_registry.rollback(action_name, **params)
                ar = ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=result.get("success", False),
                    result=result.get("result", result),
                )
                results.append(ar)
                if ar.success:
                    succeeded += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                results.append(ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=False,
                    error=str(e),
                ))

        logger.info(f"Rollback complete: {succeeded}/{len(records)} rollbacks OK")

        return BatchActionResult(
            total=len(records),
            succeeded=succeeded,
            failed=failed,
            results=results,
            batch_rollback_token=batch_token,
        )

    async def get_rollback_status(self, batch_token: str) -> dict:
        """查询回滚状态"""
        records = rollback_store.get(batch_token)
        if not records:
            return {"found": False}
        return {
            "found": True,
            "action_count": len(records),
            "actions": [
                {"action": r["action"], "success": r["success"]}
                for r in records
            ],
        }


response_executor = ResponseExecutor()
