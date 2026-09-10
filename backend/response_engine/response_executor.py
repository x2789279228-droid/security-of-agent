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

_SNAPSHOT_BEFORE = frozenset({"isolate_host", "kill_process", "quarantine_file"})


def _observe_duration(action_name: str, duration_ms: float) -> None:
    """动作耗时 → Prometheus 直方图（秒）。失败仅记日志，不影响执行。"""
    try:
        from metrics import observe_response_duration
        observe_response_duration(action_name, duration_ms / 1000.0)
    except Exception as e:
        logger.debug(f"metrics observe_response_duration failed: {e}")


def _maybe_prepend_snapshot(actions: list[dict], threat_info: Optional[dict]) -> list[dict]:
    names = [a.get("name") for a in actions]
    if "forensic_snapshot" in names:
        return actions
    if not any(n in _SNAPSHOT_BEFORE for n in names):
        return actions
    if any((a.get("params") or {}).get("skip_snapshot") for a in actions):
        return actions
    host_ip = ""
    pid = None
    if threat_info:
        host_ip = threat_info.get("host_ip") or threat_info.get("src_ip") or ""
        pid = threat_info.get("process_id") or threat_info.get("pid")
    for a in actions:
        p = a.get("params") or {}
        host_ip = p.get("host_ip") or p.get("src_ip") or host_ip
        if p.get("pid") is not None:
            pid = p.get("pid")
    snap = {"name": "forensic_snapshot", "params": {"host_ip": host_ip, "reason": "pre-containment snapshot"}}
    if pid not in (None, ""):
        snap["params"]["pid"] = pid
    return [snap] + actions


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
    """回滚令牌存储（内存+Redis双写）

    内存为主、Redis 为持久化兜底：进程重启后内存丢失，
    仍可通过 Redis 中的记录回滚已执行的动作（TTL 内有效）。
    Redis 写入失败只降级为纯内存模式，不影响动作执行。
    """

    # Redis key 前缀与 TTL（7 天）：超过 TTL 的回滚记录自动过期
    REDIS_KEY_PREFIX = "rollback:"
    ROLLED_PREFIX = "rollback:done:"
    REDIS_TTL_SEC = 7 * 24 * 3600

    def __init__(self):
        self._store: dict[str, list[dict]] = {}  # token → [action_records]
        self._rolled: set[str] = set()           # 已回滚 token（幂等标记）
        self._redis = None

    def set_redis(self, redis_client):
        self._redis = redis_client

    async def record(self, token: str, action_records: list[dict]):
        self._store[token] = action_records
        if self._redis is not None:
            try:
                await self._redis.set(
                    f"{self.REDIS_KEY_PREFIX}{token}",
                    json.dumps(action_records, ensure_ascii=False, default=str),
                    ex=self.REDIS_TTL_SEC,
                )
            except Exception as e:
                logger.warning(f"RollbackStore: failed to persist token to Redis: {e}")
        logger.info(f"RollbackStore: recorded {len(action_records)} actions under token {token[:16]}...")

    async def get(self, token: str) -> Optional[list[dict]]:
        records = self._store.get(token)
        if records:
            return records
        # 内存未命中（如进程重启后）→ 从 Redis 读取并回填
        if self._redis is not None:
            try:
                raw = await self._redis.get(f"{self.REDIS_KEY_PREFIX}{token}")
                if raw:
                    records = json.loads(raw)
                    self._store[token] = records
                    return records
            except Exception as e:
                logger.warning(f"RollbackStore: failed to read token from Redis: {e}")
        return None

    async def remove(self, token: str):
        self._store.pop(token, None)
        if self._redis is not None:
            try:
                await self._redis.delete(f"{self.REDIS_KEY_PREFIX}{token}")
            except Exception as e:
                logger.warning(f"RollbackStore: failed to delete token from Redis: {e}")

    async def mark_rolled(self, token: str):
        """标记该批次已回滚（幂等）。内存为主，Redis 持久化（TTL 与回滚记录一致 7 天）。

        进程重启后内存丢失，仍可从 Redis 判断"已回滚过"，避免重复删除规则。
        """
        self._rolled.add(token)
        if self._redis is not None:
            try:
                await self._redis.set(f"{self.ROLLED_PREFIX}{token}", "1", ex=self.REDIS_TTL_SEC)
            except Exception as e:
                logger.warning(f"RollbackStore: failed to persist rolled flag to Redis: {e}")

    async def is_rolled(self, token: str) -> bool:
        """该批次是否已回滚过（内存优先，Redis 兜底）"""
        if token in self._rolled:
            return True
        if self._redis is not None:
            try:
                if await self._redis.get(f"{self.ROLLED_PREFIX}{token}"):
                    self._rolled.add(token)
                    return True
            except Exception as e:
                logger.warning(f"RollbackStore: failed to read rolled flag from Redis: {e}")
        return False


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

        actions = _maybe_prepend_snapshot(list(actions), threat_info)
        batch_result.total = len(actions)

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
        await rollback_store.record(batch_token, action_records)

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
            elif name in ("kill_process", "quarantine_file", "clean_persistence", "forensic_snapshot"):
                if "host_ip" not in params:
                    params["host_ip"] = threat_info.get("host_ip") or threat_info.get("src_ip") or ""
                if name == "kill_process":
                    if "pid" not in params and threat_info.get("process_id"):
                        params["pid"] = threat_info["process_id"]
                    if "sha256" not in params and threat_info.get("image_hash"):
                        params["sha256"] = threat_info["image_hash"]
                if name == "quarantine_file" and "path" not in params and threat_info.get("file_path"):
                    params["path"] = threat_info["file_path"]
            elif name == "disable_account":
                if "account" not in params and threat_info.get("user_name"):
                    params["account"] = threat_info["user_name"]
            elif name == "dns_sinkhole":
                if "domain" not in params and threat_info.get("domain"):
                    params["domain"] = threat_info["domain"]
            elif name == "recall_email":
                if "internet_message_id" not in params and (
                    threat_info.get("internet_message_id") or threat_info.get("message_id")
                ):
                    params["internet_message_id"] = (
                        threat_info.get("internet_message_id") or threat_info.get("message_id")
                    )

            if "reason" not in params:
                params["reason"] = (
                    f"威胁类型={threat_info.get('threat_type','?')} "
                    f"置信度={threat_info.get('confidence',0):.2f}"
                )

        t_start = time.time()
        try:
            result = await response_registry.execute(name, **params)
            duration = (time.time() - t_start) * 1000
            _observe_duration(name, duration)
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
            _observe_duration(name, duration)
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
        records = await rollback_store.get(batch_token)
        if not records:
            return BatchActionResult(
                total=0,
                succeeded=0,
                failed=0,
                error=f"Rollback token not found: {batch_token}",
            )

        # 幂等短路: 该批次已回滚过（本进程或重启后经 Redis 恢复）
        # → 不再逐条删除，直接返回全成功 + idempotent 标记
        if await rollback_store.is_rolled(batch_token):
            logger.info(f"Rollback token {batch_token[:16]}... already rolled back (idempotent replay)")
            return BatchActionResult(
                total=len(records),
                succeeded=len(records),
                failed=0,
                results=[
                    ActionResult(
                        action_name=f"rollback_{r.get('action', '?')}",
                        success=True,
                        idempotent=True,
                        result={"idempotent": True, "message": "already rolled back"},
                    )
                    for r in reversed(records)
                ],
                batch_rollback_token=batch_token,
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
                inner = result.get("result", result) if isinstance(result, dict) else {}
                ok = bool(result.get("success", False)) if isinstance(result, dict) else False
                idem = bool(inner.get("idempotent", False)) if isinstance(inner, dict) else False
                # not_found / 幂等成功都不算失败：重复回滚是合法操作
                if isinstance(inner, dict) and inner.get("status") == "not_found":
                    ok = True
                    idem = True
                if idem and not ok:
                    ok = True
                ar = ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=ok,
                    result=inner if isinstance(inner, dict) else {},
                    idempotent=idem,
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

        # 已执行的回滚批次打上幂等标记（not_found/幂等成功也标记 —
        # 它们已按成功计数；真实错误不标记，允许调用方重试）
        if failed == 0:
            await rollback_store.mark_rolled(batch_token)

        return BatchActionResult(
            total=len(records),
            succeeded=succeeded,
            failed=failed,
            results=results,
            batch_rollback_token=batch_token,
        )

    async def get_rollback_status(self, batch_token: str) -> dict:
        """查询回滚状态"""
        records = await rollback_store.get(batch_token)
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
