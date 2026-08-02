"""
TTL 自动解封管理器 (TTL Manager)

基于 Redis 的持久化 TTL 管理，替代原有 asyncio.create_task 的内存方式。
服务重启后自动恢复未过期的解封任务。

存储结构:
  - soc:ttl:{rule_id}  → JSON(params)   EX ttl_seconds   单条规则数据
  - soc:ttl:index       → Sorted Set    score=到期时间戳  全量索引

后台任务:
  - 每 scan_interval 秒扫描 soc:ttl:index
  - 对 score <= now 的条目执行回滚回调
  - 回滚成功后删除 Redis 条目

调用方式:
    from response_engine.ttl_manager import ttl_manager
    ttl_manager.set_redis(redis_client)
    ttl_manager.set_rollback_callback(rollback_fn)
    await ttl_manager.register("FW-RULE-12345", "block_ip", {"src_ip": "1.2.3.4"}, 3600)
    await ttl_manager.start_scanner()   # 在 app startup 中调用
"""
import asyncio
import json
import logging
import time
from typing import Callable, Coroutine, Optional

logger = logging.getLogger(__name__)

_KEY_PREFIX = "soc:ttl:"
_INDEX_KEY = "soc:ttl:index"


class TtlManager:
    """TTL 自动解封管理器"""

    def __init__(self, scan_interval: int = 30):
        self._redis = None
        self._scan_interval = scan_interval
        self._rollback_fn: Optional[Callable[..., Coroutine]] = None
        self._scanner_task: Optional[asyncio.Task] = None
        self._running = False

    def set_redis(self, redis_client):
        """注入 Redis 客户端（aioredis / redis.asyncio）"""
        self._redis = redis_client
        logger.info("[TTL] Redis client set")

    def set_rollback_callback(self, fn: Callable[..., Coroutine]):
        """
        设置回滚回调函数

        签名: async def rollback(rule_id: str, action_name: str, params: dict) -> dict
        """
        self._rollback_fn = fn
        logger.info("[TTL] Rollback callback registered")

    async def register(
        self,
        rule_id: str,
        action_name: str,
        params: dict,
        ttl_seconds: int,
    ) -> dict:
        """
        注册一条 TTL 自动解封任务

        Args:
            rule_id: 规则唯一标识
            action_name: 原始动作名称 (block_ip / isolate_host)
            params: 动作参数（回滚时需要）
            ttl_seconds: 存活时间（秒），到期后自动回滚

        Returns:
            {"registered": bool, "rule_id": str, "expires_at": float}
        """
        if not self._redis:
            logger.warning("[TTL] Redis not available, TTL registration skipped")
            return {"registered": False, "rule_id": rule_id, "reason": "redis_unavailable"}

        if ttl_seconds <= 0:
            return {"registered": False, "rule_id": rule_id, "reason": "invalid_ttl"}

        expires_at = time.time() + ttl_seconds
        payload = json.dumps({
            "rule_id": rule_id,
            "action_name": action_name,
            "params": params,
            "registered_at": time.time(),
            "expires_at": expires_at,
        }, ensure_ascii=False)

        key = f"{_KEY_PREFIX}{rule_id}"
        pipe = self._redis.pipeline()
        pipe.set(key, payload, ex=ttl_seconds)
        pipe.zadd(_INDEX_KEY, {rule_id: expires_at})
        await pipe.execute()

        logger.info(
            f"[TTL] Registered: {rule_id} ({action_name}) "
            f"expires in {ttl_seconds}s at {expires_at:.0f}"
        )
        return {"registered": True, "rule_id": rule_id, "expires_at": expires_at}

    async def cancel(self, rule_id: str) -> bool:
        """取消一条 TTL 任务（手动回滚后调用）"""
        if not self._redis:
            return False
        key = f"{_KEY_PREFIX}{rule_id}"
        pipe = self._redis.pipeline()
        pipe.delete(key)
        pipe.zrem(_INDEX_KEY, rule_id)
        await pipe.execute()
        logger.info(f"[TTL] Cancelled: {rule_id}")
        return True

    async def get(self, rule_id: str) -> Optional[dict]:
        """查询一条 TTL 任务"""
        if not self._redis:
            return None
        key = f"{_KEY_PREFIX}{rule_id}"
        data = await self._redis.get(key)
        if data:
            return json.loads(data)
        return None

    async def list_active(self) -> list[dict]:
        """列出所有活跃的 TTL 任务"""
        if not self._redis:
            return []
        now = time.time()
        # 获取所有 score > now 的条目（未过期）
        entries = await self._redis.zrangebyscore(
            _INDEX_KEY, now, "+inf", withscores=True
        )
        result = []
        for rule_id, expires_at in entries:
            rid = rule_id.decode() if isinstance(rule_id, bytes) else rule_id
            data = await self.get(rid)
            if data:
                data["remaining_seconds"] = max(0, expires_at - now)
                result.append(data)
        return result

    async def start_scanner(self):
        """启动后台过期扫描任务"""
        if self._running:
            return
        self._running = True
        self._scanner_task = asyncio.create_task(self._scan_loop())
        logger.info(f"[TTL] Scanner started (interval={self._scan_interval}s)")

    async def stop_scanner(self):
        """停止后台扫描"""
        self._running = False
        if self._scanner_task:
            self._scanner_task.cancel()
            try:
                await self._scanner_task
            except asyncio.CancelledError:
                pass
            self._scanner_task = None
        logger.info("[TTL] Scanner stopped")

    async def _scan_loop(self):
        """后台扫描循环"""
        while self._running:
            try:
                await self._process_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[TTL] Scanner error: {e}")
            await asyncio.sleep(self._scan_interval)

    async def _process_expired(self):
        """处理已到期的 TTL 条目"""
        if not self._redis:
            return

        now = time.time()
        # 获取 score <= now 的条目（已过期）
        expired = await self._redis.zrangebyscore(_INDEX_KEY, "-inf", now)

        if not expired:
            return

        for rule_id_raw in expired:
            rule_id = rule_id_raw.decode() if isinstance(rule_id_raw, bytes) else rule_id_raw
            key = f"{_KEY_PREFIX}{rule_id}"

            # 读取参数（key 可能已被 Redis EX 自动删除）
            data = await self._redis.get(key)
            if data:
                payload = json.loads(data)
                action_name = payload.get("action_name", "")
                params = payload.get("params", {})
                logger.info(f"[TTL] Expiring: {rule_id} ({action_name})")

                # 执行回滚
                if self._rollback_fn:
                    try:
                        result = await self._rollback_fn(rule_id, action_name, params)
                        logger.info(
                            f"[TTL] Auto-rollback {rule_id}: "
                            f"{'OK' if result.get('success') else 'FAILED'}"
                        )
                    except Exception as e:
                        logger.error(f"[TTL] Auto-rollback {rule_id} error: {e}")
                else:
                    logger.warning(f"[TTL] No rollback callback, cannot auto-rollback {rule_id}")

            # 清理索引（无论回滚是否成功）
            await self._redis.zrem(_INDEX_KEY, rule_id)
            await self._redis.delete(key)

    async def recover_on_startup(self):
        """
        服务重启后恢复: 扫描索引中未过期的条目，重新设置 Redis key 的 TTL

        场景: Redis key 因 EX 过期被删除，但 index 中还有记录
        """
        if not self._redis:
            return

        now = time.time()
        entries = await self._redis.zrangebyscore(
            _INDEX_KEY, now, "+inf", withscores=True
        )
        recovered = 0
        for rule_id_raw, expires_at in entries:
            rule_id = rule_id_raw.decode() if isinstance(rule_id_raw, bytes) else rule_id_raw
            key = f"{_KEY_PREFIX}{rule_id}"
            exists = await self._redis.exists(key)
            if not exists:
                # key 已丢失但 index 还在 → 立即触发回滚
                logger.warning(
                    f"[TTL] Recovery: {rule_id} key lost, triggering immediate rollback"
                )
                if self._rollback_fn:
                    try:
                        await self._rollback_fn(rule_id, "unknown", {})
                    except Exception as e:
                        logger.error(f"[TTL] Recovery rollback {rule_id} error: {e}")
                await self._redis.zrem(_INDEX_KEY, rule_id)
            else:
                recovered += 1

        if entries:
            logger.info(
                f"[TTL] Startup recovery: {recovered} active, "
                f"{len(entries) - recovered} recovered/rolled-back"
            )


ttl_manager = TtlManager()
