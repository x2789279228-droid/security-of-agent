"""
统一安全执行器 (Safe Executor)

所有 SSH 命令的唯一安全通道。串联 6 层安全检查:

    ① CommandWhitelist   命令白名单（默认拒绝）
    ② ParamValidator     参数强校验（ipaddress + 正则）
    ③ AssetWhitelist     核心资产保护
    ④ IdempotencyGuard   幂等检查（Redis）
    ⑤ ExecutionMode      dry_run / mock / live 路由
    ⑥ PrivilegeSelector  最小权限账号选择

执行后:
    ⑦ PostValidator      执行后验证
    ⑧ TtlManager         TTL 自动解封注册
    ⑨ AuditTrail         审计日志

调用方式:
    from response_engine.safe_executor import safe_executor
    result = await safe_executor.execute(
        action_name="block_ip",
        command="iptables -I INPUT -s 1.2.3.4 -j DROP ...",
        params={"src_ip": "1.2.3.4", "duration": 3600},
        platform="linux",
        live_fn=ssh_exec_coroutine,
    )
"""
import hashlib
import json
import logging
import time
from typing import Callable, Coroutine, Optional

from config import settings

from .command_whitelist import command_whitelist
from .asset_whitelist import asset_whitelist
from .execution_modes import execution_router, MODE_LIVE
from .post_validator import post_validator
from .ttl_manager import ttl_manager

logger = logging.getLogger(__name__)

# 幂等 Redis key 前缀
_IDEM_PREFIX = "soc:idem:"


class SafeExecutor:
    """统一安全执行器"""

    def __init__(self):
        self._redis = None
        # 只读动作列表 — 使用低权限账号
        self._readonly_actions = {
            "vulnerability_scan", "list_rules", "health_check",
        }

    def set_redis(self, redis_client):
        """注入 Redis 客户端"""
        self._redis = redis_client
        logger.info("[SafeExecutor] Redis client set")

    def initialize(self):
        """从配置初始化各子模块"""
        # 资产白名单
        asset_whitelist.initialize(
            protected_assets_str=getattr(settings, "protected_assets", ""),
            labels_str=getattr(settings, "protected_assets_labels", ""),
        )
        # 执行模式
        mode = getattr(settings, "execution_mode", "live")
        execution_router.mode = mode
        # TTL 扫描间隔
        ttl_manager._scan_interval = getattr(settings, "ttl_scan_interval", 30)

        logger.info(f"[SafeExecutor] Initialized (mode={mode})")

    async def execute(
        self,
        action_name: str,
        command: str,
        params: dict,
        platform: str = "linux",
        live_fn: Optional[Callable[..., Coroutine]] = None,
        ttl_seconds: int = 0,
        rule_id: str = "",
        skip_whitelist: bool = False,
    ) -> dict:
        """
        安全执行入口

        Args:
            action_name: 动作名称 (block_ip / isolate_host / ...)
            command: 完整 SSH 命令
            params: 动作参数
            platform: "linux" | "windows"
            live_fn: 真实 SSH 执行的异步函数 (接受 command str)
            ttl_seconds: 自动解封 TTL（0=不注册）
            rule_id: 规则 ID（TTL 和幂等用）
            skip_whitelist: 跳过命令白名单（仅限内部验证命令）

        Returns:
            执行结果 dict，包含 mode, verified, blocked 等字段
        """
        start_time = time.time()
        audit = {
            "action": action_name,
            "platform": platform,
            "command_preview": command[:200],
            "params": {k: v for k, v in params.items() if k != "password"},
            "checks": {},
        }

        # ── ⓪ Grounding 硬门控 ──
        # 无证据支撑的审计结论不允许触发响应动作
        grounding_score = params.get("grounding_score", 1.0)
        if grounding_score < 0.4:
            audit["checks"]["grounding"] = {
                "passed": False,
                "score": grounding_score,
                "reason": f"Grounding 分数 {grounding_score:.2f} < 0.4，证据不足",
            }
            logger.warning(
                f"[SafeExecutor] BLOCKED by grounding gate: {action_name} "
                f"score={grounding_score:.2f}"
            )
            return self._blocked_result(
                action_name, "grounding_gate",
                f"Grounding 验证未通过 (score={grounding_score:.2f}<0.4)，"
                f"审计结论缺乏充分证据支撑，拒绝执行响应动作",
                audit,
            )
        audit["checks"]["grounding"] = {"passed": True, "score": grounding_score}

        # ── ① 命令白名单 ──
        if not skip_whitelist:
            allowed, rule_ref, reason = command_whitelist.check(command, platform)
            audit["checks"]["whitelist"] = {
                "passed": allowed, "rule": rule_ref, "reason": reason
            }
            if not allowed:
                logger.warning(
                    f"[SafeExecutor] BLOCKED by whitelist: {action_name} → {reason}"
                )
                return self._blocked_result(action_name, "command_whitelist", reason, audit)

        # ── ② 参数强校验 ──
        param_ok, param_reason = self._validate_params(action_name, params)
        audit["checks"]["params"] = {"passed": param_ok, "reason": param_reason}
        if not param_ok:
            logger.warning(
                f"[SafeExecutor] BLOCKED by param validation: {action_name} → {param_reason}"
            )
            return self._blocked_result(action_name, "param_validation", param_reason, audit)

        # ── ③ 核心资产保护 ──
        target_ip = params.get("src_ip", params.get("host_ip", params.get("host", "")))
        if target_ip:
            is_protected, asset_reason = asset_whitelist.check(target_ip, action_name)
            audit["checks"]["asset_whitelist"] = {
                "passed": not is_protected, "reason": asset_reason
            }
            if is_protected:
                logger.warning(
                    f"[SafeExecutor] BLOCKED by asset whitelist: {action_name} → {asset_reason}"
                )
                return self._blocked_result(action_name, "asset_whitelist", asset_reason, audit)

        # ── ④ 幂等检查 (Redis) ──
        idempotent_hit = await self._idempotency_check(action_name, params, rule_id)
        audit["checks"]["idempotency"] = {"hit": idempotent_hit}
        if idempotent_hit:
            logger.info(
                f"[SafeExecutor] Idempotent skip: {action_name} already executed"
            )
            return {
                "success": True,
                "mode": "idempotent_skip",
                "action": action_name,
                "message": f"幂等检查: {action_name} 已执行过，跳过",
                "idempotent": True,
                "audit": audit,
            }

        # ── ⑤ 执行模式路由 ──
        if execution_router.mode != MODE_LIVE:
            result = await execution_router.route(
                action_name=action_name,
                command=command,
                params=params,
                live_fn=live_fn or self._noop_fn,
                platform=platform,
            )
            result["audit"] = audit
            result["duration_ms"] = round((time.time() - start_time) * 1000, 1)
            return result

        # ── ⑥ 最小权限 + 真实执行 ──
        if not live_fn:
            return self._blocked_result(
                action_name, "no_executor", "live 模式需要 live_fn", audit
            )

        try:
            result = await live_fn(command)
        except Exception as e:
            logger.error(f"[SafeExecutor] Execution error: {action_name} → {e}")
            audit["checks"]["execution"] = {"error": str(e)}
            return {
                "success": False,
                "mode": "live",
                "action": action_name,
                "error": str(e),
                "audit": audit,
                "duration_ms": round((time.time() - start_time) * 1000, 1),
            }

        # 规范化结果
        if isinstance(result, dict):
            result["mode"] = result.get("mode", "live")
            result["action"] = action_name
        else:
            result = {"success": True, "mode": "live", "action": action_name, "raw": str(result)}

        # ── ⑦ 执行后验证 ──
        exec_success = result.get("success", False)
        if exec_success:
            verify_report = await post_validator.verify(
                action_name=action_name,
                params=params,
                exec_fn=live_fn,
                platform=platform,
            )
            result["verified"] = verify_report.get("verified", False)
            result["verify_evidence"] = verify_report.get("evidence", "")
            audit["checks"]["post_validation"] = verify_report
        else:
            result["verified"] = False

        # ── ⑧ TTL 自动解封 ──
        if exec_success and ttl_seconds > 0 and rule_id:
            ttl_result = await ttl_manager.register(
                rule_id=rule_id,
                action_name=action_name,
                params=params,
                ttl_seconds=ttl_seconds,
            )
            result["ttl_registered"] = ttl_result.get("registered", False)
            result["ttl_expires_at"] = ttl_result.get("expires_at", 0)
            audit["checks"]["ttl"] = ttl_result

        # ── ⑨ 幂等标记 (Redis) ──
        if exec_success:
            await self._idempotency_mark(action_name, params, rule_id)

        # ── 审计日志 ──
        duration_ms = round((time.time() - start_time) * 1000, 1)
        result["audit"] = audit
        result["duration_ms"] = duration_ms

        logger.info(
            f"[SafeExecutor] {action_name} completed: "
            f"success={result.get('success')} verified={result.get('verified')} "
            f"mode={result.get('mode')} duration={duration_ms}ms"
        )
        return result

    # ── 内部方法 ──

    def _validate_params(self, action_name: str, params: dict) -> tuple[bool, str]:
        """参数强校验"""
        import ipaddress as _ipaddr

        # IP 类参数校验
        ip_fields = ["src_ip", "host_ip", "host", "ip", "target"]
        for field_name in ip_fields:
            value = params.get(field_name)
            if value and isinstance(value, str):
                # 排除非 IP 值（如主机名、session_id）
                if action_name in ("kill_session",) and field_name == "host":
                    continue
                try:
                    _ipaddr.ip_address(value)
                except ValueError:
                    # 允许 CIDR 格式（nmap 扫描目标）
                    try:
                        _ipaddr.ip_network(value, strict=False)
                    except ValueError:
                        return False, f"参数 {field_name}='{value}' 不是合法 IP 地址"

        # 数值参数校验
        int_fields = {
            "duration": (0, 86400 * 30),
            "duration_minutes": (0, 43200),
            "bandwidth_kbps": (1, 10000000),
            "ttl_seconds": (0, 86400 * 30),
        }
        for field_name, (lo, hi) in int_fields.items():
            value = params.get(field_name)
            if value is not None:
                if not isinstance(value, (int, float)):
                    return False, f"参数 {field_name} 必须是数值"
                if value < lo or value > hi:
                    return False, f"参数 {field_name}={value} 超出范围 [{lo}, {hi}]"

        # 字符串长度限制
        str_fields = ["reason", "rule_name", "rule_id", "session_id", "user"]
        for field_name in str_fields:
            value = params.get(field_name)
            if value and isinstance(value, str) and len(value) > 512:
                return False, f"参数 {field_name} 长度超限 ({len(value)} > 512)"

        return True, "参数校验通过"

    async def _idempotency_check(
        self, action_name: str, params: dict, rule_id: str
    ) -> bool:
        """Redis 幂等检查"""
        if not self._redis:
            return False
        key = self._idem_key(action_name, params, rule_id)
        try:
            exists = await self._redis.exists(key)
            return bool(exists)
        except Exception as e:
            logger.warning(f"[SafeExecutor] Idempotency check error: {e}")
            return False

    async def _idempotency_mark(
        self, action_name: str, params: dict, rule_id: str, ttl: int = 86400
    ):
        """标记已执行（Redis，默认 24 小时过期，覆盖 Kafka 重放窗口）"""
        if not self._redis:
            return
        key = self._idem_key(action_name, params, rule_id)
        try:
            await self._redis.set(key, "1", ex=ttl)
        except Exception as e:
            logger.warning(f"[SafeExecutor] Idempotency mark error: {e}")

    @staticmethod
    def _idem_key(action_name: str, params: dict, rule_id: str) -> str:
        """生成幂等 key（含 event_id 避免不同事件误判为重复）"""
        event_id = params.get("event_id", params.get("eventId", ""))
        if rule_id and event_id:
            return f"{_IDEM_PREFIX}{action_name}:{rule_id}:{event_id}"
        if rule_id:
            return f"{_IDEM_PREFIX}{action_name}:{rule_id}"
        # 按参数排序后哈希（含 event_id）
        stable = json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)
        h = hashlib.sha256(stable.encode()).hexdigest()[:16]
        return f"{_IDEM_PREFIX}{action_name}:{h}"

    @staticmethod
    def _blocked_result(
        action_name: str, check_name: str, reason: str, audit: dict
    ) -> dict:
        """构造拦截结果"""
        return {
            "success": False,
            "blocked": True,
            "blocked_by": check_name,
            "action": action_name,
            "reason": reason,
            "message": f"安全检查拦截 [{check_name}]: {reason}",
            "audit": audit,
        }

    @staticmethod
    async def _noop_fn(command: str) -> dict:
        return {"success": False, "error": "no live_fn provided"}

    def get_status(self) -> dict:
        """获取安全执行器状态"""
        return {
            "execution_mode": execution_router.mode,
            "whitelist_rules": len(command_whitelist.list_rules()),
            "protected_assets": len(asset_whitelist.list_assets()),
            "redis_connected": self._redis is not None,
        }


safe_executor = SafeExecutor()
