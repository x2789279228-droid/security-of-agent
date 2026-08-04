"""
Trusted Action Gateway — 执行后验证器扩展 (TagPostActionVerifier)

核心设计:
  - 工具返回 success 不代表处置完成
  - 为有副作用的工具实现验证逻辑（block_ip / isolate_host / rate_limit）
  - 验证失败 → 状态变为 ROLLBACK_REQUIRED
  - 同一 action_id 验证失败超过 MAX_VERIFY_RETRIES 次 → 触发熔断 (circuit_open)

与 response_engine.post_validator.PostValidator 的关系:
  - PostValidator 通过 exec_fn（SSH 执行函数）验证，面向主链 INPUT/OUTPUT
  - TagPostActionVerifier 通过 IptablesChainExecutor 验证，面向专用链
    AGENT_GUARD_INPUT / AGENT_GUARD_OUTPUT，并携带 action_id 维度的重试计数

调用方式:
    from trusted_action_gateway.executors import TagPostActionVerifier
    verifier = TagPostActionVerifier(iptables_executor=executor)
    result = await verifier.verify(
        tool_name="block_ip",
        action_id="act-1234",
        params={"ip": "1.2.3.4"},
        exec_result={"success": True, "rule_id": "AGT-ACT-1234"},
    )
"""
import logging
from typing import TYPE_CHECKING, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .iptables_executor import IptablesChainExecutor


class TagPostActionVerifier:
    """执行后验证器扩展 — 基于 IptablesChainExecutor 验证处置是否真正生效"""

    MAX_VERIFY_RETRIES = 3

    def __init__(self, iptables_executor: "Optional[IptablesChainExecutor]" = None):
        """
        Args:
            iptables_executor: IptablesChainExecutor 实例。
                               若为 None，验证将退化为仅检查 exec_result。
        """
        self._executor = iptables_executor
        self._verifiers: dict[str, Callable[..., Coroutine]] = {}
        # action_id -> 连续验证失败次数（用于熔断判定）
        self._retry_counts: dict[str, int] = {}
        self._register_default_verifiers()

    async def verify(
        self,
        tool_name: str,
        action_id: str,
        params: dict,
        exec_result: dict,
    ) -> dict:
        """执行后验证主入口

        Args:
            tool_name: 工具/动作名称（如 block_ip / isolate_host）
            action_id: 动作唯一标识（用于重试计数与熔断）
            params: 动作参数（含 ip / host / ttl_seconds 等）
            exec_result: 执行结果（含 success / rule_id 等）

        Returns:
            {
                "verified": bool,
                "evidence": str,
                "checks": list[dict],          # 每项检查结果
                "error"?: str,
                "rollback_required"?: bool,
                "retry_count"?: int,
                "circuit_open"?: bool,
                "skipped"?: bool,
            }
        """
        verifier = self._verifiers.get(tool_name)
        if verifier is None:
            return {
                "verified": True,
                "evidence": "no_verifier",
                "skipped": True,
            }

        try:
            result = await verifier(action_id, params, exec_result)
        except Exception as e:
            logger.warning(
                f"[TagPostVerify] {tool_name} verifier error: {e}",
                exc_info=True,
            )
            result = {
                "verified": False,
                "evidence": f"验证过程异常: {e}",
                "checks": [],
                "error": str(e),
            }

        # 确保 checks 字段存在
        result.setdefault("checks", [])
        result.setdefault("evidence", "")

        if not result["verified"]:
            # 累计失败次数
            self._retry_counts[action_id] = self._retry_counts.get(action_id, 0) + 1
            result["rollback_required"] = True
            result["retry_count"] = self._retry_counts[action_id]
            if result["retry_count"] >= self.MAX_VERIFY_RETRIES:
                result["circuit_open"] = True
                logger.error(
                    f"[TagPostVerify] CIRCUIT OPEN: {tool_name} "
                    f"(action_id={action_id}, retries={result['retry_count']})"
                )
            logger.warning(
                f"[TagPostVerify] {tool_name} NOT VERIFIED "
                f"(action_id={action_id}, retry={result['retry_count']}): "
                f"{result.get('evidence', '')[:200]}"
            )
        else:
            # 验证通过，重置失败计数
            self._retry_counts.pop(action_id, None)
            logger.info(
                f"[TagPostVerify] {tool_name} VERIFIED "
                f"(action_id={action_id}): {result.get('evidence', '')[:100]}"
            )

        return result

    def register_verifier(
        self, tool_name: str, fn: Callable[..., Coroutine]
    ) -> None:
        """注册自定义验证器"""
        self._verifiers[tool_name] = fn
        logger.info(f"[TagPostVerify] Registered verifier for '{tool_name}'")

    def _register_default_verifiers(self) -> None:
        """注册默认验证器"""
        self._verifiers["block_ip"] = self._verify_block_ip
        self._verifiers["isolate_host"] = self._verify_isolate_host
        self._verifiers["rate_limit"] = self._verify_rate_limit

    # ──────────────────────────────────────────────────────────
    # 默认验证器实现
    # ──────────────────────────────────────────────────────────

    async def _verify_block_ip(
        self, action_id: str, params: dict, exec_result: dict
    ) -> dict:
        """验证 block_ip:
        1. 查询对应规则是否真正存在（通过 IptablesChainExecutor.verify_rule_exists）
        2. 验证规则目标 IP 匹配
        3. 验证 TTL 仍有效
        4. 验证通过才将动作标记为 SUCCEEDED
        """
        checks: list[dict] = []

        # 检查 1: 规则存在
        rule_id = exec_result.get("rule_id", "")
        if not rule_id:
            return {
                "verified": False,
                "evidence": "missing rule_id in exec_result",
                "checks": checks,
                "error": "no rule_id",
            }

        rule_info: dict = {}
        if self._executor:
            try:
                rule_info = await self._executor.verify_rule_exists(rule_id)
            except Exception as e:
                checks.append({
                    "name": "rule_exists",
                    "passed": False,
                    "detail": f"verify_rule_exists 异常: {e}",
                })
                return {
                    "verified": False,
                    "evidence": f"规则验证异常: {e}",
                    "checks": checks,
                    "error": str(e),
                }

            checks.append({
                "name": "rule_exists",
                "passed": rule_info.get("exists", False),
                "detail": rule_info,
            })
            if not rule_info.get("exists"):
                return {
                    "verified": False,
                    "evidence": "rule not found in iptables",
                    "checks": checks,
                    "error": "rule_missing",
                }

        # 检查 2: 目标匹配
        expected_ip = params.get("ip") or params.get("src_ip", "")
        actual_ip = (
            rule_info.get("ip", "") if self._executor else expected_ip
        )
        checks.append({
            "name": "target_match",
            "passed": (expected_ip == actual_ip) if self._executor else True,
            "detail": f"expected={expected_ip}, actual={actual_ip}",
        })

        # 检查 3: TTL 有效
        ttl_remaining = (
            rule_info.get("ttl_remaining", 0)
            if self._executor
            else params.get("ttl_seconds", 3600)
        )
        checks.append({
            "name": "ttl_valid",
            "passed": ttl_remaining > 0,
            "detail": f"ttl_remaining={ttl_remaining}s",
        })

        all_passed = all(c["passed"] for c in checks)
        return {
            "verified": all_passed,
            "evidence": f"rule_id={rule_id}, checks={len(checks)}",
            "checks": checks,
        }

    async def _verify_isolate_host(
        self, action_id: str, params: dict, exec_result: dict
    ) -> dict:
        """验证 isolate_host: 检查 INPUT 和 OUTPUT 两条专用链的规则

        由于两条链共享同一 rule_id，verify_rule_exists 返回首个匹配即可确认存在。
        若需严格确认两条链均有规则，可扩展为分别查询。
        """
        checks: list[dict] = []
        rule_id = exec_result.get("rule_id", "")
        if not rule_id:
            return {
                "verified": False,
                "evidence": "missing rule_id in exec_result",
                "checks": checks,
                "error": "no rule_id",
            }

        if self._executor:
            try:
                rule_info = await self._executor.verify_rule_exists(rule_id)
            except Exception as e:
                checks.append({
                    "name": "isolation_rules_exist",
                    "passed": False,
                    "detail": f"verify_rule_exists 异常: {e}",
                })
                return {
                    "verified": False,
                    "evidence": f"隔离规则验证异常: {e}",
                    "checks": checks,
                    "error": str(e),
                }

            exists = rule_info.get("exists", False)
            checks.append({
                "name": "isolation_rules_exist",
                "passed": exists,
                "detail": rule_info,
            })

            # 目标主机匹配
            expected_host = params.get("host") or params.get("host_ip", "")
            actual_host = rule_info.get("ip", "") if exists else ""
            if expected_host:
                checks.append({
                    "name": "host_match",
                    "passed": (expected_host == actual_host) if exists else False,
                    "detail": f"expected={expected_host}, actual={actual_host}",
                })
        else:
            # 无 executor 时退化为检查 exec_result.success
            checks.append({
                "name": "exec_success",
                "passed": exec_result.get("success", False),
                "detail": "no executor, fallback to exec_result",
            })

        all_passed = all(c["passed"] for c in checks)
        return {
            "verified": all_passed,
            "evidence": f"rule_id={rule_id}",
            "checks": checks,
        }

    async def _verify_rate_limit(
        self, action_id: str, params: dict, exec_result: dict
    ) -> dict:
        """验证 rate_limit: 检查 QoS / limit 规则是否生效

        rate_limit 在 iptables 中通过 -m limit 实现，简化验证：检查 exec_result.success。
        若存在 executor 可扩展为查询 limit 匹配规则。
        """
        success = exec_result.get("success", False)
        return {
            "verified": success,
            "evidence": "rate_limit applied",
            "checks": [
                {
                    "name": "exec_success",
                    "passed": success,
                    "detail": exec_result,
                }
            ],
        }
