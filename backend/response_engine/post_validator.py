"""
执行后验证 (Post-Execution Validator)

在 SSH 命令执行成功后，通过查询命令验证操作是否真正生效。
例如: block_ip 后检查 iptables/netsh 规则是否确实存在。

验证失败不触发回滚（由上层决策），仅标记 verified=False 并记录告警。

调用方式:
    from response_engine.post_validator import post_validator
    report = await post_validator.verify(
        action_name="block_ip",
        params={"src_ip": "1.2.3.4", "rule_name": "RE_Block_1_2_3_4"},
        exec_fn=ssh_exec_coroutine,
        platform="linux",
    )
"""
import logging
from typing import Callable, Coroutine, Optional

logger = logging.getLogger(__name__)


class PostValidator:
    """执行后验证器"""

    async def verify(
        self,
        action_name: str,
        params: dict,
        exec_fn: Callable[[str], Coroutine],
        platform: str = "linux",
    ) -> dict:
        """
        验证动作是否真正生效

        Args:
            action_name: 动作名称
            params: 动作参数（含 src_ip, rule_name, rule_id 等）
            exec_fn: SSH 执行函数 (接受命令字符串，返回 dict{success, stdout, ...})
            platform: "linux" | "windows"

        Returns:
            {"verified": bool, "evidence": str, "action": str}
        """
        verifier = _VERIFIERS.get(action_name)
        if not verifier:
            return {
                "verified": True,
                "evidence": "该动作无需执行后验证",
                "action": action_name,
                "skipped": True,
            }

        try:
            result = await verifier(params, exec_fn, platform)
            if result["verified"]:
                logger.info(
                    f"[PostValidate] {action_name} VERIFIED: {result['evidence'][:100]}"
                )
            else:
                logger.warning(
                    f"[PostValidate] {action_name} NOT VERIFIED: {result['evidence'][:200]}"
                )
            result["action"] = action_name
            return result
        except Exception as e:
            logger.warning(f"[PostValidate] {action_name} verification error: {e}")
            return {
                "verified": False,
                "evidence": f"验证过程异常: {e}",
                "action": action_name,
                "error": str(e),
            }


# ── 各动作的验证实现 ──

async def _verify_block_ip(
    params: dict, exec_fn: Callable, platform: str
) -> dict:
    """验证 IP 封禁规则是否存在"""
    src_ip = params.get("src_ip", "")
    rule_id = params.get("rule_id", "")
    rule_name = params.get("rule_name", "")

    if platform == "linux":
        out = await exec_fn("iptables -L INPUT -n --line-numbers")
        stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
        # 检查 IP 和 rule_id 是否出现在规则列表中
        if src_ip and src_ip in stdout:
            if rule_id and rule_id in stdout:
                return {"verified": True, "evidence": f"iptables 规则存在: {src_ip} ({rule_id})"}
            return {"verified": True, "evidence": f"iptables 中存在 {src_ip} 的 DROP 规则"}
        return {"verified": False, "evidence": f"iptables INPUT 链中未找到 {src_ip}"}

    else:  # windows
        if not rule_name:
            rule_name = f"RE_Block_{src_ip.replace('.', '_')}"
        out = await exec_fn(f'netsh advfirewall firewall show rule name="{rule_name}"')
        stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
        if "No rules" in stdout or not stdout.strip():
            return {"verified": False, "evidence": f"Windows 防火墙规则 {rule_name} 不存在"}
        return {"verified": True, "evidence": f"Windows 防火墙规则存在: {rule_name}"}


async def _verify_unblock_ip(
    params: dict, exec_fn: Callable, platform: str
) -> dict:
    """验证 IP 封禁规则已删除"""
    src_ip = params.get("src_ip", "")
    rule_id = params.get("rule_id", "")
    rule_name = params.get("rule_name", "")

    if platform == "linux":
        out = await exec_fn("iptables -L INPUT -n --line-numbers")
        stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
        check_token = rule_id or src_ip
        if check_token and check_token in stdout:
            return {"verified": False, "evidence": f"规则仍存在: {check_token}"}
        return {"verified": True, "evidence": f"规则已删除: {check_token}"}

    else:
        if not rule_name:
            rule_name = f"RE_Block_{src_ip.replace('.', '_')}"
        out = await exec_fn(f'netsh advfirewall firewall show rule name="{rule_name}"')
        stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
        if "No rules" in stdout or not stdout.strip():
            return {"verified": True, "evidence": f"规则已删除: {rule_name}"}
        return {"verified": False, "evidence": f"规则仍存在: {rule_name}"}


async def _verify_isolate_host(
    params: dict, exec_fn: Callable, platform: str
) -> dict:
    """验证主机隔离（INPUT + OUTPUT 两条规则）"""
    host_ip = params.get("host_ip", params.get("host", ""))
    isolation_id = params.get("isolation_id", "")

    if platform == "linux":
        input_ok = False
        output_ok = False
        for chain in ["INPUT", "OUTPUT"]:
            out = await exec_fn(f"iptables -L {chain} -n --line-numbers")
            stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
            check_token = isolation_id or host_ip
            if check_token and check_token in stdout:
                if chain == "INPUT":
                    input_ok = True
                else:
                    output_ok = True

        if input_ok and output_ok:
            return {"verified": True, "evidence": f"INPUT+OUTPUT 隔离规则均存在: {host_ip}"}
        missing = []
        if not input_ok:
            missing.append("INPUT")
        if not output_ok:
            missing.append("OUTPUT")
        return {"verified": False, "evidence": f"缺少 {'+'.join(missing)} 隔离规则: {host_ip}"}

    else:
        rule_in = f"RE_Isolate_In_{host_ip.replace('.', '_')}"
        rule_out = f"RE_Isolate_Out_{host_ip.replace('.', '_')}"
        found = []
        for rn in [rule_in, rule_out]:
            out = await exec_fn(f'netsh advfirewall firewall show rule name="{rn}"')
            stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
            if "No rules" not in stdout and stdout.strip():
                found.append(rn)
        if len(found) == 2:
            return {"verified": True, "evidence": f"入站+出站隔离规则均存在: {host_ip}"}
        return {"verified": False, "evidence": f"仅找到 {len(found)}/2 条隔离规则: {host_ip}"}


async def _verify_restore_host(
    params: dict, exec_fn: Callable, platform: str
) -> dict:
    """验证主机隔离已解除"""
    host_ip = params.get("host_ip", params.get("host", ""))

    if platform == "linux":
        for chain in ["INPUT", "OUTPUT"]:
            out = await exec_fn(f"iptables -L {chain} -n --line-numbers")
            stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
            if host_ip and host_ip in stdout:
                return {"verified": False, "evidence": f"{chain} 链中仍存在 {host_ip} 的规则"}
        return {"verified": True, "evidence": f"隔离规则已全部删除: {host_ip}"}

    else:
        rule_in = f"RE_Isolate_In_{host_ip.replace('.', '_')}"
        out = await exec_fn(f'netsh advfirewall firewall show rule name="{rule_in}"')
        stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
        if "No rules" in stdout or not stdout.strip():
            return {"verified": True, "evidence": f"隔离规则已删除: {host_ip}"}
        return {"verified": False, "evidence": f"隔离规则仍存在: {host_ip}"}


async def _verify_rate_limit(
    params: dict, exec_fn: Callable, platform: str
) -> dict:
    """验证 QoS 限速策略存在（仅 Windows）"""
    if platform != "windows":
        return {"verified": True, "evidence": "Linux 平台暂不支持 QoS 验证", "skipped": True}

    src_ip = params.get("src_ip", "")
    policy_name = f"RE_RateLimit_{src_ip.replace('.', '_')}"
    # 必须用 EncodedCommand 形式 — 命令白名单 WIN-004 仅放行该形态,
    # 裸 -Command 会被 GLOBAL_FORBIDDEN(引号/管道) 拒绝导致验证恒失败
    from .response_registry import _ps_cmd
    ps_cmd = _ps_cmd(
        f"Get-NetQosPolicy -Name '{policy_name}' -ErrorAction SilentlyContinue"
    )
    out = await exec_fn(ps_cmd)
    stdout = out.get("stdout", "") if isinstance(out, dict) else str(out)
    if policy_name in stdout:
        return {"verified": True, "evidence": f"QoS 策略存在: {policy_name}"}
    return {"verified": False, "evidence": f"QoS 策略未找到: {policy_name}"}


# 动作 → 验证函数映射
_VERIFIERS = {
    "block_ip": _verify_block_ip,
    "unblock_ip": _verify_unblock_ip,
    "isolate_host": _verify_isolate_host,
    "restore_host": _verify_restore_host,
    "rate_limit": _verify_rate_limit,
}


post_validator = PostValidator()
