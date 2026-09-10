"""
PR1 遏制闭环(网络双栈)单元测试 — 不依赖真实 VM。

覆盖:
  1. IPv4 isolate → 两条 iptables -I(INPUT/OUTPUT), 零 ip6tables
  2. IPv6 isolate → 两条 ip6tables -I, 零 iptables -I
  3. isolate + extra_ips(另一协议族) → 4 条命令
  4. rollback(rule_id) → 同时删除 INPUT+OUTPUT(双栈时两族都删)
  5. get_active_rules() 返回隔离记录(status=isolated)
  6. command_whitelist: 放行规范化 ip6tables -I, 拒绝注入(; rm -rf /)
  7. dns_sinkhole 拒绝注入域名 evil.com; rm
  8. restore_host 在 isolate 后经 fake adapter 报告 success 且 deleted_count>=1
  9. block_ip 按族选表(IPv6→ip6tables), 部分族失败时 complete=False 不虚报

测试方式: 把 SshFirewallAdapter._exec 换成本地状态机(fake), 记录命令并模拟
iptables/ip6tables 的 INSERT/LIST/DELETE, 不建真实 SSH。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from response_engine.command_whitelist import command_whitelist
from response_engine.post_validator import PostValidator
from response_engine.ssh_firewall import SshFirewallAdapter
import response_engine.ssh_firewall as fwmod
from response_engine import response_registry as reg
from config import settings


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ════════════════════════════════════════════
# Fake SSH 适配器(iptables/ip6tables 状态机)
# ════════════════════════════════════════════

class FakeFirewallSSH:
    """替换 _exec: 记录命令 + 模拟 (table, chain) 规则表(含注释行), 支持按行号删除。"""

    def __init__(self, fail_tables=()):
        self.calls: list[str] = []
        # (table, chain) -> [{src, dst, target, comment}]
        self._rules = {}
        for table in ("iptables", "ip6tables"):
            for chain in ("INPUT", "OUTPUT"):
                self._rules[(table, chain)] = []
        self.fail_tables = set(fail_tables)  # 命中则 -I/-D 抛错(模拟缺二进制/无权限)
        self.hosts_content = ""              # 模拟 /etc/hosts 内容
        self.dnsmasq_ok = False              # 模拟远端是否装有 dnsmasq

    def __call__(self, cmd: str, timeout=None, skip_whitelist: bool = False) -> str:
        self.calls.append(cmd)
        text = cmd.strip()
        parts = text.split()
        if parts and parts[0] == "sudo":
            parts = parts[1:]
        # sinkhole 探测/读取命令
        if parts and parts[0] == "test":
            return "DNSMASQ_OK\n" if self.dnsmasq_ok else "NO_DNSMASQ\n"
        if text == "cat /etc/hosts":
            return self.hosts_content
        if len(parts) < 3 or parts[0] not in ("iptables", "ip6tables"):
            return ""
        table, op, chain = parts[0], parts[1], parts[2]
        key = (table, chain)
        if op == "-I":
            if table in self.fail_tables:
                raise RuntimeError(f"{table}: command not found")
            flag = parts[3]
            ip = parts[4]
            comment = ""
            if "--comment" in parts:
                comment = parts[parts.index("--comment") + 1].strip("'")
            src, dst = ("0.0.0.0/0", ip) if flag == "-d" else (ip, "0.0.0.0/0")
            self._rules[key].append({"src": src, "dst": dst, "target": "DROP", "comment": comment})
            return ""
        if op == "-D":
            if table in self.fail_tables:
                raise RuntimeError(f"{table}: command not found")
            if parts[3].isdigit():  # -D <chain> <linenum>
                idx = int(parts[3]) - 1
                if 0 <= idx < len(self._rules[key]):
                    del self._rules[key][idx]
            return ""
        if op == "-L":
            return self._dump(table, chain)
        return ""

    def _dump(self, table: str, chain: str) -> str:
        lines = [f"Chain {chain} (policy ACCEPT)",
                 "num  target     prot opt source               destination"]
        for i, r in enumerate(self._rules[(table, chain)], start=1):
            lines.append(f"{i}    {r['target']:<10} all  --  {r['src']:<18} {r['dst']:<18} /* {r['comment']} */")
        return "\n".join(lines) + "\n"

    def insert_commands(self, table: str) -> list:
        return [c for c in self.calls if c.startswith(f"{table} -I")]

    def delete_commands(self) -> list:
        return [c for c in self.calls if " -D " in c]


@pytest.fixture
def fake_adapter(monkeypatch):
    """全新 SshFirewallAdapter + fake _exec(自清洁 monkeypatch)。"""
    adapter = SshFirewallAdapter()
    fake = FakeFirewallSSH()
    monkeypatch.setattr(adapter, "_exec", fake)
    adapter._connected = True
    adapter._config["host"] = "fw-host"
    adapter._config["use_sudo"] = False
    return adapter, fake


@pytest.fixture
def live_firewall_singleton(monkeypatch):
    """把模块级 ssh_firewall 单例接上 fake, 供 response_registry 路径测试。"""
    fwmod.ssh_firewall._active_rules.clear()
    fake = FakeFirewallSSH()
    monkeypatch.setattr(fwmod.ssh_firewall, "_exec", fake)
    fwmod.ssh_firewall._connected = True
    fwmod.ssh_firewall._config["host"] = "fw-host"
    return fwmod.ssh_firewall, fake


# ════════════════════════════════════════════
# 1/2/3. isolate_host 双栈命令与返回结构
# ════════════════════════════════════════════

class TestIsolateHostCommands:
    def test_ipv4_isolate_two_iptables_zero_ip6tables(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3")
        assert res["status"] == "success"
        assert res["success"] is True
        assert res["complete"] is True
        assert res["families_applied"] == ["ipv4"]
        assert res["families_missing"] == []
        assert res["host"] == "10.1.2.3"
        ins = fake.insert_commands("iptables")
        assert len(ins) == 2
        assert any(" -I INPUT -s 10.1.2.3 " in c and "-j DROP" in c for c in ins)
        assert any(" -I OUTPUT -d 10.1.2.3 " in c and "-j DROP" in c for c in ins)
        assert fake.insert_commands("ip6tables") == []
        assert res["rule_ids"] == [res["isolation_id"]]

    def test_ipv6_isolate_two_ip6tables_zero_iptables(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("2001:db8::10")
        assert res["status"] == "success"
        assert res["complete"] is True
        assert res["families_applied"] == ["ipv6"]
        ins = fake.insert_commands("ip6tables")
        assert len(ins) == 2
        assert any(" -I INPUT -s 2001:db8::10 " in c for c in ins)
        assert any(" -I OUTPUT -d 2001:db8::10 " in c for c in ins)
        assert fake.insert_commands("iptables") == []

    def test_isolate_with_extra_ips_other_family_emits_four(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3", extra_ips=["2001:db8::10"])
        assert res["status"] == "success"
        assert res["complete"] is True
        assert res["families_applied"] == ["ipv4", "ipv6"]
        assert res["families_missing"] == []
        assert len(fake.insert_commands("iptables")) == 2
        assert len(fake.insert_commands("ip6tables")) == 2
        assert len(fake.delete_commands()) == 0

    def test_isolate_single_family_complete_true_is_correct(self, fake_adapter):
        """只有 IPv4、无 extra_ips → 单个族完成即 complete=True(单栈主机语义)。"""
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3")
        assert res["complete"] is True
        assert res["families_missing"] == []

    def test_isolate_extra_family_write_failure_reports_partial(self, monkeypatch):
        """extra_ips 的族写失败 → success=True 但 complete=False + families_missing。"""
        adapter = SshFirewallAdapter()
        fake = FakeFirewallSSH(fail_tables=("ip6tables",))
        monkeypatch.setattr(adapter, "_exec", fake)
        adapter._connected = True
        adapter._config["host"] = "fw-host"
        res = adapter.isolate_host("10.1.2.3", extra_ips=["2001:db8::10"])
        assert res["status"] == "success"      # IPv4 族已写入
        assert res["success"] is True
        assert res["complete"] is False        # 有请求的族缺失 → 不得宣称完全隔离
        assert res["families_applied"] == ["ipv4"]
        assert res["families_missing"] == ["ipv6"]
        # 部分写入的隔离仍可追踪回滚
        assert res["rule_ids"] == [res["isolation_id"]]

    def test_block_ip_selects_table_by_family(self, fake_adapter):
        adapter, fake = fake_adapter
        r4 = adapter.block_ip("8.8.4.4", duration=60)
        assert r4["status"] == "success" and r4["family"] == "ipv4"
        assert len(fake.insert_commands("iptables")) == 1
        assert fake.insert_commands("ip6tables") == []
        assert "FW-RULE-" in r4["rule_id"]

        r6 = adapter.block_ip("2001:4860:4860::8888", duration=60)
        assert r6["status"] == "success" and r6["family"] == "ipv6"
        assert len(fake.insert_commands("ip6tables")) == 1
        assert fake.insert_commands("ip6tables")[0].startswith("ip6tables -I INPUT -s 2001:4860:4860::8888")


# ════════════════════════════════════════════
# 4/5. rollback / get_active_rules
# ════════════════════════════════════════════

class TestRollback:
    def test_rollback_deletes_input_and_output(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3")
        iso_id = res["isolation_id"]
        rb = adapter.rollback(iso_id)
        assert rb["status"] == "success"
        assert rb["deleted"] == 2
        delfs = fake.delete_commands()
        assert len(delfs) == 2
        # 删除命令覆盖两条链
        assert any("-D INPUT" in c for c in delfs)
        assert any("-D OUTPUT" in c for c in delfs)
        # 规则已清空
        out = fake("iptables -L INPUT -n --line-numbers")
        assert iso_id not in out

    def test_rollback_dual_stack_removes_both_families(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3", extra_ips=["2001:db8::10"])
        iso_id = res["isolation_id"]
        rb = adapter.rollback(iso_id)
        assert rb["status"] == "success"
        assert rb["deleted"] == 4
        delfs = fake.delete_commands()
        assert len(delfs) == 4
        for table in ("iptables", "ip6tables"):
            assert any(f"-D INPUT" in c and c.startswith(table) for c in delfs)
            assert any(f"-D OUTPUT" in c and c.startswith(table) for c in delfs)

    def test_rollback_block_rule(self, fake_adapter):
        adapter, fake = fake_adapter
        r = adapter.block_ip("8.8.8.8", duration=60)
        rb = adapter.rollback(r["rule_id"])
        assert rb["status"] == "success"
        assert rb["deleted"] == 1

    def test_rollback_unknown_is_idempotent_success(self, fake_adapter):
        """PR2 幂等语义: 规则不存在 = 已回滚过, success + idempotent=True(取代旧 not_found)。"""
        adapter, fake = fake_adapter
        rb = adapter.rollback("EDR-ISO-00000")
        assert rb["status"] == "success"
        assert rb["deleted"] == 0
        assert rb.get("idempotent") is True

    def test_get_active_rules_returns_isolate_rules(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.isolate_host("10.1.2.3")
        rules = adapter.get_active_rules()
        assert len(rules) == 1
        assert rules[0]["rule_id"] == res["isolation_id"]
        assert rules[0]["status"] == "isolated"
        # 回滚后不再返回
        adapter.rollback(res["isolation_id"])
        assert adapter.get_active_rules() == []


# ════════════════════════════════════════════
# 6. 命令白名单 IPv6
# ════════════════════════════════════════════

class TestWhitelistIpv6:
    def test_ip6tables_insert_allowed(self):
        ok, rid, _ = command_whitelist.check(
            "ip6tables -I INPUT -s ::1 -j DROP", "linux")
        assert ok and rid == "LX-010"

    def test_ip6tables_insert_with_comment_allowed(self):
        ok, rid, _ = command_whitelist.check(
            "ip6tables -I OUTPUT -d 2001:db8::1 -j DROP -m comment --comment 'EDR-ISO-12345'", "linux")
        assert ok and rid == "LX-010"

    def test_ip6tables_delete_by_number_allowed(self):
        ok, rid, _ = command_whitelist.check("ip6tables -D INPUT 3", "linux")
        assert ok and rid == "LX-011"

    def test_ip6tables_list_allowed(self):
        ok, rid, _ = command_whitelist.check("ip6tables -L OUTPUT -n --line-numbers", "linux")
        assert ok and rid == "LX-013"

    def test_ip6tables_injection_rejected(self):
        ok, _, reason = command_whitelist.check(
            "ip6tables -I INPUT -s ::1 -j DROP; rm -rf /", "linux")
        assert not ok
        assert "禁止子串" in reason

    def test_ipv4_address_in_ip6tables_rejected(self):
        # 点分 IPv4 不匹配规范化 IPv6 白名单
        ok, _, _ = command_whitelist.check("ip6tables -I INPUT -s 1.2.3.4 -j DROP", "linux")
        assert not ok

    def test_ipv4_rules_still_match_old_ids(self):
        ok, rid, _ = command_whitelist.check(
            "iptables -I INPUT -s 192.168.1.100 -j DROP -m comment --comment 'FW-RULE-12345'", "linux")
        assert ok and rid == "LX-001"


# ════════════════════════════════════════════
# 7. dns_sinkhole 动作(注册/校验/模式)
# ════════════════════════════════════════════

class TestDnsSinkholeRegistry:
    def test_action_registered(self):
        a = reg.get_action("dns_sinkhole")
        assert a is not None
        assert a.severity == "high"
        assert a.category == "network"
        assert a.reversible is True
        assert callable(a.rollback_fn)

    def test_dns_sinkhole_rejects_injection_domain(self):
        r = _run(reg.execute("dns_sinkhole", domain="evil.com; rm -rf /"))
        assert r["success"] is False
        assert r["result"]["mode"] == "invalid"

    def test_dns_sinkhole_rejects_path_and_spaces(self):
        for bad in ("evil.com/x", "evil.com x", "-evil.com"):
            r = _run(reg.execute("dns_sinkhole", domain=bad))
            assert r["success"] is False, bad
            assert r["result"]["mode"] == "invalid", bad

    def test_dns_sinkhole_mock_returns_without_ssh(self, monkeypatch):
        monkeypatch.setattr(settings, "execution_mode", "mock")
        fwmod.ssh_firewall._connected = False
        fwmod.ssh_firewall._config["host"] = ""
        r = _run(reg.execute("dns_sinkhole", domain="evil.example.com"))
        assert r["success"] is True
        res = r["result"]
        assert res["mode"] == "mock"
        assert res["domain"] == "evil.example.com"
        assert res["marker_id"].startswith("SOC-SH-")
        assert res["backend"] == "hosts"

    def test_dns_sinkhole_live_unconnected_is_honest_unconfigured(self, monkeypatch):
        monkeypatch.setattr(settings, "execution_mode", "live")
        fwmod.ssh_firewall._connected = False
        fwmod.ssh_firewall._config["host"] = ""

        def _raise(*a, **kw):
            raise RuntimeError("connect refused")

        monkeypatch.setattr(fwmod.ssh_firewall, "connect", _raise)
        # 不 stub 假装成功: live + 无法连接 → success=False + mode=unconfigured
        r = _run(reg.execute("dns_sinkhole", domain="evil.example.com"))
        assert r["success"] is False
        assert r["result"]["mode"] == "unconfigured"

    def test_adapter_sinkhole_writes_hosts_line(self, fake_adapter):
        adapter, fake = fake_adapter
        fake.hosts_content = "127.0.0.1 localhost\n"
        res = adapter.sinkhole_domain("evil.example", ipv4="127.0.0.2")
        assert res["status"] == "success"
        assert res["backend"] == "hosts"        # 未装 dnsmasq → hosts 模式
        assert res["marker_id"].startswith("SOC-SH-")
        assert any("tee -a /etc/hosts" in c and "evil.example" in c for c in fake.calls)

    def test_adapter_unsinkhole_cleans_hosts_line(self, fake_adapter):
        adapter, fake = fake_adapter
        res = adapter.unsinkhole_domain("evil.example", marker_id="SOC-SH-ABCDE12345")
        assert res["status"] == "success"
        assert any("sed -i" in c and "SOC-SH-ABCDE12345" in c for c in fake.calls)
        assert any("rm -f" in c and "soc-sinkhole-SOC-SH-ABCDE12345" in c for c in fake.calls)


# ════════════════════════════════════════════
# 8. restore_host(registry 层, live + fake 单例)
# ════════════════════════════════════════════

class TestRestoreHostRegistry:
    def test_restore_host_after_isolate_reports_success(self, monkeypatch, live_firewall_singleton):
        _, fake = live_firewall_singleton
        iso = _run(reg.execute("isolate_host", host_ip="10.9.9.9"))
        assert iso["success"] is True
        inner = iso["result"]
        assert inner["complete"] is True
        assert inner["families_applied"] == ["ipv4"]
        assert len(inner["rule_ids"]) == 1

        rb = _run(reg.rollback("isolate_host", host_ip="10.9.9.9"))
        assert rb["success"] is True
        res = rb["result"]
        assert res["deleted_count"] >= 1
        assert res["action"] == "restore_host"
        # 全部规则行已删(INPUT+OUTPUT), 内存记录已撤销
        assert fwmod.ssh_firewall.get_active_rules() == []

    def test_restore_host_ipv6_matching_normalized(self, monkeypatch, live_firewall_singleton):
        _, fake = live_firewall_singleton
        iso = _run(reg.execute("isolate_host", host_ip="2001:db8::10"))
        assert iso["success"] is True
        # 展开写法仍能匹配(经 ipaddress 规范化比较)
        rb = _run(reg.rollback("isolate_host", host_ip="2001:0db8:0:0:0:0:0:10"))
        assert rb["success"] is True
        assert rb["result"]["deleted_count"] >= 1

    def test_registry_isolate_mock_no_ssh(self, monkeypatch):
        monkeypatch.setattr(settings, "execution_mode", "mock")
        fwmod.ssh_firewall._connected = False
        fwmod.ssh_firewall._config["host"] = ""
        r = _run(reg.execute("isolate_host", host_ip="10.1.2.3"))
        assert r["success"] is True
        res = r["result"]
        assert res["mode"] == "mock"
        assert res["complete"] is True
        assert res["families_applied"] == ["ipv4"]


# ════════════════════════════════════════════
# 9. Post validator(按族选表)
# ════════════════════════════════════════════

class TestPostValidatorFamilies:
    def test_verify_block_ipv6_queries_ip6tables(self):
        pv = PostValidator()
        queried = []

        async def exec_fn(cmd):
            queried.append(cmd)
            return {"success": True, "stdout": "1 DROP all -- 2001:db8::9 ::/0 /* FW-RULE-777 */"}

        result = _run(pv.verify("block_ip", {"src_ip": "2001:db8::9"}, exec_fn, "linux"))
        assert result["verified"] is True
        assert any(c.startswith("ip6tables -L INPUT") for c in queried)
        assert not any(c.startswith("iptables -L") for c in queried)

    def test_verify_isolate_dual_stack_requires_both_tables(self):
        pv = PostValidator()

        async def exec_fn(cmd):
            # 只模拟 iptables 有规则, ip6tables 为空
            if cmd.startswith("iptables"):
                return {"success": True, "stdout": "1 DROP all -- 10.1.2.3 0.0.0.0/0 /* EDR-ISO-1 */"}
            return {"success": True, "stdout": "Chain INPUT (policy ACCEPT)"}

        result = _run(pv.verify(
            "isolate_host",
            {"host_ip": "10.1.2.3", "families_applied": ["ipv4", "ipv6"]},
            exec_fn, "linux",
        ))
        assert result["verified"] is False

        result4 = _run(pv.verify(
            "isolate_host",
            {"host_ip": "10.1.2.3", "families_applied": ["ipv4"]},
            exec_fn, "linux",
        ))
        assert result4["verified"] is True

    def test_verify_restore_queries_family_table(self):
        pv = PostValidator()
        queried = []

        async def exec_fn(cmd):
            queried.append(cmd)
            return {"success": True, "stdout": "Chain INPUT (policy ACCEPT)"}

        result = _run(pv.verify("restore_host", {"host_ip": "2001:db8::10"}, exec_fn, "linux"))
        assert result["verified"] is True
        assert any(c.startswith("ip6tables -L") for c in queried)
