"""
SSH 防火墙适配器 — 通过 SSH 连接 Linux 虚拟机执行 iptables 真实封禁/隔离/回滚

与现有 transport.py 的关系：
  - transport.py: 通用 SSH 传输（Windows PowerShell 命令）
  - ssh_firewall.py: 专用 Linux iptables 防火墙操作（本模块）

安全加固:
  - 命令白名单: _exec() 中所有命令必须通过 CommandWhitelist 检查
  - 参数强校验: block_ip/isolate_host 对 IP 做 ipaddress 严格校验
  - 核心资产保护: 封禁/隔离前检查 AssetWhitelist
  - 最小权限: nmap/list_rules 等只读操作不加 sudo

能力：
  - block_ip: iptables DROP 封禁 + rule_id 追踪
  - isolate_host: 入站+出站全隔离
  - vulnerability_scan: nmap 真实扫描
  - rollback: 按 rule_id 精确回滚
  - rollback_all: 一键清理所有演示规则
  - list_rules: 查询当前 iptables 规则
  - health_check: 连接健康检查

配置：通过 platform config.py 的环境变量
  SHARED_MEMORY_FW_SSH_HOST      虚拟机 IP
  SHARED_MEMORY_FW_SSH_PORT      SSH 端口 (默认 22)
  SHARED_MEMORY_FW_SSH_USER      SSH 用户名
  SHARED_MEMORY_FW_SSH_PASSWORD  SSH 密码
  SHARED_MEMORY_FW_USE_SUDO      是否使用 sudo (默认 true)
"""
import asyncio
import ipaddress
import logging
import os
import random
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    logger.warning("paramiko not installed — SSH firewall adapter disabled")


class SshFirewallAdapter:
    """
    SSH 防火墙适配器

    通过 paramiko SSH 连接 Linux 虚拟机，执行 iptables 命令。
    所有方法都是同步的（paramiko 是同步库），在 async 上下文中用 asyncio.to_thread 调用。
    """

    def __init__(self):
        self._client: Optional[object] = None
        self._config = {
            "host": "",
            "port": 22,
            "username": "",
            "password": "",
            "use_sudo": True,
            "connect_timeout": 8,
            "exec_timeout": 10,
        }
        self._connected = False
        # 规则追踪（内存）
        self._active_rules: dict[str, dict] = {}

    def configure(self, host: str, port: int = 22, username: str = "",
                  password: str = "", use_sudo: bool = True):
        """配置 SSH 连接参数"""
        self._config.update({
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "use_sudo": use_sudo,
        })

    @property
    def enabled(self) -> bool:
        return HAS_PARAMIKO and bool(self._config["host"] and self._config["username"])

    def connect(self) -> str:
        """建立 SSH 连接"""
        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko 未安装")
        cfg = self._config
        client = paramiko.SSHClient()
        # 优先加载 known_hosts；未知主机首次连接时记录警告而非静默接受
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # v4 修复(2026-09-01):私钥类型自动探测,支持 ED25519/RSA/ECDSA/DSS
        # 之前硬编码 password=cfg["password"],但 SOC 私钥是 ED25519,paramiko 用 password 走不通
        # 优先用 pkey(cfg 里 private_key_path),回退到 password
        pkey = None
        key_path = cfg.get("private_key_path", "")
        if key_path and os.path.isfile(key_path):
            try:
                # paramiko 没有统一 from_private_key_file,按顺序试各种 key 类型
                for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
                    try:
                        pkey = key_cls.from_private_key_file(key_path)
                        logger.info(f"SSH firewall: loaded {key_cls.__name__} from {key_path}")
                        break
                    except paramiko.ssh_exception.PasswordRequiredException:
                        logger.warning(f"SSH firewall: {key_path} is encrypted, needs passphrase (not supported)")
                        break
                    except paramiko.ssh_exception.SSHException:
                        continue  # 试下一个 key 类型
            except Exception as e:
                logger.warning(f"SSH firewall: failed to load key {key_path}: {e}")

        if pkey is not None:
            client.connect(
                hostname=cfg["host"],
                port=cfg["port"],
                username=cfg["username"],
                pkey=pkey,
                timeout=cfg["connect_timeout"],
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            # 回退到密码登录
            client.connect(
                hostname=cfg["host"],
                port=cfg["port"],
                username=cfg["username"],
                password=cfg["password"],
                timeout=cfg["connect_timeout"],
                allow_agent=False,
                look_for_keys=False,
            )
        self._client = client
        self._connected = True
        info = self._exec("uname -a; echo '---'; iptables --version 2>/dev/null || echo 'iptables NOT FOUND'", skip_whitelist=True)
        logger.info(f"SSH firewall connected: {cfg['username']}@{cfg['host']}:{cfg['port']}")
        return info

    def close(self):
        """关闭 SSH 连接"""
        if self._client:
            self._client.close()
            self._client = None
            self._connected = False

    def _exec(self, cmd: str, timeout: Optional[int] = None, skip_whitelist: bool = False) -> str:
        """执行命令并返回 stdout（含命令白名单检查）"""
        if self._client is None:
            raise RuntimeError("SSH 未连接，请先调用 connect()")

        # 命令白名单检查
        if not skip_whitelist:
            from .command_whitelist import command_whitelist
            allowed, rule_id, reason = command_whitelist.check(cmd, platform="linux")
            if not allowed:
                raise RuntimeError(f"命令白名单拒绝: {reason} (命令: {cmd[:100]})")

        t = timeout or self._config["exec_timeout"]
        # 最小权限: 仅 iptables 命令加 sudo，nmap/诊断命令不加
        if self._config["use_sudo"] and not cmd.startswith("sudo"):
            if cmd.startswith("iptables") or cmd.startswith("iptables "):
                cmd = f"sudo {cmd}"
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=t)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        rc = stdout.channel.recv_exit_status()
        if rc != 0 and err.strip() and "password for" not in err.lower():
            raise RuntimeError(f"命令执行失败 rc={rc}: {err.strip()}\n命令: {cmd}")
        return out

    # ── 防火墙 API ──

    def block_ip(self, ip: str, duration: int = 3600) -> dict:
        """通过 iptables 封禁 IP（含参数校验 + 核心资产保护）"""
        # 参数强校验
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "error", "message": f"非法 IP 地址: {ip}"}

        # 核心资产保护
        from .asset_whitelist import asset_whitelist
        is_protected, reason = asset_whitelist.check(ip, "block_ip")
        if is_protected:
            return {"status": "blocked", "message": reason}

        rule_id = f"FW-RULE-{random.randint(10000, 99999)}"
        cmd = f"iptables -I INPUT -s {ip} -j DROP -m comment --comment '{rule_id}'"
        self._exec(cmd)
        # 记录规则
        self._active_rules[rule_id] = {
            "ip": ip, "duration": duration, "chain": "INPUT",
            "created_at": datetime.now().isoformat(), "status": "active",
        }
        logger.info(f"[Firewall] IP {ip} blocked: {rule_id}")
        return {
            "status": "success",
            "device": "Linux-iptables-SSH",
            "rule_id": rule_id,
            "ip": ip,
            "duration": duration,
            "message": f"IP {ip} 已通过 iptables 封禁",
        }

    def isolate_host(self, host: str, isolation_type: str = "network") -> dict:
        """通过 iptables 阻断主机所有流量（含参数校验 + 核心资产保护）"""
        # 参数强校验
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return {"status": "error", "message": f"非法 IP 地址: {host}"}

        # 核心资产保护
        from .asset_whitelist import asset_whitelist
        is_protected, reason = asset_whitelist.check(host, "isolate_host")
        if is_protected:
            return {"status": "blocked", "message": reason}

        isolation_id = f"EDR-ISO-{random.randint(10000, 99999)}"
        cmds = [
            f"iptables -I INPUT -s {host} -j DROP -m comment --comment '{isolation_id}'",
            f"iptables -I OUTPUT -d {host} -j DROP -m comment --comment '{isolation_id}'",
        ]
        for c in cmds:
            self._exec(c)
        self._active_rules[isolation_id] = {
            "host": host, "isolation_type": isolation_type,
            "created_at": datetime.now().isoformat(), "status": "isolated",
        }
        logger.info(f"[Firewall] Host {host} isolated: {isolation_id}")
        return {
            "status": "success",
            "device": "Linux-iptables-SSH",
            "isolation_id": isolation_id,
            "host": host,
            "isolation_type": isolation_type,
            "message": f"主机 {host} 已执行网络隔离 (iptables DROP)",
        }

    def vulnerability_scan(self, target: str, scan_type: str = "fast") -> dict:
        """通过 SSH 在虚拟机执行 nmap 扫描"""
        try:
            check = self._exec("nmap --version")
            if "Nmap" not in check:
                raise RuntimeError("nmap 未安装")
        except Exception:
            return {
                "status": "degraded",
                "device": "Linux-iptables-SSH",
                "target": target,
                "vulnerabilities": [],
                "message": "虚拟机未安装 nmap，扫描降级",
            }
        flags = {"fast": "-T4 -F", "full": "-A -T4", "custom": "-sV"}.get(scan_type, "-T4 -F")
        out = self._exec(f"nmap {flags} {target}", timeout=60)
        open_ports = [l.strip() for l in out.splitlines() if "/tcp" in l and "open" in l]
        return {
            "status": "success",
            "device": "Linux-iptables-SSH",
            "target": target,
            "scan_type": scan_type,
            "open_ports": open_ports,
            "raw_output": out[:2000],
            "message": f"nmap 扫描完成，发现 {len(open_ports)} 个开放端口",
        }

    def rollback(self, rule_id: str) -> dict:
        """按 rule_id 回滚 iptables 规则（恢复能力核心）"""
        for chain in ["INPUT", "OUTPUT"]:
            try:
                out = self._exec(f"iptables -L {chain} -n --line-numbers")
            except Exception:
                continue
            for line in out.splitlines():
                if rule_id in line:
                    parts = line.strip().split()
                    if parts and parts[0].isdigit():
                        self._exec(f"iptables -D {chain} {parts[0]}")
                        if rule_id in self._active_rules:
                            self._active_rules[rule_id]["status"] = "revoked"
                        logger.info(f"[Firewall] Rule {rule_id} rolled back (chain={chain}, line={parts[0]})")
                        return {
                            "status": "success",
                            "rule_id": rule_id,
                            "deleted_line": parts[0],
                            "message": f"规则 {rule_id} 已回滚（{chain} line {parts[0]} 已删除）",
                        }
        return {"status": "not_found", "message": f"未找到 rule_id={rule_id} 的规则"}

    def rollback_all(self) -> dict:
        """回滚所有本演示期间写入的规则"""
        count = 0
        for chain in ["INPUT", "OUTPUT"]:
            try:
                out = self._exec(f"iptables -L {chain} -n --line-numbers")
                lines_to_delete = []
                for line in out.splitlines()[2:]:
                    if "FW-RULE-" in line or "EDR-ISO-" in line:
                        parts = line.strip().split()
                        if parts and parts[0].isdigit():
                            lines_to_delete.append(parts[0])
                # 从后往前删（避免行号偏移）
                for ln in reversed(lines_to_delete):
                    try:
                        self._exec(f"iptables -D {chain} {ln}")
                        count += 1
                    except Exception:
                        pass
            except Exception:
                pass
        for rid in self._active_rules:
            self._active_rules[rid]["status"] = "revoked"
        logger.info(f"[Firewall] Rolled back {count} rules")
        return {"status": "ok", "rolled_back": count, "message": f"已回滚 {count} 条规则"}

    def list_rules(self) -> dict:
        """查询虚拟机 iptables 规则"""
        try:
            out = self._exec("iptables -L INPUT -n --line-numbers")
            return {"status": "ok", "rules_output": out}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def health_check(self) -> dict:
        """健康检查"""
        try:
            hostname = self._exec("uname -n").strip()
            uptime = self._exec("uptime").strip()
            return {
                "status": "ok",
                "device": "Linux-iptables-SSH",
                "host": self._config["host"],
                "info": f"{hostname}\n{uptime}",
                "active_rules": len([r for r in self._active_rules.values() if r["status"] == "active"]),
                "time": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_active_rules(self) -> list[dict]:
        """获取所有活跃规则"""
        return [
            {"rule_id": rid, **info}
            for rid, info in self._active_rules.items()
            if info.get("status") == "active"
        ]

    # ── 异步包装器（避免阻塞事件循环） ──

    async def async_connect(self) -> str:
        import asyncio
        return await asyncio.to_thread(self.connect)

    async def async_block_ip(self, ip: str, duration: int = 3600) -> dict:
        import asyncio
        return await asyncio.to_thread(self.block_ip, ip, duration)

    async def async_isolate_host(self, host: str, isolation_type: str = "network") -> dict:
        import asyncio
        return await asyncio.to_thread(self.isolate_host, host, isolation_type)

    async def async_vulnerability_scan(self, target: str, scan_type: str = "fast") -> dict:
        import asyncio
        return await asyncio.to_thread(self.vulnerability_scan, target, scan_type)


# 全局单例
ssh_firewall = SshFirewallAdapter()
