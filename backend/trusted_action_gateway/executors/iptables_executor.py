"""
Trusted Action Gateway — iptables 专用链执行器

核心安全设计:
  - 不让 Agent 直接修改任意系统防火墙规则
  - 建立专用链 AGENT_GUARD_INPUT / AGENT_GUARD_OUTPUT
  - 所有 Agent 生成的规则必须写入专用链
  - 每条规则绑定 action_id / incident_id / TTL / 创建时间
  - 记录 rollback_rule_id，支持幂等回滚
  - 禁止 Agent 直接执行任意 shell
  - 不使用 shell=True
  - 使用固定 wrapper（受控命令适配器）：所有命令由本执行器按固定模板构建，
    并通过 _is_known_template 校验后才委托执行

与 response_engine.ssh_firewall.SshFirewallAdapter 的关系:
  - SshFirewallAdapter 直接操作 INPUT/OUTPUT 主链（演示用）
  - IptablesChainExecutor 操作专用子链（生产用，更强隔离）
  - 复用 SshFirewallAdapter 的 paramiko SSH 连接（通过 ssh_adapter._exec）
  - 由于通用命令白名单 (CommandWhitelist) 的 pattern 仅匹配 INPUT/OUTPUT 主链，
    本执行器使用 skip_whitelist=True，并以其自身的固定模板校验作为等效安全控制

comment 格式: rule_id|incident_id|ttl_seconds|created_timestamp
"""
import asyncio
import ipaddress
import logging
import re
import time
from typing import TYPE_CHECKING, Any, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from response_engine.ssh_firewall import SshFirewallAdapter


class IptablesChainExecutor:
    """专用链 iptables 执行器

    所有 Agent 生成的规则都写入 AGENT_GUARD_INPUT / AGENT_GUARD_OUTPUT 专用链，
    避免污染系统主链规则。每条规则通过 comment 携带 rule_id / incident_id / TTL，
    支持按 action_id 幂等回滚、TTL 过期清理与执行后验证。
    """

    CHAIN_INPUT = "AGENT_GUARD_INPUT"
    CHAIN_OUTPUT = "AGENT_GUARD_OUTPUT"
    _KNOWN_CHAINS = {CHAIN_INPUT, CHAIN_OUTPUT}
    _RULE_ID_PREFIX = "AGT-"

    # ── 固定命令模板（受控命令适配器） ──
    # 仅允许以下 5 类命令，所有用户输入均被 regex 严格约束
    _RE_CREATE_CHAIN = re.compile(
        r"^iptables -N (AGENT_GUARD_INPUT|AGENT_GUARD_OUTPUT)$"
    )
    _RE_MOUNT_CHAIN = re.compile(
        r"^iptables -I (INPUT|OUTPUT) -j (AGENT_GUARD_INPUT|AGENT_GUARD_OUTPUT)$"
    )
    _RE_APPEND_DROP = re.compile(
        r"^iptables -A (AGENT_GUARD_INPUT|AGENT_GUARD_OUTPUT) "
        r"(-s|-d) (\d{1,3}(\.\d{1,3}){3}) -j DROP "
        r"-m comment --comment '([^']{1,200})'$"
    )
    _RE_LIST_CHAIN = re.compile(
        r"^iptables -L (AGENT_GUARD_INPUT|AGENT_GUARD_OUTPUT|INPUT|OUTPUT) "
        r"-n --line-numbers$"
    )
    _RE_DELETE_LINE = re.compile(
        r"^iptables -D (AGENT_GUARD_INPUT|AGENT_GUARD_OUTPUT) (\d+)$"
    )

    def __init__(self, ssh_adapter: "Optional[SshFirewallAdapter]" = None):
        """
        Args:
            ssh_adapter: SshFirewallAdapter 实例（复用现有 paramiko SSH 连接）。
                         若为 None，使用 mock 模式（内存模拟 iptables 行为）。
        """
        self._ssh = ssh_adapter
        self._initialized = False
        # action_id -> 规则元数据（内存追踪）
        self._active_rules: dict[str, dict] = {}
        # mock 模式状态
        self._mock_chains: dict[str, list[dict]] = {}
        self._mock_mounted: set[tuple[str, str]] = set()

    @property
    def is_mock(self) -> bool:
        """是否为 mock 模式（无 SSH 连接）"""
        return self._ssh is None

    # ──────────────────────────────────────────────────────────
    # 初始化
    # ──────────────────────────────────────────────────────────

    async def initialize(self) -> dict:
        """初始化专用链 — 创建 AGENT_GUARD_INPUT/OUTPUT 并挂载到 INPUT/OUTPUT

        幂等操作：已存在的链和挂载点不会重复创建。

        Returns:
            {"initialized": bool, "chains": list[str], "mock": bool, "error"?: str}
        """
        try:
            # 1. 创建专用链（幂等）
            for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
                if not await self._chain_exists(chain):
                    await self._run_cmd(f"iptables -N {chain}")
                    logger.info(f"[IptablesExec] Created chain {chain}")

            # 2. 挂载到主链（幂等）
            mounts = [
                ("INPUT", self.CHAIN_INPUT),
                ("OUTPUT", self.CHAIN_OUTPUT),
            ]
            for parent, child in mounts:
                if not await self._is_mounted(parent, child):
                    await self._run_cmd(f"iptables -I {parent} -j {child}")
                    logger.info(f"[IptablesExec] Mounted {child} -> {parent}")

            self._initialized = True
            return {
                "initialized": True,
                "chains": [self.CHAIN_INPUT, self.CHAIN_OUTPUT],
                "mock": self.is_mock,
            }
        except Exception as e:
            logger.error(f"[IptablesExec] initialize failed: {e}")
            return {
                "initialized": False,
                "error": str(e),
                "mock": self.is_mock,
            }

    # ──────────────────────────────────────────────────────────
    # 防火墙 API
    # ──────────────────────────────────────────────────────────

    async def block_ip(
        self,
        ip: str,
        action_id: str,
        incident_id: str,
        ttl_seconds: int = 3600,
        reason: str = "",
    ) -> dict:
        """封禁 IP — 写入 AGENT_GUARD_INPUT 专用链

        Args:
            ip: 待封禁的 IP 地址
            action_id: 动作唯一标识（用于生成 rule_id 与幂等回滚）
            incident_id: 事件 ID（写入 comment 便于溯源）
            ttl_seconds: 规则存活时间（秒），到期后可被 cleanup_expired 清理
            reason: 封禁原因（记录到内存，不写入 iptables）

        Returns:
            {"success": bool, "rule_id": str, "chain": str, ...}
        """
        # 参数强校验
        ip_error = self._validate_ip(ip)
        if ip_error:
            return {"success": False, "error": ip_error, "rule_id": ""}

        inc_error = self._validate_incident_id(incident_id)
        if inc_error:
            return {"success": False, "error": inc_error, "rule_id": ""}

        if not action_id:
            return {"success": False, "error": "action_id 不能为空", "rule_id": ""}

        if not self._initialized:
            init_result = await self.initialize()
            if not init_result.get("initialized"):
                return {
                    "success": False,
                    "error": f"初始化失败: {init_result.get('error', '')}",
                    "rule_id": "",
                }

        rule_id = f"AGT-{action_id[:8].upper()}"
        created_at = time.time()
        comment = self._build_comment(rule_id, incident_id, ttl_seconds, created_at)

        cmd = (
            f"iptables -A {self.CHAIN_INPUT} -s {ip} -j DROP "
            f"-m comment --comment '{comment}'"
        )
        try:
            await self._run_cmd(cmd)
        except Exception as e:
            logger.error(f"[IptablesExec] block_ip exec failed: {e}")
            return {"success": False, "error": str(e), "rule_id": rule_id}

        # 记录到内存
        self._active_rules[action_id] = {
            "rule_id": rule_id,
            "action_id": action_id,
            "incident_id": incident_id,
            "ip": ip,
            "chain": self.CHAIN_INPUT,
            "ttl_seconds": ttl_seconds,
            "created_at": created_at,
            "reason": reason,
            "status": "active",
        }
        logger.info(
            f"[IptablesExec] block_ip {ip} -> {rule_id} "
            f"(action={action_id}, ttl={ttl_seconds}s)"
        )
        return {
            "success": True,
            "rule_id": rule_id,
            "chain": self.CHAIN_INPUT,
            "action_id": action_id,
            "incident_id": incident_id,
            "ip": ip,
            "ttl_seconds": ttl_seconds,
            "created_at": created_at,
        }

    async def isolate_host(
        self,
        host: str,
        action_id: str,
        incident_id: str,
        isolation_type: str = "network",
        ttl_seconds: int = 7200,
    ) -> dict:
        """隔离主机 — 写入 AGENT_GUARD_INPUT 和 AGENT_GUARD_OUTPUT 两条专用链

        INPUT 链阻断源为 host 的入站流量，OUTPUT 链阻断目标为 host 的出站流量。

        Args:
            host: 待隔离的主机 IP
            action_id: 动作唯一标识
            incident_id: 事件 ID
            isolation_type: 隔离类型（记录用，默认 network）
            ttl_seconds: 规则存活时间（秒）

        Returns:
            {"success": bool, "rule_id": str, "chains": list[str], ...}
        """
        ip_error = self._validate_ip(host)
        if ip_error:
            return {"success": False, "error": ip_error, "rule_id": ""}

        inc_error = self._validate_incident_id(incident_id)
        if inc_error:
            return {"success": False, "error": inc_error, "rule_id": ""}

        if not action_id:
            return {"success": False, "error": "action_id 不能为空", "rule_id": ""}

        if not self._initialized:
            init_result = await self.initialize()
            if not init_result.get("initialized"):
                return {
                    "success": False,
                    "error": f"初始化失败: {init_result.get('error', '')}",
                    "rule_id": "",
                }

        rule_id = f"AGT-{action_id[:8].upper()}"
        created_at = time.time()
        comment = self._build_comment(rule_id, incident_id, ttl_seconds, created_at)

        # INPUT 链按源 IP 阻断，OUTPUT 链按目标 IP 阻断
        cmds = [
            (
                f"iptables -A {self.CHAIN_INPUT} -s {host} -j DROP "
                f"-m comment --comment '{comment}'"
            ),
            (
                f"iptables -A {self.CHAIN_OUTPUT} -d {host} -j DROP "
                f"-m comment --comment '{comment}'"
            ),
        ]
        try:
            for cmd in cmds:
                await self._run_cmd(cmd)
        except Exception as e:
            logger.error(f"[IptablesExec] isolate_host exec failed: {e}")
            # 尽力回滚已写入的规则
            await self._delete_by_rule_id(self.CHAIN_INPUT, rule_id)
            await self._delete_by_rule_id(self.CHAIN_OUTPUT, rule_id)
            return {"success": False, "error": str(e), "rule_id": rule_id}

        self._active_rules[action_id] = {
            "rule_id": rule_id,
            "action_id": action_id,
            "incident_id": incident_id,
            "host": host,
            "chains": [self.CHAIN_INPUT, self.CHAIN_OUTPUT],
            "isolation_type": isolation_type,
            "ttl_seconds": ttl_seconds,
            "created_at": created_at,
            "status": "active",
        }
        logger.info(
            f"[IptablesExec] isolate_host {host} -> {rule_id} "
            f"(action={action_id}, type={isolation_type}, ttl={ttl_seconds}s)"
        )
        return {
            "success": True,
            "rule_id": rule_id,
            "chains": [self.CHAIN_INPUT, self.CHAIN_OUTPUT],
            "action_id": action_id,
            "incident_id": incident_id,
            "host": host,
            "isolation_type": isolation_type,
            "ttl_seconds": ttl_seconds,
            "created_at": created_at,
        }

    async def rollback(self, action_id: str) -> dict:
        """按 action_id 幂等回滚 — 通过 comment 中的 rule_id 匹配并删除

        若 action_id 不在内存追踪中，仍会根据 action_id 推导 rule_id 并扫描专用链。

        Returns:
            {"success": bool, "rule_id": str, "deleted_lines": list[dict]}
        """
        meta = self._active_rules.get(action_id)
        rule_id: str
        if meta:
            rule_id = meta.get("rule_id", "")
        else:
            # 内存中不存在，按 action_id 推导 rule_id 尝试扫描
            rule_id = f"AGT-{action_id[:8].upper()}"
            logger.info(
                f"[IptablesExec] rollback: action_id={action_id} not in memory, "
                f"inferring rule_id={rule_id}"
            )

        deleted_lines: list[dict] = []
        for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
            deleted = await self._delete_by_rule_id(chain, rule_id)
            deleted_lines.extend(deleted)

        if meta:
            meta["status"] = "revoked"
            meta["revoked_at"] = time.time()

        logger.info(
            f"[IptablesExec] rollback action_id={action_id} rule_id={rule_id} "
            f"deleted={len(deleted_lines)}"
        )
        return {
            "success": len(deleted_lines) > 0,
            "rule_id": rule_id,
            "action_id": action_id,
            "deleted_lines": deleted_lines,
        }

    async def rollback_all(self) -> dict:
        """一键回滚所有 Agent 生成的规则（含 AGT- 前缀的 comment）

        从后往前删除以避免行号偏移。

        Returns:
            {"success": bool, "rolled_back": int, "deleted_lines": list[dict]}
        """
        deleted_lines: list[dict] = []
        for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
            try:
                rules = await self.list_rules(chain)
            except Exception as e:
                logger.warning(f"[IptablesExec] rollback_all list {chain} failed: {e}")
                continue

            matching = [
                r for r in rules
                if str(r.get("rule_id", "")).startswith(self._RULE_ID_PREFIX)
            ]
            # 从后往前删（避免行号偏移）
            for r in reversed(matching):
                line = r["line"]
                try:
                    await self._run_cmd(f"iptables -D {chain} {line}")
                    deleted_lines.append({
                        "chain": chain,
                        "line": line,
                        "rule_id": r.get("rule_id", ""),
                    })
                except Exception as e:
                    logger.warning(
                        f"[IptablesExec] rollback_all delete {chain} line {line}: {e}"
                    )

        # 标记所有内存规则为已撤销
        now = time.time()
        for meta in self._active_rules.values():
            meta["status"] = "revoked"
            meta["revoked_at"] = now

        logger.info(
            f"[IptablesExec] rollback_all completed, deleted={len(deleted_lines)}"
        )
        return {
            "success": True,
            "rolled_back": len(deleted_lines),
            "deleted_lines": deleted_lines,
        }

    async def list_rules(self, chain: Optional[str] = None) -> list[dict]:
        """列出专用链中的规则

        Args:
            chain: 指定链名（AGENT_GUARD_INPUT / AGENT_GUARD_OUTPUT）。
                   若为 None，列出两条专用链的全部规则。

        Returns:
            规则列表，每项含 line / chain / src / dst / comment / rule_id /
            incident_id / ttl_seconds / created_at
        """
        if chain:
            chains = [chain]
        else:
            chains = [self.CHAIN_INPUT, self.CHAIN_OUTPUT]

        all_rules: list[dict] = []
        for c in chains:
            try:
                out = await self._run_cmd(f"iptables -L {c} -n --line-numbers")
                all_rules.extend(self._parse_iptables_output(out, c))
            except Exception as e:
                logger.warning(f"[IptablesExec] list_rules {c} failed: {e}")
        return all_rules

    async def verify_rule_exists(self, rule_id: str) -> dict:
        """验证规则是否真正存在于专用链

        扫描 AGENT_GUARD_INPUT 和 AGENT_GUARD_OUTPUT，匹配 comment 中的 rule_id。

        Returns:
            {"exists": bool, "rule_id": str, "chain"?: str, "line"?: int,
             "ip"?: str, "ttl_remaining"?: int, "created_at"?: float}
        """
        for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
            try:
                rules = await self.list_rules(chain)
            except Exception:
                continue
            for r in rules:
                if r.get("rule_id") == rule_id:
                    src = r.get("src", "")
                    dst = r.get("dst", "")
                    # INPUT 链按源 IP，OUTPUT 链按目标 IP
                    if src and src != "0.0.0.0/0":
                        ip = src
                    else:
                        ip = dst
                    return {
                        "exists": True,
                        "rule_id": rule_id,
                        "chain": chain,
                        "line": r["line"],
                        "ip": ip,
                        "ttl_remaining": self._calc_ttl_remaining(r),
                        "created_at": r.get("created_at", 0),
                    }
        return {"exists": False, "rule_id": rule_id}

    async def cleanup_expired(self) -> dict:
        """清理过期规则 — 基于 comment 中的 TTL 与创建时间

        扫描所有专用链规则，若 created_at + ttl_seconds < now 则删除。

        Returns:
            {"success": bool, "cleaned": int, "deleted": list[dict]}
        """
        now = time.time()
        deleted: list[dict] = []
        for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
            try:
                rules = await self.list_rules(chain)
            except Exception as e:
                logger.warning(f"[IptablesExec] cleanup_expired list {chain}: {e}")
                continue

            expired = [
                r for r in rules
                if self._is_expired(r, now)
            ]
            # 从后往前删
            for r in reversed(expired):
                line = r["line"]
                try:
                    await self._run_cmd(f"iptables -D {chain} {line}")
                    deleted.append({
                        "chain": chain,
                        "line": line,
                        "rule_id": r.get("rule_id", ""),
                    })
                except Exception as e:
                    logger.warning(
                        f"[IptablesExec] cleanup_expired delete {chain} {line}: {e}"
                    )

        if deleted:
            logger.info(f"[IptablesExec] cleanup_expired removed {len(deleted)} rules")
        return {"success": True, "cleaned": len(deleted), "deleted": deleted}

    async def health_check(self) -> dict:
        """健康检查 — 验证专用链是否存在且可访问

        Returns:
            {"status": "ok"|"degraded", "chains": dict, "initialized": bool,
             "mock": bool, "active_rules": int}
        """
        chains_ok: dict[str, bool] = {}
        for chain in [self.CHAIN_INPUT, self.CHAIN_OUTPUT]:
            try:
                await self._run_cmd(f"iptables -L {chain} -n --line-numbers")
                chains_ok[chain] = True
            except Exception:
                chains_ok[chain] = False

        all_ok = all(chains_ok.values()) if chains_ok else False
        active_count = sum(
            1 for r in self._active_rules.values() if r.get("status") == "active"
        )
        return {
            "status": "ok" if all_ok else "degraded",
            "chains": chains_ok,
            "initialized": self._initialized,
            "mock": self.is_mock,
            "active_rules": active_count,
        }

    # ──────────────────────────────────────────────────────────
    # comment 构建与解析
    # ──────────────────────────────────────────────────────────

    def _build_comment(
        self,
        rule_id: str,
        incident_id: str,
        ttl_seconds: int,
        created_at: float,
    ) -> str:
        """构建规则 comment — 格式: rule_id|incident_id|ttl_seconds|created_timestamp"""
        return f"{rule_id}|{incident_id}|{ttl_seconds}|{int(created_at)}"

    def _parse_comment(self, comment: str) -> dict:
        """解析规则 comment

        Returns:
            {"rule_id": str, "incident_id": str, "ttl_seconds": int, "created_at": float}
        """
        if not comment:
            return {
                "rule_id": "",
                "incident_id": "",
                "ttl_seconds": 0,
                "created_at": 0,
            }
        parts = comment.split("|")
        if len(parts) >= 4:
            return {
                "rule_id": parts[0],
                "incident_id": parts[1],
                "ttl_seconds": int(parts[2]) if parts[2].isdigit() else 0,
                "created_at": (
                    float(parts[3]) if parts[3].replace(".", "").isdigit() else 0.0
                ),
            }
        # 容错：仅 rule_id
        return {
            "rule_id": comment,
            "incident_id": "",
            "ttl_seconds": 0,
            "created_at": 0.0,
        }

    # ──────────────────────────────────────────────────────────
    # 内部工具
    # ──────────────────────────────────────────────────────────

    async def _chain_exists(self, chain: str) -> bool:
        """检查专用链是否已存在"""
        try:
            out = await self._run_cmd(f"iptables -L {chain} -n --line-numbers")
            return f"Chain {chain}" in out
        except Exception:
            return False

    async def _is_mounted(self, parent: str, child: str) -> bool:
        """检查专用链是否已挂载到主链"""
        try:
            out = await self._run_cmd(f"iptables -L {parent} -n --line-numbers")
            return child in out
        except Exception:
            return False

    async def _delete_by_rule_id(self, chain: str, rule_id: str) -> list[dict]:
        """按 rule_id 删除指定链中的规则（从后往前删以避免行号偏移）"""
        try:
            rules = await self.list_rules(chain)
        except Exception as e:
            logger.warning(f"[IptablesExec] _delete_by_rule_id list {chain}: {e}")
            return []

        matching = [r for r in rules if r.get("rule_id") == rule_id]
        deleted: list[dict] = []
        for r in reversed(matching):
            line = r["line"]
            try:
                await self._run_cmd(f"iptables -D {chain} {line}")
                deleted.append({"chain": chain, "line": line})
            except Exception as e:
                logger.warning(
                    f"[IptablesExec] delete {chain} line {line} failed: {e}"
                )
        return deleted

    def _calc_ttl_remaining(self, rule: dict) -> int:
        """计算规则剩余 TTL（秒）"""
        ttl = rule.get("ttl_seconds", 0)
        created = rule.get("created_at", 0)
        if ttl <= 0 or created <= 0:
            return 0
        remaining = int(ttl - (time.time() - float(created)))
        return max(0, remaining)

    def _is_expired(self, rule: dict, now: float) -> bool:
        """判断规则是否已过期"""
        ttl = rule.get("ttl_seconds", 0)
        created = rule.get("created_at", 0)
        if ttl <= 0 or created <= 0:
            return False
        return (float(created) + float(ttl)) < now

    @staticmethod
    def _validate_ip(ip: str) -> str:
        """校验 IP 格式，返回错误信息（空字符串表示通过）"""
        if not ip:
            return "IP 地址不能为空"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"非法 IP 地址: {ip}"
        return ""

    @staticmethod
    def _validate_incident_id(incident_id: str) -> str:
        """校验 incident_id — 禁止包含 '|'（comment 分隔符）和 "'"（shell 引号逃逸）"""
        if not incident_id:
            return "incident_id 不能为空"
        if "|" in incident_id:
            return "incident_id 包含非法字符 '|'"
        if "'" in incident_id:
            return "incident_id 包含非法字符单引号"
        return ""

    def _is_known_template(self, cmd: str) -> bool:
        """校验命令是否属于已知固定模板（受控命令适配器核心）"""
        cmd = cmd.strip()
        for pattern in [
            self._RE_CREATE_CHAIN,
            self._RE_MOUNT_CHAIN,
            self._RE_APPEND_DROP,
            self._RE_LIST_CHAIN,
            self._RE_DELETE_LINE,
        ]:
            if pattern.match(cmd):
                return True
        return False

    async def _run_cmd(self, cmd: str) -> str:
        """执行受控命令 — 校验固定模板后委托执行

        安全保证:
          - 命令必须匹配 _is_known_template 中的 5 类固定模板之一
          - 模板 regex 对 IP / chain / comment 均有严格约束
          - comment 不允许包含单引号（防止 shell 引号逃逸）
          - 不使用 shell=True（paramiko exec_command 直接执行）
        """
        if not self._is_known_template(cmd):
            raise RuntimeError(f"拒绝执行未知命令模板: {cmd[:120]}")

        if self.is_mock:
            return self._mock_exec(cmd)

        # 委托给 ssh_adapter._exec（skip_whitelist=True，由本执行器做模板校验）
        return await asyncio.to_thread(self._ssh._exec, cmd, None, True)

    # ──────────────────────────────────────────────────────────
    # mock 模式实现（无 SSH 时的内存模拟）
    # ──────────────────────────────────────────────────────────

    def _mock_exec(self, cmd: str) -> str:
        """mock 模式执行 — 模拟 iptables 行为"""
        cmd = cmd.strip()

        # -N chain（创建专用链）
        m = self._RE_CREATE_CHAIN.match(cmd)
        if m:
            chain = m.group(1)
            self._mock_chains.setdefault(chain, [])
            return ""

        # -I parent -j child（挂载到主链）
        m = self._RE_MOUNT_CHAIN.match(cmd)
        if m:
            parent, child = m.group(1), m.group(2)
            self._mock_mounted.add((parent, child))
            return ""

        # -A chain -s/-d ip -j DROP --comment 'c'（追加规则）
        m = self._RE_APPEND_DROP.match(cmd)
        if m:
            chain = m.group(1)
            direction = m.group(2)
            ip = m.group(3)
            comment = m.group(5)
            self._mock_chains.setdefault(chain, []).append({
                "src": ip if direction == "-s" else "0.0.0.0/0",
                "dst": ip if direction == "-d" else "0.0.0.0/0",
                "target": "DROP",
                "comment": comment,
            })
            return ""

        # -L chain -n --line-numbers（列出规则）
        m = self._RE_LIST_CHAIN.match(cmd)
        if m:
            return self._mock_format_chain(m.group(1))

        # -D chain line（按行号删除）
        m = self._RE_DELETE_LINE.match(cmd)
        if m:
            chain = m.group(1)
            line = int(m.group(2))
            rules = self._mock_chains.get(chain, [])
            if 1 <= line <= len(rules):
                rules.pop(line - 1)
                return ""
            raise RuntimeError(
                f"mock: 行号 {line} 超出范围 (chain={chain}, len={len(rules)})"
            )

        raise RuntimeError(f"mock: 未识别命令: {cmd}")

    def _mock_format_chain(self, chain: str) -> str:
        """格式化 mock 链输出（模拟 iptables -L 输出格式）"""
        if chain in self._mock_chains:
            rules = self._mock_chains[chain]
            refs = sum(1 for _, c in self._mock_mounted if c == chain)
            lines = [f"Chain {chain} ({refs} references)"]
            lines.append(
                "num  target  prot  opt  source  destination  comment"
            )
            for i, r in enumerate(rules, 1):
                lines.append(
                    f"{i}    DROP    all    --    {r['src']}    {r['dst']}    "
                    f"/* {r['comment']} */"
                )
            return "\n".join(lines) + "\n"

        if chain in ("INPUT", "OUTPUT"):
            refs = [c for p, c in self._mock_mounted if p == chain]
            lines = [f"Chain {chain} (policy ACCEPT)"]
            lines.append("num  target  prot  opt  source  destination")
            for i, c in enumerate(refs, 1):
                lines.append(
                    f"{i}    {c}    all    --    0.0.0.0/0    0.0.0.0/0"
                )
            return "\n".join(lines) + "\n"

        raise RuntimeError(f"mock: 链 {chain} 不存在")

    def _parse_iptables_output(self, output: str, chain: str) -> list[dict]:
        """解析 iptables -L 输出，提取规则元数据

        支持真实 iptables 与 mock 输出（comment 以 /* ... */ 包裹）。
        """
        rules: list[dict] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Chain") or line.startswith("num"):
                continue
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue

            line_num = int(parts[0])

            # 提取 comment（iptables 以 /* comment */ 形式显示）
            comment = ""
            m = re.search(r"/\*\s*(.*?)\s*\*/", line)
            if m:
                comment = m.group(1)

            # 列顺序: num target prot opt source destination [comment]
            src = parts[4] if len(parts) > 4 else ""
            dst = parts[5] if len(parts) > 5 else ""

            meta = self._parse_comment(comment)
            rules.append({
                "line": line_num,
                "chain": chain,
                "src": src,
                "dst": dst,
                "comment": comment,
                **meta,
            })
        return rules
