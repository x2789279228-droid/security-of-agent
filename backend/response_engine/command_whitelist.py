"""
命令白名单 (Command Whitelist)

SSH 执行层的最后一道防线：只有匹配白名单规则的命令才能被发送到远程主机。
默认拒绝一切未列入白名单的命令。

白名单按平台分组 (linux / windows)，每条规则包含:
  - pattern:  命令正则（必须从头匹配）
  - desc:     规则说明
  - forbidden: 命令中禁止出现的子串（注入检测）

调用方式:
    from response_engine.command_whitelist import command_whitelist
    allowed, rule_id, reason = command_whitelist.check(cmd, platform="linux")
"""
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 通用注入特征 — 任何命令中出现这些子串即拒绝
GLOBAL_FORBIDDEN = [
    "&&", "||", ";", "|", ">", "<", "`", "$(",
    "rm -rf", "mkfs", "dd if=", ":(){", "fork",
    "wget ", "curl ", "nc ", "ncat ",
    "/etc/passwd", "/etc/shadow",
    "chmod 777", "chmod +s",
]


@dataclass
class WhitelistRule:
    """单条白名单规则"""
    rule_id: str
    pattern: str
    desc: str
    forbidden: list[str] = field(default_factory=list)
    _compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern)

    def matches(self, command: str) -> bool:
        return bool(self._compiled.match(command))


# ── Linux 白名单 (iptables / nmap / 基础诊断) ──

LINUX_RULES: list[WhitelistRule] = [
    WhitelistRule(
        rule_id="LX-001",
        pattern=r"^(sudo\s+)?iptables\s+-I\s+(INPUT|OUTPUT)\s+-[sd]\s+\d{1,3}(\.\d{1,3}){3}\s+-j\s+DROP(\s+-m\s+comment\s+--comment\s+'[A-Za-z0-9\-]+')?$",
        desc="iptables 插入 DROP 规则（封禁/隔离）",
    ),
    WhitelistRule(
        rule_id="LX-002",
        pattern=r"^(sudo\s+)?iptables\s+-D\s+(INPUT|OUTPUT)\s+\d+$",
        desc="iptables 按行号删除规则（回滚）",
    ),
    WhitelistRule(
        rule_id="LX-003",
        pattern=r"^(sudo\s+)?iptables\s+-L\s+(INPUT|OUTPUT)\s+-n\s+--line-numbers$",
        desc="iptables 列出规则（查询）",
    ),
    WhitelistRule(
        rule_id="LX-004",
        pattern=r"^iptables\s+--version$",
        desc="iptables 版本检查",
    ),
    WhitelistRule(
        rule_id="LX-005",
        pattern=r"^nmap\s+(-T[0-4]\s+)?(-F|-A|-sV)(\s+-T[0-4])?\s+\d{1,3}(\.\d{1,3}){3}$",
        desc="nmap 扫描（仅限 IP 目标，禁止域名/参数注入）",
        forbidden=["--script", "-oN", "-oX", "-oG"],
    ),
    WhitelistRule(
        rule_id="LX-006",
        pattern=r"^nmap\s+--version$",
        desc="nmap 版本检查",
    ),
    WhitelistRule(
        rule_id="LX-007",
        pattern=r"^uname\s+(-a|-n)$",
        desc="系统信息（诊断）",
    ),
    WhitelistRule(
        rule_id="LX-008",
        pattern=r"^uptime$",
        desc="运行时间（健康检查）",
    ),
    WhitelistRule(
        rule_id="LX-009",
        pattern=r"^echo\s+'---'$",
        desc="分隔符输出（连接诊断用）",
    ),
]

# ── Windows 白名单 (netsh / PowerShell 受限) ──

WINDOWS_RULES: list[WhitelistRule] = [
    WhitelistRule(
        rule_id="WIN-001",
        pattern=r'^netsh\s+advfirewall\s+firewall\s+add\s+rule\s+name="RE_[A-Za-z0-9_]+"\s+direction=(in|out)\s+action=block\s+remoteip="\d{1,3}(\.\d{1,3}){3}"(\s+description="[^"]*")?$',
        desc="Windows 防火墙添加封禁规则",
    ),
    WhitelistRule(
        rule_id="WIN-002",
        pattern=r'^netsh\s+advfirewall\s+firewall\s+delete\s+rule\s+name="RE_[A-Za-z0-9_]+"$',
        desc="Windows 防火墙删除规则（回滚）",
    ),
    WhitelistRule(
        rule_id="WIN-003",
        pattern=r'^netsh\s+advfirewall\s+firewall\s+show\s+rule\s+name="RE_[A-Za-z0-9_]+"$',
        desc="Windows 防火墙查询规则（验证）",
    ),
    WhitelistRule(
        rule_id="WIN-004",
        pattern=r"^powershell\s+-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-EncodedCommand\s+[A-Za-z0-9+/=]+$",
        desc="PowerShell 编码命令（仅限 Base64 编码）",
        forbidden=["-Command ", "-File ", "-Path "],
    ),
]


class CommandWhitelist:
    """命令白名单检查器"""

    def __init__(self):
        self._rules: dict[str, list[WhitelistRule]] = {
            "linux": LINUX_RULES,
            "windows": WINDOWS_RULES,
        }

    def check(self, command: str, platform: str = "linux") -> tuple[bool, str, str]:
        """
        检查命令是否在白名单中

        Args:
            command: 待检查的完整命令
            platform: "linux" | "windows"

        Returns:
            (allowed, rule_id, reason)
        """
        command = command.strip()
        if not command:
            return False, "", "空命令"

        # 1. 全局注入检测
        for token in GLOBAL_FORBIDDEN:
            if token in command:
                logger.warning(
                    f"[Whitelist] REJECTED (global forbidden '{token}'): {command[:120]}"
                )
                return False, "GLOBAL", f"命令包含禁止子串: '{token}'"

        # 2. 按平台匹配白名单
        rules = self._rules.get(platform, [])
        for rule in rules:
            if rule.matches(command):
                # 匹配到白名单规则后，再检查该规则的局部禁止子串
                for fb in rule.forbidden:
                    if fb in command:
                        logger.warning(
                            f"[Whitelist] REJECTED (rule {rule.rule_id} forbidden '{fb}'): "
                            f"{command[:120]}"
                        )
                        return False, rule.rule_id, f"规则 {rule.rule_id} 禁止子串: '{fb}'"

                logger.debug(f"[Whitelist] ALLOWED by {rule.rule_id}: {command[:80]}")
                return True, rule.rule_id, rule.desc

        # 3. 默认拒绝
        logger.warning(f"[Whitelist] REJECTED (no match): {command[:120]}")
        return False, "", f"命令不在白名单中 (platform={platform})"

    def add_rule(self, platform: str, rule: WhitelistRule):
        """动态添加白名单规则"""
        self._rules.setdefault(platform, []).append(rule)
        logger.info(f"[Whitelist] Added rule {rule.rule_id} for {platform}: {rule.desc}")

    def list_rules(self, platform: str = "") -> list[dict]:
        """列出所有白名单规则"""
        result = []
        for plat, rules in self._rules.items():
            if platform and plat != platform:
                continue
            for r in rules:
                result.append({
                    "platform": plat,
                    "rule_id": r.rule_id,
                    "desc": r.desc,
                    "pattern": r.pattern,
                })
        return result


command_whitelist = CommandWhitelist()
