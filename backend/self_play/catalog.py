"""MITRE 风格 TTP 课程目录。

红队从这里取攻击场景;变体故意不用库存 Sigma 关键字,用来制造「蓝队没见过」的样本。
所有 message 都是 SOC 日志描述,不含利用 payload / 真实攻击工具调用。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


MAX_CURRICULUM_LEVEL = 6

KILL_CHAIN_ORDER = (
    "recon", "initial_access", "execution", "privilege",
    "lateral", "c2", "exfil", "evasion",
)


@dataclass(frozen=True)
class TTPSpec:
    ttp_id: str
    name: str
    mitre_id: str
    tactic: str
    kill_chain: str
    curriculum_level: int
    event_type: str
    severity: str
    protocol: str
    message: str
    dst_role: str
    tool: str
    variants: tuple[dict, ...] = field(default_factory=tuple)
    sub_technique_id: str = ""
    behaviors: tuple[str, ...] = field(default_factory=tuple)
    data_sources: tuple[str, ...] = field(default_factory=tuple)


# 变体 event/message 刻意避开 SIG-001..011 的 event_contains 关键字
_TTPS: tuple[TTPSpec, ...] = (
    TTPSpec(
        ttp_id="ttp-t1046-scan",
        name="Network Service Discovery",
        mitre_id="T1046",
        tactic="discovery",
        kill_chain="recon",
        curriculum_level=0,
        event_type="PORT_SCAN",
        severity="medium",
        protocol="tcp",
        message="外部主机对内网进行端口扫描",
        dst_role="web",
        tool="sim:port_probe",
        variants=(
            {"event": "SYN_ENUM", "message": "大量半开连接探测服务存活状态", "protocol": "tcp"},
            {"event": "SVC_MAP", "message": "对常见管理端口做连通性探测", "protocol": "tcp"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1110-brute",
        name="Brute Force",
        mitre_id="T1110",
        tactic="credential-access",
        kill_chain="initial_access",
        curriculum_level=1,
        event_type="BRUTE_FORCE",
        severity="high",
        protocol="ssh",
        message="SSH 暴力破解攻击,已尝试大量口令",
        dst_role="jump",
        tool="sim:auth_spray",
        variants=(
            {"event": "AUTH_SPRAY", "message": "同一来源对多个账号进行口令喷洒", "protocol": "ssh"},
            {"event": "CRED_STUFF", "message": "使用泄露凭据组合尝试远程登录", "protocol": "rdp"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1190-web",
        name="Exploit Public-Facing Application",
        mitre_id="T1190",
        tactic="initial-access",
        kill_chain="initial_access",
        curriculum_level=2,
        event_type="SQL_INJECTION",
        severity="high",
        protocol="http",
        message="Web 应用查询接口出现异常参数模式",
        dst_role="web",
        tool="sim:web_probe",
        variants=(
            {"event": "QUERY_ABUSE", "message": "检索接口参数结构偏离基线", "protocol": "http"},
            {"event": "INPUT_ANOMALY", "message": "表单字段包含非常规转义序列", "protocol": "http"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1059-script",
        name="Command and Scripting Interpreter",
        mitre_id="T1059",
        tactic="execution",
        kill_chain="execution",
        curriculum_level=3,
        event_type="SCRIPT_EXEC",
        severity="high",
        protocol="local",
        message="主机上出现解释器拉起异常脚本",
        dst_role="ws",
        tool="sim:script_watch",
        variants=(
            {"event": "LOTL_ADMIN", "message": "内置管理工具被用来执行非计划任务", "protocol": "local"},
            {"event": "INTERPRETER_SPAWN", "message": "办公时段外解释器进程被拉起", "protocol": "local"},
        ),
        behaviors=("scripting", "interpreter"),
        data_sources=("process", "command"),
    ),
    TTPSpec(
        ttp_id="ttp-t1059-001-ps",
        name="PowerShell",
        mitre_id="T1059.001",
        tactic="execution",
        kill_chain="execution",
        curriculum_level=3,
        event_type="POSH_EXEC",
        severity="high",
        protocol="local",
        message="主机上出现 PowerShell 解释器执行非计划命令",
        dst_role="ws",
        tool="sim:script_watch",
        variants=(
            {"event": "POSH_ENCODED", "message": "PowerShell 命令行携带不可读编码参数", "protocol": "local"},
            {"event": "POSH_OFFHOUR", "message": "非工作时段 PowerShell 拉起子进程", "protocol": "local"},
        ),
        sub_technique_id="T1059.001",
        behaviors=("powershell", "shell"),
        data_sources=("process", "command"),
    ),
    TTPSpec(
        ttp_id="ttp-t1059-006-py",
        name="Python",
        mitre_id="T1059.006",
        tactic="execution",
        kill_chain="execution",
        curriculum_level=3,
        event_type="PY_INTERPRETER",
        severity="high",
        protocol="local",
        message="主机上出现 Python 解释器执行异常脚本",
        dst_role="ws",
        tool="sim:script_watch",
        variants=(
            {"event": "PY_CRON_TASK", "message": "计划任务通过 Python 拉起脚本", "protocol": "local"},
            {"event": "PY_SESSION", "message": "Python 进程开启交互式会话", "protocol": "local"},
        ),
        sub_technique_id="T1059.006",
        behaviors=("python", "interpreter"),
        data_sources=("process", "command"),
    ),
    TTPSpec(
        ttp_id="ttp-t1068-privesc",
        name="Exploitation for Privilege Escalation",
        mitre_id="T1068",
        tactic="privilege-escalation",
        kill_chain="privilege",
        curriculum_level=3,
        event_type="PRIVILEGE_ESCALATION",
        severity="critical",
        protocol="local",
        message="进程尝试提升至高权限账户",
        dst_role="ws",
        tool="sim:priv_watch",
        variants=(
            {"event": "TOKEN_ABUSE", "message": "访问令牌被复制到非预期进程", "protocol": "local"},
            {"event": "ADMIN_SPAWN", "message": "普通用户会话拉起高权限子进程", "protocol": "local"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1021-lateral",
        name="Remote Services",
        mitre_id="T1021",
        tactic="lateral-movement",
        kill_chain="lateral",
        curriculum_level=4,
        event_type="LATERAL_MOVE",
        severity="high",
        protocol="smb",
        message="攻击者通过远程服务横向移动至文件服务器",
        dst_role="fs",
        tool="sim:smb_enum",
        variants=(
            {"event": "ADMIN_SHARE_HOP", "message": "通过管理共享访问另一台内网主机", "protocol": "smb"},
            {"event": "REMOTE_SVC_USE", "message": "工作站向文件服务器发起异常远程服务会话", "protocol": "smb"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1071-c2",
        name="Application Layer Protocol",
        mitre_id="T1071",
        tactic="command-and-control",
        kill_chain="c2",
        curriculum_level=5,
        event_type="C2_BEACON",
        severity="critical",
        protocol="https",
        message="内部主机疑似与 C2 服务器周期通信",
        dst_role="web",
        tool="sim:beacon_sim",
        variants=(
            {"event": "PERIODIC_HTTPS", "message": "固定间隔的出站加密会话,路径高度重复", "protocol": "https"},
            {"event": "BEACON_LIKE", "message": "心跳式短连接访问境外 CDN 节点", "protocol": "https"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1048-exfil",
        name="Exfiltration Over Alternative Protocol",
        mitre_id="T1048",
        tactic="exfiltration",
        kill_chain="exfil",
        curriculum_level=5,
        event_type="DATA_EXFIL",
        severity="critical",
        protocol="https",
        message="检测到大量敏感数据外传",
        dst_role="web",
        tool="sim:exfil_watch",
        variants=(
            {"event": "CLOUD_SYNC", "message": "工作站向未备案对象存储同步大批文件", "protocol": "https"},
            {"event": "BULK_EGRESS", "message": "非工作时间出现超基线出站流量", "protocol": "https"},
        ),
    ),
    TTPSpec(
        ttp_id="ttp-t1027-evasion",
        name="Obfuscated Files or Information",
        mitre_id="T1027",
        tactic="defense-evasion",
        kill_chain="evasion",
        curriculum_level=6,
        event_type="DEFENSE_EVASION",
        severity="high",
        protocol="local",
        message="脚本内容经过多层编码后落地执行",
        dst_role="ws",
        tool="sim:decode_watch",
        variants=(
            {"event": "ENCODED_TASK", "message": "计划任务参数为不可读编码块", "protocol": "local"},
            {"event": "PACKED_DROP", "message": "落地文件熵值显著高于办公基线", "protocol": "local"},
        ),
    ),
)


DECOY_TEMPLATES: tuple[dict, ...] = (
    {"event": "USER_LOGIN", "severity": "info", "protocol": "rdp",
     "message": "管理员登录成功", "dst_role": "ws"},
    {"event": "FILE_ACCESS", "severity": "info", "protocol": "smb",
     "message": "用户访问共享文件夹", "dst_role": "fs"},
    {"event": "DNS_QUERY", "severity": "low", "protocol": "dns",
     "message": "DNS 解析请求", "dst_role": "web"},
    {"event": "VPN_CONNECT", "severity": "info", "protocol": "ikev2",
     "message": "VPN 隧道建立", "dst_role": "vpn"},
    {"event": "BACKUP_COMPLETE", "severity": "info", "protocol": "local",
     "message": "定时备份任务完成", "dst_role": "fs"},
)


# 战术 → 课程等级 / 仿真默认值(日志场景,不是利用工具)
TACTIC_META: dict[str, dict] = {
    "reconnaissance": {"kill_chain": "recon", "level": 0, "severity": "low", "protocol": "tcp", "dst_role": "web"},
    "resource-development": {"kill_chain": "recon", "level": 0, "severity": "medium", "protocol": "https", "dst_role": "web"},
    "discovery": {"kill_chain": "recon", "level": 0, "severity": "medium", "protocol": "tcp", "dst_role": "web"},
    "initial-access": {"kill_chain": "initial_access", "level": 1, "severity": "high", "protocol": "http", "dst_role": "web"},
    "credential-access": {"kill_chain": "initial_access", "level": 1, "severity": "high", "protocol": "ssh", "dst_role": "jump"},
    "execution": {"kill_chain": "execution", "level": 3, "severity": "high", "protocol": "local", "dst_role": "ws"},
    "persistence": {"kill_chain": "privilege", "level": 3, "severity": "medium", "protocol": "local", "dst_role": "ws"},
    "privilege-escalation": {"kill_chain": "privilege", "level": 3, "severity": "critical", "protocol": "local", "dst_role": "ws"},
    "lateral-movement": {"kill_chain": "lateral", "level": 4, "severity": "high", "protocol": "smb", "dst_role": "fs"},
    "collection": {"kill_chain": "exfil", "level": 5, "severity": "medium", "protocol": "https", "dst_role": "fs"},
    "command-and-control": {"kill_chain": "c2", "level": 5, "severity": "critical", "protocol": "https", "dst_role": "web"},
    "exfiltration": {"kill_chain": "exfil", "level": 5, "severity": "critical", "protocol": "https", "dst_role": "web"},
    "defense-evasion": {"kill_chain": "evasion", "level": 6, "severity": "high", "protocol": "local", "dst_role": "ws"},
    "impact": {"kill_chain": "evasion", "level": 6, "severity": "high", "protocol": "local", "dst_role": "ws"},
}

_SNAPSHOT_PATH = Path(__file__).resolve().parent / "data" / "enterprise_techniques.json"
_ENTERPRISE_CACHE: Optional[list[TTPSpec]] = None


def _clip_desc(text: str, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _spec_from_enterprise_row(row: dict) -> TTPSpec:
    tid = str(row.get("id") or "").strip()
    tactics = [str(t) for t in (row.get("tactics") or []) if t]
    tactic = tactics[0] if tactics else "discovery"
    meta = TACTIC_META.get(tactic) or TACTIC_META["discovery"]
    name = str(row.get("name") or tid)
    desc = _clip_desc(row.get("description") or name)
    slug = tid.replace(".", "_")
    event = f"ATTCK_{slug}"
    return TTPSpec(
        ttp_id=f"ttp-{tid.lower()}",
        name=name,
        mitre_id=tid,
        tactic=tactic,
        kill_chain=str(meta["kill_chain"]),
        curriculum_level=int(meta["level"]),
        event_type=event,
        severity=str(meta["severity"]),
        protocol=str(meta["protocol"]),
        message=f"{name} ({tid}) 仿真遥测: {desc}",
        dst_role=str(meta["dst_role"]),
        tool=f"sim:{meta['kill_chain']}",
        variants=(
            {
                "event": f"{event}_OBF",
                "message": f"改写后的 {name} 行为特征,未使用库存检测关键字",
                "protocol": str(meta["protocol"]),
            },
        ),
    )


def enterprise_pool() -> list[TTPSpec]:
    """ATT&CK Enterprise 父技术全量池(快照,不联网)。"""
    global _ENTERPRISE_CACHE
    if _ENTERPRISE_CACHE is not None:
        return list(_ENTERPRISE_CACHE)
    rows: list[TTPSpec] = []
    try:
        raw = json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
        for item in raw.get("techniques") or []:
            tid = str((item or {}).get("id") or "")
            if not tid or "." in tid:
                continue
            rows.append(_spec_from_enterprise_row(item))
    except FileNotFoundError:
        rows = []
    except Exception:
        rows = []
    _ENTERPRISE_CACHE = rows
    return list(rows)


def curriculum_ttps() -> list[TTPSpec]:
    return list(_TTPS)


def all_ttps() -> list[TTPSpec]:
    """课程金标优先,其余用 Enterprise 父技术补齐(按 mitre_id 去重)。"""
    seen: dict[str, TTPSpec] = {}
    for t in list(_TTPS) + enterprise_pool():
        seen.setdefault(t.mitre_id.upper(), t)
    return list(seen.values())


def ttps_at_level(
    level: int, *, inclusive: bool = True, pool: Optional[list[TTPSpec]] = None,
) -> list[TTPSpec]:
    level = max(0, min(int(level), MAX_CURRICULUM_LEVEL))
    src = list(pool) if pool is not None else list(_TTPS)
    if inclusive:
        return [t for t in src if t.curriculum_level <= level]
    return [t for t in src if t.curriculum_level == level]


def get_ttp(key: str) -> Optional[TTPSpec]:
    """按 ttp_id 或 MITRE ID 查找;课程金标优先于 Enterprise 映射。"""
    want = (key or "").strip()
    if not want:
        return None
    wu = want.upper()
    for t in _TTPS:
        if t.ttp_id == want or t.mitre_id.upper() == wu:
            return t
    for t in enterprise_pool():
        if t.ttp_id == want or t.ttp_id.lower() == want.lower() or t.mitre_id.upper() == wu:
            return t
    return None


def lexical_candidates(
    query: str,
    *,
    level: int = 6,
    top_k: int = 8,
    covered: Optional[list[str]] = None,
    prefer_ids: Optional[list[str]] = None,
    use_enterprise: bool = True,
) -> list[TTPSpec]:
    """无向量时的词法召回: 不把 200 条塞进 prompt。"""
    pool = ttps_at_level(
        level, inclusive=True,
        pool=enterprise_pool() if use_enterprise else list(_TTPS),
    )
    covered_u = {str(c).upper() for c in (covered or []) if c}
    prefer_u = {str(p).upper() for p in (prefer_ids or []) if p}
    tokens = [tok.upper() for tok in re.findall(r"[A-Z0-9][A-Z0-9_\-]{2,}|\w{3,}", query or "", flags=re.I)]
    scored: list[tuple[int, TTPSpec]] = []
    for t in pool:
        blob = f"{t.mitre_id} {t.name} {t.tactic} {t.event_type} {t.message}".upper()
        score = sum(1 for tok in tokens if tok and tok in blob)
        if t.mitre_id.upper() in prefer_u or t.ttp_id.upper() in prefer_u:
            score += 6
        if t.event_type.upper() in covered_u:
            score -= 3
        scored.append((score, t))
    scored.sort(key=lambda x: (-x[0], x[1].curriculum_level, x[1].mitre_id))
    picked = [t for _, t in scored[: max(1, int(top_k))]]
    if not picked and pool:
        picked = pool[: max(1, int(top_k))]
    return picked


def _summary_row(t: TTPSpec) -> dict:
    return {
        "ttp_id": t.ttp_id,
        "name": t.name,
        "mitre_id": t.mitre_id,
        "tactic": t.tactic,
        "kill_chain": t.kill_chain,
        "level": t.curriculum_level,
        "event_type": t.event_type,
        "variants": [v["event"] for v in t.variants],
    }


def catalog_summary() -> list[dict]:
    """兼容旧调用: 返回课程金标列表。"""
    return [_summary_row(t) for t in _TTPS]


def catalog_overview() -> dict:
    pool = enterprise_pool()
    return {
        "max_level": MAX_CURRICULUM_LEVEL,
        "curriculum": catalog_summary(),
        "curriculum_count": len(_TTPS),
        "enterprise_count": len(pool),
        "unique_mitre_ids": len(all_ttps()),
    }
