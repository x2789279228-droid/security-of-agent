"""隔离仿真企业拓扑。

只生成安全日志,不启动真实漏洞容器,不调用 nmap/hydra/sqlmap/msf。
红队「执行」= 把 AttackStep 物化为带 ground-truth 的事件字典。

默认 10 主机拓扑保持不变 (P3-A 兼容旧测试);
diverse=True 时按 seed 随机生成 8–30 主机拓扑 (P3-B/E);
background_events 提供不出网的良性背景流量 (P3-C/D)。
"""
from __future__ import annotations

import random
import time
from typing import Optional

from self_play.types import AttackStep, MaterializedEvent

ATTACKER_IP = "203.0.113.50"
ATTACKER_HOST = "red-sim"

HOSTS: tuple[dict, ...] = (
    {"id": "web-01", "ip": "10.0.10.10", "zone": "dmz", "role": "web", "port": 80},
    {"id": "app-01", "ip": "10.0.10.20", "zone": "dmz", "role": "app", "port": 8080},
    {"id": "mail-01", "ip": "10.0.10.30", "zone": "dmz", "role": "mail", "port": 25},
    {"id": "vpn-01", "ip": "10.0.10.40", "zone": "dmz", "role": "vpn", "port": 500},
    {"id": "jump-01", "ip": "10.0.20.5", "zone": "lan", "role": "jump", "port": 22},
    {"id": "dc-01", "ip": "10.0.20.10", "zone": "lan", "role": "dc", "port": 389},
    {"id": "fs-01", "ip": "10.0.20.20", "zone": "lan", "role": "fs", "port": 445},
    {"id": "db-01", "ip": "10.0.20.30", "zone": "lan", "role": "db", "port": 5432},
    {"id": "ws-01", "ip": "10.0.30.11", "zone": "user", "role": "ws", "port": 3389},
    {"id": "ws-02", "ip": "10.0.30.12", "zone": "user", "role": "ws", "port": 3389},
)

_ROLE_ALIAS = {
    "web": "web", "app": "web", "http": "web",
    "jump": "jump", "ssh": "jump",
    "fs": "fs", "smb": "fs",
    "dc": "dc", "ws": "ws", "db": "db",
    "vpn": "vpn", "mail": "mail",
}

_DIVERSE_ROLES = ("web", "app", "db", "dc", "fs", "ws", "jump", "vpn", "mail", "dev")
_DIVERSE_ZONES = ("dmz", "lan", "user", "isolated")
_DIVERSE_ROLE_ZONE = {
    "web": "dmz", "app": "dmz", "mail": "dmz", "vpn": "dmz",
    "dc": "lan", "fs": "lan", "db": "lan", "jump": "lan",
    "ws": "user", "dev": "isolated",
}
_DIVERSE_ROLE_PORT = {
    "web": 80, "app": 8080, "db": 5432, "dc": 389, "fs": 445,
    "ws": 3389, "jump": 22, "vpn": 500, "mail": 25, "dev": 8000,
}


def generate_topology(seed: int = 0, n_hosts: int | None = None) -> list[dict]:
    """P3-B: 生成 8–30 主机的随机企业拓扑(角色/分区/IP 均异于默认固定拓扑)。

    保证至少有 web / ws / dc / fs 角色,便于攻击链与背景流量落位;
    IP 使用 10.{100..250}.x.x 段,绝不与默认 10.0.x/10.30.x 拓扑重叠。
    """
    rng = random.Random(int(seed) * 1_000_003 + 7)
    if n_hosts is None:
        n_hosts = rng.randint(8, 30)
    n = max(8, min(30, int(n_hosts)))

    core = ["web", "ws", "dc", "fs"]
    roles = core + [rng.choice(_DIVERSE_ROLES) for _ in range(max(0, n - len(core)))]
    rng.shuffle(roles)

    used_ips: set[str] = set()
    second_octet = rng.randint(100, 250)
    hosts: list[dict] = []
    for i, role in enumerate(roles):
        while True:
            ip = f"10.{second_octet}.{rng.randint(1, 250)}.{rng.randint(2, 250)}"
            if ip not in used_ips:
                used_ips.add(ip)
                break
        zone = _DIVERSE_ROLE_ZONE.get(role, "user")
        if rng.random() < 0.2:
            zone = rng.choice(_DIVERSE_ZONES)
        hosts.append({
            "id": f"{role}-{i:02d}",
            "ip": ip,
            "zone": zone,
            "role": role,
            "port": _DIVERSE_ROLE_PORT.get(role, 80),
        })
    return hosts


def topology() -> dict:
    return {
        "isolation": "in-process-sim",
        "note": "无真实漏洞服务,无外部攻击工具;事件仅在 self-play session 内流通",
        "attacker": {"host": ATTACKER_HOST, "ip": ATTACKER_IP},
        "hosts": [dict(h) for h in HOSTS],
        "zones": ["dmz", "lan", "user"],
    }


def host_by_role(role: str) -> dict:
    want = _ROLE_ALIAS.get((role or "web").lower(), "web")
    for h in HOSTS:
        if h["role"] == want:
            return h
    return HOSTS[0]


def host_by_id(host_id: str) -> Optional[dict]:
    for h in HOSTS:
        if h["id"] == host_id:
            return h
    return None


def _url_for(step: AttackStep, dst: dict) -> str:
    if step.protocol in ("http", "https"):
        path = "/health" if not step.is_attack else "/search"
        return f"{step.protocol}://{dst['ip']}{path}"
    return ""


_INTERNAL_CHAIN = frozenset({
    "lateral", "privilege", "execution", "evasion", "c2", "exfil",
})

# 良性背景流量模板 (P3-C/D): DNS / 内部 HTTP 代理 / 文件访问 / 登录,全部不出网
_BG_TEMPLATES: tuple[dict, ...] = (
    {"event": "DNS_QUERY", "severity": "low", "protocol": "dns",
     "message": "内部主机发起常规域名解析", "role": "dc"},
    {"event": "HTTP_PROXY", "severity": "info", "protocol": "http",
     "message": "内网终端经内部代理访问业务站点", "role": "web"},
    {"event": "FILE_ACCESS", "severity": "info", "protocol": "smb",
     "message": "用户访问共享文件夹", "role": "fs"},
    {"event": "USER_LOGIN", "severity": "info", "protocol": "rdp",
     "message": "管理员登录成功", "role": "ws"},
)


class SimEnv:
    """企业网仿真。默认固定 10 主机;diverse=True 用随机拓扑。物化步骤 → 安全日志。"""

    def __init__(self, *, diverse: bool = False, seed: int = 0, n_hosts: int | None = None) -> None:
        self.diverse = bool(diverse)
        self.seed = int(seed)
        self.n_hosts = n_hosts
        if self.diverse:
            self.hosts: list[dict] = generate_topology(seed=self.seed, n_hosts=n_hosts)
        else:
            self.hosts = [dict(h) for h in HOSTS]

    # ------------------------------------------------------------ host lookup
    def _host_by_role(self, role: str) -> dict:
        want = _ROLE_ALIAS.get((role or "web").lower(), "web")
        for h in self.hosts:
            if h["role"] == want:
                return h
        return self.hosts[0]

    def _host_by_id(self, host_id: str) -> Optional[dict]:
        for h in self.hosts:
            if h["id"] == host_id:
                return h
        return None

    def has_role(self, role: str) -> bool:
        want = _ROLE_ALIAS.get((role or "").lower(), (role or "").lower())
        return any(h.get("role") == want for h in self.hosts)

    def _internal_src(self) -> tuple[str, str]:
        """内部跳板源: 默认拓扑恒为 ws-01/10.0.30.11;diverse 拓扑用其首个 ws 主机。"""
        ws = [h for h in self.hosts if h.get("role") == "ws"]
        if ws:
            return str(ws[0]["id"]), str(ws[0]["ip"])
        first = self.hosts[0]
        return str(first["id"]), str(first["ip"])

    def _benign_src(self) -> tuple[str, str]:
        ws = [h for h in self.hosts if h.get("role") == "ws"]
        if len(ws) >= 2:
            return str(ws[1]["id"]), str(ws[1]["ip"])
        if ws:
            return str(ws[0]["id"]), str(ws[0]["ip"])
        alt = self.hosts[min(1, len(self.hosts) - 1)]
        return str(alt["id"]), str(alt["ip"])

    # -------------------------------------------------------------- background
    def background_events(self, n: int, *, now: float | None = None) -> list[MaterializedEvent]:
        """P3-C/D: 良性背景事件(全部 is_attack=False)。

        即使不出网也包含内部 DNS 与到内部代理角色(若无则 web)的 HTTP。
        """
        now = float(now if now is not None else time.time())
        out: list[MaterializedEvent] = []
        for i in range(max(0, int(n))):
            tpl = _BG_TEMPLATES[i % len(_BG_TEMPLATES)]
            if tpl["event"] == "HTTP_PROXY":
                # 内部代理角色若存在则优先,否则走 web
                proxy = next((h for h in self.hosts if h.get("role") == "proxy"), None)
                dst = proxy or self._host_by_role("web")
            else:
                dst = self._host_by_role(tpl["role"])
            others = [h for h in self.hosts if h.get("id") != dst.get("id")] or self.hosts
            src = others[(i * 3 + 1) % len(others)]
            out.append(MaterializedEvent(
                event=str(tpl["event"]),
                severity=str(tpl["severity"]),
                protocol=str(tpl["protocol"]),
                message=str(tpl["message"]),
                src_ip=str(src["ip"]),
                dst_ip=str(dst["ip"]),
                src_host=str(src.get("id") or ""),
                dst_host=str(dst.get("id") or ""),
                dst_port=int(dst.get("port") or 0),
                confidence=95,
                is_attack=False,
                injected_at=now + i * 0.001,
                eval_channel="sim",
                extra={"_sim": True, "_background": True},
            ))
        return out

    # -------------------------------------------------------------- materialize
    def materialize(
        self, step: AttackStep, *, now: Optional[float] = None,
        chain_index: int = 0, foothold: bool = False,
    ) -> MaterializedEvent:
        now = float(now if now is not None else time.time())
        dst = self._host_by_role(step.dst_role)
        if step.is_attack:
            from_inside = bool(foothold) or chain_index > 0 or step.kill_chain in _INTERNAL_CHAIN
            if from_inside:
                src_host, src_ip = self._internal_src()
            else:
                src_host, src_ip = ATTACKER_HOST, ATTACKER_IP
        else:
            src_host, src_ip = self._benign_src()

        extra = {
            "_sim": True,
            "_tool": step.tool,
            "_kill_chain": step.kill_chain,
            "_ttp_name": step.name,
            "_evasion": bool(step.evasion),
            "_chain_index": int(chain_index),
            "_foothold": bool(foothold),
        }
        extra.update(step.extra or {})

        return MaterializedEvent(
            event=step.event_type,
            severity=step.severity,
            protocol=step.protocol,
            message=step.message,
            src_ip=src_ip,
            dst_ip=dst["ip"],
            src_host=src_host,
            dst_host=dst["id"],
            url=_url_for(step, dst),
            method="GET" if step.protocol in ("http", "https") else "",
            dst_port=int(dst.get("port") or 0),
            confidence=88 if step.is_attack else 95,
            is_attack=bool(step.is_attack),
            ttp_id=step.ttp_id,
            mitre_id=step.mitre_id,
            sub_technique_id=str(getattr(step, "sub_technique_id", "") or ""),
            injected_at=now,
            extra=extra,
        )

    def materialize_plan(
        self, steps: list[AttackStep], decoys: list[AttackStep],
        *, background_n: int = 0,
    ) -> list[MaterializedEvent]:
        out: list[MaterializedEvent] = []
        base = time.time()
        foothold = False
        for i, step in enumerate(list(steps)):
            out.append(self.materialize(
                step, now=base + i * 0.001, chain_index=i, foothold=foothold,
            ))
            if step.is_attack:
                foothold = True
        for j, step in enumerate(list(decoys)):
            out.append(self.materialize(
                step, now=base + (len(steps) + j) * 0.001, chain_index=len(steps) + j,
            ))
        if background_n and int(background_n) > 0:
            bg_base = base + (len(steps) + len(decoys)) * 0.001
            out.extend(self.background_events(int(background_n), now=bg_base))
        return out
