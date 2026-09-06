#!/usr/bin/env python3
"""Kali → 本机 SOC 仿真性能测试。

只做：有限端口 TCP 探测 + 安全日志注入 + 延迟统计。
禁止：hydra / sqlmap / msf / 口令爆破 / 利用 payload。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("SOC_API", "http://host.docker.internal:8001").rstrip("/")
TOKEN = os.environ.get("SOC_TOKEN", "")
SESSION = os.environ.get("SOC_SESSION", f"kali-sim-{int(time.time())}")
PORTS = os.environ.get("SOC_PORTS", "8001,3001,2222,9093")
OUT = os.environ.get("SOC_REPORT", "/workspace/reports/kali-sim-perf.json")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_host() -> str:
    host = os.environ.get("SOC_HOST", "host.docker.internal")
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


def http(method: str, path: str, body: dict | None = None, timeout: float = 20.0) -> tuple[int, dict | str, float]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            try:
                parsed = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                parsed = raw.decode("utf-8", errors="replace")[:400]
            return int(resp.status), parsed, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        raw = e.read().decode("utf-8", errors="replace")[:400]
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        return int(e.code), parsed, elapsed
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return -1, {"error": str(e)[:200]}, elapsed


def nmap_platform_ports(target_ip: str) -> dict:
    ports = PORTS.replace(" ", "")
    cmd = ["nmap", "-sT", "-Pn", "-T4", "-p", ports, target_ip]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ms = (time.perf_counter() - t0) * 1000.0
        return {
            "cmd": " ".join(cmd),
            "rc": proc.returncode,
            "elapsed_ms": round(ms, 1),
            "stdout": (proc.stdout or "")[-2500:],
            "stderr": (proc.stderr or "")[-500:],
        }
    except FileNotFoundError:
        return {"cmd": "nmap", "rc": 127, "error": "nmap not installed"}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "rc": 124, "error": "nmap timeout"}


def sim_events(src: str, dst: str) -> list[dict]:
    """SOC 日志描述，不含利用 payload。"""
    rows = [
        ("PORT_SCAN", "medium", "tcp", f"外部主机对内网进行端口扫描 src={src}"),
        ("BRUTE_FORCE", "high", "ssh", "SSH 暴力破解攻击,已尝试大量口令"),
        ("SQL_INJECTION", "high", "http", "Web 应用查询接口出现异常参数模式"),
        ("LATERAL_MOVE", "high", "smb", "攻击者通过远程服务横向移动至文件服务器"),
        ("C2_BEACON", "critical", "https", "内部主机疑似与 C2 服务器周期通信"),
        ("USER_LOGIN", "info", "rdp", "管理员登录成功"),
        ("DNS_QUERY", "low", "dns", "内部主机发起常规域名解析"),
        ("FILE_ACCESS", "info", "smb", "用户访问共享文件夹"),
    ]
    out = []
    for i, (ev, sev, proto, msg) in enumerate(rows):
        out.append({
            "event": ev,
            "type": ev,
            "severity": sev,
            "protocol": proto,
            "message": msg,
            "src_ip": src if ev != "USER_LOGIN" else "10.0.30.12",
            "dst_ip": dst,
            "threat_type": ev,
            "_sim": True,
            "_kali_sim": True,
            "_ground_truth": "benign" if sev in ("info", "low") else "attack",
            "ts": _now(),
            "seq": i,
        })
    return out


def main() -> int:
    report: dict = {
        "started_at": _now(),
        "api": API,
        "session_id": SESSION,
        "constraints": "no hydra/sqlmap/msf/exploit payloads; TCP connect scan of platform ports only",
    }
    dst = resolve_host()
    src = os.environ.get("KALI_SRC", "203.0.113.77")
    report["resolved_host"] = dst

    st, health, ms = http("GET", "/api/health", timeout=8)
    report["health"] = {"status": st, "body": health, "latency_ms": round(ms, 1)}

    report["nmap"] = nmap_platform_ports(dst)

    events = sim_events(src, dst)
    latencies: list[float] = []
    ingest_ok = 0
    ingest_fail = 0
    last_resp: dict | str = {}
    t_batch = time.perf_counter()
    st, last_resp, ms = http(
        "POST",
        "/api/logs/ingest/batch",
        {"session_id": SESSION, "logs": events},
        timeout=30,
    )
    batch_ms = (time.perf_counter() - t_batch) * 1000.0
    if st in (200, 201, 202):
        ingest_ok = len(events)
        latencies.append(ms)
    else:
        ingest_fail = len(events)
        # fallback: single ingest
        for ev in events:
            st1, _, ms1 = http("POST", "/api/logs/ingest", {"session_id": SESSION, "message": ev}, timeout=15)
            latencies.append(ms1)
            if st1 in (200, 201, 202):
                ingest_ok += 1
                ingest_fail -= 1 if ingest_fail else 0
            else:
                ingest_fail += 1 if ingest_ok == 0 else 1

    latencies.sort()
    p95 = latencies[int(0.95 * (len(latencies) - 1))] if latencies else 0.0
    report["ingest"] = {
        "batch_status": st,
        "batch_latency_ms": round(batch_ms, 1),
        "ok": ingest_ok,
        "fail": max(0, ingest_fail),
        "count": len(events),
        "avg_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0.0,
        "p95_ms": round(p95, 1),
        "response": last_resp if isinstance(last_resp, dict) else str(last_resp)[:400],
    }

    st, status_body, ms = http("GET", f"/api/logs/status?session_id={SESSION}", timeout=10)
    report["log_status"] = {"http": st, "latency_ms": round(ms, 1), "body": status_body}

    report["finished_at"] = _now()
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if ingest_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
