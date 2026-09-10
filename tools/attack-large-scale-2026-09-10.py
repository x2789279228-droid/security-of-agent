#!/usr/bin/env python3
"""
大规模攻击测试生成器 (2026-09-10)
- 3000 events / ~2 req/s 持续注入
- 8 threat_type (同 9/2 baseline 口径)
- IP 池同 9/2 风格(公网 + 失陷内网 + 运维网段)
- session_id 前缀: large-scale-20260910-*
- 同时记录每条 response (latency, status)
- 写到 .tmp_large_attack_20260910.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# ---- config ----
API = os.environ.get("SOC_API", "http://localhost:8001").rstrip("/")
TOTAL = int(os.environ.get("SOC_TOTAL", "3000"))
RATE = float(os.environ.get("SOC_RATE", "2.0"))  # req/s
SESSION = os.environ.get("SOC_SESSION", f"large-scale-20260910-{int(time.time())}")
TOKEN = os.environ.get("SOC_TOKEN", "")  # JWT Bearer token (mandatory since 2026-09-10)
OUT = os.environ.get("SOC_OUT", r"D:\揭榜挂帅\shared-memory-platform\.tmp_large_attack_20260910.jsonl")
PROGRESS_EVERY = int(os.environ.get("SOC_PROGRESS_EVERY", "50"))

# ---- threat distribution (mirror 9/2 baseline × ~6.16 to reach 3000) ----
# 9/2 ratios: BRUTE_FORCE 45.2%, DDoS 16.4%, PORT_SCAN 12.3%, C2 6.6%, MALWARE 7.2%, DATA_EXFIL 4.1%, LATERAL_MOVE 4.1%, ANY(benign) 4.1%
THREAT_DIST: list[tuple[str, float]] = [
    ("BRUTE_FORCE", 0.452),
    ("DDoS_TRAFFIC", 0.164),
    ("PORT_SCAN", 0.123),
    ("C2_BEACON", 0.066),
    ("MALWARE_DETECT", 0.072),
    ("DATA_EXFIL", 0.041),
    ("LATERAL_MOVE", 0.041),
    ("USER_LOGIN", 0.041),  # benign baseline
]

# ---- IP pools (mirror 9/2: 185.220.101.x 公网 TOR exits, 203.0.113.x docs, 198.51.100.x, 失陷内网 10.0.30.x, 运维 10.0.10.x) ----
PUBLIC_TOR = [f"185.220.101.{i}" for i in range(40, 80)]              # 40 IPs
PUBLIC_DOC = [f"203.0.113.{(i % 250) + 1}" for i in range(80)]       # 80 IPs
PUBLIC_RESERVED = [f"198.51.100.{(i % 250) + 1}" for i in range(60)] # 60 IPs
INTERNAL_PWN = [f"10.0.30.{(i % 250) + 1}" for i in range(30)]       # 30 IPs (失陷)
INTERNAL_OPS = [f"10.0.10.{(i % 250) + 1}" for i in range(20)]       # 20 IPs (运维)
LOCAL_HOST = "127.0.0.1"

# threat -> IP pool & message template
THREAT_PROFILES: dict[str, dict] = {
    "BRUTE_FORCE": {
        "src_pool": PUBLIC_TOR + PUBLIC_DOC,
        "msg_tmpl": "SSH 暴力破解尝试 from {src} against {dst}:22 (user=admin)",
        "proto": "ssh",
        "sev": "high",
    },
    "DDoS_TRAFFIC": {
        "src_pool": PUBLIC_DOC + PUBLIC_RESERVED,
        "msg_tmpl": "DDoS 流量峰值 from {src} → {dst}:80 (rate=8.2Gbps SYN flood)",
        "proto": "tcp",
        "sev": "critical",
    },
    "PORT_SCAN": {
        "src_pool": PUBLIC_DOC + PUBLIC_RESERVED + PUBLIC_TOR,
        "msg_tmpl": "端口扫描 src={src} 探测 dst={dst} (ports=22,80,443,3389,8001)",
        "proto": "tcp",
        "sev": "medium",
    },
    "C2_BEACON": {
        "src_pool": INTERNAL_PWN,
        "msg_tmpl": "失陷主机 {src} 与 C2 beacon 通信 (JA3 hash match, 5min 周期)",
        "proto": "https",
        "sev": "critical",
    },
    "MALWARE_DETECT": {
        "src_pool": INTERNAL_PWN + PUBLIC_DOC,
        "msg_tmpl": "EDR 检测恶意软件 src={src} dst={dst} (Trojan.Generic)",
        "proto": "edr",
        "sev": "high",
    },
    "DATA_EXFIL": {
        "src_pool": INTERNAL_PWN,
        "msg_tmpl": "数据外泄告警 {src} → {dst} (1.2GB DNS tunnel)",
        "proto": "dns",
        "sev": "critical",
    },
    "LATERAL_MOVE": {
        "src_pool": INTERNAL_PWN,
        "msg_tmpl": "横向移动 {src} 通过 SMB 访问 {dst} (admin$ share)",
        "proto": "smb",
        "sev": "high",
    },
    "USER_LOGIN": {
        "src_pool": INTERNAL_OPS,
        "msg_tmpl": "管理员登录成功 user=admin from {src}",
        "proto": "rdp",
        "sev": "info",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_post(path: str, body: dict, timeout: float = 30.0) -> tuple[int, dict | str, float]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
        },
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.perf_counter() - t0) * 1000.0
            raw = resp.read().decode("utf-8", errors="replace")[:400]
            try:
                return int(resp.status), json.loads(raw or "{}"), elapsed
            except json.JSONDecodeError:
                return int(resp.status), raw, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        try:
            return int(e.code), json.loads(e.read().decode("utf-8", errors="replace")[:400]), elapsed
        except Exception:
            return int(e.code), {}, elapsed
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return -1, {"error": str(e)[:200]}, elapsed


def build_event(seq: int, threat: str, src: str, dst: str) -> dict:
    profile = THREAT_PROFILES[threat]
    return {
        "event_id": f"large-scale-20260910-{seq:05d}",
        "event": threat,
        "type": threat,
        "threat_type": threat,
        "severity": profile["sev"],
        "protocol": profile["proto"],
        "message": profile["msg_tmpl"].format(src=src, dst=dst),
        "src_ip": src,
        "dst_ip": dst,
        "_sim": True,
        "_ground_truth": "benign" if profile["sev"] in ("info", "low") else "attack",
        "ts": _now(),
        "seq": seq,
    }


def pick_threat() -> str:
    r = random.random()
    cum = 0.0
    for t, p in THREAT_DIST:
        cum += p
        if r <= cum:
            return t
    return THREAT_DIST[-1][0]


def pick_src_dst(threat: str) -> tuple[str, str]:
    src = random.choice(THREAT_PROFILES[threat]["src_pool"])
    if threat == "USER_LOGIN":
        dst = "10.0.0.5"
    elif threat in ("C2_BEACON", "DATA_EXFIL", "LATERAL_MOVE", "MALWARE_DETECT"):
        dst = random.choice(["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    else:
        dst = LOCAL_HOST
    return src, dst


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--total", type=int, default=TOTAL)
    parser.add_argument("--rate", type=float, default=RATE)
    parser.add_argument("--session", type=str, default=SESSION)
    parser.add_argument("--api", type=str, default=API)
    parser.add_argument("--out", type=str, default=OUT)
    parser.add_argument("--single", action="store_true", help="use single-event endpoint instead of batch")
    parser.add_argument("--warmup", type=int, default=0, help="warmup events (no count in main run)")
    args = parser.parse_args()

    api = args.api.rstrip("/")
    out = args.out
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    print(f"[CONFIG] api={api} total={args.total} rate={args.rate}/s session={args.session}")
    print(f"[CONFIG] out={out} endpoint={'single' if args.single else 'batch'}")

    # warmup
    if args.warmup > 0:
        print(f"[WARMUP] sending {args.warmup} events...")
        for i in range(args.warmup):
            threat = "BRUTE_FORCE"
            src, dst = pick_src_dst(threat)
            ev = build_event(-i - 1, threat, src, dst)
            http_post("/api/logs/ingest", {"session_id": args.session + "-warmup", "message": ev})
            time.sleep(0.3)
        print(f"[WARMUP] done")

    sent_ok = 0
    sent_fail = 0
    latencies: list[float] = []
    burst_count = 0  # events in batch (when batch mode)
    t0 = time.perf_counter()
    interval = 1.0 / args.rate

    # open output jsonl
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"_meta": True, "started_at": _now(), "session": args.session, "total": args.total, "rate": args.rate, "api": api}) + "\n")

        if args.single:
            for i in range(args.total):
                threat = pick_threat()
                src, dst = pick_src_dst(threat)
                ev = build_event(i, threat, src, dst)
                t_send = time.perf_counter()
                st, resp, ms = http_post("/api/logs/ingest", {"session_id": args.session, "message": ev})
                if st in (200, 201, 202):
                    sent_ok += 1
                else:
                    sent_fail += 1
                latencies.append(ms)
                record = {"seq": i, "threat": threat, "src": src, "dst": dst, "http": st, "latency_ms": round(ms, 1), "ts": _now()}
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                # sleep to maintain rate
                elapsed_since_send = time.perf_counter() - t_send
                sleep_for = max(0.0, interval - elapsed_since_send)
                time.sleep(sleep_for)
                if (i + 1) % PROGRESS_EVERY == 0 or i + 1 == args.total:
                    elapsed_total = time.perf_counter() - t0
                    actual_rate = (i + 1) / elapsed_total if elapsed_total > 0 else 0
                    p95 = sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0
                    print(f"[PROGRESS] sent={i+1}/{args.total} ok={sent_ok} fail={sent_fail} actual_rate={actual_rate:.2f}/s p95_ms={p95:.0f}")
        else:
            # batch mode: accumulate events for ~1s window, send as batch
            batch: list[dict] = []
            for i in range(args.total):
                threat = pick_threat()
                src, dst = pick_src_dst(threat)
                ev = build_event(i, threat, src, dst)
                batch.append(ev)
                t_send = time.perf_counter()
                if len(batch) >= max(1, int(args.rate)) or i == args.total - 1:
                    st, resp, ms = http_post("/api/logs/ingest/batch", {"session_id": args.session, "logs": batch})
                    if st in (200, 201, 202):
                        sent_ok += len(batch)
                    else:
                        sent_fail += len(batch)
                    latencies.append(ms)
                    burst_count += 1
                    record = {"batch_seq": burst_count, "batch_size": len(batch), "threats": [b["threat_type"] for b in batch[:5]], "http": st, "latency_ms": round(ms, 1), "ts": _now()}
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    batch = []
                elapsed_since_send = time.perf_counter() - t_send
                sleep_for = max(0.0, interval - elapsed_since_send)
                time.sleep(sleep_for)
                if (i + 1) % PROGRESS_EVERY == 0 or i + 1 == args.total:
                    elapsed_total = time.perf_counter() - t0
                    actual_rate = (i + 1) / elapsed_total if elapsed_total > 0 else 0
                    p95 = sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0
                    print(f"[PROGRESS] sent={i+1}/{args.total} ok={sent_ok} fail={sent_fail} actual_rate={actual_rate:.2f}/s p95_ms={p95:.0f}")

    elapsed_total = time.perf_counter() - t0
    actual_rate = args.total / elapsed_total if elapsed_total > 0 else 0
    p50 = sorted(latencies)[len(latencies) // 2] if latencies else 0
    p95 = sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0
    p99 = sorted(latencies)[int(0.99 * (len(latencies) - 1))] if latencies else 0
    summary = {
        "_summary": True,
        "session": args.session,
        "total_target": args.total,
        "sent_ok": sent_ok,
        "sent_fail": sent_fail,
        "elapsed_sec": round(elapsed_total, 1),
        "actual_rate_per_sec": round(actual_rate, 3),
        "batch_count": burst_count,
        "latency_p50_ms": round(p50, 1),
        "latency_p95_ms": round(p95, 1),
        "latency_p99_ms": round(p99, 1),
        "finished_at": _now(),
    }
    with open(out, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")
    print(f"[DONE] {json.dumps(summary, ensure_ascii=False)}")
    return 0 if sent_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
