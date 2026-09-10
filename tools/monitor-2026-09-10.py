#!/usr/bin/env python3
"""
监控循环: 每 60s 拉一次 SOC 后端 + DB 状态, 输出到 .tmp_monitor_20260910.jsonl
监控维度:
  - llm_traces: 总数 / 错误数 / degraded / caller 分布
  - security_events: 5min 内新增数 / 按 threat_type 分布
  - response_logs: 5min 内新增 / 按 action_type 分布
  - LLM token 估算 (prompt+completion)
  - audit_pipeline calls in last 5 min
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("SOC_API", "http://localhost:8001").rstrip("/")
TOKEN = os.environ.get("SOC_TOKEN", "")
OUT = os.environ.get("MON_OUT", r"D:\揭榜挂帅\shared-memory-platform\.tmp_monitor_20260910.jsonl")
INTERVAL = int(os.environ.get("MON_INTERVAL", "60"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_get(path: str, timeout: float = 10.0) -> tuple[int, dict | str]:
    req = urllib.request.Request(
        API + path,
        headers={
            "Accept": "application/json",
            **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")[:8000]
            try:
                return int(resp.status), json.loads(raw or "{}")
            except json.JSONDecodeError:
                return int(resp.status), raw
    except urllib.error.HTTPError as e:
        try:
            return int(e.code), json.loads(e.read().decode("utf-8", errors="replace")[:2000])
        except Exception:
            return int(e.code), {}
    except Exception as e:
        return -1, {"error": str(e)[:200]}


def pg_query(sql: str) -> str:
    """Run psql inside shared-memory-pg via docker exec, returns stdout (tab-separated)."""
    cmd = ["docker", "exec", "shared-memory-pg", "bash", "-c",
           f"PGPASSWORD='LWE9r70CvmHa8nbtUIofo9Q2' psql -h 127.0.0.1 -U admin -d shared_memory -tAc {sql!r}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception as e:
        return f"ERR:{e}"


def snapshot() -> dict:
    snap: dict = {"ts": _now()}

    # LLM traces (last 5 min)
    snap["llm_5min"] = pg_query(
        "SELECT 'count='||count(*)||' err='||COALESCE(SUM(CASE WHEN status='error' THEN 1 ELSE 0 END),0)"
        "||' deg='||COALESCE(SUM(CASE WHEN status='degraded' THEN 1 ELSE 0 END),0)"
        "||' tok='||COALESCE(SUM(prompt_tokens+completion_tokens),0)"
        " FROM llm_traces WHERE created_at > NOW() - INTERVAL '5 minutes'"
    )

    # LLM traces by caller (last 5 min)
    snap["llm_by_caller"] = pg_query(
        "SELECT COALESCE(caller,'?')||'='||count(*)||'/'||COALESCE(ROUND(AVG(latency_ms)::numeric,0)::text,'-')"
        " FROM llm_traces WHERE created_at > NOW() - INTERVAL '5 minutes'"
        " GROUP BY caller ORDER BY count(*) DESC LIMIT 10"
    )

    # security_events (last 5 min)
    snap["events_5min_total"] = pg_query(
        "SELECT count(*) FROM security_events WHERE created_at > NOW() - INTERVAL '5 minutes'"
    )
    snap["events_5min_by_threat"] = pg_query(
        "SELECT COALESCE(threat_type,'?')||'='||count(*) FROM security_events WHERE created_at > NOW() - INTERVAL '5 minutes'"
        " GROUP BY threat_type ORDER BY count(*) DESC LIMIT 12"
    )

    # response_logs (last 5 min)
    snap["responses_5min_total"] = pg_query(
        "SELECT count(*) FROM response_logs WHERE created_at > NOW() - INTERVAL '5 minutes'"
    )
    snap["responses_5min_by_action"] = pg_query(
        "SELECT COALESCE(action_type,'?')||'='||count(*)||'/'||COALESCE(ROUND(AVG(latency_ms)::numeric,0)::text,'-')"
        " FROM response_logs WHERE created_at > NOW() - INTERVAL '5 minutes'"
        " GROUP BY action_type ORDER BY count(*) DESC LIMIT 8"
    )

    # LLM today total
    snap["llm_today_total"] = pg_query(
        "SELECT 'calls='||count(*)||' tok='||COALESCE(SUM(prompt_tokens+completion_tokens),0)"
        " FROM llm_traces WHERE created_at > NOW() - INTERVAL '24 hours'"
    )

    # /api/health
    st, body = http_get("/api/health")
    snap["api_health"] = {"status": st, "body": body if isinstance(body, dict) else str(body)[:200]}

    return snap


def main() -> int:
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    print(f"[MONITOR] started interval={INTERVAL}s out={OUT}", flush=True)
    with open(OUT, "a", encoding="utf-8") as f:
        while True:
            try:
                snap = snapshot()
                line = json.dumps(snap, ensure_ascii=False)
                f.write(line + "\n")
                f.flush()
                # compact print
                ts = snap["ts"]
                llm = snap.get("llm_5min", "?")[:80]
                ev = snap.get("events_5min_total", "?")
                resp = snap.get("responses_5min_total", "?")
                print(f"[{ts}] llm5m={llm} | events5m={ev} | resp5m={resp}", flush=True)
            except Exception as e:
                print(f"[MONITOR ERROR] {e}", flush=True)
            time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
