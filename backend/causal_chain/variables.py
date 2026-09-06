"""把 security_events 切成 (src_ip, time_bin) 二进制样本。

节点 = 归一化攻击类型 + ANOMALY_HIGH + 观测混杂 HOUR_NIGHT / DST_HUB。
混杂不当攻击步骤,只进 PC 条件集与后门集。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import numpy as np

from correlation_engine import normalize_event_type

# 与 CEP / correlation 对齐的攻击类型(上限,超出并 OTHER)
ATTACK_NODES = [
    "PORT_SCAN", "BRUTE_FORCE", "SUSPICIOUS_LOGIN", "FILE_ACCESS",
    "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL", "SQL_INJECTION",
    "UNAUTHORIZED_ACCESS", "MALWARE_DETECT", "DNS_QUERY",
]
CONFOUNDERS = ("HOUR_NIGHT", "DST_HUB")
ANOMALY_NODE = "ANOMALY_HIGH"
OTHER_NODE = "OTHER"

# ATT&CK 战术序近似(软先验:禁止反向边)
TACTIC_RANK = {
    "PORT_SCAN": 0,
    "DNS_QUERY": 0,
    "BRUTE_FORCE": 1,
    "SUSPICIOUS_LOGIN": 1,
    "SQL_INJECTION": 1,
    "UNAUTHORIZED_ACCESS": 1,
    "FILE_ACCESS": 2,
    "MALWARE_DETECT": 2,
    "LATERAL_MOVE": 3,
    "C2_BEACON": 4,
    "DATA_EXFIL": 5,
}

DEFAULT_BIN_MINUTES = 30
DEFAULT_MIN_WINDOWS = 40
MAX_NODES = 20
DST_HUB_MIN = 3


def node_names() -> list[str]:
    return list(ATTACK_NODES) + [OTHER_NODE, ANOMALY_NODE] + list(CONFOUNDERS)


def is_attack_node(name: str) -> bool:
    return name in ATTACK_NODES or name == OTHER_NODE


def is_confounder(name: str) -> bool:
    return name in CONFOUNDERS


def _as_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _row_from_event(evt: Any) -> dict:
    if isinstance(evt, dict):
        return {
            "event_type": evt.get("event_type") or evt.get("event") or "",
            "src_ip": evt.get("src_ip") or "",
            "dst_ip": evt.get("dst_ip") or "",
            "created_at": evt.get("created_at"),
            "anomaly_score": float(evt.get("anomaly_score") or 0.0),
        }
    return {
        "event_type": getattr(evt, "event_type", "") or "",
        "src_ip": getattr(evt, "src_ip", "") or "",
        "dst_ip": getattr(evt, "dst_ip", "") or "",
        "created_at": getattr(evt, "created_at", None),
        "anomaly_score": float(getattr(evt, "anomaly_score", 0.0) or 0.0),
    }


def events_to_matrix(
    events: Iterable[Any],
    *,
    bin_minutes: int = DEFAULT_BIN_MINUTES,
    min_windows: int = DEFAULT_MIN_WINDOWS,
    dst_hub_min: int = DST_HUB_MIN,
) -> dict:
    """返回 {ok, reason, names, X, n, dropped}。X 是 (n, p) uint8。"""
    names = node_names()
    idx = {n: i for i, n in enumerate(names)}
    buckets: dict[tuple[str, int], dict] = {}
    bin_s = max(1, int(bin_minutes)) * 60

    for raw in events:
        row = _row_from_event(raw)
        src = str(row["src_ip"] or "unknown")
        dt = _as_dt(row["created_at"])
        bin_id = int(dt.timestamp() // bin_s)
        key = (src, bin_id)
        slot = buckets.get(key)
        if slot is None:
            slot = {"types": set(), "anomaly": False, "night": dt.hour < 6, "dsts": []}
            buckets[key] = slot
        et = normalize_event_type(str(row["event_type"]))
        if et in idx:
            slot["types"].add(et)
        elif et and et not in ("UNKNOWN",):
            slot["types"].add(OTHER_NODE)
        if row["anomaly_score"] >= 0.6:
            slot["anomaly"] = True
        if dt.hour < 6:
            slot["night"] = True
        if row["dst_ip"]:
            slot["dsts"].append(row["dst_ip"])

    n = len(buckets)
    if n < int(min_windows):
        return {
            "ok": False,
            "reason": "insufficient_data",
            "names": names,
            "X": np.zeros((0, len(names)), dtype=np.uint8),
            "n": n,
            "min_windows": int(min_windows),
        }

    X = np.zeros((n, len(names)), dtype=np.uint8)
    for r, slot in enumerate(buckets.values()):
        for t in slot["types"]:
            if t in idx:
                X[r, idx[t]] = 1
        if slot["anomaly"]:
            X[r, idx[ANOMALY_NODE]] = 1
        if slot["night"]:
            X[r, idx["HOUR_NIGHT"]] = 1
        dst_counts: dict[str, int] = defaultdict(int)
        for d in slot["dsts"]:
            dst_counts[d] += 1
        if any(c >= dst_hub_min for c in dst_counts.values()):
            X[r, idx["DST_HUB"]] = 1

    # 丢掉几乎常数的攻击列(边际 < 3),混杂列保留
    keep = []
    dropped = []
    for i, name in enumerate(names):
        freq = int(X[:, i].sum())
        if is_confounder(name) or name == ANOMALY_NODE:
            keep.append(i)
            continue
        if freq == 0 or freq == n:
            dropped.append(name)
            continue
        keep.append(i)
    if len(keep) < 3:
        return {
            "ok": False,
            "reason": "insufficient_data",
            "names": names,
            "X": X,
            "n": n,
            "dropped": dropped,
        }
    names_k = [names[i] for i in keep]
    return {
        "ok": True,
        "reason": "",
        "names": names_k,
        "X": X[:, keep],
        "n": n,
        "dropped": dropped,
    }


def prior_forbids(cause: str, effect: str) -> bool:
    """战术序反向边: DATA_EXFIL → PORT_SCAN 等。"""
    rc = TACTIC_RANK.get(cause)
    re = TACTIC_RANK.get(effect)
    if rc is None or re is None:
        return False
    return re < rc
