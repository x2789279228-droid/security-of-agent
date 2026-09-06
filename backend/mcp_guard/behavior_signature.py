"""工具行为指纹：Welford / 小时桶 / 类别计数 / IP 类 / Markov 载荷。

检测器只依赖本模块的纯数据结构，不碰 DB / Redis。
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

GLOBAL_CALLER = "*"
CAT_MAX = 64
HASH_TOP = 32
NUMERIC_KEYS = {
    "duration", "rate", "limit", "pid", "time_window_minutes", "duration_ms",
}
IP_KEYS = {"ip", "target", "host", "src_ip", "dst_ip"}
CAT_KEYS = {"isolation_type", "scan_type", "action", "tool_match_method"}


@dataclass
class Welford:
    """在线均值/方差。"""
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        x = float(value)
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.n - 1))

    def zscore(self, value: float) -> Optional[float]:
        if self.n < 8:
            return None
        if self.std <= 1e-12:
            return 0.0 if abs(float(value) - self.mean) < 1e-12 else 8.0
        return abs(float(value) - self.mean) / self.std

    def to_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, raw: Any) -> "Welford":
        data = raw if isinstance(raw, dict) else {}
        w = cls()
        w.n = int(data.get("n") or 0)
        w.mean = float(data.get("mean") or 0.0)
        w.m2 = float(data.get("m2") or 0.0)
        return w


def classify_ip(value: Any) -> Optional[str]:
    """返回 loopback/link_local/multicast/rfc1918/public；非 IP 返回 None。"""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text.split("/")[0])
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "rfc1918"
    return "public"


def _hash16(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def extract_features(arguments: Optional[dict]) -> dict:
    """从消毒后的 arguments 抽出 param 维特征。"""
    args = arguments if isinstance(arguments, dict) else {}
    numeric: dict[str, float] = {}
    categorical: dict[str, str] = {}
    ip_fields: list[tuple[str, str, str]] = []  # key, value, class
    hashes: dict[str, str] = {}
    str_len: dict[str, int] = {}

    for key, raw in args.items():
        if key.startswith("_"):
            continue
        if isinstance(raw, bool):
            categorical[str(key)] = "true" if raw else "false"
            continue
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            if str(key) in NUMERIC_KEYS:
                numeric[str(key)] = float(raw)
            continue
        if not isinstance(raw, str):
            continue
        text = raw.strip()
        if not text:
            continue
        ip_cls = classify_ip(text)
        if ip_cls:
            ip_fields.append((str(key), text, ip_cls))
            hashes[str(key)] = _hash16(text)
            continue
        if str(key) in IP_KEYS:
            hashes[str(key)] = _hash16(text)
            str_len[str(key)] = len(text)
            continue
        if str(key) in CAT_KEYS:
            categorical[str(key)] = text[:64]
            continue
        if str(key) in NUMERIC_KEYS:
            try:
                numeric[str(key)] = float(text)
                continue
            except ValueError:
                pass
        str_len[str(key)] = len(text)

    return {
        "numeric": numeric,
        "categorical": categorical,
        "ip_fields": ip_fields,
        "hashes": hashes,
        "str_len": str_len,
    }


def _counter_from(raw: Any) -> Counter:
    if isinstance(raw, dict):
        return Counter({str(k): int(v) for k, v in raw.items() if v is not None})
    return Counter()


def _bump_capped(counter: Counter, key: str, cap: int = CAT_MAX) -> None:
    if key in counter or len(counter) < cap:
        counter[key] += 1
        return
    counter["OTHER"] += 1


def _prune_top(counter: Counter, keep: int = HASH_TOP) -> None:
    if len(counter) <= keep * 2:
        return
    for k, _ in counter.most_common()[keep:]:
        del counter[k]


@dataclass
class ToolBehaviorSignature:
    """(tool_name, caller) 的正常调用模式。caller='*' 为工具级全局回退。"""

    tool_name: str
    caller: str
    sample_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    hourly_counts: list = field(default_factory=lambda: [0] * 24)
    weekday_counts: list = field(default_factory=lambda: [0] * 7)
    ewma_per_min: float = 0.0
    ewma_var: float = 0.0
    numeric: dict = field(default_factory=dict)
    categorical: dict = field(default_factory=dict)
    ip_class: Counter = field(default_factory=Counter)
    target_hash_top: Counter = field(default_factory=Counter)
    str_len: dict = field(default_factory=dict)
    role_counts: Counter = field(default_factory=Counter)
    source_counts: Counter = field(default_factory=Counter)
    decision_counts: Counter = field(default_factory=Counter)
    duration_ms: Welford = field(default_factory=Welford)
    minute_buckets: int = 0
    last_minute: int = -1

    def ready(self, min_samples: int) -> bool:
        return self.sample_count >= int(min_samples)

    def update(self, *, ts: float, hour: int, weekday: int, features: dict,
               role: str = "", source: str = "", decision: str = "",
               duration_ms: float = 0.0) -> None:
        if self.first_seen <= 0:
            self.first_seen = ts
        self.last_seen = ts
        self.sample_count += 1
        if 0 <= hour < 24:
            self.hourly_counts[hour] += 1
        if 0 <= weekday < 7:
            self.weekday_counts[weekday] += 1

        minute = int(ts // 60)
        if self.last_minute != minute:
            self.minute_buckets += 1
            self.last_minute = minute
            # EWMA of calls-per-minute; 当前分钟结束后才有完整计数，这里用 1 作为新桶起点
            alpha = 0.3
            observed = 1.0
            if self.ewma_per_min <= 0:
                self.ewma_per_min = observed
            else:
                delta = observed - self.ewma_per_min
                self.ewma_per_min += alpha * delta
                self.ewma_var = (1 - alpha) * (self.ewma_var + alpha * delta * delta)

        for key, value in (features.get("numeric") or {}).items():
            w = self.numeric.get(key)
            if not isinstance(w, Welford):
                w = Welford.from_dict(w) if isinstance(w, dict) else Welford()
                self.numeric[key] = w
            w.update(value)

        for key, value in (features.get("categorical") or {}).items():
            bucket = self.categorical.get(key)
            if not isinstance(bucket, Counter):
                bucket = _counter_from(bucket)
                self.categorical[key] = bucket
            _bump_capped(bucket, str(value))

        for _key, _val, cls in features.get("ip_fields") or []:
            self.ip_class[cls] += 1

        for _key, digest in (features.get("hashes") or {}).items():
            _bump_capped(self.target_hash_top, digest, HASH_TOP * 2)
        _prune_top(self.target_hash_top, HASH_TOP)

        for key, length in (features.get("str_len") or {}).items():
            w = self.str_len.get(key)
            if not isinstance(w, Welford):
                w = Welford.from_dict(w) if isinstance(w, dict) else Welford()
                self.str_len[key] = w
            w.update(float(length))

        if role:
            self.role_counts[role] += 1
        if source:
            self.source_counts[source] += 1
        if decision:
            self.decision_counts[decision] += 1
        if duration_ms:
            self.duration_ms.update(duration_ms)

    def score_params(self, features: dict) -> tuple[float, list[str]]:
        """返回 (0-1, reasons)。样本不足时由调用方避免进来。"""
        subs: list[tuple[float, str]] = []

        ip_total = sum(self.ip_class.values())
        for key, value, cls in features.get("ip_fields") or []:
            if ip_total <= 0:
                continue
            freq = self.ip_class[cls] / ip_total
            if self.ip_class[cls] <= 0:
                subs.append((0.95, f"{self.tool_name}.{key} 类别 {cls},基线未见 (值 {value})"))
            elif freq < 0.01:
                subs.append((0.9, f"{self.tool_name}.{key} 类别 {cls},基线 {freq:.1%}"))
            elif freq < 0.05:
                subs.append((0.7, f"{self.tool_name}.{key} 类别 {cls},基线 {freq:.1%}"))

        for key, value in (features.get("categorical") or {}).items():
            bucket = self.categorical.get(key)
            if not isinstance(bucket, Counter):
                bucket = _counter_from(bucket)
            total = sum(bucket.values())
            if total < 5:
                continue
            count = bucket[value]
            if count <= 0:
                subs.append((0.9, f"{self.tool_name}.{key}={value} 未见过"))
            elif count / total < 0.01:
                subs.append((0.8, f"{self.tool_name}.{key}={value} 频率 {count}/{total}"))

        for key, value in (features.get("numeric") or {}).items():
            w = self.numeric.get(key)
            if not isinstance(w, Welford):
                w = Welford.from_dict(w) if isinstance(w, dict) else None
            if w is None:
                continue
            z = w.zscore(value)
            if z is None:
                continue
            if z >= 3:
                score = min(1.0, 0.7 + (z - 3) / 10)
                subs.append((score, f"{self.tool_name}.{key}={value} 偏离 {z:.1f}σ"))

        for key, length in (features.get("str_len") or {}).items():
            w = self.str_len.get(key)
            if not isinstance(w, Welford):
                w = Welford.from_dict(w) if isinstance(w, dict) else None
            if w is None:
                continue
            z = w.zscore(length)
            if z is not None and z >= 3:
                subs.append((min(1.0, 0.65 + (z - 3) / 12), f"{self.tool_name}.{key} 长度偏离 {z:.1f}σ"))

        if not subs:
            return 0.0, []
        best = max(subs, key=lambda x: x[0])
        reasons = [r for s, r in sorted(subs, reverse=True) if s >= 0.7][:4]
        return float(best[0]), reasons

    def score_time(self, hour: int) -> tuple[float, list[str]]:
        if self.sample_count < 1 or not (0 <= hour < 24):
            return 0.0, []
        expected = self.hourly_counts[hour] / max(1, self.sample_count)
        if expected >= 0.08:
            return 0.0, []
        if expected <= 0.002:
            return 0.85, [f"{self.tool_name} 在 {hour:02d}:00 调用,该小时历史占比 {expected:.1%}"]
        # 0.002–0.08 线性
        score = min(0.7, (0.08 - expected) / 0.08)
        if score < 0.35:
            return 0.0, []
        return score, [f"{self.tool_name} 在 {hour:02d}:00 调用,该小时历史占比 {expected:.1%}"]

    def summary(self, min_samples: int = 30) -> dict:
        cats = {}
        for key, bucket in self.categorical.items():
            c = bucket if isinstance(bucket, Counter) else _counter_from(bucket)
            cats[key] = dict(c.most_common(8))
        return {
            "tool_name": self.tool_name,
            "caller": self.caller,
            "sample_count": self.sample_count,
            "ready": self.ready(min_samples),
            "hourly_counts": list(self.hourly_counts),
            "ip_class": dict(self.ip_class),
            "categorical": cats,
            "role_counts": dict(self.role_counts),
            "source_counts": dict(self.source_counts),
            "last_seen": self.last_seen,
        }

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "caller": self.caller,
            "sample_count": self.sample_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hourly_counts": list(self.hourly_counts),
            "weekday_counts": list(self.weekday_counts),
            "ewma_per_min": self.ewma_per_min,
            "ewma_var": self.ewma_var,
            "numeric": {k: (v.to_dict() if isinstance(v, Welford) else v) for k, v in self.numeric.items()},
            "categorical": {k: dict(v if isinstance(v, Counter) else _counter_from(v)) for k, v in self.categorical.items()},
            "ip_class": dict(self.ip_class),
            "target_hash_top": dict(self.target_hash_top),
            "str_len": {k: (v.to_dict() if isinstance(v, Welford) else v) for k, v in self.str_len.items()},
            "role_counts": dict(self.role_counts),
            "source_counts": dict(self.source_counts),
            "decision_counts": dict(self.decision_counts),
            "duration_ms": self.duration_ms.to_dict(),
            "minute_buckets": self.minute_buckets,
            "last_minute": self.last_minute,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "ToolBehaviorSignature":
        data = raw or {}
        sig = cls(
            tool_name=str(data.get("tool_name") or ""),
            caller=str(data.get("caller") or GLOBAL_CALLER),
            sample_count=int(data.get("sample_count") or 0),
            first_seen=float(data.get("first_seen") or 0.0),
            last_seen=float(data.get("last_seen") or 0.0),
            hourly_counts=list(data.get("hourly_counts") or [0] * 24)[:24],
            weekday_counts=list(data.get("weekday_counts") or [0] * 7)[:7],
            ewma_per_min=float(data.get("ewma_per_min") or 0.0),
            ewma_var=float(data.get("ewma_var") or 0.0),
            ip_class=_counter_from(data.get("ip_class")),
            target_hash_top=_counter_from(data.get("target_hash_top")),
            role_counts=_counter_from(data.get("role_counts")),
            source_counts=_counter_from(data.get("source_counts")),
            decision_counts=_counter_from(data.get("decision_counts")),
            duration_ms=Welford.from_dict(data.get("duration_ms")),
            minute_buckets=int(data.get("minute_buckets") or 0),
            last_minute=int(data.get("last_minute") or -1),
        )
        while len(sig.hourly_counts) < 24:
            sig.hourly_counts.append(0)
        while len(sig.weekday_counts) < 7:
            sig.weekday_counts.append(0)
        for k, v in (data.get("numeric") or {}).items():
            sig.numeric[str(k)] = Welford.from_dict(v)
        for k, v in (data.get("categorical") or {}).items():
            sig.categorical[str(k)] = _counter_from(v)
        for k, v in (data.get("str_len") or {}).items():
            sig.str_len[str(k)] = Welford.from_dict(v)
        return sig
