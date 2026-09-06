"""攻击指纹与新颖度(Jaccard,不依赖 embedding,测试/离线可复现)。

NoveltyIndex 保持旧的 token 级 score/observe/dump/load 语义;
新增分层指纹 layered_fingerprint / observe_event / score_layered (N-A/N-B):
technique / parameter / sequence / scenario 四层,不混成一个分数。
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, Optional

from self_play.types import LayeredNovelty

_TOKEN_RE = re.compile(r" [A-Z][A-Z0-9_]{2,} | [a-zA-Z][a-zA-Z0-9_]{3,} | [\u4e00-\u9fff]{2,} ", re.VERBOSE)
_STOP = frozenset({
    "detected", "detect", "host", "user", "from", "with", "that", "this",
    "http", "https", "tcp", "udp", "the", "and", "for",
    "检测", "到", "主机", "用户", "通过", "进行", "出现", "异常",
})

_LAYER_WEIGHTS = {"technique": 0.4, "parameter": 0.3, "sequence": 0.2, "scenario": 0.1}


def tokenize(*parts: str) -> set[str]:
    blob = " ".join(str(p or "") for p in parts)
    tokens = set()
    for m in _TOKEN_RE.finditer(blob):
        t = m.group(0).strip().lower()
        if t and t not in _STOP:
            tokens.add(t)
    for m in re.finditer(r"T\d{4}(?:\.\d{3})?", blob, re.I):
        tokens.add(m.group(0).upper())
    return tokens


def fingerprint(event_type: str, message: str = "", mitre_id: str = "", protocol: str = "") -> str:
    toks = sorted(tokenize(event_type, message, mitre_id, protocol))
    raw = "|".join([event_type.upper(), protocol.lower(), mitre_id.upper(), *toks])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _evt_field(evt: Any, name: str, default: Any = "") -> Any:
    if isinstance(evt, dict):
        return evt.get(name, default)
    return getattr(evt, name, default)


def layered_fingerprint(evt: Any) -> dict:
    """分层指纹: technique / parameter / sequence / scenario。

    - technique: MITRE 父技术 (T1059.001 → T1059;无 mitre 时退化为 event_type);
    - parameter: message+protocol 词法 token,扣除技术 id;
    - sequence:  event_type + kill_chain(取 extra._kill_chain);
    - scenario:  src_host / dst_host / protocol / extra zone。
    """
    mitre = str(_evt_field(evt, "mitre_id", "") or "").upper().strip()
    parent = mitre.split(".")[0] if mitre else ""
    event_type = str(_evt_field(evt, "event", "") or "").upper().strip()
    protocol = str(_evt_field(evt, "protocol", "") or "").lower().strip()
    message = str(_evt_field(evt, "message", "") or "")
    extra = _evt_field(evt, "extra", {}) or {}
    if not isinstance(extra, dict):
        extra = {}

    tech_ids = {t for t in (mitre, parent) if t}
    technique = set(tech_ids) or ({event_type} if event_type else set())
    parameter = tokenize(message, protocol) - tech_ids

    kill_chain = str(extra.get("_kill_chain") or extra.get("kill_chain") or "").lower().strip()
    sequence = {t for t in (
        f"evt:{event_type}" if event_type else "",
        f"kc:{kill_chain}" if kill_chain else "",
    ) if t}

    src_host = str(_evt_field(evt, "src_host", "") or "").lower().strip()
    dst_host = str(_evt_field(evt, "dst_host", "") or "").lower().strip()
    zone = str(extra.get("_zone") or extra.get("zone") or "").lower().strip()
    scenario = {t for t in (src_host, dst_host, protocol, zone) if t}

    return {
        "technique": sorted(technique),
        "parameter": sorted(parameter),
        "sequence": sorted(sequence),
        "scenario": sorted(scenario),
    }


class NoveltyIndex:
    """历史攻击指纹库。novelty = 1 - max Jaccard;分层版按 layer 各自比对历史。"""

    def __init__(self) -> None:
        self._history: list[set[str]] = []
        self._layered: dict[str, list[set[str]]] = {
            "technique": [], "parameter": [], "sequence": [], "scenario": [],
        }

    def observe(self, tokens: Iterable[str]) -> None:
        s = set(tokens)
        if s:
            self._history.append(s)

    def score(self, tokens: Iterable[str]) -> float:
        s = set(tokens)
        if not s:
            return 0.0
        if not self._history:
            return 1.0
        best = max(jaccard(s, h) for h in self._history)
        return max(0.0, min(1.0, 1.0 - best))

    def score_event(self, event_type: str, message: str = "", mitre_id: str = "", protocol: str = "") -> float:
        return self.score(tokenize(event_type, message, mitre_id, protocol))

    # ------------------------------------------------------------- layered API
    def observe_event(self, evt: Any) -> None:
        """N-A: 同时更新分层历史与旧 token 历史。"""
        fp = layered_fingerprint(evt)
        for layer in _LAYER_WEIGHTS:
            s = set(fp.get(layer) or [])
            if s:
                self._layered[layer].append(s)
        self.observe(tokenize(
            str(_evt_field(evt, "event", "") or ""),
            str(_evt_field(evt, "message", "") or ""),
            str(_evt_field(evt, "mitre_id", "") or ""),
            str(_evt_field(evt, "protocol", "") or ""),
        ))

    def score_layered(self, evt: Any) -> LayeredNovelty:
        fp = layered_fingerprint(evt)
        vals: dict[str, float] = {}
        for layer in _LAYER_WEIGHTS:
            s = set(fp.get(layer) or [])
            hist = self._layered.get(layer) or []
            if not s:
                vals[layer] = 0.0
            elif not hist:
                vals[layer] = 1.0
            else:
                vals[layer] = max(0.0, min(1.0, 1.0 - max(jaccard(s, h) for h in hist)))
        combined = sum(_LAYER_WEIGHTS[layer] * vals[layer] for layer in _LAYER_WEIGHTS)
        return LayeredNovelty(
            technique=vals["technique"],
            parameter=vals["parameter"],
            sequence=vals["sequence"],
            scenario=vals["scenario"],
            combined=max(0.0, min(1.0, combined)),
        )

    def dump_layered(self) -> dict[str, list[list[str]]]:
        return {layer: [sorted(s) for s in sets] for layer, sets in self._layered.items()}

    def load_layered(self, rows: Optional[dict[str, list[list[str]]]] = None) -> None:
        rows = rows or {}
        self._layered = {
            layer: [set(r) for r in (rows.get(layer) or []) if r]
            for layer in _LAYER_WEIGHTS
        }

    @property
    def size(self) -> int:
        return len(self._history)

    def dump(self) -> list[list[str]]:
        return [sorted(s) for s in self._history]

    def load(self, rows: Optional[list[list[str]]] = None) -> None:
        self._history = [set(r) for r in (rows or []) if r]
