"""CEP / Python 关联链 vs 因果 DAG。"""
from __future__ import annotations

from typing import Any, Optional

from causal_chain.do_calculus import has_directed_path, intervene
from causal_chain.variables import CONFOUNDERS, is_attack_node, prior_forbids

# 与 Flink AnomalyDetectionJob 三模式对齐(不 import Java/kafka 缓存)
CEP_PATTERNS = {
    "port_scan_to_c2": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
    "lateral_movement": ["SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE"],
    "data_exfil": ["FILE_ACCESS", "DATA_EXFIL"],
}

ACE_SPURIOUS = 0.05


def _steps_of(chain: dict) -> list[str]:
    pid = str(chain.get("pattern_id") or chain.get("patternId") or "")
    if pid in CEP_PATTERNS:
        return list(CEP_PATTERNS[pid])
    name = str(chain.get("pattern_name") or "")
    for k, steps in CEP_PATTERNS.items():
        if k in name or name.endswith(k):
            return list(steps)
    events = chain.get("events") or []
    out = []
    for e in events:
        if isinstance(e, dict):
            t = str(e.get("event_type") or "")
        else:
            t = str(e)
        if t and t not in out:
            out.append(t)
    return out


def annotate_chain(
    chain: dict,
    *,
    directed: list[tuple[str, str]],
    names: list[str],
    data,
    ace_spurious: float = ACE_SPURIOUS,
) -> dict:
    steps = [s for s in _steps_of(chain) if is_attack_node(s)]
    skip = set(CONFOUNDERS)
    path_ok = True
    missing = []
    if len(steps) >= 2:
        for a, b in zip(steps, steps[1:]):
            if a not in names or b not in names:
                path_ok = False
                missing.append((a, b))
                continue
            if not has_directed_path(directed, a, b, skip=skip):
                path_ok = False
                missing.append((a, b))
    first, last = (steps[0], steps[-1]) if steps else ("", "")
    q: dict[str, Any] = {"identifiable": False}
    if first and last and first in names and last in names and data is not None:
        q = intervene(data, names, directed, first, last, do_value=0)
    ace = q.get("ace")
    identifiable = bool(q.get("identifiable"))
    verdict = "unknown"
    if not steps:
        verdict = "unknown"
    elif identifiable and ace is not None and abs(float(ace)) < ace_spurious:
        verdict = "spurious"
    elif path_ok:
        verdict = "causal_support"

    out = dict(chain)
    out["causal_verdict"] = verdict
    out["causal_steps"] = steps
    out["causal_path_ok"] = path_ok
    out["causal_missing_edges"] = [list(p) for p in missing]
    out["ace"] = ace
    out["identifiable"] = identifiable
    out["p_y_do"] = q.get("p_y_do")
    out["do_query"] = {"x": first, "y": last, "do": 0} if first else {}
    return out


def candidate_edges(
    consensus_directed: list[dict],
    *,
    cep_pairs: Optional[set[tuple[str, str]]] = None,
) -> list[dict]:
    """两算法一致、先验不违、CEP 没有的新边 → 人审候选,不自动广播。"""
    cep_pairs = cep_pairs or set()
    for pid, steps in CEP_PATTERNS.items():
        for a, b in zip(steps, steps[1:]):
            cep_pairs.add((a, b))
    out = []
    for e in consensus_directed:
        if e.get("confidence") != "high_confidence":
            continue
        a, b = e["cause"], e["effect"]
        if not is_attack_node(a) or not is_attack_node(b):
            continue
        if prior_forbids(a, b):
            continue
        if (a, b) in cep_pairs:
            continue
        out.append({**e, "status": "candidate"})
    return out
