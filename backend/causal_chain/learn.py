"""结构学习编排:样本 → PC + GES → 共识边 → 后门 ACE。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from causal_chain.compare import annotate_chain, candidate_edges
from causal_chain.do_calculus import intervene
from causal_chain.ges import consensus, ges_learn
from causal_chain.pc import pc_learn
from causal_chain.variables import (
    DEFAULT_BIN_MINUTES,
    DEFAULT_MIN_WINDOWS,
    TACTIC_RANK,
    events_to_matrix,
    is_attack_node,
    is_confounder,
    prior_forbids,
)


def _orient_with_prior(pc: dict) -> list[tuple[str, str]]:
    """PC 未定向边用战术序 / 混杂→攻击 定向。运营 DAG 以 PC 为主,GES 只打标签。"""
    directed = [(a, b) for a, b in pc.get("directed") or []]
    have = set(directed)

    def add(a, b):
        if (a, b) in have or (b, a) in have:
            return
        have.add((a, b))
        directed.append((a, b))

    for e in pc.get("undirected") or []:
        if not e or len(e) != 2:
            continue
        a, b = e[0], e[1]
        if is_confounder(a) and not is_confounder(b):
            add(a, b)
            continue
        if is_confounder(b) and not is_confounder(a):
            add(b, a)
            continue
        ra, rb = TACTIC_RANK.get(a), TACTIC_RANK.get(b)
        if ra is not None and rb is not None:
            if ra < rb:
                add(a, b)
            elif rb < ra:
                add(b, a)
    return directed


def learn_from_matrix(
    X,
    names: list[str],
    *,
    alpha: float = 0.05,
    apply_prior: bool = True,
) -> dict:
    pc = pc_learn(X, names, alpha=alpha)
    ges = ges_learn(X, names)
    cons = consensus(pc, ges)
    directed_pairs = _orient_with_prior(pc)
    # 先验标记,不删边(消融用)
    edges = []
    for e in cons["directed"]:
        item = dict(e)
        item["prior_violation"] = prior_forbids(e["cause"], e["effect"])
        if apply_prior and item["prior_violation"]:
            item["confidence"] = "prior_violation"
        # ACE
        if is_attack_node(e["cause"]) and is_attack_node(e["effect"]):
            q = intervene(X, names, directed_pairs, e["cause"], e["effect"], do_value=0)
            item["ace"] = q.get("ace")
            item["identifiable"] = q.get("identifiable", False)
            item["p_y_do"] = q.get("p_y_do")
        else:
            item["ace"] = None
            item["identifiable"] = False
            item["p_y_do"] = None
        edges.append(item)
    return {
        "ok": True,
        "reason": "",
        "learned_at": datetime.now(timezone.utc).isoformat(),
        "n": int(getattr(X, "shape", [0])[0]),
        "names": names,
        "pc": pc,
        "ges": ges,
        "agree_rate": cons["agree_rate"],
        "edges": edges,
        "directed": directed_pairs,
        "skeleton_agree": cons["skeleton_agree"],
        "candidates": candidate_edges(edges),
        "ladder": 2,
    }


def learn_from_events(
    events,
    *,
    bin_minutes: int = DEFAULT_BIN_MINUTES,
    min_windows: int = DEFAULT_MIN_WINDOWS,
    alpha: float = 0.05,
    apply_prior: bool = True,
) -> dict:
    mat = events_to_matrix(events, bin_minutes=bin_minutes, min_windows=min_windows)
    if not mat.get("ok"):
        return {
            "ok": False,
            "reason": mat.get("reason") or "insufficient_data",
            "n": mat.get("n", 0),
            "names": mat.get("names") or [],
            "edges": [],
            "directed": [],
            "candidates": [],
            "pc": {},
            "ges": {},
            "agree_rate": 0.0,
        }
    result = learn_from_matrix(mat["X"], mat["names"], alpha=alpha, apply_prior=apply_prior)
    result["dropped"] = mat.get("dropped") or []
    result["bin_minutes"] = bin_minutes
    return result


def query_do(
    graph: dict,
    x: str,
    y: str,
    *,
    do_value: int = 0,
    data=None,
    names: Optional[list[str]] = None,
) -> dict:
    names = names or graph.get("names") or []
    directed = graph.get("directed") or []
    if data is None:
        return {"identifiable": False, "reason": "no_data", "x": x, "y": y, "do": do_value}
    return intervene(data, names, directed, x, y, do_value=do_value)


def annotate_chains(chains: list[dict], graph: dict, *, data=None) -> list[dict]:
    if not graph or not graph.get("ok"):
        return [{**c, "causal_verdict": "unknown", "identifiable": False, "ace": None} for c in chains]
    directed = graph.get("directed") or []
    names = graph.get("names") or []
    return [
        annotate_chain(c, directed=directed, names=names, data=data)
        for c in chains
    ]
