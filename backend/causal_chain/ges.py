"""GES-style BIC 贪心搜索(小 p 二进制 DAG)。

不是 Chickering 全套 CPDAG 算子;节点 ≤ 20 时 forward/backward/reverse 足够作 PC 对照。
两算法骨架一致的边才标 high_confidence。
"""
from __future__ import annotations

import numpy as np


def _pack_parents(data: np.ndarray, parents: tuple[int, ...]) -> np.ndarray:
    if not parents:
        return np.zeros(data.shape[0], dtype=np.int64)
    z = data[:, list(parents)].astype(np.int64)
    weights = (1 << np.arange(z.shape[1], dtype=np.int64))
    return (z * weights).sum(axis=1)


def bic_node(data: np.ndarray, child: int, parents: tuple[int, ...]) -> float:
    n = data.shape[0]
    y = data[:, child].astype(np.int8)
    keys = _pack_parents(data, parents)
    ll = 0.0
    k_params = 0
    for k in np.unique(keys):
        mask = keys == k
        ys = y[mask]
        m = int(ys.size)
        if m == 0:
            continue
        p = float(np.clip(ys.mean(), 1e-9, 1 - 1e-9))
        ones = int(ys.sum())
        ll += ones * np.log(p) + (m - ones) * np.log(1 - p)
        k_params += 1
    return float(ll - 0.5 * k_params * np.log(max(n, 2)))


def bic_graph(data: np.ndarray, parents: dict[int, tuple[int, ...]]) -> float:
    return float(sum(bic_node(data, i, parents.get(i, ())) for i in range(data.shape[1])))


def _has_cycle(parents: dict[int, tuple[int, ...]], p: int) -> bool:
    visiting = set()
    seen = set()

    def dfs(n: int) -> bool:
        if n in visiting:
            return True
        if n in seen:
            return False
        visiting.add(n)
        for pr in parents.get(n, ()):
            if dfs(pr):
                return True
        visiting.remove(n)
        seen.add(n)
        return False

    return any(dfs(i) for i in range(p))


def ges_learn(
    data: np.ndarray,
    names: list[str],
    *,
    max_parents: int = 3,
) -> dict:
    data = np.asarray(data, dtype=np.uint8)
    p = data.shape[1]
    parents: dict[int, tuple[int, ...]] = {i: () for i in range(p)}
    score = bic_graph(data, parents)

    def try_apply(new_parents) -> bool:
        nonlocal parents, score
        if _has_cycle(new_parents, p):
            return False
        s = bic_graph(data, new_parents)
        if s > score + 1e-9:
            parents = new_parents
            score = s
            return True
        return False

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            pa = parents[child]
            if len(pa) >= max_parents:
                continue
            for pr in range(p):
                if pr == child or pr in pa:
                    continue
                cand = dict(parents)
                cand[child] = tuple(sorted(pa + (pr,)))
                if _has_cycle(cand, p):
                    continue
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            pa = parents[child]
            for pr in pa:
                cand = dict(parents)
                cand[child] = tuple(x for x in pa if x != pr)
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            for pr in parents[child]:
                if child in parents[pr]:
                    continue
                cand = dict(parents)
                cand[child] = tuple(x for x in parents[child] if x != pr)
                if len(cand[pr]) >= max_parents:
                    continue
                cand[pr] = tuple(sorted(cand[pr] + (child,)))
                if _has_cycle(cand, p):
                    continue
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    directed = []
    for child, pa in parents.items():
        for pr in pa:
            directed.append((names[pr], names[child]))
    skeleton = {tuple(sorted(e)) for e in directed}
    return {
        "algorithm": "ges",
        "directed": sorted(directed),
        "undirected": [],
        "skeleton": sorted(skeleton),
        "bic": score,
        "n": int(data.shape[0]),
        "p": p,
    }


def consensus(pc_result: dict, ges_result: dict) -> dict:
    """骨架一致 → high_confidence;只一边有 → algorithm_disagree。"""
    pc_sk = {tuple(sorted(e)) for e in pc_result.get("skeleton") or []}
    ges_sk = {tuple(sorted(e)) for e in ges_result.get("skeleton") or []}
    both = pc_sk & ges_sk
    only_pc = pc_sk - ges_sk
    only_ges = ges_sk - pc_sk
    pc_dir = {(a, b) for a, b in pc_result.get("directed") or []}
    ges_dir = {(a, b) for a, b in ges_result.get("directed") or []}
    directed = []
    for a, b in sorted(pc_dir | ges_dir):
        sk = tuple(sorted((a, b)))
        if sk not in both:
            conf = "algorithm_disagree"
        elif (a, b) in pc_dir and (a, b) in ges_dir:
            conf = "high_confidence"
        elif (a, b) in pc_dir or (a, b) in ges_dir:
            # 骨架一致但定向不一
            if (b, a) in pc_dir or (b, a) in ges_dir:
                conf = "undirected_or_conflict"
            else:
                conf = "high_confidence" if (a, b) in pc_dir and (a, b) in ges_dir else "oriented_by_one"
        else:
            conf = "algorithm_disagree"
        directed.append({"cause": a, "effect": b, "confidence": conf})
    return {
        "directed": directed,
        "skeleton_agree": [list(e) for e in sorted(both)],
        "only_pc": [list(e) for e in sorted(only_pc)],
        "only_ges": [list(e) for e in sorted(only_ges)],
        "agree_rate": (len(both) / max(len(pc_sk | ges_sk), 1)),
    }
