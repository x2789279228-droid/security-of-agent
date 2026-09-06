"""PC 算法(约束式) — 二进制变量 + G² 条件独立。

输出 CPDAG: directed 有向边, undirected 未定向边。未定向边不算 CEP 因果支持。
Pearl 第 1→2 层的结构输入,不在本文件做 do()。
"""
from __future__ import annotations

from itertools import combinations
from typing import Iterable, Optional

import numpy as np

try:
    from scipy.stats import chi2 as _chi2
except Exception:  # pragma: no cover
    _chi2 = None


def _chi2_sf(stat: float, df: int) -> float:
    if df <= 0:
        return 1.0
    if _chi2 is not None:
        return float(_chi2.sf(max(stat, 0.0), df))
    # df=1 退化: erfc 近似
    import math
    z = math.sqrt(max(stat, 0.0))
    return float(math.erfc(z / math.sqrt(2.0)))


def g2_pvalue(data: np.ndarray, i: int, j: int, cond: Iterable[int]) -> float:
    """G² 条件独立 p 值。p 大 → 不能拒绝独立。"""
    n = data.shape[0]
    if i == j or n < 8:
        return 1.0
    cond = tuple(int(c) for c in cond)
    x = data[:, i].astype(np.int8)
    y = data[:, j].astype(np.int8)
    if cond:
        z = data[:, list(cond)].astype(np.int64)
        weights = (1 << np.arange(z.shape[1], dtype=np.int64))
        keys = (z * weights).sum(axis=1)
    else:
        keys = np.zeros(n, dtype=np.int64)

    g2 = 0.0
    df = 0
    for k in np.unique(keys):
        mask = keys == k
        xs = x[mask]
        ys = y[mask]
        if xs.size < 4:
            continue
        n00 = int(np.sum((xs == 0) & (ys == 0)))
        n01 = int(np.sum((xs == 0) & (ys == 1)))
        n10 = int(np.sum((xs == 1) & (ys == 0)))
        n11 = int(np.sum((xs == 1) & (ys == 1)))
        table = np.array([[n00, n01], [n10, n11]], dtype=float)
        if table.sum() < 4:
            continue
        if (table.sum(axis=0) == 0).any() or (table.sum(axis=1) == 0).any():
            continue
        expected = table.sum(axis=1, keepdims=True) * table.sum(axis=0, keepdims=True) / table.sum()
        nz = table > 0
        exp = np.clip(expected, 1e-12, None)
        g2 += float(2.0 * np.sum(table[nz] * np.log(table[nz] / exp[nz])))
        df += 1
    if df <= 0:
        return 1.0
    return _chi2_sf(g2, df)


def pc_skeleton(
    data: np.ndarray,
    *,
    alpha: float = 0.05,
    max_cond: int = 3,
) -> tuple[set[tuple[int, int]], dict[tuple[int, int], tuple[int, ...]]]:
    """无向骨架 + sepset。边以 i<j 存储。"""
    p = data.shape[1]
    adj = {i: set(j for j in range(p) if j != i) for i in range(p)}
    sepset: dict[tuple[int, int], tuple[int, ...]] = {}
    for depth in range(0, max_cond + 1):
        changed = True
        while changed:
            changed = False
            pairs = [(i, j) for i in range(p) for j in sorted(adj[i]) if i < j]
            for i, j in pairs:
                if j not in adj[i]:
                    continue
                candidates = [k for k in adj[i] if k != j]
                if len(candidates) < depth:
                    continue
                for s in combinations(candidates, depth):
                    pval = g2_pvalue(data, i, j, s)
                    if pval > alpha:
                        adj[i].discard(j)
                        adj[j].discard(i)
                        sepset[(i, j)] = tuple(s)
                        sepset[(j, i)] = tuple(s)
                        changed = True
                        break
    skeleton = {(min(i, j), max(i, j)) for i in adj for j in adj[i] if i < j}
    return skeleton, sepset


def _orient_v_structures(
    skeleton: set[tuple[int, int]],
    sepset: dict[tuple[int, int], tuple[int, ...]],
    p: int,
):
    undirected = {frozenset(e) for e in skeleton}
    directed: set[tuple[int, int]] = set()
    neighbors = {i: set() for i in range(p)}
    for a, b in skeleton:
        neighbors[a].add(b)
        neighbors[b].add(a)
    for z in range(p):
        nbrs = list(neighbors[z])
        for x, y in combinations(nbrs, 2):
            if frozenset((x, y)) in undirected:
                continue
            s = sepset.get((x, y), sepset.get((y, x), ()))
            if z not in s:
                directed.add((x, z))
                directed.add((y, z))
                undirected.discard(frozenset((x, z)))
                undirected.discard(frozenset((y, z)))
    return directed, undirected, neighbors


def _meek_rules(directed: set[tuple[int, int]], undirected: set[frozenset], neighbors: dict) -> None:
    def is_adj(a, b):
        return frozenset((a, b)) in undirected or (a, b) in directed or (b, a) in directed

    changed = True
    while changed:
        changed = False
        # R1: a→b − c, a not adj c ⇒ b→c
        for a, b in list(directed):
            for c in list(neighbors[b]):
                if c == a:
                    continue
                if frozenset((b, c)) not in undirected:
                    continue
                if is_adj(a, c):
                    continue
                directed.add((b, c))
                undirected.discard(frozenset((b, c)))
                changed = True
        # R2: a→b→c 且 a−c ⇒ a→c
        for a, b in list(directed):
            for c in [t for (s, t) in directed if s == b]:
                if frozenset((a, c)) in undirected:
                    directed.add((a, c))
                    undirected.discard(frozenset((a, c)))
                    changed = True
        # R3: a−b, c→b, d→b, a−c, a−d, c not adj d ⇒ a→b
        for edge in list(undirected):
            a, b = tuple(edge)
            for src, dst in ((a, b), (b, a)):
                parents = [s for (s, t) in directed if t == dst and s != src]
                if len(parents) < 2:
                    continue
                for c, d in combinations(parents, 2):
                    if is_adj(c, d):
                        continue
                    if frozenset((src, c)) in undirected and frozenset((src, d)) in undirected:
                        directed.add((src, dst))
                        undirected.discard(frozenset((src, dst)))
                        changed = True
                        break


def pc_learn(
    data: np.ndarray,
    names: list[str],
    *,
    alpha: float = 0.05,
    max_cond: int = 3,
) -> dict:
    """返回 {directed:[(u,v)], undirected:[(u,v)], skeleton:[...]} 用变量名。"""
    data = np.asarray(data, dtype=np.uint8)
    p = data.shape[1]
    if p != len(names):
        raise ValueError("names length mismatch")
    skeleton, sepset = pc_skeleton(data, alpha=alpha, max_cond=max_cond)
    directed, undirected, neighbors = _orient_v_structures(skeleton, sepset, p)
    _meek_rules(directed, undirected, neighbors)
    # 丢掉双向冲突:保留都不定向
    both = {(a, b) for (a, b) in directed if (b, a) in directed}
    for a, b in list(both):
        directed.discard((a, b))
        directed.discard((b, a))
        undirected.add(frozenset((a, b)))
    return {
        "algorithm": "pc",
        "directed": [(names[a], names[b]) for a, b in sorted(directed)],
        "undirected": [tuple(sorted((names[a], names[b]))) for a, b in sorted((tuple(e) for e in undirected))],
        "skeleton": [(names[a], names[b]) for a, b in sorted(skeleton)],
        "alpha": alpha,
        "n": int(data.shape[0]),
        "p": p,
    }
