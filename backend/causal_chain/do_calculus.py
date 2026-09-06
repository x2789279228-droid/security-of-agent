"""Do-calculus 子集:后门调整。

实现的是 Pearl 阶梯第 2 层(干预):P(Y | do(X=x))。
不可识别时 identifiable=false,不编造数字。
分析员问句「若 X 没发生 Y 还会出现吗」用 P(Y=1|do(X=0)) 回答(人群级,不是个体反事实)。
"""
from __future__ import annotations

from itertools import combinations
from typing import Iterable, Optional

import numpy as np

from causal_chain.variables import CONFOUNDERS, is_confounder


def _parents(directed: list[tuple[str, str]]) -> dict[str, set[str]]:
    pa: dict[str, set[str]] = {}
    for a, b in directed:
        pa.setdefault(b, set()).add(a)
        pa.setdefault(a, set())
    return pa


def _children(directed: list[tuple[str, str]]) -> dict[str, set[str]]:
    ch: dict[str, set[str]] = {}
    for a, b in directed:
        ch.setdefault(a, set()).add(b)
        ch.setdefault(b, set())
    return ch


def descendants(directed: list[tuple[str, str]], node: str) -> set[str]:
    ch = _children(directed)
    out: set[str] = set()
    stack = list(ch.get(node, ()))
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(ch.get(n, ()))
    return out


def ancestors(directed: list[tuple[str, str]], node: str) -> set[str]:
    pa = _parents(directed)
    out: set[str] = set()
    stack = list(pa.get(node, ()))
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(pa.get(n, ()))
    return out


def has_directed_path(
    directed: list[tuple[str, str]],
    src: str,
    dst: str,
    *,
    skip: Optional[Iterable[str]] = None,
) -> bool:
    skip_set = set(skip or ())
    ch = _children(directed)
    seen = set()
    stack = [src]
    while stack:
        n = stack.pop()
        if n == dst and n != src:
            return True
        if n in seen:
            continue
        seen.add(n)
        for nxt in ch.get(n, ()):
            if nxt in skip_set:
                continue
            stack.append(nxt)
    return False


def d_separated(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    z: Iterable[str],
) -> bool:
    """祖先图道德化后无向可达性。"""
    zset = set(z)
    nodes = {x, y} | zset | ancestors(directed, x) | ancestors(directed, y)
    for zz in list(zset):
        nodes |= ancestors(directed, zz)
    pa = _parents(directed)
    undirected: dict[str, set[str]] = {n: set() for n in nodes}

    def link(a, b):
        if a in nodes and b in nodes and a != b:
            undirected.setdefault(a, set()).add(b)
            undirected.setdefault(b, set()).add(a)

    for a, b in directed:
        if a in nodes and b in nodes:
            link(a, b)
    for n in nodes:
        parents = [p for p in pa.get(n, ()) if p in nodes]
        for a, b in combinations(parents, 2):
            link(a, b)
    for zz in zset:
        undirected.pop(zz, None)
        for n in list(undirected):
            undirected[n].discard(zz)
    if x not in undirected or y not in undirected:
        return True
    seen = {x}
    stack = [x]
    while stack:
        n = stack.pop()
        if n == y:
            return False
        for nxt in undirected.get(n, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return True


def backdoor_set(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    names: list[str],
) -> Optional[list[str]]:
    """优先 {HOUR_NIGHT, DST_HUB} 中出现在图里的节点;再试空集与单点。"""
    present = set(names)
    preferred = [c for c in CONFOUNDERS if c in present]
    candidates: list[list[str]] = [preferred, []]
    for c in preferred:
        candidates.append([c])
    extra = [n for n in names if n not in preferred and n not in (x, y) and is_confounder(n)]
    for e in extra:
        candidates.append(preferred + [e])
    desc_x = descendants(directed, x)
    for z in candidates:
        z = [n for n in z if n != x and n != y]
        if set(z) & desc_x:
            continue
        # G_{\\overline{X}}: 去掉 X 发出的边
        g_bar = [(a, b) for a, b in directed if a != x]
        if d_separated(g_bar, x, y, z):
            return z
    return None


def intervene(
    data: np.ndarray,
    names: list[str],
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    *,
    do_value: int = 0,
) -> dict:
    """P(Y=1 | do(X=do_value)) 后门估计。"""
    if x not in names or y not in names:
        return {"identifiable": False, "reason": "unknown_variable", "x": x, "y": y}
    if x == y:
        return {"identifiable": False, "reason": "same_variable", "x": x, "y": y}
    z = backdoor_set(directed, x, y, names)
    if z is None:
        return {
            "identifiable": False,
            "reason": "no_backdoor",
            "x": x, "y": y,
            "do": int(do_value),
            # ladder-2: 不可识别就不给概率
        }
    xi = names.index(x)
    yi = names.index(y)
    zi = [names.index(c) for c in z]
    p0 = intervene_raw(data, xi, yi, zi, 0)
    p1 = intervene_raw(data, xi, yi, zi, 1)
    p_do = p0 if int(do_value) == 0 else p1
    if p_do is None:
        return {
            "identifiable": False,
            "reason": "sparse_stratum",
            "x": x, "y": y, "do": int(do_value),
            "z": z,
        }
    xv = data[:, xi].astype(np.int8)
    yv = data[:, yi].astype(np.int8)
    mask_x = xv == int(do_value)
    p_obs = float(yv[mask_x].mean()) if int(mask_x.sum()) else None
    ace = None if (p0 is None or p1 is None) else float(p1 - p0)
    return {
        "identifiable": True,
        "reason": "backdoor",
        "x": x,
        "y": y,
        "do": int(do_value),
        "z": z,
        "p_y_do": round(float(p_do), 4),
        "p_y_obs_given_x": None if p_obs is None else round(p_obs, 4),
        "p_y": round(float(yv.mean()), 4),
        "ace": None if ace is None else round(ace, 4),
        "ladder": 2,
        "note": "P(Y|do(X)) via backdoor; population intervention, not unit-level counterfactual",
    }


def intervene_raw(data, xi, yi, zi, do_value: int) -> Optional[float]:
    n = data.shape[0]
    xv = data[:, xi].astype(np.int8)
    yv = data[:, yi].astype(np.int8)
    if zi:
        zmat = data[:, zi].astype(np.int64)
        weights = (1 << np.arange(len(zi), dtype=np.int64))
        keys = (zmat * weights).sum(axis=1)
    else:
        keys = np.zeros(n, dtype=np.int64)
    p_do = 0.0
    used = 0
    mass = 0.0
    for k in np.unique(keys):
        mask_z = keys == k
        pz = float(mask_z.mean())
        mask_xz = mask_z & (xv == int(do_value))
        m = int(mask_xz.sum())
        if m < 1:
            continue
        p_do += float(yv[mask_xz].mean()) * pz
        used += m
        mass += pz
    if used < 8 or mass <= 0:
        return None
    return float(p_do / mass) if mass < 0.999 else float(p_do)
