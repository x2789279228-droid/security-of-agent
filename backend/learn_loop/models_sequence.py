"""
learn_loop.models_sequence — 攻击链一阶马尔可夫转移(纯函数)

对每个案例的有序事件类型序列统计 A→B 转移; 命中计数/概率阈值的
(A, B) 提议为候选序列签名(转 CEP 模式前需人工确认)。

事件名归一:
  - 先经 correlation_engine.normalize_event_type(中文词表 → 标准英文枚举)
  - 再映射到 case_manager.KILLCHAIN_RANK 的键空间(只 import KILLCHAIN_RANK)

去重: 若 correlation_engine 已存在某模式的相邻 stage 与 (A,B) 一致,
该转移标记 duplicate=True, propose 阶段跳过。
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _killchain_rank() -> dict:
    """惰性 import case_manager.KILLCHAIN_RANK(仅取键集做阶段归一)。"""
    try:
        from case_manager import KILLCHAIN_RANK
        return KILLCHAIN_RANK
    except Exception as e:  # pragma: no cover - import 失败退化为空表
        logger.warning("[learn_loop.sequence] KILLCHAIN_RANK unavailable: %s", e)
        return {}


def _correlation_patterns() -> dict:
    """已登记的 CEP 攻击链模式(用于 duplicate 判定)。"""
    try:
        from correlation_engine import ATTACK_CHAIN_PATTERNS
        return ATTACK_CHAIN_PATTERNS
    except Exception as e:  # pragma: no cover
        logger.debug("[learn_loop.sequence] patterns unavailable: %s", e)
        return {}


def normalize_stage(stage: str) -> str:
    """事件类型归一: 中文→英文枚举, 别名→KILLCHAIN_RANK 键名。"""
    if not stage:
        return ""
    try:
        from correlation_engine import normalize_event_type
        stage = normalize_event_type(stage)
    except Exception:
        pass
    s = str(stage).strip().upper().replace("-", "_").replace(" ", "_")
    rank = _killchain_rank()
    if s in rank:
        return s
    # SSH_BRUTE / LATERAL_MOVEMENT 等别名已由 correlation normalize 收敛到键名
    return s


def _is_known(stage: str) -> bool:
    return stage in _killchain_rank()


def build_sequences(
    case_type_lists: list,
    *,
    patterns: dict = None,
    min_count: int = 0,
    min_p: float = 0.0,
) -> dict:
    """统计有序事件类型序列的一阶转移。

    Args:
        case_type_lists: 每个元素是一条已按时间排序的 event_type 列表
            (可能混有中文名/别名)。
        patterns: CEP 已知模式 dict; None=自动 import correlation_engine 模式。
        min_count / min_p: 签名提议阈值(<=0 时取 settings)。

    Returns:
        {sequences_count, transitions: {"A>B": count},
         signatures: [{from, to, count, p, duplicate}]}
    """
    from config import settings as _cfg

    if min_count <= 0:
        min_count = int(getattr(_cfg, "learn_loop_markov_min_count", 5) or 5)
    if min_p <= 0:
        min_p = float(getattr(_cfg, "learn_loop_markov_min_p", 0.4) or 0.4)

    patterns = _correlation_patterns() if patterns is None else (patterns or {})

    # 已知模式的有序相邻边 → duplicate 集合
    known_edges: set[tuple] = set()
    for pat in patterns.values():
        if not isinstance(pat, dict):
            continue
        steps = [normalize_stage(s) for s in (pat.get("steps") or [])]
        known_edges.update(zip(steps, steps[1:]))

    transition_counts: dict[tuple, int] = {}
    from_stage_counts: dict[str, int] = {}
    n_sequences = 0
    for seq in (case_type_lists or []):
        ordered = [normalize_stage(t) for t in (seq or []) if normalize_stage(t)]
        if len(ordered) < 2:
            continue
        n_sequences += 1
        for a, b in zip(ordered, ordered[1:]):
            if not a or not b:
                continue
            transition_counts[(a, b)] = transition_counts.get((a, b), 0) + 1
            from_stage_counts[a] = from_stage_counts.get(a, 0) + 1

    transitions = {f"{a}>{b}": c for (a, b), c in transition_counts.items()}

    signatures = []
    for (a, b), c in sorted(transition_counts.items(), key=lambda kv: -kv[1]):
        if c < min_count:
            continue
        if not (_is_known(a) and _is_known(b)):
            continue  # 只对攻击链阶段(位于 KILLCHAIN_RANK)提议签名
        total_from = from_stage_counts.get(a, 0)
        p = round(c / max(total_from, 1), 4) if total_from else 0.0
        if p < min_p:
            continue
        signatures.append({
            "from": a,
            "to": b,
            "count": c,
            "p": p,
            "duplicate": (a, b) in known_edges,
        })

    return {
        "sequences_count": n_sequences,
        "transitions": transitions,
        "signatures": signatures,
    }
