"""因果推理攻击链 — PC / GES-style + 后门 do()。

只读 security_events,不改 Flink CEP 热路径。失败降级为仅 CEP。
"""
from causal_chain.learn import annotate_chains, learn_from_events, learn_from_matrix, query_do
from causal_chain.variables import events_to_matrix

__all__ = [
    "learn_from_events",
    "learn_from_matrix",
    "query_do",
    "annotate_chains",
    "events_to_matrix",
]
