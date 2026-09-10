"""
learn_loop.models_cluster — FP/漏报事件的相似聚类(纯函数)

复用:
  - zeroday_detect.variant_cluster.jaccard_similarity(不重复实现第三份 Jaccard)
  - self_play.novelty.tokenize(只读导入工具函数, 不触碰 self_play 其它模块)

事件特征集合:
  - event:{event_type}
  - rule:{rule_id}(若有)
  - net:{src_ip/24}(IPv6 用 /64; 解析失败退化为整 IP)
  - 消息词法 token

贪心聚类: 与已有簇代表取 Jaccard, 相似度 >= learn_loop_jaccard 并入,
否则新建簇。只返回 size >= learn_loop_cluster_min_size 的簇。
"""
from __future__ import annotations

import ipaddress
import logging

from zeroday_detect.variant_cluster import jaccard_similarity

from config import settings

logger = logging.getLogger(__name__)


def _subnet(ip: str) -> str:
    """IPv4 → ip/24, IPv6 → ip/64; 解析失败返回原 IP。"""
    if not ip:
        return ""
    ip = str(ip).strip()
    try:
        ver = ipaddress.ip_address(ip).version
        prefix = 24 if ver == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ip


def event_feature_set(evt: dict) -> set:
    """把单个事件转成聚类特征集合。"""
    features = set()
    event_type = str(evt.get("event_type") or evt.get("event") or evt.get("type") or "").strip()
    if event_type:
        features.add(f"event:{event_type.upper()}")
    rule_id = str(evt.get("rule_id") or "").strip()
    if rule_id:
        features.add(f"rule:{rule_id.upper()}")
    src_ip = str(evt.get("src_ip") or "").strip()
    net = _subnet(src_ip)
    if net:
        features.add(f"net:{net}")
    message = str(evt.get("message") or evt.get("msg") or "")
    if message:
        try:
            from self_play.novelty import tokenize  # 只读工具导入
            features.update(f"tok:{t}" for t in tokenize(message))
        except Exception as e:
            logger.debug("[learn_loop.cluster] tokenize unavailable: %s", e)
    return features


def build_clusters(
    events: list[dict],
    *,
    min_size: int = 0,
    threshold: float = 0.5,
) -> list[dict]:
    """贪心聚类事件 dict 列表 → size>=min_size 的簇(按 size 降序)。

    每簇记录: cluster_id / size / event_ids / event_type(众数) / net(众数) /
    feature_count(代表特征数, 供人工打标参考)。
    """
    if min_size <= 0:
        try:
            min_size = int(getattr(settings, "learn_loop_cluster_min_size", 3) or 3)
        except Exception:
            min_size = 3
    if threshold <= 0:
        try:
            threshold = float(getattr(settings, "learn_loop_jaccard", 0.5) or 0.5)
        except Exception:
            threshold = 0.5

    clusters: list[dict] = []
    for evt in events:
        if not isinstance(evt, dict):
            continue
        feats = event_feature_set(evt)
        if not feats:
            continue
        best_idx = -1
        best_sim = threshold
        for idx, cl in enumerate(clusters):
            rep = cl["_features"]
            sim = jaccard_similarity(feats, rep)
            if sim >= best_sim:
                best_sim = sim
                best_idx = idx
        if best_idx >= 0:
            cl = clusters[best_idx]
            cl["_features"] |= feats
            cl["_events"].append(evt)
        else:
            clusters.append({
                "_features": set(feats),
                "_events": [evt],
            })

    result = []
    for idx, cl in enumerate(clusters):
        size = len(cl["_events"])
        if size < min_size:
            continue
        from collections import Counter
        types = Counter(str(e.get("event_type") or "") for e in cl["_events"])
        nets = Counter(_subnet(str(e.get("src_ip") or "")) for e in cl["_events"] if e.get("src_ip"))
        result.append({
            "cluster_id": f"learn_cluster_{idx}",
            "size": size,
            "event_ids": sorted({int(e.get("id")) for e in cl["_events"] if e.get("id") is not None}),
            "event_type": types.most_common(1)[0][0] if types else "",
            "net": nets.most_common(1)[0][0] if nets else "",
            "feature_count": len(cl["_features"]),
            "similarity_threshold": round(threshold, 3),
        })

    result.sort(key=lambda c: c["size"], reverse=True)
    return result
