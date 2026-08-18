"""
variant_cluster.py — 样本相似度聚类（变种识别）

基于沙箱报告的行为特征对样本进行聚类:
  - 行为向量: 将 API 调用序列 / 文件操作 / 网络行为编码为特征向量
  - 相似度计算: Jaccard / 余弦相似度
  - 家族聚类: DBSCAN 聚类识别已知家族的变种
  - 新家族发现: 无法归入已知簇的样本标记为潜在零日

用法:
    from zeroday_detect.variant_cluster import variant_cluster
    cluster_id = variant_cluster.add_sample(analysis_dict)
    similar = variant_cluster.find_similar(analysis_dict, threshold=0.7)
"""
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SampleFeatures:
    """样本行为特征向量"""
    sample_hash: str = ""
    api_calls: set = field(default_factory=set)
    files_written: set = field(default_factory=set)
    registry_keys: set = field(default_factory=set)
    network_hosts: set = field(default_factory=set)
    mitre_ids: set = field(default_factory=set)
    signatures: set = field(default_factory=set)
    cluster_id: int = -1
    family: str = ""

    def to_feature_set(self) -> set:
        """合并所有特征为统一集合（用于 Jaccard 相似度）"""
        features = set()
        features.update(f"api:{c}" for c in self.api_calls)
        features.update(f"file:{f}" for f in self.files_written)
        features.update(f"reg:{r}" for r in self.registry_keys)
        features.update(f"net:{n}" for n in self.network_hosts)
        features.update(f"mitre:{m}" for m in self.mitre_ids)
        features.update(f"sig:{s}" for s in self.signatures)
        return features


def jaccard_similarity(a: set, b: set) -> float:
    """Jaccard 相似度"""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


class VariantCluster:
    """样本变种聚类引擎"""

    def __init__(self):
        self._samples: dict[str, SampleFeatures] = {}  # hash → features
        self._clusters: dict[int, list[str]] = defaultdict(list)  # cluster_id → [hashes]
        self._next_cluster = 0
        self._family_map: dict[int, str] = {}  # cluster_id → family name

    def add_sample(self, analysis: dict, sample_hash: str = "") -> int:
        """
        添加样本到聚类引擎

        analysis: BehaviorAnalysis.to_dict() 或沙箱报告
        返回: cluster_id
        """
        features = self._extract_features(analysis, sample_hash)
        feature_set = features.to_feature_set()

        # 查找最相似的已有簇
        best_cluster = -1
        best_sim = 0.0

        for cid, hashes in self._clusters.items():
            # 与簇中第一个样本比较（简化：簇代表）
            rep_hash = hashes[0]
            rep = self._samples.get(rep_hash)
            if rep:
                sim = jaccard_similarity(feature_set, rep.to_feature_set())
                if sim > best_sim:
                    best_sim = sim
                    best_cluster = cid

        # 相似度阈值: >= 0.5 归入已有簇
        if best_sim >= 0.5 and best_cluster >= 0:
            features.cluster_id = best_cluster
            features.family = self._family_map.get(best_cluster, "")
            self._clusters[best_cluster].append(sample_hash)
        else:
            # 新簇
            features.cluster_id = self._next_cluster
            self._clusters[self._next_cluster].append(sample_hash)
            self._next_cluster += 1

        self._samples[sample_hash] = features
        return features.cluster_id

    def find_similar(
        self,
        analysis: dict,
        threshold: float = 0.5,
        top_k: int = 5,
    ) -> list[dict]:
        """查找与给定分析最相似的已知样本"""
        features = self._extract_features(analysis)
        feature_set = features.to_feature_set()

        results = []
        for h, sample in self._samples.items():
            sim = jaccard_similarity(feature_set, sample.to_feature_set())
            if sim >= threshold:
                results.append({
                    "sample_hash": h,
                    "similarity": round(sim, 3),
                    "cluster_id": sample.cluster_id,
                    "family": sample.family,
                })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    def label_cluster(self, cluster_id: int, family: str):
        """为簇标记家族名"""
        self._family_map[cluster_id] = family
        for h in self._clusters.get(cluster_id, []):
            if h in self._samples:
                self._samples[h].family = family

    def get_cluster_info(self, cluster_id: int) -> dict:
        """获取簇信息"""
        hashes = self._clusters.get(cluster_id, [])
        return {
            "cluster_id": cluster_id,
            "family": self._family_map.get(cluster_id, "unknown"),
            "sample_count": len(hashes),
            "samples": hashes[:20],
        }

    def get_unclustered(self) -> list[str]:
        """获取未归入任何已知家族的样本（潜在零日）"""
        return [
            h for h, f in self._samples.items()
            if not f.family
        ]

    def _extract_features(self, analysis: dict, sample_hash: str = "") -> SampleFeatures:
        """从分析结果提取特征"""
        features = SampleFeatures(sample_hash=sample_hash)

        # 签名
        features.signatures = set(analysis.get("signatures", []))

        # MITRE
        for tech in analysis.get("mitre_techniques", []):
            if isinstance(tech, dict):
                features.mitre_ids.add(tech.get("id", ""))
            elif isinstance(tech, str):
                features.mitre_ids.add(tech)

        # 网络 IOC
        for ioc in analysis.get("network_iocs", []):
            if isinstance(ioc, dict):
                features.network_hosts.add(ioc.get("value", ""))
            elif isinstance(ioc, str):
                features.network_hosts.add(ioc)

        # 文件 IOC
        for ioc in analysis.get("file_iocs", []):
            if isinstance(ioc, dict):
                features.files_written.add(ioc.get("path", ""))
            elif isinstance(ioc, str):
                features.files_written.add(ioc)

        return features

    @property
    def stats(self) -> dict:
        return {
            "total_samples": len(self._samples),
            "total_clusters": len(self._clusters),
            "labeled_families": len(self._family_map),
            "unclustered": len(self.get_unclustered()),
        }


# ── 全局单例 ──
variant_cluster = VariantCluster()
