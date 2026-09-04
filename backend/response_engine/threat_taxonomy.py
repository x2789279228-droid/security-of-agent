"""
威胁分类树 — leaf ↔ category 两级解析

taxonomy.yml 外置；与策略 YAML 一样支持 mtime 热加载。
不在封禁链路上调用 LLM。
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_TAXONOMY_PATH = os.path.join(os.path.dirname(__file__), "taxonomy.yml")


@dataclass
class ThreatClassification:
    leaf: str = ""
    category: str = ""
    source: str = ""  # alias | enum | keyword | empty


@dataclass
class _TaxonomyIndex:
    leaf_to_category: dict[str, str] = field(default_factory=dict)
    alias_to_leaf: dict[str, str] = field(default_factory=dict)
    alias_to_category: dict[str, str] = field(default_factory=dict)
    # (keyword_lower, category, optional_leaf)
    keywords: list[tuple[str, str, str]] = field(default_factory=list)
    leaf_aliases: dict[str, str] = field(default_factory=dict)
    known_leaves: set[str] = field(default_factory=set)
    mtime: float = 0.0
    path: str = ""


_INDEX = _TaxonomyIndex()
_LAST_CHECK = 0.0
_RELOAD_SEC = int(os.environ.get("RESPONSE_TAXONOMY_RELOAD_SEC", "30") or "30")


def _compact(s: str) -> str:
    return str(s or "").strip().replace(" ", "").replace("　", "")


def _build_index(data: dict, path: str = "", mtime: float = 0.0) -> _TaxonomyIndex:
    idx = _TaxonomyIndex(path=path, mtime=mtime)
    leaf_aliases = data.get("leaf_aliases") or {}
    if isinstance(leaf_aliases, dict):
        for k, v in leaf_aliases.items():
            idx.leaf_aliases[str(k).strip().upper().replace("-", "_")] = str(v).strip()

    categories = data.get("categories") or {}
    for cat, body in categories.items():
        cat_name = str(cat).strip().upper()
        if not isinstance(body, dict):
            continue
        leaves = body.get("leaves") or []
        for leaf in leaves:
            leaf_u = str(leaf).strip()
            if not leaf_u:
                continue
            idx.known_leaves.add(leaf_u)
            idx.leaf_to_category[leaf_u.upper()] = cat_name
            # 大小写变体
            idx.leaf_to_category[leaf_u.upper().replace("-", "_")] = cat_name

        alias_leaves = body.get("alias_leaves") or {}
        if isinstance(alias_leaves, dict):
            for alias, leaf in alias_leaves.items():
                a = _compact(alias)
                if a:
                    idx.alias_to_leaf[a] = str(leaf).strip()
                    idx.alias_to_leaf[a.lower()] = str(leaf).strip()
                    idx.alias_to_category[a] = cat_name
                    idx.alias_to_category[a.lower()] = cat_name

        for alias in body.get("aliases") or []:
            a = _compact(alias)
            if not a:
                continue
            idx.alias_to_category[a] = cat_name
            idx.alias_to_category[a.lower()] = cat_name
            # 无 alias_leaves 时不强制 leaf

        for kw in body.get("keywords") or []:
            k = str(kw or "").strip()
            if not k:
                continue
            idx.keywords.append((k.lower(), cat_name, ""))

    # 长关键词优先
    idx.keywords.sort(key=lambda x: len(x[0]), reverse=True)
    return idx


def _empty_index() -> _TaxonomyIndex:
    return _TaxonomyIndex()


def load_taxonomy(path: Optional[str] = None) -> _TaxonomyIndex:
    global _INDEX, _LAST_CHECK
    taxonomy_path = (
        path
        or os.environ.get("RESPONSE_TAXONOMY_PATH", "").strip()
        or DEFAULT_TAXONOMY_PATH
    )
    try:
        mtime = os.path.getmtime(taxonomy_path) if os.path.isfile(taxonomy_path) else 0.0
        with open(taxonomy_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        _INDEX = _build_index(data if isinstance(data, dict) else {}, taxonomy_path, mtime)
        _LAST_CHECK = time.time()
        logger.info(
            f"Loaded threat taxonomy from {taxonomy_path}: "
            f"{len(_INDEX.known_leaves)} leaves, "
            f"{len(_INDEX.alias_to_category)} aliases, "
            f"{len(_INDEX.keywords)} keywords"
        )
    except FileNotFoundError:
        logger.warning(f"Taxonomy file missing: {taxonomy_path}; empty index")
        _INDEX = _empty_index()
        _LAST_CHECK = time.time()
    except Exception as e:
        logger.warning(f"Taxonomy load failed ({taxonomy_path}): {e}")
        _INDEX = _empty_index()
        _LAST_CHECK = time.time()
    return _INDEX


def reload_taxonomy(path: Optional[str] = None) -> int:
    idx = load_taxonomy(path)
    return len(idx.known_leaves)


def _maybe_reload() -> None:
    global _LAST_CHECK
    if _RELOAD_SEC < 0:
        return
    now = time.time()
    if _RELOAD_SEC > 0 and now - _LAST_CHECK < _RELOAD_SEC:
        return
    _LAST_CHECK = now
    path = _INDEX.path or DEFAULT_TAXONOMY_PATH
    try:
        mtime = os.path.getmtime(path) if path and os.path.isfile(path) else 0.0
    except OSError:
        return
    if mtime > (_INDEX.mtime or 0):
        load_taxonomy(path)


def category_for_leaf(leaf: str) -> str:
    _maybe_reload()
    if not leaf:
        return ""
    key = str(leaf).strip().upper().replace("-", "_")
    # DDoS_TRAFFIC 等保留原大小写键
    return (
        _INDEX.leaf_to_category.get(str(leaf).strip().upper())
        or _INDEX.leaf_to_category.get(key)
        or ""
    )


def normalize_leaf(raw: str) -> str:
    """英文别名 → 标准 leaf。"""
    _maybe_reload()
    if not raw:
        return ""
    upper = str(raw).strip().upper().replace("-", "_").replace(" ", "_")
    aliased = _INDEX.leaf_aliases.get(upper)
    if aliased:
        return aliased
    # 已知 leaf 大小写归一
    for leaf in _INDEX.known_leaves:
        if leaf.upper().replace("-", "_") == upper:
            return leaf
    return ""


def classify(name: str) -> ThreatClassification:
    """自然语言 / 枚举 → (leaf, category)。"""
    _maybe_reload()
    if not name or not str(name).strip():
        return ThreatClassification()

    raw = str(name).strip()
    compact = _compact(raw)
    compact_l = compact.lower()

    # 1) 精确 alias
    if compact in _INDEX.alias_to_leaf or compact_l in _INDEX.alias_to_leaf:
        leaf = _INDEX.alias_to_leaf.get(compact) or _INDEX.alias_to_leaf.get(compact_l) or ""
        cat = (
            _INDEX.alias_to_category.get(compact)
            or _INDEX.alias_to_category.get(compact_l)
            or category_for_leaf(leaf)
        )
        return ThreatClassification(leaf=leaf, category=cat, source="alias")

    if compact in _INDEX.alias_to_category or compact_l in _INDEX.alias_to_category:
        cat = _INDEX.alias_to_category.get(compact) or _INDEX.alias_to_category.get(compact_l) or ""
        return ThreatClassification(leaf="", category=cat, source="alias")

    # 2) 已是枚举 / 英文别名
    if raw.isascii() or raw.replace("_", "").replace("-", "").isalnum():
        leaf = normalize_leaf(raw)
        if leaf:
            return ThreatClassification(
                leaf=leaf, category=category_for_leaf(leaf), source="enum",
            )
        # 透传已知大写枚举（即使不在 taxonomy leaves 里）
        upper = raw.strip().upper().replace("-", "_").replace(" ", "_")
        if upper.isascii() and upper in {x.upper().replace("-", "_") for x in _INDEX.known_leaves}:
            leaf = normalize_leaf(upper) or raw.strip()
            return ThreatClassification(
                leaf=leaf, category=category_for_leaf(leaf), source="enum",
            )

    # 3) 关键词（长词优先）
    hay_l = raw.lower()
    hay_c = compact.lower()
    for kw, cat, leaf_hint in _INDEX.keywords:
        if kw in hay_l or kw in hay_c or kw in compact:
            leaf = leaf_hint or ""
            return ThreatClassification(leaf=leaf, category=cat, source="keyword")

    return ThreatClassification(source="empty")


# 模块导入时加载
load_taxonomy()
