"""
词法检索原语 — BM25 稀疏编码、IOC/CJK 切词、进程内 RRF

Qdrant `Modifier.IDF` 在服务端补 IDF，客户端只发词频稀疏向量。
默认用稳定哈希把 token 映到 index，不下载 FastEmbed 模型（测试/CI 零外网）。
`rag_bm25_backend=fastembed` 时改走 Qdrant/bm25。
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter, defaultdict
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ASCII_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_+.-]{1,}")
CJK_RE = re.compile(r"[\u4e00-\u9fff]+")

# 本仓库威胁类型 / 常见 ATT&CK 短名 → 检索扩展词
ATTACK_ALIASES: dict[str, tuple[str, ...]] = {
    "T1059": ("command and scripting interpreter", "命令执行", "powershell", "cmd"),
    "T1059.001": ("powershell", "命令执行"),
    "T1021": ("remote services", "横向移动", "rdp", "ssh"),
    "T1021.001": ("rdp", "remote desktop", "横向移动"),
    "T1071": ("application layer protocol", "c2", "beacon", "回连"),
    "T1071.001": ("c2", "http beacon", "回连"),
    "T1041": ("exfiltration over c2", "数据外泄", "data exfil"),
    "T1048": ("exfiltration over alternative protocol", "数据外泄"),
    "T1110": ("brute force", "暴力破解", "password spray"),
    "T1046": ("network service discovery", "端口扫描", "port scan"),
    "T1053": ("scheduled task", "持久化"),
    "T1547": ("boot or logon autostart", "持久化"),
    "T1003": ("os credential dumping", "凭证窃取", "mimikatz"),
    "T1078": ("valid accounts", "凭证", "横向移动"),
    "T1190": ("exploit public-facing application", "web攻击"),
    "T1566": ("phishing", "钓鱼"),
    "C2_BEACON": ("c2", "beacon", "回连", "T1071"),
    "DATA_EXFIL": ("exfiltration", "数据外泄", "T1041"),
    "BRUTE_FORCE": ("brute force", "暴力破解", "T1110"),
    "PORT_SCAN": ("port scan", "端口扫描", "T1046"),
    "LATERAL_MOVE": ("lateral movement", "横向移动", "rdp", "T1021"),
    "PRIVILEGE_ESCALATION": ("privilege escalation", "权限提升"),
    "PERSISTENCE": ("persistence", "持久化"),
    "CREDENTIAL_ACCESS": ("credential access", "凭证窃取", "T1003"),
}

# CVE ↔ 俗称；精确词查询必须能靠别名召回
CVE_ALIASES: dict[str, tuple[str, ...]] = {
    "CVE-2021-44228": ("log4shell", "log4j", "jndi", "ldap", "log4j2"),
    "CVE-2021-45046": ("log4shell", "log4j"),
    "CVE-2017-0144": ("eternalblue", "ms17-010", "wannacry"),
    "LOG4SHELL": ("CVE-2021-44228", "log4j", "jndi"),
    "LOG4J": ("CVE-2021-44228", "log4shell", "jndi"),
}

DEFAULT_RRF_K = 60


def extract_security_terms(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for rx in (CVE_RE, ATTACK_RE, HASH_RE, IP_RE):
        found.extend(rx.findall(text))
    # 稳定去重、保序
    seen: set[str] = set()
    out: list[str] = []
    for t in found:
        key = t.upper() if t[:3].upper() in ("CVE", "T10", "T11", "T12", "T15", "T16") else t.lower()
        if t.upper().startswith("CVE-") or ATTACK_RE.fullmatch(t or ""):
            key = t.upper()
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


def cjk_bigrams(text: str) -> list[str]:
    grams: list[str] = []
    for run in CJK_RE.findall(text or ""):
        if len(run) == 1:
            grams.append(run)
        else:
            grams.extend(run[i : i + 2] for i in range(len(run) - 1))
    return grams


def tokenize(text: str) -> list[str]:
    """SOC 混合中英切词：安全专有名词 + ASCII 词 + 汉字 bigram。"""
    if not text:
        return []
    tokens: list[str] = []
    for term in extract_security_terms(text):
        tokens.append(term.lower())
        up = term.upper()
        if up in ATTACK_ALIASES:
            tokens.extend(a.lower() for a in ATTACK_ALIASES[up])
        # T1059.001 同时保留 T1059
        if ATTACK_RE.fullmatch(term) and "." in term:
            parent = term.split(".")[0].upper()
            tokens.append(parent.lower())
            tokens.extend(a.lower() for a in ATTACK_ALIASES.get(parent, ()))
    tokens.extend(w.lower() for w in ASCII_WORD_RE.findall(text) if len(w) > 1)
    tokens.extend(cjk_bigrams(text))
    for raw in re.findall(r"[A-Z][A-Z0-9_]+", text):
        if raw in ATTACK_ALIASES:
            tokens.extend(a.lower() for a in ATTACK_ALIASES[raw])
    return [t for t in tokens if t]


def build_search_lex(title: str = "", content: str = "", extra: Optional[Iterable[str]] = None) -> str:
    """写入 knowledge_chunks.search_lex，供 Postgres tsvector / 词法召回。"""
    parts = tokenize(f"{title or ''} {content or ''}")
    if extra:
        parts.extend(str(x).lower() for x in extra if x)
    # 专有名词再挂一遍大写形式，方便 plainto_tsquery
    for term in extract_security_terms(f"{title or ''} {content or ''}"):
        parts.append(term)
        parts.append(term.upper())
    seen: set[str] = set()
    ordered: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return " ".join(ordered[:400])


def lexical_needles(query: str) -> list[str]:
    """精确召回用的子串：CVE/T-ID/哈希 + 少量别名。"""
    st = expand_query_text(query)
    raw = list(extract_security_terms(query)) + list(st.get("keywords") or [])
    out: list[str] = []
    seen: set[str] = set()
    for n in raw:
        s = str(n or "").strip()
        if len(s) < 3:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
        if len(out) >= 12:
            break
    return out


def expand_query_text(query: str) -> dict:
    """规则扩展。返回 lexical_query / expanded / keywords / lexical_first。"""
    q = (query or "").strip()
    terms = extract_security_terms(q)
    keywords: list[str] = list(terms)
    extras: list[str] = []
    for t in terms:
        up = t.upper()
        parent = up.split(".")[0] if up.startswith("T") else up
        aliases = (
            ATTACK_ALIASES.get(up)
            or ATTACK_ALIASES.get(parent)
            or CVE_ALIASES.get(up)
            or ()
        )
        extras.extend(aliases)
        if parent != up and parent.startswith("T"):
            keywords.append(parent)
    q_low = q.lower()
    q_compact = re.sub(r"[^a-z0-9]", "", q_low)
    for alias_key, alias_vals in CVE_ALIASES.items():
        key_hit = alias_key.lower() in q_low or alias_key.replace("-", "").lower() in q_compact
        val_hit = any(a.lower() in q_low for a in alias_vals)
        if key_hit or val_hit:
            extras.extend(alias_vals)
            extras.append(alias_key)
            if alias_key.startswith("CVE-"):
                keywords.append(alias_key)
                terms.append(alias_key)
    # 威胁类型枚举
    for token in re.findall(r"[A-Z][A-Z0-9_]+", q):
        if token in ATTACK_ALIASES:
            extras.extend(ATTACK_ALIASES[token])
            keywords.append(token)
    lexical_first = bool(terms) and (
        any(HASH_RE.fullmatch(t) for t in terms)
        or any(t.upper().startswith("CVE-") for t in terms)
        or any(ATTACK_RE.fullmatch(t) for t in terms)
    )
    expanded = q
    if extras:
        expanded = f"{q} {' '.join(dict.fromkeys(extras))}"
    lexical_query = " ".join(dict.fromkeys([q] + keywords + extras))
    return {
        "original": q,
        "expanded": expanded,
        "lexical_query": lexical_query,
        "keywords": list(dict.fromkeys(keywords + extras))[:24],
        "lexical_first": lexical_first,
        "hyde_text": "",
        "step_back": "",
        "rewritten": q,
    }


def token_index(token: str) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest[:4], "little") & 0x7FFFFFFF


def to_sparse_tf(text: str) -> tuple[list[int], list[float]]:
    """词频稀疏向量（Qdrant IDF modifier 的输入）。"""
    tf: dict[int, float] = {}
    for tok in tokenize(text):
        idx = token_index(tok)
        tf[idx] = tf.get(idx, 0.0) + 1.0
    if not tf:
        return [], []
    indices = sorted(tf)
    return indices, [tf[i] for i in indices]


_fastembed_model = None
_fastembed_failed = False


def to_sparse_fastembed(text: str) -> tuple[list[int], list[float]]:
    global _fastembed_model, _fastembed_failed
    if _fastembed_failed:
        return to_sparse_tf(text)
    try:
        if _fastembed_model is None:
            from fastembed import SparseTextEmbedding
            _fastembed_model = SparseTextEmbedding(model_name="Qdrant/bm25")
        emb = next(_fastembed_model.embed([text or " "]))
        indices = [int(i) for i in list(emb.indices)]
        values = [float(v) for v in list(emb.values)]
        return indices, values
    except Exception as e:
        logger.warning(f"[lexical] fastembed BM25 不可用, 回退哈希 TF: {e}")
        _fastembed_failed = True
        return to_sparse_tf(text)


def encode_sparse(text: str, backend: str = "builtin") -> tuple[list[int], list[float]]:
    if (backend or "builtin").lower() == "fastembed":
        return to_sparse_fastembed(text)
    return to_sparse_tf(text)


def rrf_fuse(
    ranked_lists: dict[str, list[str]],
    *,
    k: int = DEFAULT_RRF_K,
) -> list[dict]:
    """倒数排序融合。ranked_lists: 通道名 → 已按相关度降序的 id 列表。

    返回 [{id, rrf_score, ranks: {channel: 1-based rank}}]，按 rrf_score 降序。
    """
    scores: dict[str, float] = defaultdict(float)
    ranks: dict[str, dict[str, int]] = defaultdict(dict)
    for channel, ids in (ranked_lists or {}).items():
        seen: set[str] = set()
        for i, doc_id in enumerate(ids):
            if not doc_id or doc_id in seen:
                continue
            seen.add(doc_id)
            rank = i + 1
            scores[doc_id] += 1.0 / (k + rank)
            ranks[doc_id][channel] = rank
    fused = [
        {
            "id": doc_id,
            "rrf_score": round(score, 6),
            "ranks": ranks[doc_id],
        }
        for doc_id, score in scores.items()
    ]
    fused.sort(key=lambda x: (-x["rrf_score"], x["id"]))
    return fused


def lexical_overlap_rank(query: str, content: str) -> float:
    """无 Postgres ts_rank 时的简易重叠分（sqlite 测试 / 降级）。"""
    q = set(tokenize(query))
    if not q:
        return 0.0
    d = set(tokenize(content))
    if not d:
        return 0.0
    return round(len(q & d) / len(q), 4)
