"""域名访问钓鱼检测器 — 5 维度分析

维度:
  1. Typosquatting 仿冒 (typosquat)
  2. Homograph 攻击 (homograph)
  3. 域名结构 (structure)
  4. TLD 风险 (tld)
  5. DGA 模式 (dga)
"""
import re
import math
import logging
import unicodedata

from .models import DomainPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# ── 常量 ──

# Top 品牌域名（用于 typosquatting 比对）
TOP_BRANDS = [
    "google", "apple", "microsoft", "amazon", "paypal",
    "facebook", "instagram", "twitter", "netflix", "linkedin",
    "github", "dropbox", "steam", "ebay", "yahoo",
    "alipay", "taobao", "wechat", "baidu", "jd",
    "icbc", "ccb", "boc", "abc", "cmb", "bank",
    "dhl", "fedex", "ups", "zoom", "slack",
]

# 高风险 TLD 及风险权重
HIGH_RISK_TLDS: dict[str, str] = {
    ".tk": "critical", ".ml": "critical", ".ga": "critical",
    ".cf": "critical", ".gq": "critical",
    ".xyz": "high", ".top": "high", ".pw": "high",
    ".cc": "high", ".ws": "high", ".buzz": "medium",
    ".club": "medium", ".work": "medium", ".icu": "medium",
    ".online": "low", ".site": "low", ".store": "low",
}

# Cyrillic 与 Latin 同形字符映射
HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    "\u051d": "w",
}


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def _check_typosquat(domain_base: str) -> list[PhishingIndicator]:
    """维度 1: Typosquatting 仿冒检测"""
    indicators: list[PhishingIndicator] = []

    for brand in TOP_BRANDS:
        if domain_base == brand:
            continue
        dist = _levenshtein(domain_base, brand)
        if 0 < dist <= 2 and len(domain_base) >= 3:
            severity = "critical" if dist == 1 else "high"
            indicators.append(PhishingIndicator(
                name="Typosquatting 仿冒",
                category="typosquat",
                severity=severity,
                detail=f"域名 \"{domain_base}\" 与品牌 \"{brand}\" 编辑距离仅 {dist}",
            ))

    return indicators


def _check_homograph(domain: str) -> list[PhishingIndicator]:
    """维度 2: Homograph 同形攻击检测"""
    indicators: list[PhishingIndicator] = []

    scripts: set[str] = set()
    has_homoglyph = False

    for ch in domain:
        if ch in (".", "-"):
            continue
        cat = unicodedata.category(ch)
        if cat.startswith("L"):
            try:
                script = unicodedata.name(ch).split()[0]
            except ValueError:
                script = "UNKNOWN"
            scripts.add(script)

        if ch in HOMOGLYPH_MAP:
            has_homoglyph = True

    # 混合脚本（Latin + Cyrillic 等）
    if len(scripts) > 1 and "LATIN" in scripts:
        non_latin = scripts - {"LATIN"}
        indicators.append(PhishingIndicator(
            name="混合脚本域名",
            category="homograph",
            severity="critical",
            detail=f"域名混用多种文字脚本: Latin + {', '.join(non_latin)}，疑似同形攻击",
        ))

    # 含已知同形字符
    if has_homoglyph:
        replaced = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in domain)
        indicators.append(PhishingIndicator(
            name="同形字符替换",
            category="homograph",
            severity="critical",
            detail=f"域名含 Cyrillic 同形字符，视觉等效为 \"{replaced}\"",
        ))

    return indicators


def _check_structure(domain_base: str, full_domain: str) -> list[PhishingIndicator]:
    """维度 3: 域名结构分析"""
    indicators: list[PhishingIndicator] = []

    # 连字符过多
    hyphen_count = domain_base.count("-")
    if hyphen_count >= 3:
        indicators.append(PhishingIndicator(
            name="连字符过多",
            category="structure",
            severity="medium",
            detail=f"域名含 {hyphen_count} 个连字符，疑似仿冒拼接: {full_domain}",
        ))

    # 数字过多
    digit_count = sum(1 for c in domain_base if c.isdigit())
    if digit_count >= 4:
        indicators.append(PhishingIndicator(
            name="数字过多",
            category="structure",
            severity="low",
            detail=f"域名含 {digit_count} 个数字，可能为随机生成",
        ))

    # 异常长度
    if len(domain_base) > 25:
        indicators.append(PhishingIndicator(
            name="域名异常过长",
            category="structure",
            severity="low",
            detail=f"域名主体长度 {len(domain_base)} 字符，超出正常范围",
        ))

    # 子域名层级过多
    dot_count = full_domain.count(".")
    if dot_count >= 4:
        indicators.append(PhishingIndicator(
            name="子域名层级异常",
            category="structure",
            severity="medium",
            detail=f"域名层级达 {dot_count + 1} 级，可能用于混淆: {full_domain}",
        ))

    return indicators


def _check_tld(full_domain: str) -> list[PhishingIndicator]:
    """维度 4: TLD 风险评分"""
    indicators: list[PhishingIndicator] = []

    for tld, severity in HIGH_RISK_TLDS.items():
        if full_domain.endswith(tld):
            indicators.append(PhishingIndicator(
                name="高风险 TLD",
                category="tld",
                severity=severity,
                detail=f"顶级域名 {tld} 在钓鱼攻击中高频出现",
            ))
            break

    return indicators


def _check_dga(domain_base: str) -> list[PhishingIndicator]:
    """维度 5: DGA（域名生成算法）模式检测"""
    indicators: list[PhishingIndicator] = []

    if len(domain_base) < 6:
        return indicators

    # 计算 Shannon 熵
    freq: dict[str, int] = {}
    for ch in domain_base:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(domain_base)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())

    # 高熵 + 无元音 → 疑似 DGA
    vowels = set("aeiou")
    vowel_ratio = sum(1 for c in domain_base if c in vowels) / length
    has_digits = any(c.isdigit() for c in domain_base)

    if entropy > 3.5 and vowel_ratio < 0.15 and length >= 8:
        indicators.append(PhishingIndicator(
            name="DGA 随机域名",
            category="dga",
            severity="high",
            detail=f"域名熵值 {entropy:.2f}，元音比例 {vowel_ratio:.1%}，疑似算法生成",
        ))
    elif entropy > 3.8 and length >= 10:
        indicators.append(PhishingIndicator(
            name="高熵域名",
            category="dga",
            severity="medium",
            detail=f"域名熵值 {entropy:.2f}，字符分布异常随机",
        ))

    # 辅音连续串
    consonant_run = 0
    max_run = 0
    for ch in domain_base:
        if ch.isalpha() and ch not in vowels:
            consonant_run += 1
            max_run = max(max_run, consonant_run)
        else:
            consonant_run = 0
    if max_run >= 5:
        indicators.append(PhishingIndicator(
            name="异常辅音连续",
            category="dga",
            severity="medium",
            detail=f"连续 {max_run} 个辅音字母，不符合自然语言模式",
        ))

    return indicators


def detect(req: DomainPhishingRequest) -> list[PhishingIndicator]:
    """执行域名访问钓鱼全维度检测。"""
    domain = req.domain.strip().lower()
    # 去除协议前缀
    domain = re.sub(r'^https?://', '', domain)
    # 去除路径
    domain = domain.split("/")[0]
    # 去除端口
    domain = domain.split(":")[0]

    if not domain:
        return [PhishingIndicator(
            name="域名无效",
            category="structure",
            severity="info",
            detail="未提供有效域名",
        )]

    domain_base = domain.split(".")[0] if "." in domain else domain

    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_typosquat(domain_base))
    indicators.extend(_check_homograph(domain))
    indicators.extend(_check_structure(domain_base, domain))
    indicators.extend(_check_tld(domain))
    indicators.extend(_check_dga(domain_base))

    return indicators
