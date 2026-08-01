"""网页钓鱼检测器 — 5 维度分析

维度:
  1. URL 结构 (url)
  2. 品牌仿冒 (brand)
  3. 路径语义 (path)
  4. 协议安全 (protocol)
  5. 页面内容 (content) — 可选 LLM 增强
"""
import re
import logging
from urllib.parse import urlparse

from .models import WebPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# ── 常量 ──

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".pw", ".cc", ".ws",
    ".buzz", ".club", ".work", ".icu",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "amazon", "google",
    "alipay", "wechat", "taobao", "jd", "bank",
    "icbc", "ccb", "boc", "abc", "cmb",
    "netflix", "linkedin", "dropbox", "github",
    "dhl", "fedex", "ups", "steam", "ebay",
]

# 钓鱼高频路径关键词
PHISHING_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "security", "update", "confirm",
    "password", "reset", "unlock", "suspend", "validate",
    "webscr", "cmd", "auth", "authenticate", "session",
]

# 合法品牌主域名映射（用于判断仿冒）
BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "alipay": "alipay.com",
    "wechat": "wechat.com",
    "taobao": "taobao.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "steam": "steampowered.com",
    "ebay": "ebay.com",
}


def _check_url_structure(url: str, parsed) -> list[PhishingIndicator]:
    """维度 1: URL 结构分析"""
    indicators: list[PhishingIndicator] = []
    host = parsed.hostname or ""

    # IP 直连
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        indicators.append(PhishingIndicator(
            name="IP 直连",
            category="url",
            severity="high",
            detail=f"使用 IP 地址代替域名: {host}",
        ))

    # 可疑 TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            indicators.append(PhishingIndicator(
                name="高风险 TLD",
                category="url",
                severity="medium",
                detail=f"顶级域名 {tld} 常被用于钓鱼攻击",
            ))
            break

    # 过多子域名
    dot_count = host.count(".")
    if dot_count >= 4:
        indicators.append(PhishingIndicator(
            name="异常多级子域名",
            category="url",
            severity="medium",
            detail=f"子域名达 {dot_count + 1} 级，可能用于混淆: {host}",
        ))

    # @ 符号绕过
    netloc = parsed.netloc or ""
    if "@" in netloc:
        indicators.append(PhishingIndicator(
            name="@ 符号绕过",
            category="url",
            severity="high",
            detail=f"URL 含 @ 符号，真实目标为 @{netloc.split('@')[-1]}",
        ))

    # 异常端口
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        indicators.append(PhishingIndicator(
            name="非标准端口",
            category="url",
            severity="low",
            detail=f"使用非标准端口 {parsed.port}",
        ))

    # URL 过长（混淆）
    if len(url) > 150:
        indicators.append(PhishingIndicator(
            name="URL 异常过长",
            category="url",
            severity="low",
            detail=f"URL 长度 {len(url)} 字符，可能用于隐藏真实目标",
        ))

    # 连字符过多
    if host.count("-") >= 3:
        indicators.append(PhishingIndicator(
            name="域名连字符过多",
            category="url",
            severity="low",
            detail=f"域名含 {host.count('-')} 个连字符，疑似仿冒: {host}",
        ))

    return indicators


def _check_brand(url: str, parsed) -> list[PhishingIndicator]:
    """维度 2: 品牌仿冒检测"""
    indicators: list[PhishingIndicator] = []
    host = parsed.hostname or ""
    host_base = host.split(".")[0].lower() if host else ""
    url_lower = url.lower()

    for brand in BRAND_KEYWORDS:
        if brand not in url_lower:
            continue

        legitimate_domain = BRAND_DOMAINS.get(brand, f"{brand}.com")
        legit_base = legitimate_domain.split(".")[0]

        # 品牌词出现在 URL 中但主域名不匹配
        if host_base != legit_base and brand not in host_base:
            indicators.append(PhishingIndicator(
                name="品牌仿冒",
                category="brand",
                severity="high",
                detail=f"URL 含品牌词 \"{brand}\" 但域名为 {host}，非官方 {legitimate_domain}",
            ))
        # 品牌词在子域名/路径中（主域名不同）
        elif brand in host_base and host_base != legit_base:
            indicators.append(PhishingIndicator(
                name="子域名品牌仿冒",
                category="brand",
                severity="high",
                detail=f"子域名 \"{host_base}\" 仿冒品牌 \"{brand}\"，实际域名 {host}",
            ))

    return indicators


def _check_path(parsed) -> list[PhishingIndicator]:
    """维度 3: 路径语义分析"""
    indicators: list[PhishingIndicator] = []
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    combined = f"{path}?{query}"

    hits = [kw for kw in PHISHING_PATH_KEYWORDS if kw in combined]
    if len(hits) >= 3:
        indicators.append(PhishingIndicator(
            name="高密度钓鱼路径",
            category="path",
            severity="high",
            detail=f"URL 路径含 {len(hits)} 个钓鱼高频词: {', '.join(hits[:5])}",
        ))
    elif len(hits) >= 1:
        indicators.append(PhishingIndicator(
            name="钓鱼路径关键词",
            category="path",
            severity="medium",
            detail=f"URL 路径含钓鱼高频词: {', '.join(hits)}",
        ))

    return indicators


def _check_protocol(url: str, parsed) -> list[PhishingIndicator]:
    """维度 4: 协议安全"""
    indicators: list[PhishingIndicator] = []

    if parsed.scheme == "http":
        indicators.append(PhishingIndicator(
            name="HTTP 无加密",
            category="protocol",
            severity="medium",
            detail="使用 HTTP 明文传输，无 TLS 保护",
        ))

    # data: URI 或 javascript: 协议
    if url.lower().startswith(("data:", "javascript:")):
        indicators.append(PhishingIndicator(
            name="危险协议",
            category="protocol",
            severity="critical",
            detail=f"使用 {url.split(':')[0]}: 协议，常见于 XSS/钓鱼攻击",
        ))

    return indicators


def _check_content(req: WebPhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 页面内容分析（规则层）"""
    indicators: list[PhishingIndicator] = []
    content = f"{req.page_title} {req.page_content}".lower()
    if not content.strip():
        return indicators

    # 仿冒表单关键词
    form_keywords = ["password", "密码", "ssn", "social security", "credit card",
                     "银行卡", "身份证", "cvv", "expiry", "有效期"]
    form_hits = [kw for kw in form_keywords if kw in content]
    if form_hits:
        indicators.append(PhishingIndicator(
            name="敏感信息表单",
            category="content",
            severity="high",
            detail=f"页面内容涉及敏感信息采集: {', '.join(form_hits[:3])}",
        ))

    # 紧迫性话术
    urgency = ["立即", "紧急", "马上", "过期", "冻结",
               "immediately", "urgent", "expire", "suspend", "locked"]
    urgency_hits = [kw for kw in urgency if kw in content]
    if len(urgency_hits) >= 2:
        indicators.append(PhishingIndicator(
            name="页面紧迫性话术",
            category="content",
            severity="medium",
            detail=f"页面含紧迫性关键词: {', '.join(urgency_hits[:3])}",
        ))

    return indicators


def detect(req: WebPhishingRequest) -> list[PhishingIndicator]:
    """执行网页钓鱼全维度检测。"""
    indicators: list[PhishingIndicator] = []

    try:
        parsed = urlparse(req.url)
    except Exception:
        return [PhishingIndicator(
            name="URL 解析失败",
            category="url",
            severity="info",
            detail=f"无法解析 URL: {req.url[:100]}",
        )]

    indicators.extend(_check_url_structure(req.url, parsed))
    indicators.extend(_check_brand(req.url, parsed))
    indicators.extend(_check_path(parsed))
    indicators.extend(_check_protocol(req.url, parsed))
    indicators.extend(_check_content(req))

    return indicators
