"""邮件钓鱼检测器 — 6 维度分析

维度:
  1. 发件人伪造 (sender)
  2. URL 链接风险 (url)
  3. 附件风险 (attachment)
  4. 内容语义 (content)
  5. 邮件头异常 (header)
  6. 综合研判 (overall)
"""
import re
import logging
from urllib.parse import urlparse

from .models import EmailPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# ── 常量 ──

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "163.com", "126.com", "qq.com", "sina.com", "foxmail.com",
    "proton.me", "icloud.com", "aol.com", "mail.com",
}

# 常被冒充的企业品牌关键词
BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "bank",
    "alipay", "wechat", "taobao", "jd", "icbc", "ccb", "boc",
    "dhl", "fedex", "ups", "netflix", "linkedin", "dropbox",
]

# 紧迫性 / 凭证收割关键词
URGENCY_KEYWORDS = [
    "立即", "马上", "紧急", "24小时", "48小时", "过期", "冻结",
    "immediately", "urgent", "expire", "suspend", "verify",
    "action required", "account locked", "unauthorized",
    "点击", "验证", "更新", "确认", "登录", "密码",
    "click here", "verify your", "update your", "confirm your",
    "reset password", "sign in", "secure your",
]

THREAT_KEYWORDS = [
    "封禁", "冻结", "删除", "取消", "法律", "起诉",
    "suspend", "terminate", "legal action", "penalty", "fine",
    "deactivate", "permanent", "last warning", "final notice",
]

# 高风险附件扩展名
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".com",
    ".pif", ".hta", ".cpl", ".msi", ".ps1", ".wsf", ".jar",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam"}

# URL 提取正则
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+', re.IGNORECASE
)


def _extract_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def _check_sender(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """维度 1: 发件人伪造检测"""
    indicators: list[PhishingIndicator] = []
    sender = req.sender.strip()
    if not sender:
        return indicators

    # 解析 "Display Name <email>" 格式
    display_name = ""
    email_addr = sender
    m = re.match(r'^(.+?)\s*<(.+?)>$', sender)
    if m:
        display_name = m.group(1).strip().strip('"')
        email_addr = m.group(2).strip()

    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""

    # 1a: 免费邮箱冒充企业
    if display_name and domain in FREE_EMAIL_DOMAINS:
        name_lower = display_name.lower()
        for brand in BRAND_KEYWORDS:
            if brand in name_lower:
                indicators.append(PhishingIndicator(
                    name="免费邮箱冒充企业",
                    category="sender",
                    severity="high",
                    detail=f"显示名 \"{display_name}\" 含品牌词 \"{brand}\"，但发件域名为免费邮箱 {domain}",
                ))
                break

    # 1b: 显示名与域名不匹配
    if display_name and domain:
        name_lower = display_name.lower().replace(" ", "")
        domain_base = domain.split(".")[0]
        # 显示名看起来像企业但域名完全不同
        for brand in BRAND_KEYWORDS:
            if brand in name_lower and brand not in domain_base:
                indicators.append(PhishingIndicator(
                    name="显示名与域名不匹配",
                    category="sender",
                    severity="medium",
                    detail=f"显示名暗示 \"{brand}\"，但实际域名为 {domain}",
                ))
                break

    # 1c: 域名 typosquatting（简单检测）
    if domain:
        for brand in BRAND_KEYWORDS:
            if _is_typosquat(domain.split(".")[0], brand):
                indicators.append(PhishingIndicator(
                    name="发件域名疑似仿冒",
                    category="sender",
                    severity="critical",
                    detail=f"域名 {domain} 与品牌 \"{brand}\" 高度相似（typosquatting）",
                ))
                break

    return indicators


def _is_typosquat(candidate: str, brand: str) -> bool:
    """简易 typosquatting 检测：编辑距离 ≤ 2 且不完全相同"""
    candidate = candidate.lower()
    brand = brand.lower()
    if candidate == brand:
        return False
    if abs(len(candidate) - len(brand)) > 2:
        return False
    dist = _levenshtein(candidate, brand)
    return 0 < dist <= 2


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


def _check_urls(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """维度 2: URL 链接风险"""
    indicators: list[PhishingIndicator] = []
    urls = req.urls if req.urls else _extract_urls(req.body + " " + req.headers)

    for url in urls[:20]:  # 限制数量
        try:
            parsed = urlparse(url)
        except Exception:
            continue

        host = parsed.hostname or ""

        # IP 直连
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            indicators.append(PhishingIndicator(
                name="IP 直连链接",
                category="url",
                severity="high",
                detail=f"邮件中包含 IP 直连链接: {url[:80]}",
            ))

        # 可疑 TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc"}
        for tld in suspicious_tlds:
            if host.endswith(tld):
                indicators.append(PhishingIndicator(
                    name="高风险 TLD 链接",
                    category="url",
                    severity="medium",
                    detail=f"链接使用高风险顶级域名 {tld}: {url[:80]}",
                ))
                break

        # URL 中含 @ 符号（绕过技巧）
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            indicators.append(PhishingIndicator(
                name="URL @ 绕过",
                category="url",
                severity="high",
                detail=f"URL 含 @ 符号，可能伪装真实域名: {url[:80]}",
            ))

        # 过多子域名
        if host.count(".") >= 4:
            indicators.append(PhishingIndicator(
                name="异常多级子域名",
                category="url",
                severity="medium",
                detail=f"子域名层级异常 ({host.count('.') + 1} 级): {host}",
            ))

        # 品牌词出现在 URL 路径/子域名中
        url_lower = url.lower()
        for brand in BRAND_KEYWORDS:
            if brand in url_lower and brand not in host.split(".")[0]:
                indicators.append(PhishingIndicator(
                    name="URL 路径仿冒品牌",
                    category="url",
                    severity="medium",
                    detail=f"URL 路径/子域名含品牌词 \"{brand}\" 但主域名不匹配",
                ))
                break

    return indicators


def _check_attachments(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """维度 3: 附件风险"""
    indicators: list[PhishingIndicator] = []
    for name in req.attachments:
        name_lower = name.lower().strip()
        ext = ""
        if "." in name_lower:
            ext = "." + name_lower.rsplit(".", 1)[-1]

        if ext in HIGH_RISK_EXTENSIONS:
            indicators.append(PhishingIndicator(
                name="高危可执行附件",
                category="attachment",
                severity="critical",
                detail=f"附件 \"{name}\" 为可执行文件类型 ({ext})",
            ))
        elif ext in MACRO_EXTENSIONS:
            indicators.append(PhishingIndicator(
                name="宏文件附件",
                category="attachment",
                severity="high",
                detail=f"附件 \"{name}\" 支持宏执行 ({ext})，可能携带恶意代码",
            ))
        elif ext in {".zip", ".rar", ".7z", ".tar", ".gz"}:
            indicators.append(PhishingIndicator(
                name="压缩包附件",
                category="attachment",
                severity="low",
                detail=f"附件 \"{name}\" 为压缩包，可能隐藏恶意文件",
            ))

    return indicators


def _check_content(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """维度 4: 内容语义分析"""
    indicators: list[PhishingIndicator] = []
    text = f"{req.subject} {req.body}".lower()
    if not text.strip():
        return indicators

    # 紧迫性话术
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in text]
    if len(urgency_hits) >= 3:
        indicators.append(PhishingIndicator(
            name="密集紧迫性话术",
            category="content",
            severity="high",
            detail=f"检测到 {len(urgency_hits)} 个紧迫性关键词: {', '.join(urgency_hits[:5])}",
        ))
    elif len(urgency_hits) >= 1:
        indicators.append(PhishingIndicator(
            name="紧迫性话术",
            category="content",
            severity="medium",
            detail=f"检测到紧迫性关键词: {', '.join(urgency_hits[:3])}",
        ))

    # 威胁话术
    threat_hits = [kw for kw in THREAT_KEYWORDS if kw in text]
    if threat_hits:
        indicators.append(PhishingIndicator(
            name="威胁/恐吓话术",
            category="content",
            severity="high",
            detail=f"检测到威胁性关键词: {', '.join(threat_hits[:3])}",
        ))

    # 凭证收割模式
    cred_patterns = [
        (r'(密码|password|passwd)', "密码索取"),
        (r'(银行卡|card\s*number|cvv|信用卡)', "银行卡信息索取"),
        (r'(身份证|id\s*card|ssn|social\s*security)', "身份信息索取"),
        (r'(验证码|verification\s*code|otp)', "验证码索取"),
    ]
    for pattern, label in cred_patterns:
        if re.search(pattern, text):
            indicators.append(PhishingIndicator(
                name=f"凭证收割: {label}",
                category="content",
                severity="high",
                detail=f"邮件内容涉及 {label}",
            ))

    return indicators


def _check_headers(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 邮件头分析"""
    indicators: list[PhishingIndicator] = []
    headers = req.headers
    if not headers:
        return indicators

    headers_lower = headers.lower()

    # SPF 校验失败
    if "spf=fail" in headers_lower or "spf=softfail" in headers_lower:
        indicators.append(PhishingIndicator(
            name="SPF 校验失败",
            category="header",
            severity="high",
            detail="邮件头显示 SPF 校验未通过，发件人可能伪造",
        ))

    # DKIM 校验失败
    if "dkim=fail" in headers_lower or "dkim=none" in headers_lower:
        indicators.append(PhishingIndicator(
            name="DKIM 校验失败",
            category="header",
            severity="medium",
            detail="DKIM 签名校验失败或缺失",
        ))

    # DMARC 校验失败
    if "dmarc=fail" in headers_lower or "dmarc=none" in headers_lower:
        indicators.append(PhishingIndicator(
            name="DMARC 校验失败",
            category="header",
            severity="medium",
            detail="DMARC 策略校验失败，域名保护不足",
        ))

    # Received 链异常：过多跳转
    received_count = headers_lower.count("received:")
    if received_count > 6:
        indicators.append(PhishingIndicator(
            name="异常邮件跳转链",
            category="header",
            severity="medium",
            detail=f"Received 头多达 {received_count} 跳，可能存在转发混淆",
        ))

    # 缺少常见合法头
    if "message-id" not in headers_lower and headers.strip():
        indicators.append(PhishingIndicator(
            name="缺少 Message-ID",
            category="header",
            severity="low",
            detail="邮件缺少 Message-ID 头，可能为伪造邮件",
        ))

    return indicators


def detect(req: EmailPhishingRequest) -> list[PhishingIndicator]:
    """执行邮件钓鱼全维度检测，返回指标列表。"""
    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_sender(req))
    indicators.extend(_check_urls(req))
    indicators.extend(_check_attachments(req))
    indicators.extend(_check_content(req))
    indicators.extend(_check_headers(req))
    return indicators
