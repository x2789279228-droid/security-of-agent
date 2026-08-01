"""二维码钓鱼检测器 — 5 维度分析

维度:
  1. URL 风险 (url) — 复用 web_detector + domain_detector
  2. 来源上下文 (context)
  3. 品牌仿冒 (brand)
  4. 短链/重定向 (shortener)
  5. 支付劫持 (payment)
"""
import re
import logging
from urllib.parse import urlparse

from .models import QrCodePhishingRequest, PhishingIndicator
from . import web_detector, domain_detector
from .models import WebPhishingRequest, DomainPhishingRequest

logger = logging.getLogger(__name__)

# 短链服务域名
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.cn", "dwz.cn", "suo.im",
    "url.cn", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "tiny.cc", "rb.gy", "cutt.ly", "rebrand.ly",
}

# 支付相关品牌
PAYMENT_BRANDS = {
    "支付宝": "alipay.com",
    "alipay": "alipay.com",
    "微信": "wechat.com",
    "wechat": "wechat.com",
    "微信支付": "wechat.com",
    "银联": "unionpay.com",
    "unionpay": "unionpay.com",
    "paypal": "paypal.com",
    "云闪付": "unionpay.com",
}

# 品牌域名映射
BRAND_DOMAINS: dict[str, str] = {
    "支付宝": "alipay.com", "alipay": "alipay.com",
    "微信": "wechat.com", "wechat": "wechat.com",
    "淘宝": "taobao.com", "taobao": "taobao.com",
    "京东": "jd.com", "jd": "jd.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "银行": "bank",
}


def _check_url(decoded_url: str) -> list[PhishingIndicator]:
    """维度 1: URL 风险（复用 web_detector + domain_detector）"""
    indicators: list[PhishingIndicator] = []

    # 非 URL 内容（如纯文本、WiFi 配置等）
    if not decoded_url.startswith(("http://", "https://")):
        # WiFi 钓鱼：WIFI:T:WPA;S:...;P:...;;
        if decoded_url.upper().startswith("WIFI:"):
            indicators.append(PhishingIndicator(
                name="WiFi 配置二维码",
                category="url",
                severity="high",
                detail="二维码为 WiFi 配置，可能引导连接恶意热点进行中间人攻击",
            ))
        return indicators

    # 复用 web_detector
    web_req = WebPhishingRequest(url=decoded_url)
    web_indicators = web_detector.detect(web_req)
    for ind in web_indicators:
        ind.category = "url"
        ind.name = f"[QR] {ind.name}"
    indicators.extend(web_indicators)

    # 复用 domain_detector
    try:
        parsed = urlparse(decoded_url)
        host = parsed.hostname or ""
        if host:
            domain_req = DomainPhishingRequest(domain=host)
            domain_indicators = domain_detector.detect(domain_req)
            for ind in domain_indicators:
                ind.category = "url"
                ind.name = f"[QR] {ind.name}"
            indicators.extend(domain_indicators)
    except Exception:
        pass

    return indicators


def _check_context(req: QrCodePhishingRequest) -> list[PhishingIndicator]:
    """维度 2: 来源上下文"""
    indicators: list[PhishingIndicator] = []
    ctx = req.source_context.lower().strip()

    # 邮件中的二维码 — 高风险（绕过 URL 检测）
    if ctx in ("email", "邮件"):
        indicators.append(PhishingIndicator(
            name="邮件内嵌二维码",
            category="context",
            severity="high",
            detail="二维码嵌入邮件中，可能用于绕过邮件网关的 URL 检测",
        ))

    # 物理海报/贴纸 — 中风险（可被篡改）
    if ctx in ("poster", "海报", "贴纸", "sticker"):
        indicators.append(PhishingIndicator(
            name="物理载体二维码",
            category="context",
            severity="medium",
            detail="二维码来自物理载体（海报/贴纸），存在被覆盖替换的风险",
        ))

    return indicators


def _check_brand(req: QrCodePhishingRequest) -> list[PhishingIndicator]:
    """维度 3: 品牌仿冒"""
    indicators: list[PhishingIndicator] = []
    brand_hint = req.brand_hint.lower().strip()
    if not brand_hint:
        return indicators

    try:
        parsed = urlparse(req.decoded_url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return indicators

    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in brand_hint:
            if legit_domain not in host:
                indicators.append(PhishingIndicator(
                    name="二维码品牌仿冒",
                    category="brand",
                    severity="high",
                    detail=f"声称品牌 \"{brand_hint}\" 但 URL 域名为 {host}，非官方 {legit_domain}",
                ))
            break

    return indicators


def _check_shortener(decoded_url: str) -> list[PhishingIndicator]:
    """维度 4: 短链/重定向"""
    indicators: list[PhishingIndicator] = []

    try:
        parsed = urlparse(decoded_url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return indicators

    for s in SHORTENER_DOMAINS:
        if s in host:
            indicators.append(PhishingIndicator(
                name="短链服务",
                category="shortener",
                severity="medium",
                detail=f"二维码指向短链服务 {s}，隐藏真实目标地址",
            ))
            break

    return indicators


def _check_payment(req: QrCodePhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 支付劫持"""
    indicators: list[PhishingIndicator] = []
    ctx = req.source_context.lower().strip()
    brand_hint = req.brand_hint.lower().strip()

    # 支付场景 + 非官方域名
    is_payment_context = ctx in ("payment", "支付", "收款", "付款")
    is_payment_brand = any(b in brand_hint for b in PAYMENT_BRANDS)

    if is_payment_context or is_payment_brand:
        try:
            parsed = urlparse(req.decoded_url)
            host = (parsed.hostname or "").lower()
        except Exception:
            host = ""

        # 检查是否指向官方支付域名
        is_official = False
        for brand, domain in PAYMENT_BRANDS.items():
            if brand in brand_hint and domain in host:
                is_official = True
                break

        if not is_official and host:
            indicators.append(PhishingIndicator(
                name="支付二维码劫持",
                category="payment",
                severity="critical",
                detail=f"支付场景二维码指向非官方域名 {host}，可能为收款码篡改",
            ))

    return indicators


def detect(req: QrCodePhishingRequest) -> list[PhishingIndicator]:
    """执行二维码钓鱼全维度检测。"""
    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_url(req.decoded_url))
    indicators.extend(_check_context(req))
    indicators.extend(_check_brand(req))
    indicators.extend(_check_shortener(req.decoded_url))
    indicators.extend(_check_payment(req))
    return indicators
