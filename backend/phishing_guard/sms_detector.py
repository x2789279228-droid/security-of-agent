"""短信钓鱼检测器 — 5 维度分析

维度:
  1. 发送号码 (sender)
  2. URL 风险 (url) — 复用 web_detector 逻辑
  3. 内容语义 (content)
  4. 品牌仿冒 (brand)
  5. 退订陷阱 (unsubscribe)
"""
import re
import logging
from urllib.parse import urlparse

from .models import SmsPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# URL 提取正则
URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)

# 合法短号（中国运营商/银行/快递）
LEGIT_SHORT_CODES = {
    "10086", "10010", "10000", "10011", "10015",
    "95588", "95533", "95566", "95501", "95508",
    "95559", "95561", "95568", "95577", "95595",
    "95599", "95528", "95558", "95500", "95511",
    "12306", "12345", "12110", "12117",
}

# 银行/运营商/快递品牌
BRAND_KEYWORDS = [
    "银行", "工商", "建设", "农业", "中国", "招商", "交通",
    "bank", "icbc", "ccb", "abc", "boc", "cmb",
    "移动", "联通", "电信", "10086", "10010", "10000",
    "顺丰", "圆通", "中通", "韵达", "申通", "快递", "包裹",
    "支付宝", "微信", "淘宝", "京东",
]

# 诈骗话术关键词
SCAM_KEYWORDS = [
    "中奖", "领取", "奖品", "兑换", "积分到期", "积分清零",
    "异常", "冻结", "锁定", "过期", "停用", "失效",
    "点击", "立即", "马上", "紧急", "最后", "限时",
    "退款", "理赔", "补偿", "补贴", "退税",
    "贷款", "额度", "提额", "降息", "免息",
    "中奖", "彩票", "奖金", "领取",
    "包裹", "快递", "派送", "无法投递", "退件",
]

# 威胁话术
THREAT_KEYWORDS = [
    "起诉", "法律", "征信", "黑名单", "处罚", "罚款",
    "拘留", "通缉", "涉案", "洗钱", "犯罪",
]


def _check_sender(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """维度 1: 发送号码分析"""
    indicators: list[PhishingIndicator] = []
    sender = req.sender_number.strip()
    if not sender:
        return indicators

    # 纯数字短号
    digits = re.sub(r'[\s\-\+]', '', sender)

    if digits in LEGIT_SHORT_CODES:
        return indicators  # 合法短号，不报警

    # 国际号码（+开头）
    if sender.startswith("+") and not sender.startswith("+86"):
        indicators.append(PhishingIndicator(
            name="国际号码发送",
            category="sender",
            severity="high",
            detail=f"短信来自国际号码 {sender}，境内机构通常不使用国际号码发送通知",
        ))

    # 非常规短号（5-6位但不在白名单）
    if digits.isdigit() and 3 <= len(digits) <= 6 and digits not in LEGIT_SHORT_CODES:
        indicators.append(PhishingIndicator(
            name="非常规短号",
            category="sender",
            severity="medium",
            detail=f"短号 {sender} 不在已知合法服务号列表中",
        ))

    # 手机号伪装（+86 13x/15x/18x 等）
    if re.match(r'^(\+86)?1[3-9]\d{9}$', digits):
        indicators.append(PhishingIndicator(
            name="个人手机号发送",
            category="sender",
            severity="low",
            detail=f"短信来自个人手机号 {sender}，机构通知通常使用服务号",
        ))

    return indicators


def _check_urls(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """维度 2: URL 风险（复用 web_detector 逻辑）"""
    indicators: list[PhishingIndicator] = []
    urls = req.urls if req.urls else URL_PATTERN.findall(req.message_body)

    suspicious_tlds = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc")
    shorteners = ("bit.ly", "tinyurl.com", "t.cn", "dwz.cn", "suo.im", "url.cn")

    for url in urls[:10]:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        host = (parsed.hostname or "").lower()

        # IP 直连
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            indicators.append(PhishingIndicator(
                name="短信内 IP 链接",
                category="url",
                severity="high",
                detail=f"短信含 IP 直连链接: {url[:80]}",
            ))

        # 可疑 TLD
        for tld in suspicious_tlds:
            if host.endswith(tld):
                indicators.append(PhishingIndicator(
                    name="短信内高风险链接",
                    category="url",
                    severity="medium",
                    detail=f"短信链接使用高风险 TLD {tld}: {url[:80]}",
                ))
                break

        # 短链服务
        for s in shorteners:
            if s in host:
                indicators.append(PhishingIndicator(
                    name="短链服务",
                    category="url",
                    severity="medium",
                    detail=f"短信使用短链服务 {s}，隐藏真实目标: {url[:80]}",
                ))
                break

        # HTTP 无加密
        if parsed.scheme == "http":
            indicators.append(PhishingIndicator(
                name="HTTP 明文链接",
                category="url",
                severity="low",
                detail=f"短信链接使用 HTTP 明文传输: {url[:80]}",
            ))

    return indicators


def _check_content(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """维度 3: 内容语义分析"""
    indicators: list[PhishingIndicator] = []
    text = req.message_body.lower()
    if not text.strip():
        return indicators

    # 诈骗话术
    scam_hits = [kw for kw in SCAM_KEYWORDS if kw in text]
    if len(scam_hits) >= 3:
        indicators.append(PhishingIndicator(
            name="密集诈骗话术",
            category="content",
            severity="high",
            detail=f"检测到 {len(scam_hits)} 个诈骗关键词: {', '.join(scam_hits[:5])}",
        ))
    elif len(scam_hits) >= 1:
        indicators.append(PhishingIndicator(
            name="诈骗话术",
            category="content",
            severity="medium",
            detail=f"检测到诈骗关键词: {', '.join(scam_hits[:3])}",
        ))

    # 威胁话术
    threat_hits = [kw for kw in THREAT_KEYWORDS if kw in text]
    if threat_hits:
        indicators.append(PhishingIndicator(
            name="威胁恐吓话术",
            category="content",
            severity="high",
            detail=f"检测到威胁性关键词: {', '.join(threat_hits[:3])}",
        ))

    # 凭证索取
    cred_patterns = [
        (r'(密码|password|验证码|verification)', "密码/验证码索取"),
        (r'(银行卡|card|cvv|身份证)', "敏感信息索取"),
    ]
    for pattern, label in cred_patterns:
        if re.search(pattern, text):
            indicators.append(PhishingIndicator(
                name=f"凭证收割: {label}",
                category="content",
                severity="high",
                detail=f"短信内容涉及 {label}",
            ))

    return indicators


def _check_brand(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """维度 4: 品牌仿冒"""
    indicators: list[PhishingIndicator] = []
    text = req.message_body.lower()
    sender = req.sender_number.strip()

    # 短信内容含品牌名但发送号码不是官方短号
    digits = re.sub(r'[\s\-\+]', '', sender)
    is_official = digits in LEGIT_SHORT_CODES

    if not is_official:
        for brand in BRAND_KEYWORDS:
            if brand in text:
                indicators.append(PhishingIndicator(
                    name="品牌仿冒",
                    category="brand",
                    severity="high",
                    detail=f"短信内容提及 \"{brand}\" 但发送号码 {sender} 非官方服务号",
                ))
                break

    return indicators


def _check_unsubscribe(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 退订陷阱"""
    indicators: list[PhishingIndicator] = []
    text = req.message_body.lower()

    # 虚假退订指令
    unsub_patterns = [
        r'回复\s*[a-z0-9]+\s*退订',
        r'退订请回复',
        r'取消请回复',
        r'reply\s+\w+\s+to\s+(unsubscribe|stop|cancel)',
    ]
    for pattern in unsub_patterns:
        if re.search(pattern, text):
            indicators.append(PhishingIndicator(
                name="退订陷阱",
                category="unsubscribe",
                severity="medium",
                detail="短信含退订指令，回复可能确认号码活跃或触发扣费",
            ))
            break

    return indicators


def detect(req: SmsPhishingRequest) -> list[PhishingIndicator]:
    """执行短信钓鱼全维度检测。"""
    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_sender(req))
    indicators.extend(_check_urls(req))
    indicators.extend(_check_content(req))
    indicators.extend(_check_brand(req))
    indicators.extend(_check_unsubscribe(req))
    return indicators
