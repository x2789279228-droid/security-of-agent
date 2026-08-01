"""商务诈骗 (BEC) 检测器 — 6 维度分析

BEC = Business Email Compromise（商务邮件入侵）

维度:
  1. 高管仿冒 (executive)
  2. 财务操作 (financial)
  3. 保密施压 (secrecy)
  4. 回复地址不一致 (reply_to)
  5. 发票篡改 (invoice)
  6. 时间压力 (urgency)
"""
import re
import logging

from .models import BecPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# 高管头衔关键词
EXECUTIVE_TITLES = [
    "ceo", "cfo", "cto", "coo", "总裁", "总经理", "董事长",
    "副总", "总监", "director", "vp", "vice president",
    "president", "chairman", "chief", "合伙人", "partner",
]

# 免费邮箱域名
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "163.com", "126.com", "qq.com", "sina.com", "foxmail.com",
    "proton.me", "icloud.com", "aol.com", "mail.com",
}

# 财务操作关键词
FINANCIAL_KEYWORDS = [
    "汇款", "转账", "打款", "付款", "电汇", "wire transfer",
    "payment", "transfer", "remittance", "pay",
    "礼品卡", "gift card", "itunes", "amazon card",
    "预付", "prepaid", "充值", "top up",
    "保证金", "deposit", "押金",
    "紧急付款", "urgent payment", "立即转账",
]

# 保密施压关键词
SECRECY_KEYWORDS = [
    "保密", "机密", "不要告诉", "别告诉", "不要声张",
    "confidential", "secret", "don't tell", "do not share",
    "不要回复", "不要联系", "不要确认",
    "仅限你知", "only you", "between us", "private",
    "不要跟任何人", "keep this to yourself",
    "不需要审批", "跳过审批", "bypass approval",
]

# 发票篡改关键词
INVOICE_KEYWORDS = [
    "发票", "invoice", "账单", "billing",
    "银行账户", "bank account", "账号变更", "账户变更",
    "收款账户", "收款账号", "routing number", "swift",
    "变更通知", "更新账户", "新账户", "new account",
    "付款信息变更", "payment detail", "remittance advice",
]

# 时间压力关键词
URGENCY_KEYWORDS = [
    "今天", "下班前", "周末前", "月底", "立即", "马上",
    "today", "before end of day", "eod", "asap", "immediately",
    "urgent", "紧急", "尽快", "限时", "deadline",
    "税务", "审计", "tax", "audit", "合规", "compliance",
    "最后期限", "截止", "过期不候",
]


def _parse_sender(sender: str) -> tuple[str, str]:
    """解析 'Display Name <email>' 格式，返回 (display_name, email)"""
    m = re.match(r'^(.+?)\s*<(.+?)>$', sender.strip())
    if m:
        return m.group(1).strip().strip('"'), m.group(2).strip()
    if "@" in sender:
        return "", sender.strip()
    return sender.strip(), ""


def _check_executive(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 1: 高管仿冒"""
    indicators: list[PhishingIndicator] = []
    display_name, email = _parse_sender(req.sender)
    if not display_name and not email:
        return indicators

    name_lower = display_name.lower()
    domain = email.split("@")[-1].lower() if "@" in email else ""

    # 头衔 + 免费邮箱
    has_title = any(t in name_lower for t in EXECUTIVE_TITLES)
    if has_title and domain in FREE_EMAIL_DOMAINS:
        indicators.append(PhishingIndicator(
            name="高管仿冒 + 免费邮箱",
            category="executive",
            severity="critical",
            detail=f"发件人 \"{display_name}\" 含高管头衔，但使用免费邮箱 {domain}",
        ))
    elif has_title:
        indicators.append(PhishingIndicator(
            name="高管头衔发件",
            category="executive",
            severity="medium",
            detail=f"发件人 \"{display_name}\" 含高管头衔，请核实身份",
        ))

    # 显示名含中文称呼 + 外部邮箱
    cn_titles = ["总", "董", "经理", "主管", "主任"]
    has_cn_title = any(t in display_name for t in cn_titles)
    if has_cn_title and domain in FREE_EMAIL_DOMAINS:
        indicators.append(PhishingIndicator(
            name="中文高管称谓 + 外部邮箱",
            category="executive",
            severity="high",
            detail=f"发件人 \"{display_name}\" 使用中文高管称谓，但邮箱为外部域名 {domain}",
        ))

    return indicators


def _check_financial(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 2: 财务操作"""
    indicators: list[PhishingIndicator] = []
    text = f"{req.subject} {req.body}".lower()

    hits = [kw for kw in FINANCIAL_KEYWORDS if kw in text]
    if len(hits) >= 2:
        indicators.append(PhishingIndicator(
            name="密集财务操作",
            category="financial",
            severity="high",
            detail=f"检测到 {len(hits)} 个财务关键词: {', '.join(hits[:4])}",
        ))
    elif len(hits) == 1:
        indicators.append(PhishingIndicator(
            name="财务操作请求",
            category="financial",
            severity="medium",
            detail=f"检测到财务关键词: {hits[0]}",
        ))

    # 礼品卡购买 — 高度可疑
    gift_card_kw = ["礼品卡", "gift card", "itunes", "amazon card"]
    gc_hits = [kw for kw in gift_card_kw if kw in text]
    if gc_hits:
        indicators.append(PhishingIndicator(
            name="礼品卡购买请求",
            category="financial",
            severity="critical",
            detail=f"要求购买礼品卡: {', '.join(gc_hits)}，这是 BEC 诈骗的典型手法",
        ))

    return indicators


def _check_secrecy(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 3: 保密施压"""
    indicators: list[PhishingIndicator] = []
    text = f"{req.subject} {req.body}".lower()

    hits = [kw for kw in SECRECY_KEYWORDS if kw in text]
    if len(hits) >= 2:
        indicators.append(PhishingIndicator(
            name="密集保密施压",
            category="secrecy",
            severity="high",
            detail=f"检测到 {len(hits)} 个保密/施压关键词: {', '.join(hits[:4])}",
        ))
    elif len(hits) == 1:
        indicators.append(PhishingIndicator(
            name="保密施压话术",
            category="secrecy",
            severity="medium",
            detail=f"检测到保密/施压关键词: {hits[0]}",
        ))

    return indicators


def _check_reply_to(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 4: 回复地址不一致"""
    indicators: list[PhishingIndicator] = []
    if not req.reply_to or not req.sender:
        return indicators

    _, sender_email = _parse_sender(req.sender)
    reply_email = req.reply_to.strip()

    if sender_email and reply_email:
        sender_domain = sender_email.split("@")[-1].lower()
        reply_domain = reply_email.split("@")[-1].lower()

        if sender_domain != reply_domain:
            indicators.append(PhishingIndicator(
                name="回复地址不一致",
                category="reply_to",
                severity="high",
                detail=f"发件域名 {sender_domain} ≠ 回复域名 {reply_domain}，回复将被发送到不同地址",
            ))

    return indicators


def _check_invoice(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 发票篡改"""
    indicators: list[PhishingIndicator] = []
    text = f"{req.subject} {req.body}".lower()

    hits = [kw for kw in INVOICE_KEYWORDS if kw in text]
    if len(hits) >= 2:
        indicators.append(PhishingIndicator(
            name="发票/账户篡改",
            category="invoice",
            severity="high",
            detail=f"检测到 {len(hits)} 个发票/账户变更关键词: {', '.join(hits[:4])}",
        ))
    elif len(hits) == 1:
        indicators.append(PhishingIndicator(
            name="发票相关请求",
            category="invoice",
            severity="medium",
            detail=f"检测到发票/账户关键词: {hits[0]}",
        ))

    # 附件 + 发票变更 → 更可疑
    if req.has_attachment and hits:
        indicators.append(PhishingIndicator(
            name="发票变更含附件",
            category="invoice",
            severity="high",
            detail="发票/账户变更请求附带附件，附件可能含恶意宏或篡改后的发票",
        ))

    return indicators


def _check_urgency(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """维度 6: 时间压力"""
    indicators: list[PhishingIndicator] = []
    text = f"{req.subject} {req.body}".lower()

    hits = [kw for kw in URGENCY_KEYWORDS if kw in text]
    if len(hits) >= 3:
        indicators.append(PhishingIndicator(
            name="密集时间压力",
            category="urgency",
            severity="high",
            detail=f"检测到 {len(hits)} 个时间压力关键词: {', '.join(hits[:4])}",
        ))
    elif len(hits) >= 1:
        indicators.append(PhishingIndicator(
            name="时间压力话术",
            category="urgency",
            severity="medium",
            detail=f"检测到时间压力关键词: {', '.join(hits[:3])}",
        ))

    return indicators


def detect(req: BecPhishingRequest) -> list[PhishingIndicator]:
    """执行商务诈骗 (BEC) 全维度检测。"""
    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_executive(req))
    indicators.extend(_check_financial(req))
    indicators.extend(_check_secrecy(req))
    indicators.extend(_check_reply_to(req))
    indicators.extend(_check_invoice(req))
    indicators.extend(_check_urgency(req))
    return indicators
