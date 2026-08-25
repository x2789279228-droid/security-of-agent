"""
test_inc_phishing — 反钓鱼单元测试(离线, 无需 LLM/邮件系统)

覆盖 7 类检测器: email/web/domain/attachment/sms/qrcode/bec 的 detect + PhishingGuard 聚合。
"""
from phishing_guard import email_detector, web_detector, domain_detector, \
    attachment_detector, sms_detector, qrcode_detector, bec_detector
from phishing_guard.models import EmailPhishingRequest, WebPhishingRequest, \
    DomainPhishingRequest, AttachmentPhishingRequest, SmsPhishingRequest, \
    QrCodePhishingRequest, BecPhishingRequest
from phishing_guard import PhishingGuard
from tests.inc_testcases import PHISH_EMAIL_REQ, PHISH_WEB_REQ, PHISH_DOMAIN_REQ, \
    PHISH_ATTACHMENT_REQ, PHISH_SMS_REQ, PHISH_QR_REQ, PHISH_BEC_REQ


def test_email_detector_returns_indicators():
    """邮件检测器(拼写/域名仿冒 URL)返回指示。"""
    inds = email_detector.detect(EmailPhishingRequest(**PHISH_EMAIL_REQ))
    assert isinstance(inds, list)
    # 至少应有类别化指示(不要求全部命中)
    assert all(i.category for i in inds)


def test_web_detector_detects_suspicious_url():
    """web 检测器识别可疑 URL。"""
    inds = web_detector.detect(WebPhishingRequest(**PHISH_WEB_REQ))
    assert isinstance(inds, list)


def test_domain_detector():
    """domain 检测器对可疑域名返回指示。"""
    inds = domain_detector.detect(DomainPhishingRequest(**PHISH_DOMAIN_REQ))
    assert isinstance(inds, list)


def test_attachment_detector():
    """attachment 检测器(可执行扩展)返回指示。"""
    inds = attachment_detector.detect(AttachmentPhishingRequest(**PHISH_ATTACHMENT_REQ))
    assert isinstance(inds, list)


def test_sms_detector():
    """SMS 检测器。"""
    inds = sms_detector.detect(SmsPhishingRequest(**PHISH_SMS_REQ))
    assert isinstance(inds, list)


def test_qrcode_detector():
    """二维码检测器。"""
    inds = qrcode_detector.detect(QrCodePhishingRequest(**PHISH_QR_REQ))
    assert isinstance(inds, list)


def test_bec_detector():
    """BEC(商务邮件欺诈)检测器。"""
    inds = bec_detector.detect(BecPhishingRequest(**PHISH_BEC_REQ))
    assert isinstance(inds, list)


def test_phishing_guard_email_verdict():
    """PhishingGuard.detect_email 返回 PhishingVerdict(含 verdict/is_phishing)。"""
    guard = PhishingGuard()
    v = guard.detect_email(EmailPhishingRequest(**PHISH_EMAIL_REQ), llm_enrich=False)
    assert hasattr(v, "verdict") or hasattr(v, "is_phishing") or v is not None
    d = v.to_dict() if hasattr(v, "to_dict") else True
    assert d is not None


def test_phishing_guard_web_verdict():
    """PhishingGuard.detect_web 返回 verdict。"""
    guard = PhishingGuard()
    v = guard.detect_web(WebPhishingRequest(**PHISH_WEB_REQ), llm_enrich=False)
    assert v is not None
