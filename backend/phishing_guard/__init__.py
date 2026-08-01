"""钓鱼检测模块 — 统一入口

提供八个攻击面的钓鱼检测能力：
  - 邮件钓鱼 (email)
  - 网页钓鱼 (web)
  - 域名访问钓鱼 (domain)
  - 附件钓鱼 (attachment)
  - 短信钓鱼 (sms)
  - 二维码钓鱼 (qrcode)
  - 商务诈骗 (bec)

调用方式：
    from phishing_guard import phishing_guard

    verdict = phishing_guard.detect_email(req)
    verdict = phishing_guard.detect_web(req)
    verdict = phishing_guard.detect_domain(req)
    verdict = phishing_guard.detect_attachment(req)
    verdict = phishing_guard.detect_sms(req)
    verdict = phishing_guard.detect_qrcode(req)
    verdict = phishing_guard.detect_bec(req)
"""
import logging

from .models import (
    EmailPhishingRequest,
    WebPhishingRequest,
    DomainPhishingRequest,
    AttachmentPhishingRequest,
    SmsPhishingRequest,
    QrCodePhishingRequest,
    BecPhishingRequest,
    PhishingVerdict,
)
from . import (
    email_detector, web_detector, domain_detector,
    attachment_detector, sms_detector, qrcode_detector, bec_detector,
)
from .scoring import aggregate

logger = logging.getLogger(__name__)


class PhishingGuard:
    """钓鱼检测编排器：调用各检测器 + 评分引擎，输出统一裁决。"""

    def detect_email(self, req: EmailPhishingRequest) -> PhishingVerdict:
        indicators = email_detector.detect(req)
        target = req.sender or req.subject or "(邮件)"
        summary = self._build_summary("邮件", indicators)
        return aggregate("email", target[:120], indicators, summary)

    def detect_web(self, req: WebPhishingRequest) -> PhishingVerdict:
        indicators = web_detector.detect(req)
        target = req.url[:120]
        summary = self._build_summary("网页", indicators)
        return aggregate("web", target, indicators, summary)

    def detect_domain(self, req: DomainPhishingRequest) -> PhishingVerdict:
        indicators = domain_detector.detect(req)
        target = req.domain[:120]
        summary = self._build_summary("域名", indicators)
        return aggregate("domain", target, indicators, summary)

    def detect_attachment(self, req: AttachmentPhishingRequest) -> PhishingVerdict:
        indicators = attachment_detector.detect(req)
        target = req.filename[:120]
        summary = self._build_summary("附件", indicators)
        return aggregate("attachment", target, indicators, summary)

    def detect_sms(self, req: SmsPhishingRequest) -> PhishingVerdict:
        indicators = sms_detector.detect(req)
        target = req.sender_number or req.message_body[:60] or "(短信)"
        summary = self._build_summary("短信", indicators)
        return aggregate("sms", target[:120], indicators, summary)

    def detect_qrcode(self, req: QrCodePhishingRequest) -> PhishingVerdict:
        indicators = qrcode_detector.detect(req)
        target = req.decoded_url[:120]
        summary = self._build_summary("二维码", indicators)
        return aggregate("qrcode", target, indicators, summary)

    def detect_bec(self, req: BecPhishingRequest) -> PhishingVerdict:
        indicators = bec_detector.detect(req)
        target = req.sender or req.subject or "(商务邮件)"
        summary = self._build_summary("商务诈骗", indicators)
        return aggregate("bec", target[:120], indicators, summary)

    @staticmethod
    def _build_summary(label: str, indicators: list) -> str:
        if not indicators:
            return f"{label}检测未发现钓鱼指标"
        critical = sum(1 for i in indicators if i.severity == "critical")
        high = sum(1 for i in indicators if i.severity == "high")
        parts = []
        if critical:
            parts.append(f"{critical} 项严重")
        if high:
            parts.append(f"{high} 项高危")
        other = len(indicators) - critical - high
        if other:
            parts.append(f"{other} 项中低危")
        return f"{label}检测发现 {'、'.join(parts)} 钓鱼指标"


phishing_guard = PhishingGuard()
