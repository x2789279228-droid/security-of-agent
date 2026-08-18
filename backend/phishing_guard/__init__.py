"""钓鱼检测模块 — 统一入口

提供八个攻击面的钓鱼检测能力：
  - 邮件钓鱼 (email)
  - 网页钓鱼 (web)
  - 域名访问钓鱼 (domain)
  - 附件钓鱼 (attachment)
  - 短信钓鱼 (sms)
  - 二维码钓鱼 (qrcode)
  - 商务诈骗 (bec)

P0.S 升级: 全部 detect_xxx 接受 async llm_enrich=False 参数 (默认 False,
保留原同步签名).设 True 时,规则 verdict 仍立即返回,LLM 维度
通过 llm_enhancer.safe_dispatch 异步派发,完成后广播 event_bus 事件
"phishing_llm_verdict" 供前端审计 trail / 二次查询.

调用方式：
    from phishing_guard import phishing_guard
    verdict = phishing_guard.detect_email(req)                    # 同步,0 LLM
    verdict = phishing_guard.detect_email(req, llm_enrich=True)   # 同步 + LLM 异步派发
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
from .scoring import aggregate, aggregate_with_llm

logger = logging.getLogger(__name__)


class PhishingGuard:
    """钓鱼检测编排器：调用各检测器 + 评分引擎，输出统一裁决。"""

    def detect_email(self, req: EmailPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = email_detector.detect(req)
        target = req.sender or req.subject or "(邮件)"
        summary = self._build_summary("邮件", indicators)
        verdict = aggregate("email", target[:120], indicators, summary)
        if llm_enrich:
            self._dispatch_llm("email", target, req, indicators, verdict)
        return verdict

    def detect_web(self, req: WebPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = web_detector.detect(req)
        target = req.url[:120]
        summary = self._build_summary("网页", indicators)
        verdict = aggregate("web", target, indicators, summary)
        if llm_enrich:
            self._dispatch_llm("web", target, req, indicators, verdict)
        return verdict

    def detect_domain(self, req: DomainPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = domain_detector.detect(req)
        target = req.domain[:120]
        summary = self._build_summary("域名", indicators)
        verdict = aggregate("domain", target, indicators, summary)
        if llm_enrich:
            self._dispatch_llm("domain", target, req, indicators, verdict)
        return verdict

    def detect_attachment(self, req: AttachmentPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = attachment_detector.detect(req)
        target = req.filename[:120]
        summary = self._build_summary("附件", indicators)
        verdict = aggregate("attachment", target, indicators, summary)
        if llm_enrich:
            self._dispatch_llm("attachment", target, req, indicators, verdict)
        return verdict

    def detect_sms(self, req: SmsPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = sms_detector.detect(req)
        target = req.sender_number or req.message_body[:60] or "(短信)"
        summary = self._build_summary("短信", indicators)
        verdict = aggregate("sms", target[:120], indicators, summary)
        if llm_enrich:
            self._dispatch_llm("sms", target, req, indicators, verdict)
        return verdict

    def detect_qrcode(self, req: QrCodePhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = qrcode_detector.detect(req)
        target = req.decoded_url[:120]
        summary = self._build_summary("二维码", indicators)
        verdict = aggregate("qrcode", target, indicators, summary)
        if llm_enrich:
            self._dispatch_llm("qrcode", target, req, indicators, verdict)
        return verdict

    def detect_bec(self, req: BecPhishingRequest, llm_enrich: bool = False) -> PhishingVerdict:
        indicators = bec_detector.detect(req)
        target = req.sender or req.subject or "(商务邮件)"
        summary = self._build_summary("商务诈骗", indicators)
        verdict = aggregate("bec", target[:120], indicators, summary)
        if llm_enrich:
            self._dispatch_llm("bec", target, req, indicators, verdict)
        return verdict

    @staticmethod
    def _dispatch_llm(
        detection_type: str, target: str, request,
        indicators: list, rule_verdict: PhishingVerdict,
    ) -> None:
        """
        异步派发 LLM 复核任务.主路径 0 等待.
        - should_trigger_llm 检查模块开关 + 规则 verdict 范围 (suspicious / phishing)
        - LLM 完成后通过 event_bus 广播,供前端审计 trail / 二次查询消费
        - 失败静默吃掉,不影响主路径
        """
        try:
            from .llm_dimension import should_trigger_llm, enrich_with_llm
            from llm_enhancer import safe_dispatch
            if not should_trigger_llm(rule_verdict):
                return

            async def _task():
                llm_indicator = await enrich_with_llm(
                    detection_type=detection_type, target=target,
                    request=request, rule_indicators=indicators,
                    rule_verdict=rule_verdict,
                )
                if llm_indicator is None:
                    return
                # 二次聚合新 verdict
                new_verdict = aggregate_with_llm(rule_verdict, llm_indicator)
                # 广播事件,前端可监听;审计 trail 由 trace_hook 自动留痕
                try:
                    from event_bus import event_bus
                    event_bus.publish("phishing_llm_verdict", {
                        "detection_type": detection_type,
                        "target": target[:200],
                        "rule_risk_level": rule_verdict.risk_level,
                        "rule_score": rule_verdict.score,
                        "llm_risk_level": new_verdict.risk_level,
                        "llm_score": new_verdict.score,
                        "llm_indicator": llm_indicator.model_dump(),
                    })
                except Exception:
                    pass

            safe_dispatch(_task(), log_label=f"phishing:{detection_type}")
        except Exception as e:
            logger.debug(f"[LLM-Phishing] dispatch failed: {e}")

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
