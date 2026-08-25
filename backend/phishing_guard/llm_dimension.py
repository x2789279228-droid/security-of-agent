"""
钓鱼大模型 (LLM Dimension) — P0.S

职责:
  在规则检测之后,LLM 用语义理解能力做"规则不能做的判定":
    - 仿冒品牌语义识别 (paypa1 vs paypal 规则抓不到)
    - 上下文诈骗意图推断 (正常业务告警 vs 社工)
    - 中英文混排绕过 ( urg3nt verify your account 这类 l33t)
    - BEC 高管语调识别 (CEO 紧急打款要求)

您选定的覆盖范围: 全部规则检测后的非 safe verdict (80% 覆盖)

性能保障:
  - API 用户立即拿规则 verdict (< 5ms),LLM 异步广播
  - 单次成本 0.1¥,日预算 75¥ → 750 次/日
  - 5 并发上限
  - 失败/降级 → 0 指标 → 不影响 aggregate() 重算结果

调用方式:
    from phishing_guard.llm_dimension import enrich_with_llm
    verdict = await enrich_with_llm(
        detection_type="email", target="...",
        request=EmailPhishingRequest(...),
        rule_indicators=[...],
    )
"""
import logging
from typing import Optional

from .models import (
    PhishingIndicator, PhishingVerdict,
    EmailPhishingRequest, WebPhishingRequest, DomainPhishingRequest,
    AttachmentPhishingRequest, SmsPhishingRequest,
    QrCodePhishingRequest, BecPhishingRequest,
)

logger = logging.getLogger(__name__)


# ── 触发阈值 (规则 verdict 等级决定是否调 LLM) ──
# 您选: 全部规则非 safe 都调 (80% 覆盖,成本 +2400¥/月)
# safe (score<30) 不调; suspicious(30-70) / phishing(>70) 都调
_LLM_TRIGGER_LEVELS = {"suspicious", "phishing"}


def should_trigger_llm(rule_verdict: PhishingVerdict) -> bool:
    """
    规则 verdict 完成后调用:判断是否需要发起 LLM 增强.
    主路径同步调用,本函数 < 0.01ms.
    """
    from config import settings
    if not settings.llm_phishing_enabled:
        return False
    return rule_verdict.risk_level in _LLM_TRIGGER_LEVELS


# ── 各检测器输入 → 统一 LLM prompt 文本摘要 ──

def _build_request_summary(
    detection_type: str,
    request,
    rule_indicators: list[PhishingIndicator],
) -> dict:
    """
    把不同检测器请求统一成 LLM 输入摘要.
    严格截断,token < 500。
    """
    summary: dict = {"type": detection_type}

    if detection_type == "email" and isinstance(request, EmailPhishingRequest):
        summary.update({
            "sender": (request.sender or "")[:200],
            "subject": (request.subject or "")[:200],
            "body_snippet": (request.body or "")[:400],
            "urls": list(request.urls or [])[:5],
            "attachments": list(request.attachments or [])[:5],
        })
    elif detection_type == "web" and isinstance(request, WebPhishingRequest):
        summary.update({
            "url": (request.url or "")[:300],
            "page_title": (request.page_title or "")[:100],
            "content_snippet": (request.page_content or "")[:400],
        })
    elif detection_type == "domain" and isinstance(request, DomainPhishingRequest):
        summary.update({
            "domain": (request.domain or "")[:200],
            "context": (request.access_context or "")[:200],
        })
    elif detection_type == "attachment" and isinstance(request, AttachmentPhishingRequest):
        summary.update({
            "filename": (request.filename or "")[:200],
            "mime_type": (request.mime_type or "")[:100],
            "size": request.file_size,
            "has_macros": request.has_macros,
            "is_encrypted": request.is_encrypted,
        })
    elif detection_type == "sms" and isinstance(request, SmsPhishingRequest):
        summary.update({
            "sender_number": (request.sender_number or "")[:50],
            "body_snippet": (request.message_body or "")[:400],
            "urls": list(request.urls or [])[:3],
        })
    elif detection_type == "qrcode" and isinstance(request, QrCodePhishingRequest):
        summary.update({
            "decoded_url": (request.decoded_url or "")[:300],
            "brand_hint": (request.brand_hint or "")[:100],
            "source_context": (request.source_context or "")[:100],
        })
    elif detection_type == "bec" and isinstance(request, BecPhishingRequest):
        summary.update({
            "sender": (request.sender or "")[:200],
            "reply_to": (request.reply_to or "")[:200],
            "subject": (request.subject or "")[:200],
            "body_snippet": (request.body or "")[:400],
            "has_attachment": request.has_attachment,
        })

    # 规则已抓到的指标作为 LLM 参考
    summary["rule_indicators"] = [
        {"name": i.name, "category": i.category, "severity": i.severity}
        for i in (rule_indicators or [])[:10]
    ]
    summary["rule_risk_level"] = None  # 由调用方填

    return summary


# ── 主入口 (供 __init__.py 调用) ──

async def enrich_with_llm(
    *,
    detection_type: str,
    target: str,
    request,
    rule_indicators: list[PhishingIndicator],
    rule_verdict: PhishingVerdict,
) -> Optional[PhishingIndicator]:
    """
    规则 verdict 完成后前端立即拿到 verdict;
    本函数异步被调用,产出额外 0 或 1 条 LLM indicator,
    由 scoring.aggregate() 二次聚合到最终 verdict.

    Returns:
        PhishingIndicator (LLM 命中) / None (降级/未启用/超预算)
    """
    from llm_enhancer import enhance_phishing

    summary = _build_request_summary(detection_type, request, rule_indicators)
    summary["rule_risk_level"] = rule_verdict.risk_level
    summary["rule_score"] = rule_verdict.score

    # 缓存键:同一 (type + 关键字段 + 规则分数桶) 一段时间内只跑一次
    cache_key = f"phish:{detection_type}:{target[:80]}:{int(rule_verdict.score // 10)}"

    from prompts import render
    summary_rendered = _format_summary_for_prompt(summary)
    prompt_messages = [
        {"role": "system", "content": render("security/phishing_system")},
        {"role": "user", "content": render(
            "security/phishing_user",
            risk_level=rule_verdict.risk_level,
            score=rule_verdict.score,
            indicators=summary["rule_indicators"],
            det_type=detection_type,
            target=str(target)[:200],
            summary_rendered=summary_rendered,
        )},
    ]

    result = await enhance_phishing(
        cache_key=cache_key,
        prompt_messages=prompt_messages,
        budget_cost_jpy=0.1,
    )

    if result is None:
        return None

    # 字段校验
    is_phishing = bool(result.get("is_phishing", False))
    severity = result.get("severity", "medium")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "medium"
    confidence = result.get("confidence", 0.5)
    try:
        confidence = float(confidence)
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    # 规则说 safe + LLM 也说 safe → 不加 indicator (节省聚合开销)
    # 规则说 phishing + LLM 说 not phishing → 加 high indicator (反向,扣分)
    # 规则说 suspicious + LLM 说 phishing → 加 high indicator (升格)
    rule_level = rule_verdict.risk_level
    if rule_level == "safe" and not is_phishing:
        return None
    if rule_level == "phishing" and is_phishing:
        # 规则已确认,LLM 同意,补一条 llm_confirm (低分,不改变 verdict)
        return PhishingIndicator(
            name=result.get("indicator_name", "LLM 确认"),
            category="llm_semantic",
            severity="medium",
            detail=f"LLM 复核确认钓鱼:{str(result.get('detail', ''))[:300]}",
            score=20.0,
        )
    # 不一致:LLM 给反向或升格信号 → high indicator
    return PhishingIndicator(
        name=result.get("indicator_name", "LLM 语义判定"),
        category="llm_semantic",
        severity=severity,
        detail=(
            f"LLM 判定: {'钓鱼' if is_phishing else '安全'}, "
            f"置信度 {confidence:.2f}:{str(result.get('detail', ''))[:300]}"
        ),
        score=32.0 if is_phishing else 0.0,
    )


def _format_summary_for_prompt(summary: dict) -> str:
    """把摘要 dict 渲染为 prompt 文本 (token 友好)."""
    parts = []
    for k, v in summary.items():
        if k in ("rule_indicators", "rule_risk_level", "rule_score"):
            continue
        if not v:
            continue
        parts.append(f"{k}: {v}")
    return "\n".join(parts)