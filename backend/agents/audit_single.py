"""
Audit Single — llm_single 车道: 本进程单次 LLM 快审, 不启动 Temporal 4 层 Agent。

目标 (2026-q3 审计分级 P2, R-B/R-C/R-D):
  - P1(及硬预算降级后的 P0)默认 llm_single: 恰好 1 次本进程 LLM 调用,
    **禁止** start_audit_workflow; 4 层 Agent(Temporal)只留给真 llm_agent 车道。
  - LLM 槽位经 llm_limiter 门禁: LLMClient.chat 内部按 trace 上下文 tier
    (set_trace_context(tier=...)) 获取, 与 decomposer/executor 同一闸, 不叠两层 acquire。
  - 整体超时: run(timeout_s) → asyncio.wait_for, 由调用方
    settings.audit_llm_single_timeout_s(默认 15s) 驱动; 超时/降级/解析失败
    一律返回 {"fallback": True, ...} 由 _audit_pipeline 收口到 _fallback_analysis。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 与 log_ingestion.AUDIT_PROMPT_VERSION 区分: 本模块用独立快审 prompt 版本
AUDIT_SINGLE_PROMPT_VERSION = "audit_single-v1.0.0"

_SYSTEM_PROMPT = (
    "你是安全运营中心的资深审计员。对给定的一条安全事件做单次判定, 不要调用任何工具。\n"
    "只依据事件本身、Sigma 命中与统计异常信号; 不要脑补事件之外的攻击链。\n"
    "最后必须输出一个 JSON 对象(不要 Markdown 代码块包裹, 不要输出 JSON 之外的文字), 字段:\n"
    '{"threat_detected": true/false, "confidence": 0-1, '
    '"severity": "critical|high|medium|low|info", '
    '"verdict": "confirmed|suspicious|benign", "summary": "≤120字中文结论"}'
)

_VALID_VERDICTS = frozenset({"confirmed", "suspicious", "benign"})
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        try:
            return json.dumps(v, ensure_ascii=False)[:300]
        except Exception:
            return str(v)[:300]
    return str(v)


def _sigma_summary(log_data: dict) -> str:
    sigma = log_data.get("_sigma") or {}
    if not sigma.get("detected"):
        return "无"
    parts = []
    hits = sigma.get("hits") or []
    for h in hits[:5]:
        if isinstance(h, dict):
            rid = h.get("rule_id") or h.get("rule") or h.get("title") or ""
            conf = h.get("confidence") or ""
            parts.append(f"{rid}({conf})" if conf else _fmt(rid))
        else:
            parts.append(_fmt(h))
    return "命中规则: " + ", ".join(parts) if parts else (
        f"detected sev={sigma.get('max_severity') or ''}"
    )


def _build_messages(log_data: dict, anomaly_report: Any) -> list[dict]:
    """构造 SHORT system+user prompt — 事件摘要, 不塞全文。

    message[:500] 经 memory_guard 消毒; src/dst/sigma/anomaly 均为结构化字段。
    """
    sev = log_data.get("severity") or "info"
    evt = (
        log_data.get("threat_type")
        or log_data.get("event")
        or log_data.get("type")
        or "UNKNOWN"
    )
    anom_score = getattr(anomaly_report, "anomaly_score", 0) or 0
    try:
        anom_score = float(anom_score)
    except (TypeError, ValueError):
        anom_score = 0.0
    anom_reasons = list(getattr(anomaly_report, "reasons", None) or [])[:3]

    try:
        from memory_guard import sanitize_untrusted_text
        msg = sanitize_untrusted_text(str(log_data.get("message") or ""), max_len=500)
    except Exception:
        msg = str(log_data.get("message") or "")[:500]

    lines = [
        "请判定以下安全事件是否为真实威胁(单次快审):",
        f"- 事件类型: {evt}",
        f"- 严重级别: {sev}",
        f"- 源 IP: {log_data.get('src_ip') or '-'}  目标 IP: {log_data.get('dst_ip') or '-'}",
        f"- 协议: {log_data.get('protocol') or '-'}  HTTP: {log_data.get('method') or '-'} {log_data.get('status') or '-'}",
        f"- Sigma: {_sigma_summary(log_data)}",
        f"- 统计异常分: {anom_score:.3f}" + (
            f" 原因: {', '.join(_fmt(r) for r in anom_reasons)}" if anom_reasons else ""
        ),
        f"- 原始消息(截断 500 字): {msg}",
        "",
        "输出 JSON: threat_detected / confidence / severity / verdict / summary。",
    ]
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]


def _norm_verdict(raw: Any, threat_detected: bool) -> str:
    s = str(raw or "").strip().lower()
    if s in _VALID_VERDICTS:
        return s
    if s in ("true_positive", "tp", "malicious", "attack", "威胁", "攻击"):
        return "confirmed"
    if s in ("false_positive", "fp", "noise", "误报", "normal", "clean"):
        return "benign"
    if s in ("insufficient_evidence", "uncertain", "unknown", "需要复核"):
        return "suspicious"
    return "confirmed" if threat_detected else "benign"


def _norm_severity(raw: Any, fallback: str) -> str:
    s = str(raw or "").strip().lower()
    if s in _VALID_SEVERITIES:
        return s
    return str(fallback or "info").lower()


def _norm_confidence(raw: Any) -> float:
    try:
        c = float(raw)
    except (TypeError, ValueError):
        c = 0.0
    return max(0.0, min(1.0, c))


def _parse_threat_detected(raw: Any, verdict: str) -> bool:
    if isinstance(raw, str):
        td = raw.strip().lower() in ("true", "1", "yes", "y", "confirmed", "suspicious")
    else:
        td = bool(raw)
    # verdict 与 threat_detected 矛盾时以 verdict 为准(benign ⇒ 非威胁; confirmed ⇒ 威胁)
    if verdict == "benign":
        return False
    if verdict == "confirmed":
        return True
    return td


def _compose_payload(
    data: dict, log_data: dict, anomaly_report: Any, duration_s: float
) -> dict:
    verdict = _norm_verdict(data.get("verdict"), bool(data.get("threat_detected")))
    threat_detected = _parse_threat_detected(data.get("threat_detected"), verdict)
    sev = _norm_severity(data.get("severity"), log_data.get("severity") or "info")
    conf = _norm_confidence(data.get("confidence"))
    summary = _fmt(data.get("summary")).strip() or (
        "单次快审: 未给出文本结论"
    )
    sigma = log_data.get("_sigma") or {}
    evidence_trail = [
        {
            "claim": f"llm_single:{t}",
            "type": str(t),
            "confidence": conf,
            "evidence_ids": [],
            "severity": sev,
            "round": 0,
        }
        for t in (sigma.get("attack_types") or [])[:5]
    ]
    return {
        "prompt_version": AUDIT_SINGLE_PROMPT_VERSION,
        "status": "completed",
        "quality": "llm",
        "lane": "llm_single",
        "completed_by": "audit_single",
        "threat_detected": threat_detected,
        "confidence": conf,
        "severity": sev,
        "verdict": verdict,
        "summary": summary[:300],
        "reviewer": {
            "conclusion": verdict,
            "agent": "audit_single",
            "notes": "llm_single 本进程单次快审, 未走 Temporal 4 层 Agent",
        },
        "evidence_trail": evidence_trail,
        "duration_s": round(duration_s, 2),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def _fallback_payload(reason: str, err_detail: str = "") -> dict:
    return {
        "fallback": True,
        "status": "failed",
        "quality": "fallback",
        "lane": "llm_single",
        "error": reason,
        "reason": reason,
        "detail": _fmt(err_detail)[:300],
    }


async def run(
    event_id: int,
    session_id: str,
    log_data: dict,
    anomaly_report: Any,
    timeout_s: float = 15,
) -> dict:
    """本进程单次 LLM 快审 (llm_single 车道)。

    Returns:
        dict — 成功: 可直接写入 raw_data._audit_llm 的 payload
              (status=completed, quality=llm, lane=llm_single);
              失败/超时/解析失败/LLM 降级: {"fallback": True, "error": ..., "status": "failed"}
    禁止: 启动 Temporal workflow、任何第二轮 LLM。
    """
    from agents.llm_fallback import is_llm_fallback, parse_llm_json
    from summary_compression import summary
    from trace_hook import clear_trace_context, set_trace_context

    triage = (
        log_data.get("_audit_triage") or {}
        if isinstance(log_data, dict)
        else {}
    )
    tier = str(triage.get("tier") or "P1")
    to = max(0.05, float(timeout_s or 15))
    messages = _build_messages(log_data, anomaly_report)
    set_trace_context(
        caller="audit_single",
        operation="llm_single",
        event_id=int(event_id or 0),
        session_id=str(session_id or ""),
        tier=tier,
    )
    t0 = time.time()
    try:
        # LLMClient.chat 内部经 get_llm_limiter().acquire(tier=<ctx.tier>) 门禁;
        # 这里不再外层叠 acquire, 避免同闸双重占用(并发打满时互相等死)。
        raw = await asyncio.wait_for(
            summary.llm.chat(messages, temperature=0.1),
            timeout=to,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[Audit-Single] LLM timeout after %.1fs for event #%s tier=%s",
            to, event_id, tier,
        )
        return _fallback_payload("audit_single_timeout", f"timeout_s={to}")
    except Exception as e:
        logger.warning(
            "[Audit-Single] LLM call failed for event #%s tier=%s: %s",
            event_id, tier, e,
        )
        return _fallback_payload("audit_single_llm_error", str(e))
    finally:
        clear_trace_context()

    duration_s = time.time() - t0
    fb, fb_reason = is_llm_fallback(raw)
    if fb:
        logger.warning(
            "[Audit-Single] LLM degraded (fallback=%s) for event #%s",
            fb_reason, event_id,
        )
        return _fallback_payload(f"audit_single_fallback:{fb_reason}", raw)

    data = parse_llm_json(raw)
    if not isinstance(data, dict):
        logger.warning(
            "[Audit-Single] LLM JSON parse failed for event #%s", event_id,
        )
        return _fallback_payload("audit_single_parse_error", str(raw)[:200])

    logger.info(
        "[Audit-Single] event #%s tier=%s verdict=%s threat=%s conf=%.2f (%.1fs)",
        event_id, tier,
        _norm_verdict(data.get("verdict"), bool(data.get("threat_detected"))),
        bool(data.get("threat_detected")), _norm_confidence(data.get("confidence")),
        duration_s,
    )
    return _compose_payload(data, log_data, anomaly_report, duration_s)
