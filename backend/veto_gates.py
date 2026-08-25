"""
否决闸 — Audit-LLM 程序化硬约束（不依赖 LLM）

对应修复计划 PR1:
  P0-1  ungrounded 主张不得进入 threat_detected
  P0-3  confirmed 必须绑定非 LLM 信号（Sigma / CEP / 异常 / IOC）
  P0-4  多轮禁止 OR 合并
  P0-8  逐步错误预算、早停、Reviewer 只准降级
  P0-9  默认路径 LLM hop ≤ 3
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


# ── 常量 ──

GROUNDED = "grounded"
PARTIALLY_GROUNDED = "partially_grounded"
UNGROUNDED = "ungrounded"

VERDICT_CONFIRMED = "confirmed"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_INSUFFICIENT = "insufficient_evidence"

CONCLUSION_CONFIRMED = "threat_confirmed"
CONCLUSION_SUSPICIOUS = "suspicious"
CONCLUSION_FALSE_POSITIVE = "false_positive"
CONCLUSION_INSUFFICIENT = "insufficient_evidence"

CONCLUSION_RANK = {
    CONCLUSION_FALSE_POSITIVE: 0,
    CONCLUSION_INSUFFICIENT: 1,
    CONCLUSION_SUSPICIOUS: 2,
    CONCLUSION_CONFIRMED: 3,
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

ADMITTED_VERDICTS = {GROUNDED, PARTIALLY_GROUNDED}

# 非 LLM 异常分达到该值才算"检测信号"（与 fallback_analysis 一致）
ANOMALY_SIGNAL_THRESHOLD = 0.6

# SubAuditor 平均幻觉风险超过该值 → 跳过后续推理 hop
HALLUCINATION_EARLY_STOP = 0.3
GROUNDING_EARLY_STOP = 0.5
COMPLETENESS_EARLY_STOP = 0.3

HIGH_RISK_EVENT_TYPES = {
    "C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT",
    "RANSOMWARE", "LATERAL_MOVE", "PRIV_ESC",
}


# ═══════════════════════════════════════════
# P0-1 主张剥离
# ═══════════════════════════════════════════

def strip_ungrounded_claims(
    claims: list[dict],
    claim_reports: Optional[list[Any]] = None,
) -> tuple[list[dict], list[dict]]:
    """
    将 ungrounded 主张从可投票集合中剥离。

    claim_reports: GroundingVerifier 返回的 ClaimGroundingReport 列表（按 claims 对齐）。
    无 report 时，缺少 evidence_ids 的主张视为 ungrounded。

    Returns:
        (admitted, discarded)
    """
    admitted: list[dict] = []
    discarded: list[dict] = []

    if not claims:
        return admitted, discarded

    for i, claim in enumerate(claims):
        annotated = dict(claim)
        verdict = UNGROUNDED
        score = 0.0

        if claim_reports is not None and i < len(claim_reports):
            report = claim_reports[i]
            verdict = getattr(report, "verdict", None) or report.get("verdict", UNGROUNDED)
            score = getattr(report, "grounding_score", None)
            if score is None and isinstance(report, dict):
                score = report.get("grounding_score", 0.0)
            score = float(score or 0.0)
        else:
            ev_ids = claim.get("evidence_ids") or []
            quotes = claim.get("evidence_quotes") or []
            if ev_ids and quotes:
                verdict = PARTIALLY_GROUNDED
                score = 0.5
            elif ev_ids:
                verdict = PARTIALLY_GROUNDED
                score = 0.4
            else:
                verdict = UNGROUNDED
                score = 0.0

        annotated["grounding_verdict"] = verdict
        annotated["grounding_score"] = round(score, 4)

        if verdict in ADMITTED_VERDICTS:
            admitted.append(annotated)
        else:
            discarded.append(annotated)

    return admitted, discarded


def has_admitted_threat_claims(admitted: list[dict]) -> bool:
    return any(c.get("grounding_verdict") in ADMITTED_VERDICTS for c in admitted)


# ═══════════════════════════════════════════
# P0-3 非 LLM 信号 + confirmed 闸
# ═══════════════════════════════════════════

@dataclass
class NonLlmSignals:
    sigma_hit: bool = False
    sigma_severity: str = ""
    cep_chain: bool = False
    anomaly_triggered: bool = False
    anomaly_score: float = 0.0
    ioc_hit: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def has_signal(self) -> bool:
        return bool(
            self.sigma_hit
            or self.cep_chain
            or self.anomaly_triggered
            or self.ioc_hit
        )

    def to_dict(self) -> dict:
        return {
            "sigma_hit": self.sigma_hit,
            "sigma_severity": self.sigma_severity,
            "cep_chain": self.cep_chain,
            "anomaly_triggered": self.anomaly_triggered,
            "anomaly_score": round(self.anomaly_score, 4),
            "ioc_hit": self.ioc_hit,
            "has_signal": self.has_signal,
            "reasons": self.reasons[:8],
        }


def extract_non_llm_signals(
    raw_event: Optional[dict] = None,
    tool_results: Optional[Iterable[Any]] = None,
    chain_info: str = "",
    anomaly_score: Optional[float] = None,
) -> NonLlmSignals:
    """从原始事件 / 工具结果提取非 LLM 检测信号。"""
    event = raw_event or {}
    signals = NonLlmSignals()

    sigma = event.get("_sigma") or {}
    if isinstance(sigma, dict) and sigma.get("detected"):
        signals.sigma_hit = True
        signals.sigma_severity = str(sigma.get("max_severity") or "")
        signals.reasons.append(
            f"sigma:{sigma.get('rule_count', 1)}:{','.join(sigma.get('attack_types') or [])}"
        )

    score = anomaly_score
    if score is None:
        score = event.get("_anomaly_score")
        if score is None:
            anomaly = event.get("_anomaly") or {}
            if isinstance(anomaly, dict):
                score = anomaly.get("score")
    try:
        signals.anomaly_score = float(score or 0.0)
    except (TypeError, ValueError):
        signals.anomaly_score = 0.0
    if signals.anomaly_score >= ANOMALY_SIGNAL_THRESHOLD:
        signals.anomaly_triggered = True
        signals.reasons.append(f"anomaly:{signals.anomaly_score:.2f}")

    ioc = event.get("_ioc") or event.get("_ioc_matches") or event.get("ioc_matches")
    intel = event.get("_intel") or {}
    if ioc:
        if isinstance(ioc, list) and len(ioc) > 0:
            signals.ioc_hit = True
        elif isinstance(ioc, dict) and ioc.get("matched"):
            signals.ioc_hit = True
        elif ioc is True:
            signals.ioc_hit = True
    if isinstance(intel, dict) and (intel.get("matched") or intel.get("hit")):
        signals.ioc_hit = True
    if signals.ioc_hit:
        signals.reasons.append("ioc")

    chain_text = (chain_info or "").strip()
    if chain_text and chain_text not in ("（无）", "(无)", "无"):
        signals.cep_chain = True
        signals.reasons.append("cep_chain_text")

    if tool_results:
        for r in tool_results:
            tool = getattr(r, "tool", None) or (r.get("tool") if isinstance(r, dict) else "")
            success = getattr(r, "success", True)
            if isinstance(r, dict):
                success = r.get("success", True)
            data = getattr(r, "data", None)
            if isinstance(r, dict):
                data = r.get("data")
            if not success or not data:
                continue
            if tool == "correlation.chains" and isinstance(data, list) and data:
                signals.cep_chain = True
                signals.reasons.append(f"cep_tool:{len(data)}")

    return signals


@dataclass
class ConfirmationDecision:
    threat_detected: bool
    verdict: str
    needs_human_review: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "threat_detected": self.threat_detected,
            "verdict": self.verdict,
            "needs_human_review": self.needs_human_review,
            "reason": self.reason,
        }


def apply_confirmation_gate(
    *,
    llm_threat_detected: bool,
    llm_abstain: bool = False,
    signals: Optional[NonLlmSignals] = None,
    has_admitted_claims: bool = False,
    extra_human: bool = False,
) -> ConfirmationDecision:
    """
    LLM 不得单独把事件升级为 confirmed。

    confirmed 必要条件: 非 LLM 信号 AND 至少一条 admitted claim AND LLM 未弃权。
    """
    signals = signals or NonLlmSignals()

    if llm_abstain:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_INSUFFICIENT,
            needs_human_review=True,
            reason="llm_abstain",
        )

    if not has_admitted_claims:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_INSUFFICIENT,
            needs_human_review=True,
            reason="no_grounded_claims",
        )

    if llm_threat_detected and signals.has_signal:
        return ConfirmationDecision(
            threat_detected=True,
            verdict=VERDICT_CONFIRMED,
            needs_human_review=extra_human,
            reason="grounded+non_llm_signal",
        )

    if llm_threat_detected and not signals.has_signal:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_SUSPICIOUS,
            needs_human_review=True,
            reason="llm_threat_without_detector",
        )

    if not llm_threat_detected and signals.has_signal:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_SUSPICIOUS,
            needs_human_review=True,
            reason="detector_hit_llm_cleared",
        )

    return ConfirmationDecision(
        threat_detected=False,
        verdict=VERDICT_FALSE_POSITIVE,
        needs_human_review=extra_human,
        reason="no_threat",
    )


# ═══════════════════════════════════════════
# P0-4 多轮合并（禁止 OR）
# ═══════════════════════════════════════════

def _severity_index(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


def _median_severity(severities: list[str], cap: str = "medium") -> str:
    """无证据合并时取下中位数，并封顶 cap，禁止抬到 critical。"""
    if not severities:
        return "info"
    idxs = sorted(_severity_index(s) for s in severities)
    mid = idxs[(len(idxs) - 1) // 2]
    sev = SEVERITY_ORDER[mid]
    if cap and _severity_index(sev) > _severity_index(cap):
        return cap
    return sev


def merge_audit_rounds(
    all_rounds: list[dict],
    signals: Optional[NonLlmSignals] = None,
) -> dict:
    """
    多轮合并：禁止"任意一轮发现威胁 → 最终有威胁"。

    confirmed 当且仅当:
      至少一轮 threat_detected（已经过单轮闸）且 has_non_llm_signal。
    单轮 LLM 喊威胁、无检测信号 → suspicious + 人审。
    severity: 有 confirmed 轮取其中最高；否则取中位数，禁止无证据抬到 critical。
    """
    if not all_rounds:
        return {
            "threat_detected": False,
            "verdict": VERDICT_INSUFFICIENT,
            "confidence": 0.0,
            "severity": "info",
            "needs_human": False,
            "total_rounds": 0,
            "all_missed_count": 0,
            "confirming_rounds": 0,
        }

    signals = signals or NonLlmSignals()
    # 单轮闸可能已把 CEP/工具信号写进 audit.non_llm_signal；合并时并入，避免只看原始日志漏掉链检测
    if any((r.get("audit") or {}).get("non_llm_signal") for r in all_rounds):
        signals = NonLlmSignals(
            sigma_hit=signals.sigma_hit,
            sigma_severity=signals.sigma_severity,
            cep_chain=True,
            anomaly_triggered=signals.anomaly_triggered,
            anomaly_score=signals.anomaly_score,
            ioc_hit=signals.ioc_hit,
            reasons=list(signals.reasons) + ["round_non_llm_signal"],
        )

    threat_rounds = [
        r for r in all_rounds
        if (r.get("audit") or {}).get("threat_detected")
        or (r.get("audit") or {}).get("verdict") == VERDICT_CONFIRMED
    ]
    verdicts = [
        (r.get("audit") or {}).get("verdict")
        or ((r.get("verdict") or {}).get("conclusion") if isinstance(r.get("verdict"), dict) else None)
        for r in all_rounds
    ]
    confirming = len(threat_rounds)

    weights = [0.6, 0.3, 0.1]
    total_weight = 0.0
    weighted_conf = 0.0
    for i, r in enumerate(all_rounds):
        w = weights[i] if i < len(weights) else 0.05
        weighted_conf += float((r.get("audit") or {}).get("confidence") or 0) * w
        total_weight += w
    confidence = weighted_conf / total_weight if total_weight > 0 else 0.0

    needs_human = any(
        (r.get("audit") or {}).get("needs_human_review")
        for r in all_rounds
    )

    seen_descriptions: set[str] = set()
    all_missed: list = []
    for r in all_rounds:
        for mt in r.get("missed_threats") or []:
            if not isinstance(mt, dict):
                continue
            if not missed_threat_is_actionable(mt):
                continue
            desc = mt.get("description", "")
            if desc and desc not in seen_descriptions:
                seen_descriptions.add(desc)
                all_missed.append(mt)

    # 核心：无非 LLM 信号不得 confirmed，即使多轮 LLM 一致
    if confirming >= 1 and signals.has_signal:
        verdict = VERDICT_CONFIRMED
        threat_detected = True
        sev_pool = [
            (r.get("audit") or {}).get("severity", "info")
            for r in threat_rounds
        ]
        severity = max(sev_pool, key=_severity_index) if sev_pool else "info"
    elif confirming >= 1 and not signals.has_signal:
        verdict = VERDICT_SUSPICIOUS
        threat_detected = False
        needs_human = True
        severity = _median_severity([
            (r.get("audit") or {}).get("severity", "info") for r in all_rounds
        ], cap="medium")
    elif VERDICT_SUSPICIOUS in verdicts or any(
        (r.get("audit") or {}).get("verdict") == VERDICT_SUSPICIOUS for r in all_rounds
    ):
        verdict = VERDICT_SUSPICIOUS
        threat_detected = False
        needs_human = True
        severity = _median_severity([
            (r.get("audit") or {}).get("severity", "info") for r in all_rounds
        ], cap="medium")
    else:
        verdict = VERDICT_FALSE_POSITIVE
        threat_detected = False
        severity = _median_severity([
            (r.get("audit") or {}).get("severity", "info") for r in all_rounds
        ], cap="medium")

    return {
        "threat_detected": threat_detected,
        "verdict": verdict,
        "confidence": round(min(confidence, 1.0), 4),
        "severity": severity,
        "needs_human": needs_human,
        "total_rounds": len(all_rounds),
        "all_missed_count": len(all_missed),
        "confirming_rounds": confirming,
    }


# ═══════════════════════════════════════════
# P0-8 逐步错误预算 / 早停 / Reviewer 只准降级
# ═══════════════════════════════════════════

@dataclass
class HopStats:
    avg_hallucination_risk: float = 0.0
    evidence_completeness: float = 1.0
    avg_grounding: float = 1.0
    admitted_claims: int = 0
    discarded_claims: int = 0

    @property
    def skip_reasoning(self) -> bool:
        return (
            self.avg_hallucination_risk > HALLUCINATION_EARLY_STOP
            or self.avg_grounding < GROUNDING_EARLY_STOP
            or self.evidence_completeness < COMPLETENESS_EARLY_STOP
        )


def hop_stats_from_verdicts(verdicts: list[Any]) -> HopStats:
    if not verdicts:
        return HopStats()

    risks = []
    grounds = []
    admitted = 0
    discarded = 0
    valid = 0
    total = 0
    for v in verdicts:
        risks.append(float(getattr(v, "hallucination_risk", 0.0) or 0.0))
        grounds.append(float(getattr(v, "grounding_score", 1.0) or 1.0))
        claims = getattr(v, "threat_claims", None) or []
        dumped = getattr(v, "discarded_claims", None) or []
        admitted += len(claims)
        discarded += len(dumped)
        total += len(claims) + len(dumped)
        valid += len(claims)

    n = len(verdicts)
    return HopStats(
        avg_hallucination_risk=sum(risks) / n,
        evidence_completeness=(valid / total) if total else 1.0,
        avg_grounding=sum(grounds) / n,
        admitted_claims=admitted,
        discarded_claims=discarded,
    )


def should_skip_reasoning_hops(stats: HopStats) -> bool:
    return stats.skip_reasoning


def executor_conclusion_floor(
    *,
    threat_detected: bool,
    verdict: str,
    needs_human_review: bool,
) -> str:
    """Executor 结论映射到 Reviewer conclusion 上限。"""
    if verdict == VERDICT_CONFIRMED or (threat_detected and verdict != VERDICT_SUSPICIOUS):
        return CONCLUSION_CONFIRMED
    if verdict == VERDICT_INSUFFICIENT:
        return CONCLUSION_INSUFFICIENT
    if verdict == VERDICT_SUSPICIOUS or needs_human_review:
        return CONCLUSION_SUSPICIOUS
    return CONCLUSION_FALSE_POSITIVE


def clamp_reviewer_conclusion(
    executor_level: str,
    reviewer_conclusion: str,
) -> str:
    """Reviewer 只准降级，禁止升级。"""
    if reviewer_conclusion not in CONCLUSION_RANK:
        reviewer_conclusion = CONCLUSION_SUSPICIOUS
    if executor_level not in CONCLUSION_RANK:
        executor_level = CONCLUSION_SUSPICIOUS
    if CONCLUSION_RANK[reviewer_conclusion] > CONCLUSION_RANK[executor_level]:
        return executor_level
    return reviewer_conclusion


def missed_threat_is_actionable(missed: dict) -> bool:
    """
    复核"新发现"必须自带可核验证据，否则视为幻觉，不触发补审轮。
    """
    if not isinstance(missed, dict):
        return False
    evidence = str(missed.get("evidence") or "")
    evidence_ids = missed.get("evidence_ids") or []
    if evidence_ids:
        return True
    # 证据字段里至少要有一个数字 ID
    return any(part.strip().isdigit() for part in evidence.replace("，", ",").split(","))


def filter_missed_threats(missed: list) -> list:
    return [m for m in (missed or []) if missed_threat_is_actionable(m)]


def should_run_llm_reviewer(depth: str) -> bool:
    """P0-9: 仅 deep 走 LLM 复核；quick/standard 确定性映射，不增加 hop。"""
    return (depth or "") == "deep"


def should_run_deep_llm_hops(depth: str, skip_reasoning: bool) -> bool:
    """deep_analyze / recheck / EvidenceVerifier LLM 仅在 deep 且未早停时运行。"""
    return (depth or "") == "deep" and not skip_reasoning
