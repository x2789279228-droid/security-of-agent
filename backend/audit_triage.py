"""
审计分流 (Audit Triage) — LLM 通道优先级与车道

设计目标:
  - 规则/特征(L0) + 统计/关联(L1) 先分流
  - LLM Agent 只审「该审」的事件; 高压时降 hop, 不关死通道
  - 废除全局 budget 一刀切: P0 始终可走最小 LLM hop

车道 (lane) 2026-q3:
  llm_agent    — Temporal 多 Agent（仅真 P0）
  llm_single   — 本进程 1 次 LLM，不走 Temporal
  tools_only   — 规则+sigma 收口，0 LLM
  rule_close   — 噪声关闭，0 LLM
  manual_review— 占位，本轮走 fallback
旧名兼容: llm_deep→agent, llm_standard/llm_light→single
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

LANE_LLM_AGENT = "llm_agent"
LANE_LLM_SINGLE = "llm_single"
LANE_LLM_DEEP = "llm_deep"          # 旧名, needs_llm/uses_temporal 仍识别
LANE_LLM_STANDARD = "llm_standard"  # 旧名 → single
LANE_LLM_LIGHT = "llm_light"        # 旧名 → single
LANE_TOOLS_ONLY = "tools_only"
LANE_RULE_CLOSE = "rule_close"
LANE_MANUAL_REVIEW = "manual_review"

AGENT_LANES = frozenset({LANE_LLM_AGENT, LANE_LLM_DEEP})
SINGLE_LANES = frozenset({LANE_LLM_SINGLE, LANE_LLM_STANDARD, LANE_LLM_LIGHT})
LLM_LANES = AGENT_LANES | SINGLE_LANES

VOLUMETRIC_EVENT_TYPES = frozenset({
    "DDOS_TRAFFIC", "DDOS", "PORT_SCAN", "SYN_FLOOD", "FLOOD", "HTTP_FLOOD",
})


@dataclass
class TriageResult:
    priority: int = 50          # 0-100, 越高越优先
    tier: str = "P2"            # P0|P1|P2|P3
    lane: str = LANE_LLM_LIGHT
    fused_conf: float = 0.0
    reasons: list[str] = field(default_factory=list)
    skip_llm: bool = False      # True → tools_only/rule_close/cache
    force_depth: str = ""       # quick|standard|deep 覆盖 decomposer
    fastpath_demoted: bool = False
    strong_count: int = 0
    signals_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "tier": self.tier,
            "lane": self.lane,
            "fused_conf": round(self.fused_conf, 4),
            "reasons": self.reasons[:12],
            "skip_llm": self.skip_llm,
            "force_depth": self.force_depth,
            "fastpath_demoted": self.fastpath_demoted,
            "strong_count": self.strong_count,
            "signals": self.signals_summary,
        }


def _fused_confidence(log_data: dict, anomaly_score: float) -> float:
    """与 FastPath 同源的融合置信度。"""
    sigma = log_data.get("_sigma") or {}
    sigma_conf_map = {"high": 0.85, "medium": 0.65, "low": 0.45}
    sigma_conf = 0.0
    for hit in (sigma.get("hits") or []):
        if isinstance(hit, dict):
            sigma_conf = max(
                sigma_conf,
                sigma_conf_map.get(str(hit.get("confidence") or "").lower(), 0.5),
            )
    if sigma.get("detected") and str(sigma.get("max_severity") or "").lower() == "critical":
        sigma_conf = max(sigma_conf, 0.85)
    evt_conf = log_data.get("confidence", 0)
    try:
        evt_f = float(evt_conf)
        if evt_f > 1:
            evt_f = evt_f / 100.0
    except (TypeError, ValueError):
        evt_f = 0.0
    return min(1.0, max(float(anomaly_score or 0) * 1.2, sigma_conf, evt_f))


def score_event(
    log_data: dict,
    anomaly_score: float = 0.0,
    *,
    fastpath_strong: bool = False,
    asset_criticality: str = "",
) -> TriageResult:
    """根据非 LLM 信号计算优先级与默认车道。"""
    from veto_gates import (
        extract_non_llm_signals,
        HIGH_RISK_EVENT_TYPES,
        TYPE_SIGNAL_EVENTS,
    )

    severity = str(log_data.get("severity") or "info").lower()
    event_type = str(
        log_data.get("threat_type")
        or log_data.get("event")
        or log_data.get("type")
        or "UNKNOWN"
    ).upper()
    sigma = log_data.get("_sigma") or {}
    sigma_hit = bool(sigma.get("detected"))
    sigma_sev = str(sigma.get("max_severity") or "").lower()
    signals = extract_non_llm_signals(log_data, anomaly_score=anomaly_score)
    fused = _fused_confidence(log_data, anomaly_score)
    reasons: list[str] = []

    # ── 打分 ──
    priority = 20
    if severity == "critical":
        priority += 35
        reasons.append("sev:critical")
    elif severity == "high":
        priority += 25
        reasons.append("sev:high")
    elif severity == "medium":
        priority += 12
        reasons.append("sev:medium")

    if sigma_hit and sigma_sev == "critical":
        priority += 40
        reasons.append("sigma:critical")
    elif sigma_hit:
        priority += 20
        reasons.append(f"sigma:{sigma_sev or 'hit'}")

    if anomaly_score >= 0.7:
        priority += 25
        reasons.append(f"anomaly:{anomaly_score:.2f}")
    elif anomaly_score >= 0.5:
        priority += 15
        reasons.append(f"anomaly:{anomaly_score:.2f}")
    elif anomaly_score >= 0.3:
        priority += 8

    if signals.has_signal:
        priority += 15
        reasons.append("non_llm_signal")
    if event_type in HIGH_RISK_EVENT_TYPES or event_type in TYPE_SIGNAL_EVENTS:
        priority += 10
        reasons.append(f"type:{event_type}")

    if fused >= 0.85:
        priority += 15
        reasons.append(f"fused:{fused:.2f}")
    elif fused >= 0.7:
        priority += 8

    crit = str(asset_criticality or "").lower()
    if crit in ("critical", "high"):
        priority += 12
        reasons.append(f"asset:{crit}")

    if fastpath_strong:
        reasons.append("fastpath_strong")

    priority = max(0, min(100, priority))

    sigma_critical = sigma_hit and sigma_sev == "critical"
    ioc_hit = bool(getattr(signals, "ioc_hit", False))
    volumetric = event_type in VOLUMETRIC_EVENT_TYPES
    high_risk_type = event_type in HIGH_RISK_EVENT_TYPES

    strong = []
    if sigma_critical:
        strong.append("sigma_critical")
    if fused >= 0.85:
        strong.append("fused_high")
    if high_risk_type:
        strong.append("high_risk_type")
    if ioc_hit:
        strong.append("ioc")
    strong_count = len(strong)
    if strong:
        reasons.append(f"strong:{strong_count}:{','.join(strong)}")

    # ── 分档 / 默认车道（P0 必须 ≥2 强信号；流量型默认不进 LLM）──
    skip_vol = True
    try:
        from config import settings as _st
        skip_vol = bool(getattr(_st, "audit_volumetric_skip_llm", True))
    except Exception:
        skip_vol = True
    if volumetric and skip_vol and not sigma_critical:
        tier, lane, depth = "P2", LANE_TOOLS_ONLY, "quick"
        reasons.append("rule_fast:volumetric")
    elif strong_count >= 2:
        tier, lane, depth = "P0", LANE_LLM_AGENT, "deep"
    elif (not volumetric) and (sigma_hit or high_risk_type or severity == "critical"):
        tier, lane, depth = "P1", LANE_LLM_SINGLE, "quick"
    elif severity == "medium" or anomaly_score >= 0.3 or volumetric:
        tier, lane, depth = "P2", LANE_TOOLS_ONLY, "quick"
    else:
        tier, lane, depth = "P3", LANE_RULE_CLOSE, "quick"

    fastpath_demoted = False
    if fastpath_strong:
        keep_agent = sigma_critical or fused >= 0.9
        if not keep_agent:
            lane = LANE_TOOLS_ONLY
            depth = "quick"
            fastpath_demoted = True
            if tier in ("P0", "P1"):
                tier = "P2"
            reasons.append("demote:fastpath_replay")

    skip_llm = lane in (LANE_TOOLS_ONLY, LANE_RULE_CLOSE, LANE_MANUAL_REVIEW)
    if skip_llm:
        reasons.append(f"lane:{lane}")

    return TriageResult(
        priority=priority,
        tier=tier,
        lane=lane,
        fused_conf=fused,
        reasons=reasons,
        skip_llm=skip_llm,
        force_depth=depth,
        fastpath_demoted=fastpath_demoted,
        strong_count=strong_count,
        signals_summary=signals.to_dict(),
    )


def budget_water_level(usage_pct: float, soft_pct: float = 70.0, hard_pct: float = 95.0) -> str:
    """返回 normal | soft | hard。"""
    if usage_pct >= hard_pct:
        return "hard"
    if usage_pct >= soft_pct:
        return "soft"
    return "normal"


def admit(
    triage: TriageResult,
    *,
    usage_pct: float = 0.0,
    over_budget: bool = False,
    soft_pct: float = 70.0,
    hard_pct: float = 95.0,
    inflight_full: bool = False,
) -> TriageResult:
    """按预算水位与 inflight 调整车道 — 永不对 P0 关死 LLM。"""
    water = "hard" if over_budget else budget_water_level(usage_pct, soft_pct, hard_pct)
    out = TriageResult(
        priority=triage.priority,
        tier=triage.tier,
        lane=triage.lane,
        fused_conf=triage.fused_conf,
        reasons=list(triage.reasons),
        skip_llm=triage.skip_llm,
        force_depth=triage.force_depth,
        fastpath_demoted=triage.fastpath_demoted,
        signals_summary=dict(triage.signals_summary or {}),
    )

    if water == "normal" and not inflight_full:
        return out

    if water == "soft":
        # llm_single 保持; 仅 P3 关闭; 旧 llm_light 若仍出现也保持 single
        if out.tier == "P3":
            out.lane = LANE_RULE_CLOSE
            out.skip_llm = True
            out.reasons.append("admit:soft_budget→rule_close")
        return out

    # hard / over_budget: P0 最小 1 hop (llm_single), 不再占 4 层 Agent
    if out.tier == "P0":
        out.lane = LANE_LLM_SINGLE
        out.skip_llm = False
        out.force_depth = "quick"
        out.reasons.append("admit:hard_budget→p0_llm_single")
        out.signals_summary = {
            **(out.signals_summary or {}),
            "skip_pre_analyze": True,
        }
        return out

    if out.tier == "P1":
        out.lane = LANE_TOOLS_ONLY
        out.skip_llm = True
        out.force_depth = "quick"
        out.reasons.append("admit:hard_budget→tools_only")
        return out

    out.lane = LANE_RULE_CLOSE
    out.skip_llm = True
    out.force_depth = "quick"
    out.reasons.append("admit:hard_budget→rule_close")

    if inflight_full and out.tier in ("P0", "P1") and out.lane in LLM_LANES:
        out.reasons.append("admit:inflight_full_queue")
    elif inflight_full and out.tier in ("P2", "P3"):
        out.lane = LANE_RULE_CLOSE if out.tier == "P3" else LANE_TOOLS_ONLY
        out.skip_llm = True
        out.reasons.append("admit:inflight_full→close")

    return out


def needs_llm(lane: str) -> bool:
    return str(lane or "") in LLM_LANES


def uses_temporal(lane: str) -> bool:
    """仅 llm_agent / 旧 llm_deep 走 Temporal。"""
    return str(lane or "") in AGENT_LANES


def uses_llm_single(lane: str) -> bool:
    return str(lane or "") in SINGLE_LANES


def lane_max_rounds(lane: str, requested: int = 3) -> int:
    """按车道封顶补审轮次,避免默认 3 轮把 slot 空转完。"""
    from config import settings
    lane = str(lane or "")
    if lane in AGENT_LANES:
        cap = int(getattr(settings, "audit_max_rounds_agent", 1)
                  or getattr(settings, "audit_max_rounds_deep", 1) or 1)
    elif lane in SINGLE_LANES:
        cap = 1
    else:
        return 1
    req = int(requested or cap)
    return max(1, min(req, cap))


def lane_timeout_s(tier: str) -> float:
    from config import settings
    t = str(tier or "P2").upper()
    if t == "P0":
        return float(getattr(settings, "audit_timeout_p0_s", 90) or 90)
    if t == "P1":
        return float(getattr(settings, "audit_timeout_p1_s", 45) or 45)
    if t == "P3":
        return float(getattr(settings, "audit_timeout_p3_s", 10) or 10)
    return float(getattr(settings, "audit_timeout_p2_s", 20) or 20)


def pq_ttl_for_tier(tier: str) -> int:
    from config import settings
    t = str(tier or "P2").upper()
    if t == "P0":
        return int(getattr(settings, "audit_pq_ttl_p0_s", 3600) or 3600)
    if t == "P1":
        return int(getattr(settings, "audit_pq_ttl_p1_s", 1800) or 1800)
    if t == "P2":
        return int(getattr(settings, "audit_pq_ttl_p2_s", 300) or 300)
    return int(getattr(settings, "audit_pq_ttl_s", 900) or 900)
