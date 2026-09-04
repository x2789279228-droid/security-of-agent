"""
审计分流 (Audit Triage) — LLM 通道优先级与车道

设计目标:
  - 规则/特征(L0) + 统计/关联(L1) 先分流
  - LLM Agent 只审「该审」的事件; 高压时降 hop, 不关死通道
  - 废除全局 budget 一刀切: P0 始终可走最小 LLM hop

车道 (lane):
  llm_deep     — 完整深度 Agent (含 reviewer/deep)
  llm_standard — SubAuditor + synthesize, 无 deep/review
  llm_light    — 轻量 LLM (quick + 限 hop)
  tools_only   — 仅工具/规则确定性结论, 不调 LLM
  rule_close   — 增强 fallback 直接收口
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

LANE_LLM_DEEP = "llm_deep"
LANE_LLM_STANDARD = "llm_standard"
LANE_LLM_LIGHT = "llm_light"
LANE_TOOLS_ONLY = "tools_only"
LANE_RULE_CLOSE = "rule_close"

LLM_LANES = frozenset({LANE_LLM_DEEP, LANE_LLM_STANDARD, LANE_LLM_LIGHT})


@dataclass
class TriageResult:
    priority: int = 50          # 0-100, 越高越优先
    tier: str = "P2"            # P0|P1|P2|P3
    lane: str = LANE_LLM_LIGHT
    fused_conf: float = 0.0
    reasons: list[str] = field(default_factory=list)
    skip_llm: bool = False      # True → tools_only/rule_close
    force_depth: str = ""       # quick|standard|deep 覆盖 decomposer
    fastpath_demoted: bool = False
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

    # ── 分档 / 默认车道 ──
    sigma_critical = sigma_hit and sigma_sev == "critical"
    if (
        sigma_critical
        or fused >= 0.85
        or (severity == "critical" and signals.has_signal)
        or (crit == "critical" and (signals.has_signal or event_type in HIGH_RISK_EVENT_TYPES))
    ):
        tier, lane, depth = "P0", LANE_LLM_DEEP, "deep"
    elif (
        severity in ("critical", "high")
        or sigma_hit
        or anomaly_score >= 0.6
        or signals.has_signal
        or fastpath_strong
        or fused >= 0.7
    ):
        tier, lane, depth = "P1", LANE_LLM_STANDARD, "standard"
    elif severity == "medium" or anomaly_score >= 0.3:
        tier, lane, depth = "P2", LANE_LLM_LIGHT, "quick"
    else:
        tier, lane, depth = "P3", LANE_TOOLS_ONLY, "quick"

    # FastPath 已强处置 → 默认降为复盘轻车道(仍可审计,少占深度槽)
    fastpath_demoted = False
    if fastpath_strong and tier in ("P1", "P2"):
        # 灰区仍升 standard; 已强封禁则 demote 到 light
        if fused < 0.85 and not sigma_critical:
            lane = LANE_LLM_LIGHT
            depth = "quick"
            fastpath_demoted = True
            reasons.append("demote:fastpath_replay")

    skip_llm = lane in (LANE_TOOLS_ONLY, LANE_RULE_CLOSE)
    if lane == LANE_TOOLS_ONLY:
        reasons.append("lane:tools_only")

    return TriageResult(
        priority=priority,
        tier=tier,
        lane=lane,
        fused_conf=fused,
        reasons=reasons,
        skip_llm=skip_llm,
        force_depth=depth,
        fastpath_demoted=fastpath_demoted,
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
        # 仅保留 deep/standard; light → tools_only
        if out.lane == LANE_LLM_LIGHT:
            out.lane = LANE_TOOLS_ONLY
            out.skip_llm = True
            out.force_depth = "quick"
            out.reasons.append("admit:soft_budget→tools_only")
        elif out.tier == "P3":
            out.lane = LANE_RULE_CLOSE
            out.skip_llm = True
            out.reasons.append("admit:soft_budget→rule_close")
        return out

    # hard / over_budget
    if out.tier == "P0":
        # 最小 hop: 仍走 LLM(deep 车道),跳过昂贵 pre-analyze; SubAuditor+synthesize 保留
        out.lane = LANE_LLM_DEEP
        out.skip_llm = False
        out.force_depth = "deep"
        out.reasons.append("admit:hard_budget→p0_min_llm")
        # 供 decomposer 跳过 _llm_pre_analyze
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
        # inflight 满时 P0/P1 由调用方入队; 此处仅标记
        out.reasons.append("admit:inflight_full_queue")
    elif inflight_full and out.tier in ("P2", "P3"):
        out.lane = LANE_RULE_CLOSE if out.tier == "P3" else LANE_TOOLS_ONLY
        out.skip_llm = True
        out.reasons.append("admit:inflight_full→close")

    return out


def needs_llm(lane: str) -> bool:
    return lane in LLM_LANES
