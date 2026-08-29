"""
审计主路径忠实度闸 — PR3 / P0-2、P0-5

每次 Audit 合并后、自动响应前：
  1. 词法支撑阈值 0.35
  2. 程序化蕴含：summary 中的 IP/CVE/ATT&CK/端口必须出现在证据里
  3. faithfulness < 0.75 或无支撑断言过多 → 强制人审、禁止 confirmed 自动响应
"""
from __future__ import annotations

from typing import Any, Optional

from eval_metrics import (
    LEXICAL_SUPPORT_THRESHOLD,
    claim_is_supported,
    context_text,
    extract_grounding_entities,
    lexical_overlap_score,
    split_claims,
)


FAITHFULNESS_THRESHOLD = 0.75
UNSUPPORTED_RATIO_THRESHOLD = 0.75  # 1 - unsupported/total 须 ≥ 0.75
BENIGN_LLM_FP_SLO = 0.05            # LLM 单独 FP ≤ 5%


def _evidence_blob(contexts: list[dict]) -> str:
    return "\n".join(context_text(c) for c in (contexts or []) if c)


def compute_faithfulness(
    answer: str,
    contexts: list[dict],
    query: str = "",
) -> dict:
    """同步忠实度计算，不落库、不调 LLM。"""
    evidence = _evidence_blob(contexts)
    claims = split_claims(answer)
    if not claims:
        # 无可检验断言：视为通过（没有胡编的句子）
        return {
            "claim_count": 0,
            "supported_count": 0,
            "unsupported_count": 0,
            "faithfulness": 1.0,
            "unsupported_claim_ratio_score": 1.0,
            "entity_entailment": 1.0,
            "entity_count": 0,
            "phantom_entities": [],
            "support_scores": [],
            "passed": True,
            "reasons": [],
        }

    support_scores = [
        lexical_overlap_score(c, evidence) if evidence else 0.0 for c in claims
    ]
    supported_flags = [claim_is_supported(c, evidence) for c in claims]
    supported_count = sum(1 for f in supported_flags if f)
    unsupported_count = len(claims) - supported_count
    faithfulness = round(supported_count / len(claims), 4)
    unsupported_score = round(1 - (unsupported_count / len(claims)), 4)

    all_ents = set()
    phantom = []
    for c in claims:
        ents = extract_grounding_entities(c)
        all_ents |= ents
        for e in ents:
            probe = e.split(":", 1)[1] if e.startswith("port:") else e
            hay = evidence.upper() if (e.startswith("CVE-") or e.startswith("T")) else evidence
            if e.startswith("port:"):
                if probe not in evidence:
                    phantom.append(e)
            elif e.startswith("CVE-") or (e.startswith("T") and len(e) >= 5):
                if e not in hay.upper():
                    phantom.append(e)
            else:
                if e not in evidence.lower():
                    phantom.append(e)
    entity_entailment = 0.0 if phantom else 1.0

    reasons = []
    passed = True
    if faithfulness < FAITHFULNESS_THRESHOLD:
        passed = False
        reasons.append(f"faithfulness={faithfulness:.2f}<{FAITHFULNESS_THRESHOLD}")
    if unsupported_score < UNSUPPORTED_RATIO_THRESHOLD:
        passed = False
        reasons.append(f"unsupported_ratio_score={unsupported_score:.2f}")
    if phantom:
        passed = False
        reasons.append(f"phantom_entities={phantom[:8]}")

    return {
        "claim_count": len(claims),
        "supported_count": supported_count,
        "unsupported_count": unsupported_count,
        "faithfulness": faithfulness,
        "unsupported_claim_ratio_score": unsupported_score,
        "entity_entailment": entity_entailment,
        "entity_count": len(all_ents),
        "phantom_entities": phantom[:12],
        "support_scores": [round(s, 4) for s in support_scores],
        "passed": passed,
        "reasons": reasons,
        "lexical_threshold": LEXICAL_SUPPORT_THRESHOLD,
    }


def has_non_llm_threat_signal(signals: Optional[dict] = None) -> bool:
    """Sigma / 异常 / 显式 admitted 等非 LLM 背书信号。"""
    if not signals:
        return False
    if signals.get("sigma_detected") or signals.get("detected"):
        return True
    if signals.get("has_admitted_claims") or signals.get("confirmation_admitted"):
        return True
    try:
        if float(signals.get("anomaly_score") or 0) >= 0.6:
            return True
    except (TypeError, ValueError):
        pass
    hits = signals.get("hits") or signals.get("sigma_hits") or []
    return bool(hits)


def apply_faithfulness_gate(
    merged: dict,
    *,
    answer: str,
    contexts: list[dict],
    query: str = "",
    abstain: bool = False,
    non_llm_signals: Optional[dict] = None,
) -> dict:
    """
    就地/返回更新 merged：
      闸失败或 abstain：
        - 无非 LLM 信号 → 硬降级（threat=False，禁自动响应，人审）
        - 有非 LLM 信号 → 软降级（保留 threat，verdict≤suspicious，强制人审）
    """
    out = dict(merged or {})
    report = compute_faithfulness(answer or "", contexts or [], query=query)
    out["faithfulness"] = report

    blocked = (not report["passed"]) or bool(abstain)
    if abstain:
        report["reasons"] = list(report["reasons"]) + ["llm_abstain"]
        report["passed"] = False
        out["faithfulness"] = report

    if blocked:
        out["needs_human"] = True
        backed = has_non_llm_threat_signal(non_llm_signals)
        if backed and (out.get("verdict") == "confirmed" or out.get("threat_detected")):
            # 规则/异常已背书：保留威胁事实，仅取消 confirmed 自动信任
            out["verdict"] = "suspicious"
            out["threat_detected"] = True
            out["response_blocked"] = False
            out["demoted_by"] = "faithfulness_gate_soft"
            report["reasons"] = list(report.get("reasons") or []) + ["soft_demote_non_llm_signal"]
            out["faithfulness"] = report
        else:
            out["response_blocked"] = True
            if out.get("verdict") == "confirmed" or out.get("threat_detected"):
                out["verdict"] = "suspicious"
                out["threat_detected"] = False
                out["demoted_by"] = "faithfulness_gate"
            if abstain and out.get("verdict") not in ("false_positive",):
                # 弃权优先于 suspicious：证据不足（仅硬降级路径）
                if not out.get("threat_detected"):
                    out["verdict"] = "insufficient_evidence"
    else:
        out.setdefault("response_blocked", False)

    return out


def contexts_from_audit(
    log_data: Optional[dict] = None,
    evidence_trail: Optional[list] = None,
    tool_preview: str = "",
) -> list[dict]:
    """把原始事件 + 证据链拼成 faithfulness 的 contexts。"""
    ctx: list[dict] = []
    event = log_data or {}
    bits = [
        str(event.get("event") or event.get("type") or ""),
        str(event.get("src_ip") or ""),
        str(event.get("dst_ip") or ""),
        str(event.get("message") or ""),
        str(event.get("severity") or ""),
        str(event.get("protocol") or ""),
    ]
    ctx.append({"content": " ".join(b for b in bits if b)})
    for item in evidence_trail or []:
        if not isinstance(item, dict):
            continue
        quotes = item.get("evidence_quotes") or []
        ctx.append({
            "content": " ".join([
                str(item.get("claim") or ""),
                str(item.get("type") or ""),
                " ".join(str(q) for q in quotes),
                " ".join(str(i) for i in (item.get("evidence_ids") or [])),
            ])
        })
    if tool_preview:
        ctx.append({"content": tool_preview[:4000]})
    return ctx


def llm_alone_false_positive_rate(decisions: list[dict]) -> float:
    """
    良性样本上，LLM 单独把事件判成 confirmed 的比例。
    SLO: ≤ BENIGN_LLM_FP_SLO (5%)。
    """
    if not decisions:
        return 0.0
    fp = sum(1 for d in decisions if d.get("verdict") == "confirmed" or d.get("threat_detected"))
    return fp / len(decisions)
