"""
运营闭环 — PR4

P1-2  规则 7 天 FP>15% → 降级为仅告警、禁止自动封禁
P1-5  CAD 定位流水线第一个失败 hop
P1-3  LLM Enhancer 只作附加特征，不得单独升档/响应
P1-1  知识库过期不得作为 grounding 支撑
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


FP_RATE_DOWNGRADE = 0.15
DOWNGRADE_WINDOW_DAYS = 7
DOWNGRADE_MIN_SAMPLES = 5

_BLOCKING_ACTIONS = {"block_ip", "isolate_host", "terminate_process", "rate_limit"}


# ═══════════════════════════════════════════
# P1-5 步级归因
# ═══════════════════════════════════════════

_HOP_ORDER = (
    "decomposer",
    "sub_auditor",
    "evidence_verifier",
    "deep_analyze",
    "synthesize",
    "recheck",
    "reviewer",
    "faithfulness_gate",
)


def _hop_failed(hop: dict) -> bool:
    if not isinstance(hop, dict):
        return False
    if hop.get("skip_reasoning"):
        return True
    if hop.get("failed") or hop.get("error"):
        return True
    risk = hop.get("avg_hallucination_risk")
    if risk is not None and float(risk) > 0.3:
        return True
    grounding = hop.get("avg_grounding")
    if grounding is not None and float(grounding) < 0.5:
        return True
    reason = str(hop.get("reason") or "")
    if reason in (
        "no_grounded_claims",
        "llm_threat_without_detector",
        "llm_abstain",
        "llm_feature_only",
    ):
        return True
    if hop.get("passed") is False:
        return True
    if (hop.get("discarded_claims") or 0) > 0 and hop.get("admitted_claims", 1) == 0:
        return True
    return False


def locate_first_failed_hop(audit_llm_data: Optional[dict] = None) -> dict:
    """
    从 Audit 产物里找出第一个失败 hop。
    找不到则 hop=""（整单通过或无轨迹）。
    """
    data = audit_llm_data or {}
    traces: list[dict] = []

    merged = data.get("merged") or {}
    if isinstance(merged.get("faithfulness"), dict):
        traces.append({
            "hop": "faithfulness_gate",
            "passed": merged["faithfulness"].get("passed", True),
            "reason": ",".join(merged["faithfulness"].get("reasons") or []),
        })

    for rd in data.get("rounds_detail") or []:
        if not isinstance(rd, dict):
            continue
        for h in rd.get("hop_trace") or []:
            if isinstance(h, dict):
                traces.append(h)
        audit = rd.get("audit") or {}
        if isinstance(audit, dict):
            for h in audit.get("hop_trace") or []:
                if isinstance(h, dict):
                    traces.append(h)

    for h in data.get("hop_trace") or []:
        if isinstance(h, dict):
            traces.append(h)

    grounding = data.get("grounding") or {}
    if grounding.get("schema_valid") is False:
        traces.append({"hop": "synthesize", "failed": True, "reason": "schema_invalid"})

    # 按已知顺序找第一个失败
    by_name: dict[str, dict] = {}
    ordered: list[dict] = []
    for h in traces:
        name = h.get("hop") or "unknown"
        ordered.append(h)
        by_name.setdefault(name, h)

    for name in _HOP_ORDER:
        h = by_name.get(name)
        if h and _hop_failed(h):
            return {
                "hop": name,
                "reason": h.get("reason") or _describe_fail(h),
                "detail": {k: h.get(k) for k in h if k != "detail"},
            }

    for h in ordered:
        if _hop_failed(h):
            return {
                "hop": h.get("hop") or "unknown",
                "reason": h.get("reason") or _describe_fail(h),
                "detail": h,
            }

    return {"hop": "", "reason": "", "detail": {}}


def _describe_fail(h: dict) -> str:
    if h.get("skip_reasoning"):
        return "hop_budget_early_stop"
    if h.get("avg_hallucination_risk") is not None and float(h["avg_hallucination_risk"]) > 0.3:
        return f"hallucination_risk={h['avg_hallucination_risk']}"
    if h.get("avg_grounding") is not None and float(h["avg_grounding"]) < 0.5:
        return f"grounding={h['avg_grounding']}"
    if h.get("passed") is False:
        return "gate_failed"
    return "failed"


# ═══════════════════════════════════════════
# P1-3 LLM 只作特征
# ═══════════════════════════════════════════

_LEVEL_RANK = {"safe": 0, "suspicious": 1, "phishing": 2, "malicious": 2, "threat": 2}


def clamp_llm_risk_level(rule_level: str, llm_level: str) -> str:
    """LLM 不得把规则 verdict 升到更高风险档。"""
    rule_level = (rule_level or "safe").lower()
    llm_level = (llm_level or rule_level).lower()
    if _LEVEL_RANK.get(llm_level, 0) > _LEVEL_RANK.get(rule_level, 0):
        return rule_level
    return llm_level


def llm_may_open_work_order(*, rule_hit: bool, llm_sensitive: bool) -> bool:
    """没有规则/模型主分时，LLM 不得单独开处置工单。"""
    return bool(rule_hit) and bool(llm_sensitive)


# ═══════════════════════════════════════════
# P1-1 知识新鲜度
# ═══════════════════════════════════════════

def parse_iso(ts: Any) -> Optional[datetime]:
    if ts is None or ts == "":
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, str):
        s = ts.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def kb_chunk_is_fresh(chunk: dict, now: Optional[datetime] = None) -> bool:
    """过期知识不得作为 grounding / 检索支撑。无 valid_until 视为有效。"""
    now = now or datetime.now(timezone.utc)
    until = parse_iso(chunk.get("valid_until") if isinstance(chunk, dict) else None)
    if until is not None and now > until:
        return False
    return True


def filter_fresh_chunks(chunks: list[dict], now: Optional[datetime] = None) -> list[dict]:
    return [c for c in (chunks or []) if kb_chunk_is_fresh(c, now)]


# ═══════════════════════════════════════════
# P1-2 规则降级
# ═══════════════════════════════════════════

def downgrade_response_policy(policy) -> dict:
    """就地：关闭自动执行、强制审批、去掉封禁类动作。"""
    changed = []
    if getattr(policy, "auto_execute", False):
        policy.auto_execute = False
        changed.append("auto_execute=false")
    if not getattr(policy, "require_approval", True):
        policy.require_approval = True
        changed.append("require_approval=true")
    actions = list(getattr(policy, "actions", None) or [])
    new_actions = []
    stripped = False
    for act in actions:
        name = act.get("name") if isinstance(act, dict) else str(act)
        if name in _BLOCKING_ACTIONS:
            stripped = True
            continue
        new_actions.append(act)
    if stripped or not new_actions:
        new_actions.append({"name": "alert_only", "params": {"reason": "fp_auto_downgrade"}})
        changed.append("actions=alert_only")
        policy.actions = new_actions
    return {"policy": getattr(policy, "name", ""), "changes": changed}


def apply_rule_downgrade(rule_id: str) -> dict:
    """对 Sigma（shadow）+ 响应策略执行 alert_only 降级。"""
    result = {"rule_id": rule_id, "sigma": None, "response_policy": None}

    try:
        from sigma_engine import store as sigma_store
        result["sigma"] = sigma_store.shadow(rule_id, True)
    except Exception as e:
        try:
            from sigma_detector import sigma_detector
            for r in getattr(sigma_detector, "rules", []) or []:
                if getattr(r, "rule_id", "") == rule_id:
                    r.shadow_mode = True
                    if hasattr(r, "action_recommend"):
                        r.action_recommend = "alert"
                    result["sigma"] = {"success": True, "shadow_mode": True}
                    break
        except Exception as e2:
            result["sigma"] = {"success": False, "error": f"{e}; {e2}"}

    try:
        from response_engine.response_policies import policy_engine
        p = policy_engine.get_policy(rule_id)
        if p is not None:
            result["response_policy"] = downgrade_response_policy(p)
    except Exception as e:
        result["response_policy"] = {"success": False, "error": str(e)}

    return result
