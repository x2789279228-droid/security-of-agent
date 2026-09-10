"""
learn_loop.propose — 证据 → 动作提议(纯函数)

把 harvest/stats/clusters/sequences 映射成 LearningAction 候选:
  {action_type, target_type, target_id, mechanism, payload, confidence, auto}

去重键 = f"{action_type}:{target_id}"; 24h 内已提议的键(existing_keys)跳过。

auto=True 白名单(apply 侧强制): draft_post_mortem / shadow_rule /
decay_baseline_entity / update_reputation_prior / persist_tuning_suggestion /
open_review_work_order。其余动作(apply_sigma_change / adjust_anomaly_threshold /
label_cluster / propose_sequence_signature)只提议, 交由人工。

LLM 门: 任何 original_conclusion 以 "llm:" 开头的证据 → auto=False,
绝不自动 shadow / apply_sigma_change。
"""
from __future__ import annotations

import logging

from learn_loop.types import AUTO_APPLY_TYPES, LLM_PREFIX

logger = logging.getLogger(__name__)


def _is_llm(payload: dict) -> bool:
    """payload 是否携带 LLM 来源结论。"""
    for key in ("original_conclusion", "conclusion", "source_conclusion"):
        v = payload.get(key)
        if isinstance(v, str) and v.startswith(LLM_PREFIX):
            return True
    return bool(payload.get("llm_sourced"))


def propose(
    harvest,
    stats,
    clusters,
    sequences,
    *,
    existing_keys: set = frozenset(),
) -> list[dict]:
    """生成去重后的动作提议列表(与 24h existing_keys 对比)。"""
    seen = set(existing_keys or ())
    actions: list[dict] = []

    def _add(action_type, target_type, target_id, mechanism, payload=None,
             confidence=0.5, auto=False):
        key = f"{action_type}:{target_id}"
        if key in seen:
            return None
        seen.add(key)
        payload = dict(payload or {})
        payload["_auto"] = bool(auto)  # 供 orchestrator 落库后按行精确过滤
        action = {
            "action_type": action_type,
            "target_type": target_type,
            "target_id": str(target_id),
            "mechanism": mechanism,
            "payload": payload,
            "confidence": round(float(confidence), 3),
            "auto": bool(auto),
        }
        actions.append(action)
        return action

    # ── 1. 已关闭但缺复盘 → 自动补复盘草稿 ──
    for c in ((harvest or {}).get("postmortem", {}) or {}).get("closed_without_pm", []):
        _add(
            "draft_post_mortem", "case", c.get("id", ""),
            "postmortem",
            payload={"case_id": c.get("id"), "case_number": c.get("case_number", "")},
            confidence=0.8, auto=True,
        )

    # ── 2. 统计建议(analyze_feedback) ──
    for s in ((stats or {}).get("suggestions", []) or []):
        stype = s.get("type")
        rid = str(s.get("rule_id") or "")
        llm = bool(_is_llm(s))
        if stype == "shadow_rule":
            if not rid:
                continue
            _add(
                "shadow_rule", "rule", rid, "degrade",
                payload={
                    "rule_id": rid, "n": s.get("n"), "fp": s.get("fp"),
                    "tp": s.get("tp"), "fp_rate": s.get("fp_rate"),
                    "lo": s.get("lo"), "llm_sourced": llm,
                    "original_conclusion": s.get("original_conclusion", ""),
                    "suggestion": s.get("suggestion", ""),
                },
                confidence=s.get("confidence", 0.7),
                auto=(not llm) and s.get("auto", True),
            )
        elif stype == "adjust_anomaly_threshold":
            _add(
                "adjust_anomaly_threshold", "rule", rid, "degrade",
                payload={"rule_id": rid, "fp": s.get("fp"), "tp": s.get("tp"),
                         "fp_rate": s.get("fp_rate"), "suggestion": s.get("suggestion", "")},
                confidence=s.get("confidence", 0.5), auto=False,
            )
        elif stype == "missed_threat":
            _add(
                "persist_tuning_suggestion", "type", "missed_threat", "tune",
                payload={"count": s.get("count"), "suggestion": s.get("suggestion", "")},
                confidence=s.get("confidence", 0.7), auto=True,
            )

    # ── 3. 信誉 / 基线(反馈驱动的 IP 证据) ──
    ip_counts = ((harvest or {}).get("reputation", {}) or {}).get("ip_counts", {}) or {}
    for ip, cnt in ip_counts.items():
        fp = int(cnt.get("fp") or 0)
        tp = int(cnt.get("tp") or 0)
        if fp > 0:
            _add(
                "decay_baseline_entity", "ip", ip, "baseline",
                payload={"entity_type": "src_ip", "entity_key": ip, "factor": 0.5,
                         "fp": fp, "tp": tp},
                confidence=min(0.9, 0.4 + 0.1 * fp), auto=True,
            )
        if tp + fp > 0:
            _add(
                "update_reputation_prior", "ip", ip, "reputation",
                payload={"target_type": "ip", "target": ip, "tp": tp, "fp": fp},
                confidence=min(0.9, 0.3 + 0.1 * (tp + fp)), auto=True,
            )

    # ── 4. feedback_loop 调优建议 → 持久化记账 ──
    for s in ((harvest or {}).get("tune", {}) or {}).get("suggestions", []) or []:
        if not isinstance(s, dict):
            continue
        rid = str(s.get("rule_id") or "")
        llm = bool(_is_llm(s))
        if rid:
            _add(
                "persist_tuning_suggestion", "rule", rid, "tune",
                payload={**s, "llm_sourced": llm},
                confidence=s.get("severity") == "critical" and 0.8 or 0.6,
                auto=not llm,
            )
        else:
            stype = str(s.get("type") or "tuning")
            _add(
                "persist_tuning_suggestion", "type", stype, "tune",
                payload={**s, "llm_sourced": llm},
                confidence=0.6, auto=not llm,
            )

    # ── 5. FP/漏报事件聚类 → 人工打标 ──
    for cl in (clusters or []):
        _add(
            "label_cluster", "cluster", cl.get("cluster_id", ""), "feedback",
            payload={
                "cluster_id": cl.get("cluster_id", ""), "size": cl.get("size"),
                "event_ids": cl.get("event_ids", [])[:50],
                "event_type": cl.get("event_type", ""), "net": cl.get("net", ""),
            },
            confidence=min(0.8, 0.3 + 0.1 * int(cl.get("size") or 0)), auto=False,
        )

    # ── 6. 攻击链序列签名(未被既有 CEP 模式覆盖的转移) ──
    for sig in ((sequences or {}).get("signatures", []) or []):
        if sig.get("duplicate"):
            continue
        pair = f"{sig.get('from')}>{sig.get('to')}"
        _add(
            "propose_sequence_signature", "event_type", pair, "case",
            payload={"from": sig.get("from"), "to": sig.get("to"),
                     "count": sig.get("count"), "p": sig.get("p"),
                     "suggestion": f"收割窗口内 {sig.get('from')}→{sig.get('to')} "
                                   f"出现 {sig.get('count')} 次(P={sig.get('p'):.0%}),建议新增 CEP 序列签名"},
            confidence=min(0.85, 0.3 + float(sig.get("p") or 0) * 0.5), auto=False,
        )

    return actions
