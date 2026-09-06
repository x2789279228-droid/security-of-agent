"""
Agent 思维链 — 结构化决策步骤 → SSE `agent_thought` + 内存缓冲 + 存量投影

不打开模型 thinking / reasoning_effort。只复用已有产物：
  非 LLM 信号、Decomposer 子任务、ToolBuilder 映射、SubAuditor claims、
  hop_trace、confirmation gate、Reviewer evidence_chain、CAD、响应阻断。

SSE 按阶段批量推送（每 emit_* 一条），避免打爆 event_bus 历史窗口。
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

SUMMARY_MAX = 240
TITLE_MAX = 80
QUOTE_MAX = 80
QUOTE_LIMIT = 2
MAX_EVENTS = 100
MAX_STEPS_PER_EVENT = 80
MAX_CLAIMS_PER_BATCH = 8
MAX_TOOLS_PER_BATCH = 10
MAX_RAG_PER_BATCH = 8

VALID_STAGES = frozenset({
    "ingest", "decomposer", "tool_builder", "executor",
    "reviewer", "cad_verify", "response",
})
VALID_KINDS = frozenset({
    "signal", "plan", "tool_map", "tool", "rag", "claim", "discard", "hop",
    "verdict", "gate", "review", "cad", "response",
})
VALID_STATUS = frozenset({
    "running", "success", "error", "discarded", "abstain", "blocked",
})

KIND_LABELS = {
    "signal": "检测信号",
    "plan": "审核计划",
    "tool_map": "工具映射",
    "tool": "工具调用",
    "rag": "知识片段",
    "claim": "威胁断言",
    "discard": "丢弃断言",
    "hop": "推理跳数",
    "verdict": "汇总结论",
    "gate": "确认闸门",
    "review": "复核裁决",
    "cad": "CAD 监督",
    "response": "响应",
}


def _clip(text: Any, n: int) -> str:
    s = str(text or "").strip()
    if len(s) <= n:
        return s
    return s[: max(0, n - 1)] + "…"


def _as_int_list(values: Any) -> list[int]:
    if not values:
        return []
    if not isinstance(values, (list, tuple)):
        values = [values]
    out: list[int] = []
    for item in values:
        try:
            if isinstance(item, bool):
                continue
            out.append(int(str(item).strip().lstrip("#")))
        except (TypeError, ValueError):
            continue
    return out[:12]


def _quotes(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, (list, tuple)):
        values = [values]
    out: list[str] = []
    for item in values:
        q = _clip(item, QUOTE_MAX)
        if q:
            out.append(q)
        if len(out) >= QUOTE_LIMIT:
            break
    return out


def _ctx_ids(**overrides: Any) -> dict:
    event_id = int(overrides.get("event_id") or 0)
    session_id = str(overrides.get("session_id") or "")
    trace_id = str(overrides.get("trace_id") or "")
    round_num = int(overrides.get("round") or overrides.get("round_num") or 0)
    try:
        from trace_hook import get_trace_context
        ctx = get_trace_context() or {}
        if not event_id:
            event_id = int(ctx.get("event_id") or 0)
        if not session_id:
            session_id = str(ctx.get("session_id") or "")
        if not trace_id:
            trace_id = str(ctx.get("trace_id") or "")
        if not round_num:
            round_num = int(ctx.get("round") or 0)
    except Exception:
        pass
    return {
        "event_id": event_id,
        "session_id": session_id,
        "trace_id": trace_id,
        "round": round_num or 1,
    }


def compact_step(raw: dict, *, seq: int = 0) -> Optional[dict]:
    """规范化并裁剪一条 ThoughtStep。缺 event_id 则丢弃。"""
    if not isinstance(raw, dict):
        return None
    event_id = int(raw.get("event_id") or 0)
    if not event_id:
        return None
    stage = str(raw.get("stage") or "executor")
    if stage not in VALID_STAGES:
        stage = "executor"
    kind = str(raw.get("kind") or "hop")
    if kind not in VALID_KINDS:
        kind = "hop"
    status = str(raw.get("status") or "success")
    if status not in VALID_STATUS:
        status = "success"
    round_num = int(raw.get("round") or 1)
    step_id = str(raw.get("step_id") or "").strip()
    if not step_id:
        step_id = f"e{event_id}-r{round_num}-{stage}-{kind}-{seq}"

    confidence = raw.get("confidence")
    try:
        confidence = None if confidence is None else round(float(confidence), 4)
    except (TypeError, ValueError):
        confidence = None

    metrics = raw.get("metrics") if isinstance(raw.get("metrics"), dict) else {}
    parent_ids = [str(p) for p in (raw.get("parent_ids") or []) if p][:8]
    title = _clip(raw.get("title") or KIND_LABELS.get(kind, kind), TITLE_MAX)
    summary = _clip(raw.get("summary") or "", SUMMARY_MAX)
    rag_score = raw.get("rag_score")
    try:
        rag_score = None if rag_score is None else round(float(rag_score), 4)
    except (TypeError, ValueError):
        rag_score = None
    tool_ok = raw.get("tool_ok")
    if not isinstance(tool_ok, bool):
        tool_ok = None
    signature_score = raw.get("signature_score")
    try:
        signature_score = None if signature_score is None else round(float(signature_score), 4)
    except (TypeError, ValueError):
        signature_score = None
    raw_reasons = raw.get("signature_reasons")
    signature_reasons = []
    if isinstance(raw_reasons, list):
        for item in raw_reasons[:4]:
            clipped = _clip(item, 120)
            if clipped:
                signature_reasons.append(clipped)

    return {
        "step_id": step_id[:80],
        "event_id": event_id,
        "session_id": str(raw.get("session_id") or "")[:100],
        "trace_id": str(raw.get("trace_id") or "")[:32],
        "round": round_num,
        "stage": stage,
        "kind": kind,
        "title": title,
        "summary": summary,
        "status": status,
        "confidence": confidence,
        "parent_ids": parent_ids,
        "evidence_ids": _as_int_list(raw.get("evidence_ids")),
        "evidence_quotes": _quotes(raw.get("evidence_quotes")),
        "metrics": {str(k): v for k, v in list(metrics.items())[:8]},
        "tool_name": str(raw.get("tool_name") or "")[:80],
        "tool_ok": tool_ok,
        "signature_score": signature_score,
        "signature_reasons": signature_reasons,
        "chunk_id": str(raw.get("chunk_id") or "")[:80],
        "rag_score": rag_score,
        "source": str(raw.get("source") or "")[:80],
        "ts": float(raw.get("ts") or time.time()),
    }


class ThoughtChainBuffer:
    """按 event_id 聚合的环形缓冲。"""

    def __init__(self, max_events: int = MAX_EVENTS, max_steps: int = MAX_STEPS_PER_EVENT):
        self.max_events = max_events
        self.max_steps = max_steps
        self._by_event: OrderedDict[int, list[dict]] = OrderedDict()
        self._seq: dict[int, int] = {}

    def next_seq(self, event_id: int) -> int:
        n = self._seq.get(event_id, 0) + 1
        self._seq[event_id] = n
        return n

    def add(self, step: dict) -> Optional[dict]:
        event_id = int(step.get("event_id") or 0)
        if not event_id:
            return None
        compacted = compact_step(step, seq=self.next_seq(event_id))
        if not compacted:
            return None
        if event_id in self._by_event:
            self._by_event.move_to_end(event_id)
        else:
            self._by_event[event_id] = []
            while len(self._by_event) > self.max_events:
                old_id, _ = self._by_event.popitem(last=False)
                self._seq.pop(old_id, None)
        bucket = self._by_event[event_id]
        existing = {s["step_id"] for s in bucket}
        if compacted["step_id"] in existing:
            for i, s in enumerate(bucket):
                if s["step_id"] == compacted["step_id"]:
                    bucket[i] = compacted
                    break
        else:
            bucket.append(compacted)
            if len(bucket) > self.max_steps:
                del bucket[: len(bucket) - self.max_steps]
        return compacted

    def get(self, event_id: int) -> list[dict]:
        return list(self._by_event.get(int(event_id), []))

    def clear(self, event_id: Optional[int] = None) -> None:
        if event_id is None:
            self._by_event.clear()
            self._seq.clear()
            return
        self._by_event.pop(int(event_id), None)
        self._seq.pop(int(event_id), None)


thought_buffer = ThoughtChainBuffer()


def publish_thought_batch(steps: Iterable[dict], *, stage: str = "") -> list[dict]:
    """写入缓冲并推送一条 SSE（steps 数组）。失败静默。"""
    compacted: list[dict] = []
    try:
        for raw in steps:
            item = thought_buffer.add(raw)
            if item:
                compacted.append(item)
        if not compacted:
            return []
        from event_bus import event_bus
        head = compacted[0]
        payload = {
            "event_id": head["event_id"],
            "session_id": head.get("session_id") or "",
            "trace_id": head.get("trace_id") or "",
            "stage": stage or head.get("stage") or "",
            "agent_id": stage or head.get("stage") or "",
            "round": head.get("round") or 1,
            "steps": compacted,
            "thought_count": len(compacted),
            "kind": head.get("kind"),
            "title": head.get("title"),
            "severity": "high" if any(
                s.get("status") in ("error", "discarded") for s in compacted
            ) else "info",
        }
        event_bus.publish("agent_thought", payload)
    except Exception as e:
        logger.debug(f"[thought_events] publish failed: {e}")
    return compacted


def snapshot(event_id: int) -> list[dict]:
    return thought_buffer.get(event_id)


def merge_thought_into_raw(raw: Optional[dict], steps: Iterable[dict]) -> dict:
    """把新 thought 步骤并入 raw_data._audit_llm.thought_chain(幂等 by step_id)。"""
    out = dict(raw or {})
    extra = [s for s in (steps or []) if isinstance(s, dict) and s.get("step_id")]
    if not extra:
        return out
    audit = dict(out.get("_audit_llm") or {})
    chain = list(audit.get("thought_chain") or [])
    seen = {s.get("step_id") for s in chain if isinstance(s, dict)}
    for s in extra:
        sid = s.get("step_id")
        if sid in seen:
            continue
        chain.append(s)
        seen.add(sid)
    audit["thought_chain"] = chain
    out["_audit_llm"] = audit
    return out


def attach_to_audit(audit: dict, event_id: int) -> dict:
    """把当前缓冲快照写入 `_audit_llm.thought_chain`（同进程 HTTP 路径）。"""
    steps = snapshot(event_id)
    if not steps:
        return audit
    out = dict(audit or {})
    out["thought_chain"] = steps
    return out


def _sid(ids: dict, stage: str, kind: str, slug: str = "") -> str:
    tail = f"-{slug}" if slug else ""
    return f"e{ids['event_id']}-r{ids['round']}-{stage}-{kind}{tail}"


def emit_signals(log_data: Optional[dict], **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"]:
        return []
    data = log_data or {}
    steps: list[dict] = []
    sigma = data.get("_sigma") or {}
    if sigma.get("detected") or sigma.get("hits"):
        hits = sigma.get("hits") or []
        names = []
        if isinstance(hits, list):
            for h in hits[:4]:
                if isinstance(h, dict):
                    names.append(str(h.get("name") or h.get("rule") or ""))
                else:
                    names.append(str(h))
        steps.append({
            **ids,
            "step_id": _sid(ids, "ingest", "signal", "sigma"),
            "stage": "ingest",
            "kind": "signal",
            "title": "Sigma 命中",
            "summary": "；".join(n for n in names if n) or "规则检测命中",
            "status": "success",
            "evidence_ids": [ids["event_id"]],
        })
    anomaly = data.get("_anomaly") or {}
    score = anomaly.get("score")
    if score is None:
        score = data.get("anomaly_score")
    try:
        score_f = float(score) if score is not None else None
    except (TypeError, ValueError):
        score_f = None
    if score_f is not None and score_f >= 0.4:
        reasons = anomaly.get("reasons") or []
        steps.append({
            **ids,
            "step_id": _sid(ids, "ingest", "signal", "anomaly"),
            "stage": "ingest",
            "kind": "signal",
            "title": f"异常 {score_f:.2f}",
            "summary": "；".join(str(r) for r in reasons[:3]) or "异常检测抬升",
            "status": "success",
            "confidence": min(1.0, score_f),
            "evidence_ids": [ids["event_id"]],
        })
    if data.get("_chain"):
        steps.append({
            **ids,
            "step_id": _sid(ids, "ingest", "signal", "cep"),
            "stage": "ingest",
            "kind": "signal",
            "title": "攻击链关联",
            "summary": "CEP / 关联引擎命中",
            "status": "success",
            "evidence_ids": [ids["event_id"]],
        })
    return publish_thought_batch(steps, stage="ingest")


def emit_plan(decomp_output: Optional[dict], **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"] or not isinstance(decomp_output, dict):
        return []
    sub_tasks = decomp_output.get("sub_tasks") or []
    depth = decomp_output.get("audit_depth") or decomp_output.get("depth") or ""
    names = []
    for st in sub_tasks[:8]:
        if isinstance(st, dict):
            names.append(str(st.get("type") or st.get("task_id") or ""))
        else:
            names.append(str(getattr(st, "type", "") or getattr(st, "task_id", "")))
    parent = [_sid(ids, "ingest", "signal", "sigma"),
              _sid(ids, "ingest", "signal", "anomaly"),
              _sid(ids, "ingest", "signal", "cep")]
    step = {
        **ids,
        "step_id": _sid(ids, "decomposer", "plan"),
        "stage": "decomposer",
        "kind": "plan",
        "title": f"深度 {depth or 'standard'} · {len(sub_tasks)} 子任务",
        "summary": _clip(
            decomp_output.get("depth_reason") or decomp_output.get("llm_analysis")
            or ("、".join(n for n in names if n) or "规则分解"),
            SUMMARY_MAX,
        ),
        "status": "success" if sub_tasks else "abstain",
        "parent_ids": parent,
        "metrics": {"sub_tasks": len(sub_tasks), "mode": decomp_output.get("mode") or ""},
    }
    return publish_thought_batch([step], stage="decomposer")


def emit_tool_map(sub_tasks: Any, tool_calls: Any, **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"]:
        return []
    tasks = sub_tasks or []
    calls = tool_calls or []
    mapped = []
    per_tool: list[dict] = []
    map_id = _sid(ids, "tool_builder", "tool_map")
    for i, tc in enumerate(calls[:MAX_TOOLS_PER_BATCH]):
        if hasattr(tc, "tool"):
            name = str(getattr(tc, "tool", "") or "")
            task_id = str(getattr(tc, "task_id", "") or "")
        elif isinstance(tc, dict):
            name = str(tc.get("tool") or "")
            task_id = str(tc.get("task_id") or "")
        else:
            continue
        mapped.append(f"{task_id}→{name}")
        slug = (name or task_id or str(i)).replace(".", "-")[:40]
        per_tool.append({
            **ids,
            "step_id": _sid(ids, "tool_builder", "tool", f"{slug}-{i}"),
            "stage": "tool_builder",
            "kind": "tool",
            "title": name or "tool",
            "summary": f"task={task_id}" if task_id else name,
            "status": "success",
            "parent_ids": [map_id],
            "tool_name": name,
            "tool_ok": True,
            "metrics": {"task_id": task_id},
        })
    dropped = max(0, len(tasks) - len(calls))
    overview = {
        **ids,
        "step_id": map_id,
        "stage": "tool_builder",
        "kind": "tool_map",
        "title": f"{len(calls)} 个工具" + (f" · 丢弃 {dropped}" if dropped else ""),
        "summary": "；".join(mapped) or "无工具映射",
        "status": "success" if calls else "abstain",
        "parent_ids": [_sid(ids, "decomposer", "plan")],
        "metrics": {"tools": len(calls), "dropped": dropped},
    }
    return publish_thought_batch([overview, *per_tool], stage="tool_builder")


def emit_tool_result(
    tool_name: str,
    *,
    success: bool = True,
    duration_ms: float = 0.0,
    report: Any = None,
    **ids_kw: Any,
) -> list[dict]:
    """一次实际工具执行 → kind=tool 节点，带上行为签名分数。缺 event_id 则跳过。"""
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"]:
        return []
    score = None
    reasons: list[str] = []
    is_anomaly = False
    if report is not None:
        score = getattr(report, "anomaly_score", None)
        if score is None and isinstance(report, dict):
            score = report.get("anomaly_score") or report.get("score")
        raw_reasons = getattr(report, "reasons", None)
        if raw_reasons is None and isinstance(report, dict):
            raw_reasons = report.get("reasons")
        if isinstance(raw_reasons, list):
            reasons = [str(r) for r in raw_reasons[:4] if r]
        is_anomaly = bool(getattr(report, "is_anomaly", False))
        if isinstance(report, dict):
            is_anomaly = bool(report.get("is_anomaly"))
    status = "error" if (not success or is_anomaly) else "success"
    summary = "; ".join(reasons) if reasons else (
        f"{tool_name} {'ok' if success else 'failed'} {duration_ms:.0f}ms"
    )
    step = {
        **ids,
        "step_id": _sid(ids, "executor", "tool", (tool_name or "tool").replace(".", "-")[:40]),
        "stage": "executor",
        "kind": "tool",
        "title": tool_name or "tool",
        "summary": summary,
        "status": status,
        "parent_ids": [_sid(ids, "tool_builder", "tool_map")],
        "tool_name": tool_name,
        "tool_ok": bool(success) and not is_anomaly,
        "confidence": score,
        "signature_score": score,
        "signature_reasons": reasons,
        "metrics": {
            "duration_ms": round(float(duration_ms or 0), 1),
            "signature_score": score,
            "anomaly": is_anomaly,
        },
    }
    return publish_thought_batch([step], stage="executor")


def _iter_tool_results(tool_results: Any) -> list[Any]:
    if tool_results is None:
        return []
    if hasattr(tool_results, "tool_results"):
        tool_results = tool_results.tool_results
    if not isinstance(tool_results, (list, tuple)):
        return []
    return list(tool_results)


def emit_rag_chunks(tool_results: Any, **ids_kw: Any) -> list[dict]:
    """knowledge.search 命中的每个 chunk → rag 节点。parent 为对应 tool 步。"""
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"]:
        return []
    steps: list[dict] = []
    n = 0
    for tr in _iter_tool_results(tool_results):
        if hasattr(tr, "tool"):
            tool = str(getattr(tr, "tool", "") or "")
            ok = bool(getattr(tr, "success", True))
            data = getattr(tr, "data", None)
            task_id = str(getattr(tr, "task_id", "") or "")
        elif isinstance(tr, dict):
            tool = str(tr.get("tool") or "")
            ok = bool(tr.get("success", True))
            data = tr.get("data")
            task_id = str(tr.get("task_id") or "")
        else:
            continue
        if tool != "knowledge.search" or not ok or not isinstance(data, list):
            continue
        tool_slug = "knowledge-search"
        tool_parent = None
        for existing in thought_buffer.get(ids["event_id"]):
            if existing.get("kind") == "tool" and existing.get("tool_name") == "knowledge.search":
                tool_parent = existing["step_id"]
                break
        if not tool_parent:
            tool_parent = _sid(ids, "tool_builder", "tool", f"{tool_slug}-0")
        for chunk in data:
            if n >= MAX_RAG_PER_BATCH:
                break
            if not isinstance(chunk, dict):
                continue
            cid = str(chunk.get("id") or chunk.get("chunk_id") or n)
            score = chunk.get("score")
            try:
                score_f = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_f = None
            title = str(chunk.get("title") or f"chunk {cid}")
            steps.append({
                **ids,
                "step_id": _sid(ids, "tool_builder", "rag", str(cid)[:24]),
                "stage": "tool_builder",
                "kind": "rag",
                "title": title[:TITLE_MAX],
                "summary": _clip(chunk.get("content") or "", SUMMARY_MAX),
                "status": "success",
                "parent_ids": [tool_parent],
                "chunk_id": cid,
                "rag_score": score_f,
                "source": str(chunk.get("source") or ""),
                "evidence_quotes": _quotes([chunk.get("content")]),
                "metrics": {
                    "weight": score_f if score_f is not None else 0.0,
                    "task_id": task_id,
                },
            })
            n += 1
        if n >= MAX_RAG_PER_BATCH:
            break
    if not steps:
        return []
    return publish_thought_batch(steps, stage="tool_builder")


def _iter_claims(audit_result: Any) -> tuple[list[dict], list[dict]]:
    claims: list[dict] = []
    discarded: list[dict] = []
    evidence = getattr(audit_result, "evidence", None)
    if evidence is None and isinstance(audit_result, dict):
        evidence = audit_result.get("evidence")
    for block in evidence or []:
        if not isinstance(block, dict):
            continue
        for c in block.get("threat_claims") or []:
            if isinstance(c, dict):
                claims.append(c)
        for d in block.get("discarded_claims") or []:
            if isinstance(d, dict):
                discarded.append(d)
    extra = getattr(audit_result, "discarded_claims", None)
    if extra is None and isinstance(audit_result, dict):
        extra = audit_result.get("discarded_claims")
    for d in extra or []:
        if isinstance(d, dict):
            discarded.append(d)
    return claims, discarded


def emit_executor(audit_result: Any, **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"] or audit_result is None:
        return []
    parent_map = [_sid(ids, "tool_builder", "tool_map")]
    rag_ids = [
        s["step_id"] for s in thought_buffer.get(ids["event_id"])
        if s.get("kind") == "rag" and s.get("step_id")
    ][:4]
    claim_parents = parent_map + rag_ids
    steps: list[dict] = []
    claims, discarded = _iter_claims(audit_result)

    for i, c in enumerate(claims[:MAX_CLAIMS_PER_BATCH]):
        conf = c.get("confidence")
        title = str(c.get("type") or c.get("summary") or "断言")
        if conf is not None:
            try:
                title = f"{title} · {float(conf):.2f}"
            except (TypeError, ValueError):
                pass
        steps.append({
            **ids,
            "step_id": _sid(ids, "executor", "claim", str(i)),
            "stage": "executor",
            "kind": "claim",
            "title": title,
            "summary": c.get("summary") or "",
            "status": "success",
            "confidence": c.get("confidence"),
            "parent_ids": claim_parents,
            "evidence_ids": c.get("evidence_ids") or [],
            "evidence_quotes": c.get("evidence_quotes") or [],
            "metrics": {"severity": c.get("severity") or ""},
        })

    for i, d in enumerate(discarded[:MAX_CLAIMS_PER_BATCH]):
        steps.append({
            **ids,
            "step_id": _sid(ids, "executor", "discard", str(i)),
            "stage": "executor",
            "kind": "discard",
            "title": str(d.get("type") or d.get("summary") or "丢弃"),
            "summary": d.get("reason") or d.get("summary") or "闸门丢弃未落地断言",
            "status": "discarded",
            "parent_ids": parent_map,
            "evidence_ids": d.get("evidence_ids") or [],
        })

    hop_trace = getattr(audit_result, "hop_trace", None)
    if hop_trace is None and isinstance(audit_result, dict):
        hop_trace = audit_result.get("hop_trace")
    for i, h in enumerate((hop_trace or [])[:6]):
        if not isinstance(h, dict):
            continue
        hop_name = str(h.get("hop") or f"hop-{i}")
        skip = bool(h.get("skip_reasoning") or h.get("skip_llm"))
        summary_parts = []
        if h.get("reason"):
            summary_parts.append(str(h["reason"]))
        if h.get("verdict"):
            summary_parts.append(f"verdict={h['verdict']}")
        if h.get("avg_grounding") is not None:
            summary_parts.append(f"grounding={h['avg_grounding']}")
        if skip:
            summary_parts.append("skip_reasoning")
        steps.append({
            **ids,
            "step_id": _sid(ids, "executor", "hop", hop_name),
            "stage": "executor",
            "kind": "hop",
            "title": hop_name + (" · 跳过推理" if skip else ""),
            "summary": "；".join(summary_parts) or hop_name,
            "status": "abstain" if skip else "success",
            "parent_ids": parent_map,
            "metrics": {k: h[k] for k in ("avg_grounding", "avg_hallucination_risk", "skip_reasoning") if k in h},
        })

    verdict = getattr(audit_result, "verdict", None)
    if verdict is None and isinstance(audit_result, dict):
        verdict = audit_result.get("verdict")
    summary = getattr(audit_result, "summary", None)
    if summary is None and isinstance(audit_result, dict):
        summary = audit_result.get("summary")
    confidence = getattr(audit_result, "confidence", None)
    if confidence is None and isinstance(audit_result, dict):
        confidence = audit_result.get("confidence")
    threat = getattr(audit_result, "threat_detected", None)
    if threat is None and isinstance(audit_result, dict):
        threat = audit_result.get("threat_detected")
    grounding = getattr(audit_result, "grounding_score", None)
    if grounding is None and isinstance(audit_result, dict):
        grounding = (audit_result.get("grounding_score")
                     if isinstance(audit_result, dict) else None)
    claim_ids = [_sid(ids, "executor", "claim", str(i)) for i in range(min(len(claims), MAX_CLAIMS_PER_BATCH))]
    hop_ids = [
        _sid(ids, "executor", "hop", str((h or {}).get("hop") or i))
        for i, h in enumerate((hop_trace or [])[:6])
        if isinstance(h, dict)
    ]
    abstain = str(verdict or "") == "insufficient_evidence"
    steps.append({
        **ids,
        "step_id": _sid(ids, "executor", "verdict"),
        "stage": "executor",
        "kind": "verdict",
        "title": str(verdict or ("威胁" if threat else "安全")),
        "summary": summary or "",
        "status": "abstain" if abstain else "success",
        "confidence": confidence,
        "parent_ids": claim_ids or hop_ids or parent_map,
        "metrics": {
            "threat_detected": bool(threat),
            "grounding": grounding,
        },
    })

    # confirmation gate 往往编码在 hop synthesize.reason / verdict
    gate_reason = ""
    for h in hop_trace or []:
        if isinstance(h, dict) and h.get("hop") == "synthesize" and h.get("reason"):
            gate_reason = str(h.get("reason"))
            break
    if gate_reason:
        steps.append({
            **ids,
            "step_id": _sid(ids, "executor", "gate"),
            "stage": "executor",
            "kind": "gate",
            "title": "确认闸门",
            "summary": gate_reason,
            "status": "success",
            "parent_ids": [_sid(ids, "executor", "verdict")],
        })
    return publish_thought_batch(steps, stage="executor")


def emit_review(verdict: Any, **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"] or verdict is None:
        return []
    if isinstance(verdict, dict):
        conclusion = verdict.get("conclusion") or ""
        confidence = verdict.get("confidence")
        summary = verdict.get("final_summary") or verdict.get("reviewer_notes") or ""
        chain = list(verdict.get("evidence_chain") or [])
        abstain = bool(verdict.get("abstain"))
        human = bool(verdict.get("human_intervention"))
        missed = list(verdict.get("missed_threats") or [])
    else:
        conclusion = getattr(verdict, "conclusion", "") or ""
        confidence = getattr(verdict, "confidence", None)
        summary = getattr(verdict, "final_summary", "") or getattr(verdict, "reviewer_notes", "")
        chain = list(getattr(verdict, "evidence_chain", None) or [])
        abstain = bool(getattr(verdict, "abstain", False))
        human = bool(getattr(verdict, "human_intervention", False))
        missed = list(getattr(verdict, "missed_threats", None) or [])
    status = "abstain" if abstain or conclusion == "insufficient_evidence" else "success"
    step = {
        **ids,
        "step_id": _sid(ids, "reviewer", "review"),
        "stage": "reviewer",
        "kind": "review",
        "title": str(conclusion or "复核"),
        "summary": summary or ("；".join(str(x) for x in chain[:3])),
        "status": status,
        "confidence": confidence,
        "parent_ids": [_sid(ids, "executor", "verdict"), _sid(ids, "executor", "gate")],
        "evidence_quotes": chain[:QUOTE_LIMIT],
        "metrics": {
            "human_intervention": human,
            "missed_count": len(missed),
            "abstain": abstain,
        },
    }
    return publish_thought_batch([step], stage="reviewer")


def emit_cad(cad_report: Optional[dict], **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    if not ids["event_id"] or not isinstance(cad_report, dict):
        return []
    pv = cad_report.get("penetrating_verification") or {}
    cb = cad_report.get("circuit_breaker") or {}
    tripped = bool(cb.get("tripped"))
    verified = pv.get("verified_claims") or pv.get("verified") or 0
    total = pv.get("total_claims") or pv.get("total") or 0
    step = {
        **ids,
        "step_id": _sid(ids, "cad_verify", "cad"),
        "stage": "cad_verify",
        "kind": "cad",
        "title": "熔断" if tripped else f"穿透验证 {verified}/{total}",
        "summary": cb.get("reason") or pv.get("summary") or "CAD 独立核验完成",
        "status": "error" if tripped else "success",
        "parent_ids": [_sid(ids, "reviewer", "review")],
        "metrics": {"tripped": tripped, "verified": verified, "total": total},
    }
    return publish_thought_batch([step], stage="cad_verify")


def emit_response(payload: Optional[dict], **ids_kw: Any) -> list[dict]:
    ids = _ctx_ids(**ids_kw)
    data = payload or {}
    if not ids["event_id"]:
        if data.get("event_id"):
            ids["event_id"] = int(data["event_id"])
        else:
            return []
    status_raw = str(data.get("status") or "triggered")
    blocked = status_raw in ("blocked", "abstain") or bool(data.get("blocked"))
    status = "blocked" if blocked else ("error" if status_raw == "error" else "success")
    title = "响应阻断" if blocked else f"响应 {data.get('threat_type') or status_raw}"
    step = {
        **ids,
        "step_id": _sid(ids, "response", "response"),
        "stage": "response",
        "kind": "response",
        "title": title,
        "summary": data.get("summary") or data.get("reason") or status_raw,
        "status": status,
        "confidence": data.get("confidence"),
        "parent_ids": [_sid(ids, "cad_verify", "cad"), _sid(ids, "reviewer", "review")],
        "metrics": {"threat_type": data.get("threat_type") or ""},
    }
    return publish_thought_batch([step], stage="response")


def build_edges(nodes: list[dict]) -> list[dict]:
    known = {n["step_id"] for n in nodes if n.get("step_id")}
    cited_from: dict[int, list[str]] = {}
    edges: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for n in nodes:
        sid = n.get("step_id") or ""
        for pid in n.get("parent_ids") or []:
            if pid not in known or not sid:
                continue
            rel = "vetoed" if n.get("kind") == "discard" else (
                "retrieved" if n.get("kind") == "rag" else "derived"
            )
            key = (pid, sid, rel)
            if key not in seen:
                seen.add(key)
                edges.append({"from": pid, "to": sid, "rel": rel})
        for eid in n.get("evidence_ids") or []:
            cited_from.setdefault(int(eid), []).append(sid)
    for n in nodes:
        if n.get("kind") != "claim":
            continue
        sid = n.get("step_id") or ""
        for eid in n.get("evidence_ids") or []:
            key = (sid, f"evidence:{eid}", "evidences")
            if key not in seen and sid:
                seen.add(key)
                edges.append({"from": sid, "to": f"evidence:{eid}", "rel": "evidences"})
    return edges


def _grounding_from_nodes(nodes: list[dict], audit: Optional[dict] = None) -> dict:
    cited: list[int] = []
    for n in nodes:
        cited.extend(n.get("evidence_ids") or [])
    uniq = sorted(set(int(x) for x in cited))
    score = None
    if isinstance(audit, dict):
        g = audit.get("grounding") or {}
        score = g.get("score")
        if score is None:
            merged = audit.get("merged") or {}
            score = merged.get("grounding_score")
    return {"score": score, "cited_event_ids": uniq}


def project_from_audit_llm(
    audit: dict,
    event_id: int,
    cad: Optional[dict] = None,
    session_id: str = "",
) -> list[dict]:
    """从存量 `_audit_llm` 投影 ThoughtStep（无 thought_chain 的旧事件）。"""
    if not event_id or not isinstance(audit, dict):
        return []
    ids = {"event_id": event_id, "session_id": session_id, "trace_id": "", "round": 1}
    steps: list[dict] = []
    merged = audit.get("merged") or {}
    trail = audit.get("evidence_trail") or []
    hops = audit.get("hop_trace") or []
    if not hops:
        for rd in audit.get("rounds_detail") or []:
            hops.extend(rd.get("hop_trace") or [])
    reviewer = audit.get("reviewer") or audit.get("final_verdict") or {}
    if not isinstance(reviewer, dict):
        reviewer = {}

    for rd in audit.get("rounds_detail") or []:
        r = int(rd.get("round") or 1)
        depth = rd.get("mode") or rd.get("depth") or ""
        steps.append(compact_step({
            **ids, "round": r,
            "step_id": f"e{event_id}-r{r}-decomposer-plan",
            "stage": "decomposer", "kind": "plan",
            "title": f"第 {r} 轮 · {depth or 'audit'}",
            "summary": f"threat={rd.get('threat_detected')} conf={rd.get('confidence')}",
            "status": "success",
        }) or {})

    for i, c in enumerate(trail[:MAX_CLAIMS_PER_BATCH]):
        if not isinstance(c, dict):
            continue
        r = int(c.get("round") or 1)
        steps.append(compact_step({
            **ids, "round": r,
            "step_id": f"e{event_id}-r{r}-executor-claim-{i}",
            "stage": "executor", "kind": "claim",
            "title": f"{c.get('type') or '断言'} · {c.get('confidence') or ''}",
            "summary": c.get("claim") or c.get("summary") or "",
            "confidence": c.get("confidence"),
            "evidence_ids": c.get("evidence_ids") or [],
            "evidence_quotes": c.get("evidence_quotes") or [],
            "parent_ids": [f"e{event_id}-r{r}-decomposer-plan"],
            "status": "success",
        }) or {})

    for i, h in enumerate(hops[:6]):
        if not isinstance(h, dict):
            continue
        hop_name = str(h.get("hop") or f"hop-{i}")
        steps.append(compact_step({
            **ids,
            "step_id": f"e{event_id}-r1-executor-hop-{hop_name}",
            "stage": "executor", "kind": "hop",
            "title": hop_name,
            "summary": h.get("reason") or h.get("verdict") or hop_name,
            "status": "abstain" if h.get("skip_reasoning") else "success",
            "parent_ids": [f"e{event_id}-r1-decomposer-plan"],
            "metrics": {k: h[k] for k in ("avg_grounding", "skip_reasoning") if k in h},
        }) or {})

    verdict = merged.get("verdict") or ""
    steps.append(compact_step({
        **ids,
        "step_id": f"e{event_id}-r1-executor-verdict",
        "stage": "executor", "kind": "verdict",
        "title": str(verdict or ("威胁" if merged.get("threat_detected") else "安全")),
        "summary": merged.get("summary") or "",
        "confidence": merged.get("confidence"),
        "status": "abstain" if verdict == "insufficient_evidence" else "success",
        "parent_ids": [s["step_id"] for s in steps if s.get("kind") == "claim"][:4],
    }) or {})

    if reviewer:
        chain = reviewer.get("evidence_chain") or []
        steps.append(compact_step({
            **ids,
            "step_id": f"e{event_id}-r1-reviewer-review",
            "stage": "reviewer", "kind": "review",
            "title": reviewer.get("conclusion") or "复核",
            "summary": reviewer.get("final_summary") or "",
            "confidence": reviewer.get("confidence"),
            "status": "abstain" if reviewer.get("abstain") else "success",
            "parent_ids": [f"e{event_id}-r1-executor-verdict"],
            "evidence_quotes": chain[:QUOTE_LIMIT] if isinstance(chain, list) else [],
        }) or {})

    if isinstance(cad, dict) and cad:
        pv = cad.get("penetrating_verification") or {}
        cb = cad.get("circuit_breaker") or {}
        steps.append(compact_step({
            **ids,
            "step_id": f"e{event_id}-r1-cad_verify-cad",
            "stage": "cad_verify", "kind": "cad",
            "title": "CAD 监督",
            "summary": cb.get("reason") or "穿透验证",
            "status": "error" if cb.get("tripped") else "success",
            "parent_ids": [f"e{event_id}-r1-reviewer-review"],
            "metrics": {"tripped": bool(cb.get("tripped")), "verified": pv.get("verified_claims") or 0},
        }) or {})

    if merged.get("response_blocked"):
        steps.append(compact_step({
            **ids,
            "step_id": f"e{event_id}-r1-response-response",
            "stage": "response", "kind": "response",
            "title": "响应阻断",
            "summary": "faithfulness / 否决闸阻止自动响应",
            "status": "blocked",
            "parent_ids": [f"e{event_id}-r1-reviewer-review"],
        }) or {})

    return [s for s in steps if s]


def _merge_nodes(*groups: list[dict]) -> list[dict]:
    by_id: OrderedDict[str, dict] = OrderedDict()
    for group in groups:
        for n in group or []:
            if not n or not n.get("step_id"):
                continue
            by_id[n["step_id"]] = n
    return list(by_id.values())


def summarize_thought_chain(
    event_id: int,
    audit: Optional[dict],
    cad: Optional[dict] = None,
) -> dict:
    """列表摘要：节点数 / 来源。不含 prompt、completion、thinking。"""
    audit = audit if isinstance(audit, dict) else {}
    chain = audit.get("thought_chain") if isinstance(audit.get("thought_chain"), list) else []
    node_count = len(chain)
    source = "persisted" if node_count else "empty"
    if node_count == 0:
        projected = project_from_audit_llm(audit, event_id, cad=cad)
        if projected:
            node_count = len(projected)
            source = "projected"
    return {
        "event_id": int(event_id or 0),
        "node_count": int(node_count),
        "source": source,
    }


async def list_recent_thought_chains(session, limit: int = 8) -> list[dict]:
    """最近带 _audit_llm 的已分析事件（Monitor 空闲默认选中）。"""
    from sqlalchemy import select

    from models import SecurityEvent

    cap = max(8, min(int(limit or 8), 40))
    result = await session.execute(
        select(SecurityEvent)
        .where(SecurityEvent.analyzed.is_(True))
        .order_by(SecurityEvent.id.desc())
        .limit(cap * 4)
    )
    out: list[dict] = []
    for evt in result.scalars().all():
        raw = evt.raw_data if isinstance(evt.raw_data, dict) else {}
        audit = raw.get("_audit_llm")
        if not isinstance(audit, dict):
            continue
        cad = raw.get("_cad_audit") if isinstance(raw.get("_cad_audit"), dict) else None
        summary = summarize_thought_chain(int(evt.id), audit, cad)
        if summary["node_count"] <= 0:
            continue
        status = str(audit.get("status") or "") or ("completed" if evt.analyzed else "running")
        created = evt.created_at.isoformat() if getattr(evt, "created_at", None) else None
        out.append({
            "event_id": int(evt.id),
            "status": status,
            "event_type": evt.event_type or "",
            "src_ip": evt.src_ip or "",
            "created_at": created,
            "node_count": summary["node_count"],
            "source": summary["source"],
        })
        if len(out) >= cap:
            break
    return out


def assemble_thought_chain(
    event_id: int,
    *,
    audit: Optional[dict] = None,
    cad: Optional[dict] = None,
    session_id: str = "",
    status: str = "running",
) -> dict:
    """组装监控页 DAG：live 缓冲 → 落库 thought_chain → 存量投影。"""
    live = snapshot(event_id)
    persisted = []
    if isinstance(audit, dict):
        persisted = list(audit.get("thought_chain") or [])
        persisted = [compact_step(s, seq=i + 1) for i, s in enumerate(persisted)]
        persisted = [s for s in persisted if s]
    source = "live"
    projected: list[dict] = []
    if not live and not persisted:
        projected = project_from_audit_llm(audit or {}, event_id, cad=cad, session_id=session_id)
        source = "projected" if projected else "empty"
    elif persisted and not live:
        source = "persisted"
    elif live and persisted:
        source = "live"
    nodes = _merge_nodes(projected, persisted, live)
    if not nodes and projected:
        nodes = projected
    return {
        "event_id": event_id,
        "status": status,
        "nodes": nodes,
        "edges": build_edges(nodes),
        "grounding": _grounding_from_nodes(nodes, audit),
        "source": source,
    }
