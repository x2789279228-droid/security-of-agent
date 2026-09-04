"""LLM 降级响应识别 — 预算耗尽/调用失败时禁止当正常 JSON 去 schema-retry。

summary.llm.chat 在预算耗尽等场景返回:
  {"error": "每日 LLM 预算已用尽", "fallback": true, ...}

SubAuditor 等组件若把它当格式错误再 MAX_RETRIES,会空转占满审计槽位
(r6: 1100 events / 20 并发 → 测试窗口 analyzed=0)。
"""
from __future__ import annotations

import json
from typing import Any, Optional, Tuple


_FALLBACK_MARKERS = (
    "每日 LLM 预算已用尽",
    "LLM未配置",
    "LLM调用失败",
    "budget_exhausted",
)


def parse_llm_json(text: str) -> Optional[dict]:
    """尽力解析 LLM 返回文本为 dict；失败返回 None。"""
    if not text or not isinstance(text, str):
        return None
    raw = text.strip()
    if not raw:
        return None
    # 常见 ```json ... ``` 包裹
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    try:
        obj = json.loads(raw)
    except Exception:
        # 截取首个 {...}
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            obj = json.loads(raw[start : end + 1])
        except Exception:
            return None
    return obj if isinstance(obj, dict) else None


def is_llm_fallback(text: Any) -> Tuple[bool, str]:
    """判断是否为 LLM 客户端主动降级响应。

    Returns:
        (is_fallback, reason) — reason 为短标签,便于落库/日志。
    """
    if text is None:
        return False, ""
    if isinstance(text, dict):
        data = text
    else:
        data = parse_llm_json(str(text))
        if data is None:
            # 纯文本兜底: 预算文案偶发未包 JSON
            s = str(text)
            for m in _FALLBACK_MARKERS:
                if m in s:
                    return True, _reason_from_marker(m)
            return False, ""

    if data.get("fallback") is True:
        err = str(data.get("error") or "")
        return True, _reason_from_error(err)

    err = str(data.get("error") or "")
    for m in _FALLBACK_MARKERS:
        if m in err:
            return True, _reason_from_marker(m)
    return False, ""


def _reason_from_error(err: str) -> str:
    for m in _FALLBACK_MARKERS:
        if m in err:
            return _reason_from_marker(m)
    return "llm_fallback"


def _reason_from_marker(marker: str) -> str:
    if "预算" in marker or marker == "budget_exhausted":
        return "budget_exhausted"
    if "未配置" in marker:
        return "llm_not_configured"
    if "调用失败" in marker:
        return "llm_call_failed"
    return "llm_fallback"


def budget_exhausted() -> bool:
    """当前进程是否已触达日预算门禁。"""
    try:
        from summary_compression import cost_tracker
        return bool(cost_tracker.is_over_budget())
    except Exception:
        return False


def budget_usage_pct() -> float:
    """今日预算使用百分比 0-100+。"""
    try:
        from summary_compression import cost_tracker
        stats = cost_tracker.stats()
        return float(stats.get("usage_pct") or 0.0)
    except Exception:
        return 0.0


def should_short_circuit_for_tier(tier: str) -> bool:
    """硬预算下是否应对该档位短路 LLM。

    P0 永不因预算关闭 LLM 通道(走最小 hop);
    其他档位在 over_budget 时可 short-circuit。
    """
    if (tier or "").upper() == "P0":
        return False
    return budget_exhausted()
