"""
查询变换 — 规则扩展（默认）+ 可选 LLM rewrite/step-back + 可选 HyDE

审计 skip_llm / tools_only 路径只走规则，不额外打 LLM。
HyDE 默认 empty_only，且 lexical_first（CVE/哈希/T-ID）时跳过。
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from .lexical import expand_query_text

logger = logging.getLogger(__name__)


def _cfg(name: str, default: str) -> str:
    try:
        from config import settings
        return str(getattr(settings, name, default) or default)
    except Exception:
        return default


async def transform_query(
    query: str,
    *,
    rewrite: Optional[str] = None,
    hyde: Optional[str] = None,
    skip_llm: bool = False,
    empty_hits: bool = False,
) -> dict:
    """返回 expand_query_text 结构，并按开关填充 rewritten / hyde_text / step_back。"""
    state = expand_query_text(query)
    rewrite_mode = (rewrite if rewrite is not None else _cfg("rag_query_rewrite", "rules")).lower()
    hyde_mode = (hyde if hyde is not None else _cfg("rag_hyde", "empty_only")).lower()

    if skip_llm:
        return state

    if rewrite_mode == "llm" and state["original"]:
        try:
            extra = await _llm_rewrite(state["original"])
            if extra.get("rewritten"):
                state["rewritten"] = extra["rewritten"]
                state["expanded"] = extra["rewritten"]
            if extra.get("step_back"):
                state["step_back"] = extra["step_back"]
                state["expanded"] = f"{state['expanded']} {extra['step_back']}"
            if extra.get("keywords"):
                kws = [str(k) for k in extra["keywords"] if k]
                state["keywords"] = list(dict.fromkeys(state["keywords"] + kws))[:24]
                state["lexical_query"] = " ".join(
                    dict.fromkeys([state["lexical_query"]] + kws)
                )
        except Exception as e:
            logger.warning(f"[query_transform] LLM rewrite 失败, 用规则扩展: {e}")

    want_hyde = hyde_mode == "always" or (hyde_mode == "empty_only" and empty_hits)
    if want_hyde and not state["lexical_first"] and state["original"]:
        try:
            state["hyde_text"] = await _llm_hyde(state["rewritten"] or state["original"])
        except Exception as e:
            logger.warning(f"[query_transform] HyDE 失败: {e}")
    return state


async def _llm_rewrite(query: str) -> dict:
    from summary_compression import summary
    from trace_hook import set_trace_context
    from prompts import render

    set_trace_context(operation="rag_rewrite", caller="rag")
    try:
        prompt = render("rag/query_rewrite", query=query)
        sys_p = render("rag/query_rewrite_system")
    except Exception:
        sys_p = (
            "你是 SOC 检索查询改写器。只输出 JSON："
            '{"rewritten":"...","keywords":["..."],"step_back":"..."}。'
            "rewritten 保留专有名词（CVE/T-ID/哈希）；step_back 是更抽象的 ATT&CK 技术问法。"
            "不要编造不存在的 CVE 编号。"
        )
        prompt = f"改写以下安全检索查询:\n{query}"
    raw = await summary.llm.chat([
        {"role": "system", "content": sys_p},
        {"role": "user", "content": prompt},
    ])
    return _parse_json(raw)


async def _llm_hyde(query: str) -> str:
    from summary_compression import summary
    from trace_hook import set_trace_context
    from prompts import render

    set_trace_context(operation="rag_hyde", caller="rag")
    try:
        prompt = render("rag/hyde", query=query)
        sys_p = render("rag/hyde_system")
    except Exception:
        sys_p = (
            "你是安全知识作者。根据查询写一段 80-120 字的假想检测/处置说明，"
            "像 MITRE 技术或 playbook 片段。不要编造具体 CVE 编号或哈希。"
        )
        prompt = f"为检索生成假设文档:\n{query}"
    text = await summary.llm.chat([
        {"role": "system", "content": sys_p},
        {"role": "user", "content": prompt},
    ])
    return (text or "").strip()[:600]


def _parse_json(raw: str) -> dict:
    text = (raw or "").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            data = json.loads(text[start : end + 1])
        else:
            return {}
    if not isinstance(data, dict):
        return {}
    return data
