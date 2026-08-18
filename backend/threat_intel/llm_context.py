"""
威胁情报大模型 (LLM Context) — NDR 扩展

职责:
  当 intel_enricher 发现多源 IOC 命中时,
  LLM 生成威胁上下文摘要:
    - 关联威胁活动/家族识别
    - 攻击基础设施画像 (hosting provider, 地理分布)
    - 与当前事件的关联度评估
    - 防御建议 (是否需要主动封禁/猎杀)

触发条件:
  - intel_enricher.enrich_event() 产出 >= 2 个 IOC 命中
  - settings.llm_intel_enabled == True

性能保障:
  - 主路径不等待 (safe_dispatch)
  - 单次 0.03¥, 日预算 3¥ → 100 次/日
  - 失败 → 返回 None → 仅保留结构化 IOC 数据
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_LLM_TRIGGER_HITS = 2


def should_trigger_llm(ioc_hits: list) -> bool:
    """判断是否需要 LLM 上下文摘要"""
    if not settings.llm_intel_enabled:
        return False
    return len(ioc_hits) >= _LLM_TRIGGER_HITS


async def llm_summarize_threat_context(
    *,
    event_type: str,
    src_ip: str,
    dst_ip: str,
    ioc_hits: list,
    reputation_scores: dict,
) -> Optional[dict]:
    """
    LLM 生成威胁情报上下文摘要

    Returns:
        {threat_actor, campaign, infrastructure_profile, relevance, defense_actions} 或 None
    """
    from llm_enhancer import enhance_intel

    hits_str = "\n".join(
        f"- [{h.get('ioc_type', '?')}] {h.get('ioc_value', '?')} "
        f"(来源: {h.get('source', '?')}, 威胁: {h.get('threat_type', '?')}, "
        f"置信度: {h.get('confidence', 0):.0%})"
        for h in ioc_hits[:10]
    )

    prompt = f"""你是一位威胁情报分析师。请根据以下 IOC 命中信息,生成威胁上下文摘要。

## 触发事件
类型: {event_type}, 源: {src_ip} → 目标: {dst_ip}

## IOC 命中 ({len(ioc_hits)} 条)
{hits_str}

## 信誉评分
{reputation_scores}

## 输出要求 (严格 JSON)
{{
  "threat_actor": "APT组织名/犯罪团伙/未知",
  "campaign": "关联的攻击活动名称或描述",
  "infrastructure_profile": "C2基础设施特征描述(1句话)",
  "relevance": "high|medium|low (与当前事件的关联度)",
  "defense_actions": ["建议1", "建议2"]
}}"""

    cache_key = f"intel:{src_ip}:{dst_ip}:{len(ioc_hits)}"

    result = await enhance_intel(
        cache_key=cache_key,
        prompt_messages=[
            {"role": "system", "content": "你是威胁情报分析师。只输出 JSON。"},
            {"role": "user", "content": prompt},
        ],
        budget_cost_jpy=0.03,
    )

    if result:
        logger.info(
            "[Intel-LLM] %s→%s actor=%s relevance=%s",
            src_ip, dst_ip,
            result.get("threat_actor", "?"),
            result.get("relevance", "?"),
        )
    return result
