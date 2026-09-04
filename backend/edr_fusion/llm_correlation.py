"""
EDR 跨源关联大模型 (LLM Correlation) — NDR 扩展

职责:
  在 cross_correlator 产出高置信度关联结果后,
  LLM 生成攻击叙事 (将离散事件串联为可读的攻击故事):
    - 攻击阶段推断 (初始访问 → 执行 → 横向 → 外泄)
    - 攻击者意图与能力评估
    - 处置建议优先级排序

触发条件:
  - cross_correlator.correlate() 返回 confidence >= 0.7 的结果
  - settings.llm_edr_enabled == True

性能保障:
  - 主路径不等待 (safe_dispatch)
  - 单次 0.05¥, 日预算 5¥ → 100 次/日
  - 失败 → 返回 None → 使用模板叙事兜底
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_LLM_TRIGGER_CONFIDENCE = 0.7


def should_trigger_llm(correlation_result) -> bool:
    """判断是否需要 LLM 叙事增强"""
    if not settings.llm_edr_enabled:
        return False
    conf = correlation_result.confidence if hasattr(correlation_result, "confidence") else correlation_result.get("confidence", 0)
    return conf >= _LLM_TRIGGER_CONFIDENCE


async def llm_narrate_correlation(
    *,
    correlation_type: str,
    confidence: float,
    network_event: dict,
    edr_event: dict,
    mitre_technique: str,
    indicators: list,
) -> Optional[dict]:
    """
    LLM 生成跨源关联攻击叙事

    Returns:
        {narrative, attack_phase, attacker_capability, priority_actions} 或 None
    """
    from llm_enhancer import enhance_edr

    from prompts import render
    prompt = render(
        "security/edr_correlation",
        correlation_type=correlation_type,
        confidence=confidence,
        network_event=network_event,
        edr_event=edr_event,
        mitre_technique=mitre_technique,
        indicators=indicators,
    )

    cache_key = f"edr_corr:{correlation_type}:{network_event.get('src_ip', '')}:{edr_event.get('computer', '')}"

    result = await enhance_edr(
        cache_key=cache_key,
        prompt_messages=[
            {"role": "system", "content": render("security/edr_correlation_system")},
            {"role": "user", "content": prompt},
        ],
        budget_cost_yuan=0.05,
    )

    if result:
        logger.info(
            "[EDR-LLM] %s phase=%s capability=%s",
            correlation_type,
            result.get("attack_phase", "?"),
            result.get("attacker_capability", "?"),
        )
    return result
