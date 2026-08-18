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

    prompt = f"""你是一位 SOC 高级分析师。请根据以下跨源关联证据,生成简洁的攻击叙事和处置建议。

## 关联类型
{correlation_type} (置信度: {confidence:.0%})

## 网络侧证据
{network_event}

## 终端侧证据
{edr_event}

## MITRE ATT&CK
{mitre_technique}

## 检测指标
{', '.join(indicators) if indicators else '无'}

## 输出要求 (严格 JSON)
{{
  "narrative": "2-3句话描述攻击行为",
  "attack_phase": "initial_access|execution|persistence|lateral_movement|exfiltration|impact",
  "attacker_capability": "script_kiddie|organized_crime|apt|insider",
  "priority_actions": ["建议1", "建议2", "建议3"]
}}"""

    cache_key = f"edr_corr:{correlation_type}:{network_event.get('src_ip', '')}:{edr_event.get('computer', '')}"

    result = await enhance_edr(
        cache_key=cache_key,
        prompt_messages=[
            {"role": "system", "content": "你是 SOC 高级分析师。只输出 JSON。"},
            {"role": "user", "content": prompt},
        ],
        budget_cost_jpy=0.05,
    )

    if result:
        logger.info(
            "[EDR-LLM] %s phase=%s capability=%s",
            correlation_type,
            result.get("attack_phase", "?"),
            result.get("attacker_capability", "?"),
        )
    return result
