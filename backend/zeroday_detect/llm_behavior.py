"""
沙箱行为大模型 (LLM Behavior) — NDR 扩展

职责:
  在 behavior_analyzer 产出分析结果后,
  LLM 对恶意/可疑样本做深度行为解读:
    - 攻击链阶段还原 (从进程树+网络行为推断完整攻击路径)
    - 家族变种关系判断 (与已知家族的相似度语义评估)
    - 防御绕过技术识别 (反沙箱/反调试/延迟执行)
    - 处置建议 (是否需要全网猎杀/隔离/取证)

触发条件:
  - behavior_analyzer.analyze() 返回 verdict in ("malicious", "suspicious")
  - settings.llm_sandbox_enabled == True

性能保障:
  - 主路径不等待 (safe_dispatch)
  - 单次 0.05¥, 日预算 5¥ → 100 次/日
  - 失败 → 返回 None → 使用规则分析结果兜底
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_LLM_TRIGGER_VERDICTS = {"malicious", "suspicious"}


def should_trigger_llm(analysis_result) -> bool:
    """判断是否需要 LLM 行为解读"""
    if not settings.llm_sandbox_enabled:
        return False
    verdict = analysis_result.verdict if hasattr(analysis_result, "verdict") else analysis_result.get("verdict", "")
    return verdict in _LLM_TRIGGER_VERDICTS


async def llm_interpret_behavior(
    *,
    sample_hash: str,
    verdict: str,
    score: float,
    behavior_summary: str,
    mitre_techniques: list,
    network_iocs: list,
    process_tree: list,
    signatures: list,
) -> Optional[dict]:
    """
    LLM 深度解读沙箱行为

    Returns:
        {attack_narrative, evasion_techniques, family_assessment, kill_chain, response_actions} 或 None
    """
    from llm_enhancer import enhance_sandbox

    techniques_str = ", ".join(
        t.get("id", t) if isinstance(t, dict) else str(t)
        for t in mitre_techniques[:8]
    )
    network_str = ", ".join(
        f"{n.get('type', '?')}:{n.get('value', '?')}" if isinstance(n, dict) else str(n)
        for n in network_iocs[:5]
    )
    process_str = " → ".join(
        p.get("name", "?") if isinstance(p, dict) else str(p)
        for p in process_tree[:6]
    )

    from prompts import render
    prompt = render(
        "security/zeroday_sandbox",
        sample_hash=sample_hash,
        verdict=verdict,
        score=score,
        behavior_summary=behavior_summary,
        techniques_str=techniques_str,
        network_str=network_str,
        process_str=process_str,
        signatures=signatures,
    )

    cache_key = f"sandbox:{sample_hash}"

    result = await enhance_sandbox(
        cache_key=cache_key,
        prompt_messages=[
            {"role": "system", "content": render("security/zeroday_sandbox_system")},
            {"role": "user", "content": prompt},
        ],
        budget_cost_yuan=0.05,
    )

    if result:
        logger.info(
            "[Sandbox-LLM] %s family=%s evasion=%s",
            sample_hash[:16],
            result.get("family_assessment", "?")[:30],
            result.get("evasion_techniques", []),
        )
    return result
