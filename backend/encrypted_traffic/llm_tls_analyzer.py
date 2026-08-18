"""
加密流量大模型 (LLM TLS Analyzer) — NDR 扩展

职责:
  在 tls_metadata.score_session() 产出 risk_score 后,
  LLM 对高分可疑会话做语义判定:
    - JA3 指纹 + 证书特征组合是否匹配已知恶意工具 (Cobalt Strike / Metasploit / Sliver)
    - SNI 与证书 SAN 不匹配的真实意图 (CDN 误报 vs 恶意伪装)
    - 加密隧道 vs 正常 HTTPS 的上下文判断

触发条件 (严格):
  - tls_metadata.score_session() 返回 risk_score >= 0.6
  - settings.llm_encrypted_traffic_enabled == True

性能保障:
  - 主路径不等待 (调用方走 llm_enhancer.safe_dispatch)
  - 单次成本 0.05¥,日预算 5¥ → 最多 100 次/日
  - 失败/超预算 → 返回 None → 不影响规则评分

结果:
  {verdict, confidence, tool_family, rationale, suggested_action}
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_LLM_TRIGGER_SCORE = 0.6


def should_trigger_llm(session_data) -> bool:
    """判断是否需要 LLM 增强（主路径同步调用, < 0.01ms）"""
    if not settings.llm_encrypted_traffic_enabled:
        return False
    score = getattr(session_data, "risk_score", 0) if not isinstance(session_data, dict) else session_data.get("risk_score", 0)
    return score >= _LLM_TRIGGER_SCORE


async def llm_analyze_tls_session(
    *,
    src_ip: str,
    dst_ip: str,
    sni: str,
    ja3_hash: str,
    tls_version: str,
    cipher_suite: str,
    cert_subject: str,
    cert_issuer: str,
    cert_is_self_signed: bool,
    risk_score: float,
    risk_reasons: list,
) -> Optional[dict]:
    """
    LLM 语义判定可疑 TLS 会话

    Returns:
        {verdict, confidence, tool_family, rationale, suggested_action} 或 None
    """
    from llm_enhancer import enhance_encrypted_traffic

    prompt = f"""你是一位加密流量分析专家。请分析以下 TLS 会话元数据，判断是否为恶意工具通信。

## 会话信息
- 源IP: {src_ip} → 目标IP: {dst_ip}
- SNI: {sni or '(空)'}
- JA3 指纹: {ja3_hash or '(未计算)'}
- TLS 版本: {tls_version}
- 密码套件: {cipher_suite}
- 证书 Subject: {cert_subject}
- 证书 Issuer: {cert_issuer}
- 自签名: {'是' if cert_is_self_signed else '否'}
- 风险评分: {risk_score:.2f}
- 风险原因: {', '.join(risk_reasons) if risk_reasons else '无'}

## 已知恶意 JA3 特征参考
- Cobalt Strike: 72a589da586844d7f0818ce684948eea
- Metasploit: 72a589da586844d7f0818ce684948eea (与 CS 相同)
- Sliver C2: 常见自签名 + 短有效期 + 非标准 SNI
- 正常浏览器: JA3 通常包含 GREASE 值, 密码套件 > 10 个

## 输出要求 (严格 JSON)
{{
  "verdict": "malicious|suspicious|benign|uncertain",
  "confidence": 0.0-1.0,
  "tool_family": "Cobalt Strike|Metasploit|Sliver|其他工具名|无",
  "rationale": "一句话判定理由",
  "suggested_action": "block|monitor|ignore"
}}"""

    cache_key = f"tls:{src_ip}:{dst_ip}:{ja3_hash}:{sni}"

    result = await enhance_encrypted_traffic(
        cache_key=cache_key,
        prompt_messages=[
            {"role": "system", "content": "你是加密流量分析专家。只输出 JSON,不加解释。"},
            {"role": "user", "content": prompt},
        ],
        budget_cost_jpy=0.05,
    )

    if result:
        logger.info(
            "[TLS-LLM] %s→%s verdict=%s family=%s conf=%.2f",
            src_ip, dst_ip,
            result.get("verdict", "?"),
            result.get("tool_family", "?"),
            result.get("confidence", 0),
        )
    return result
