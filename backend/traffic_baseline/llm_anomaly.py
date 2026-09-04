"""
流量大模型 (LLM Anomaly) — P0.S

职责:
  在 SeasonalDetector 触发 3σ 异常后,LLM 解读异常流量的语义判定
  (这是规则不能给的:C2 beacon / DNS 隧道 / 数据外泄 vs 业务突发)

触发条件 (严格,绝不降低):
  - seasonal_detector.detect() 返回 is_anomaly=True
  - |z_score| >= _RESIDUAL_THRESHOLD (3.0)
  - settings.llm_traffic_enabled == True

性能保障:
  - 主路径不等待 (调用方走 llm_enhancer.safe_dispatch)
  - 单次成本估 0.05¥,日预算 5¥ → 最多 100 次/日
  - 单次超时 15s,5 并发上限
  - 失败/超预算/超时 → 返回 None → 不影响规则路径

结果落库:
  network_flows.raw_data.llm_verdict = {verdict, confidence, rationale, suggested_action}
  (复用已有 JSONB 列,不动 schema)
"""
import logging
import time
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


# ── LLM 触发阈值 (与 seasonal.py 对齐,绝不降低) ──
_LLM_TRIGGER_ZSCORE = 3.0


def should_trigger_llm(detect_result: dict) -> bool:
    """
    由 seasonal_detector.detect() 末尾调用,判断是否需要发起 LLM 增强.
    主路径同步调用,本函数 < 0.01ms.
    """
    if not settings.llm_traffic_enabled:
        return False
    if not detect_result or not detect_result.get("is_anomaly"):
        return False
    z = abs(detect_result.get("z_score", 0))
    return z >= _LLM_TRIGGER_ZSCORE


async def llm_analyze_anomaly(
    *,
    ip: str,
    metric: str,
    detect_result: dict,
    recent_pattern: str = "",
    flow_id: int = 0,
) -> Optional[dict]:
    """
    LLM 解读异常流量的语义判定.

    Args:
        ip: 异常 IP
        metric: bytes_out / packets_in / flow_count / ...
        detect_result: seasonal_detector.detect() 返回值
        recent_pattern: 最近流量模式文字描述 (可选,由调用方提取)
        flow_id: 关联的 network_flows.id (用于回写 raw_data.llm_verdict)

    Returns:
        {
            "verdict": "c2_beacon" | "data_exfil" | "dns_tunnel" | "normal_burst" | "unknown",
            "confidence": 0.0-1.0,
            "rationale": "...",
            "suggested_action": "isolate_host" | "rate_limit" | "monitor" | "ignore"
        }
        或 None (降级)
    """
    from llm_enhancer import enhance_traffic

    # ── 构造 LLM 输入:仅统计摘要 (不传原始报文,token < 200) ──
    cache_key = f"traffic:{ip}:{metric}:{int(detect_result.get('z_score', 0) * 10)}"

    from prompts import render
    _d = detect_result or {}
    prompt_messages = [
        {"role": "system", "content": render("security/traffic_anomaly_system")},
        {"role": "user", "content": render(
            "security/traffic_anomaly_user",
            ip=ip,
            metric=metric,
            current_value=_d.get("current_value", 0),
            expected=_d.get("expected", 0),
            mean=_d.get("mean", 0),
            std=_d.get("std", 0),
            z_score=_d.get("z_score", 0),
            seasonal_component=_d.get("seasonal_component", 0),
            reasons=_d.get("reasons", []),
            recent_pattern=recent_pattern,
        )},
    ]

    result = await enhance_traffic(
        cache_key=cache_key,
        prompt_messages=prompt_messages,
        budget_cost_yuan=0.05,
    )

    if result is None:
        return None

    # 字段校验 + 兜底
    valid_verdicts = {"c2_beacon", "data_exfil", "dns_tunnel", "normal_burst", "unknown"}
    valid_actions = {"isolate_host", "rate_limit", "monitor", "ignore"}

    verdict = result.get("verdict", "unknown")
    if verdict not in valid_verdicts:
        verdict = "unknown"

    action = result.get("suggested_action", "monitor")
    if action not in valid_actions:
        action = "monitor"

    confidence = result.get("confidence", 0.5)
    try:
        confidence = float(confidence)
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "rationale": str(result.get("rationale", ""))[:500],
        "suggested_action": action,
        "analyzed_at": int(time.time()),
        "flow_id": flow_id,
    }


async def persist_verdict_to_flow(flow_id: int, verdict: dict) -> None:
    """
    异步把 LLM 判定回写 network_flows.raw_data.llm_verdict.
    flow_id=0 时跳过 (单元测试 / 无 flow 上下文时).
    复用已有 raw_data JSONB 列,不动 schema.
    """
    if not flow_id or not verdict:
        return
    try:
        from models import async_session, NetworkFlow
        async with async_session() as s:
            flow = await s.get(NetworkFlow, flow_id)
            if flow:
                raw = dict(flow.raw_data or {})
                raw["llm_verdict"] = verdict
                flow.raw_data = raw
                await s.commit()
                logger.info(
                    f"[LLM-Anomaly] flow #{flow_id} verdict={verdict['verdict']} "
                    f"conf={verdict['confidence']}"
                )
    except Exception as e:
        logger.warning(f"[LLM-Anomaly] persist verdict failed: {e}")


async def analyze_and_persist(
    *,
    ip: str,
    metric: str,
    detect_result: dict,
    recent_pattern: str = "",
    flow_id: int = 0,
) -> None:
    """
    完整流程:LLM 分析 → 异步回写 DB.
    供 seasonal_detector 末尾以 llm_enhancer.safe_dispatch 派发,
    主路径不等待.
    """
    verdict = await llm_analyze_anomaly(
        ip=ip, metric=metric, detect_result=detect_result,
        recent_pattern=recent_pattern, flow_id=flow_id,
    )
    if verdict is not None:
        await persist_verdict_to_flow(flow_id, verdict)


# ── 全局单例 ──

class LlmAnomalyEngine:
    """状态包装,便于引入测试桩"""

    should_trigger_llm = staticmethod(should_trigger_llm)
    analyze = staticmethod(llm_analyze_anomaly)
    analyze_and_persist = staticmethod(analyze_and_persist)
    persist = staticmethod(persist_verdict_to_flow)


llm_anomaly_engine = LlmAnomalyEngine()