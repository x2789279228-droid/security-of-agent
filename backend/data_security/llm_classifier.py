"""
数据安全大模型 (Data Security LLM) — P0.S

职责:
  HTTP 会话命中敏感关键字后,LLM 做意图与分类判定
  (规则只能看关键字,LLM 能区分真敏感数据 vs 业务正常字段)

触发条件 (严格,绝不降低):
  - http_linker._detect_threats() 命中 "sensitive_data_leak" 标志
  - settings.llm_data_security_enabled == True

性能保障:
  - 主路径 0 等待 (调用方走 llm_enhancer.safe_dispatch)
  - 单次成本 0.1¥,日预算 5¥ → 50 次/日
  - 5 并发上限
  - 失败/超预算 → 不影响 tx.security_flags

结果:
  - 通过 event_bus 广播 "data_security_llm_verdict"
  - 不篡改原 tx (主路径已返),审计 trail 自动留痕
  - 高置信度命中 → 同时异步触发响应引擎审计工单

调用方式:
    from data_security import classify_session
    await classify_session(http_summary)  # 由 http_linker 调用
"""
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


# 高置信阈值:超过则同步推 audit-llm 复审
_HIGH_CONF_THRESHOLD = 0.8


async def classify_session(
    *,
    http_summary: dict,
    sensor_id: str = "",
) -> Optional[dict]:
    """
    LLM 复核 HTTP 会话是否真为敏感数据外泄,并分类.

    Args:
        http_summary: {
            "url": "/api/export/users.csv",
            "method": "GET",
            "request_headers": {...},
            "response_content_type": "text/csv",
            "response_size": 12345,
            "body_snippet": "first 500 chars of response body",
            "rule_hit": "sensitive_data_leak",
            "src_ip": "...",
            "dst_ip": "...",
            "sensor_id": "sensor-01",
        }

    Returns:
        {
            "is_sensitive": true/false,
            "category": "PII" | "financial" | "credentials" | "ip" | "none",
            "confidence": 0.0-1.0,
            "false_positive_prob": 0.0-1.0,
            "rationale": "...",
            "recommended_action": "block" | "audit" | "monitor" | "ignore"
        }
        或 None (降级)
    """
    from llm_enhancer import enhance_data_security

    if not settings.llm_data_security_enabled:
        return None

    # 缓存键:url + method + rule_hit (同一接口反复命中只跑一次)
    cache_key = (
        f"data_sec:{http_summary.get('method', '')}:"
        f"{http_summary.get('url', '')[:200]}:"
        f"{http_summary.get('rule_hit', '')}"
    )

    # 构造 prompt (严格限 token:body_snippet <= 500 chars)
    from prompts import render
    _p = http_summary
    prompt_messages = [
        {"role": "system", "content": render("security/data_security_classifier_system")},
        {"role": "user", "content": render(
            "security/data_security_classifier_user",
            m=_p.get("method", "GET"),
            url=str(_p.get("url", ""))[:200],
            response_content_type=_p.get("response_content_type", ""),
            response_size=_p.get("response_size", 0),
            src_ip=_p.get("src_ip", ""),
            dst_ip=_p.get("dst_ip", ""),
            rule_hit=_p.get("rule_hit", ""),
            body_snippet=str(_p.get("body_snippet", ""))[:500],
        )},
    ]

    result = await enhance_data_security(
        cache_key=cache_key,
        prompt_messages=prompt_messages,
        budget_cost_yuan=0.1,
    )

    if result is None:
        return None

    # 字段校验
    valid_categories = {"PII", "financial", "credentials", "ip", "none"}
    valid_actions = {"block", "audit", "monitor", "ignore"}

    category = result.get("category", "none")
    if category not in valid_categories:
        category = "none"
    action = result.get("recommended_action", "audit")
    if action not in valid_actions:
        action = "audit"

    confidence = _safe_float(result.get("confidence", 0.5), 0.5)
    fp_prob = _safe_float(result.get("false_positive_prob", 0.5), 0.5)

    return {
        "is_sensitive": bool(result.get("is_sensitive", False)),
        "category": category,
        "confidence": round(confidence, 3),
        "false_positive_prob": round(fp_prob, 3),
        "rationale": str(result.get("rationale", ""))[:500],
        "recommended_action": action,
        "sensor_id": sensor_id,
    }


async def classify_and_broadcast(
    *, http_summary: dict, sensor_id: str = "",
) -> None:
    """
    完整流程:LLM 分类 → 广播事件 → (高置信) 触发响应.
    供 http_linker 以 llm_enhancer.safe_dispatch 派发,主路径不等待.
    """
    verdict = await classify_session(
        http_summary=http_summary, sensor_id=sensor_id,
    )
    if verdict is None:
        return

    # 1. 广播事件 (前端可监听;审计 trail 由 trace_hook 自动留痕)
    try:
        from event_bus import event_bus
        event_bus.publish("data_security_llm_verdict", {
            "url": http_summary.get("url", "")[:200],
            "src_ip": http_summary.get("src_ip", ""),
            **verdict,
        })
    except Exception:
        pass

    # 2. 高置信 + 真敏感 → 仅当规则/传感器已命中时才开工单（LLM 不得单独处置）
    from ops_loop import llm_may_open_work_order
    rule_hit = bool(
        http_summary.get("rule_hit")
        or http_summary.get("dlp_hit")
        or http_summary.get("sensor_alert")
    )
    if (
        llm_may_open_work_order(rule_hit=rule_hit, llm_sensitive=verdict["is_sensitive"])
        and verdict["confidence"] >= _HIGH_CONF_THRESHOLD
        and verdict["category"] != "none"
    ):
        try:
            from models import async_session
            from work_order_service import work_order_service

            async with async_session() as s:
                await work_order_service.create_order(
                    s,
                    order_type="review",
                    title=f"[数据安全] {verdict['category']} 疑似外泄 {http_summary.get('url', '')[:100]}",
                    description=(
                        f"LLM 检测到敏感数据外泄:\n"
                        f"  URL: {http_summary.get('url', '')}\n"
                        f"  类别: {verdict['category']}\n"
                        f"  置信度: {verdict['confidence']}\n"
                        f"  误报概率: {verdict['false_positive_prob']}\n"
                        f"  理由: {verdict['rationale']}\n"
                        f"  建议动作: {verdict['recommended_action']}"
                    ),
                    priority="high",
                    created_by="llm_data_security",
                )
            logger.info(
                f"[LLM-DataSecurity] high-conf verdict → "
                f"work order created for {http_summary.get('url', '')[:100]}"
            )
        except Exception as e:
            logger.warning(f"[LLM-DataSecurity] create work order failed: {e}")


def _safe_float(v, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default