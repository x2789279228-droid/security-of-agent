"""钓鱼检测 — 统一风险评分引擎

将各检测器产出的 PhishingIndicator 列表聚合为最终 PhishingVerdict。
评分逻辑：
  1. 每条指标按 severity 映射基础分
  2. 同类指标取最高分 + 衰减叠加（避免同类重复刷分）
  3. 加权求和 → 归一化到 0-100
  4. 三级分类：safe(0-30) / suspicious(31-69) / phishing(70-100)

P0.S 升级: 支持 LLM 维度异步注入
  - aggregate_llm(rule_verdict, llm_indicator) 返回新 verdict
  - 仅在 risk_level in {suspicious, phishing} 时调用方触发 LLM
  - LLM 失败 → 返回原 verdict (0 副作用)
"""
from typing import Optional

from .models import PhishingIndicator, PhishingVerdict

# severity → 基础分
SEVERITY_SCORE: dict[str, float] = {
    "info": 2.0,
    "low": 8.0,
    "medium": 18.0,
    "high": 32.0,
    "critical": 50.0,
}

# 风险等级阈值
THRESHOLD_SUSPICIOUS = 30.0
THRESHOLD_PHISHING = 70.0


def _classify(score: float) -> str:
    if score >= THRESHOLD_PHISHING:
        return "phishing"
    if score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _confidence(score: float, indicator_count: int) -> float:
    """置信度：分数越高 + 指标越多 → 越确信"""
    base = min(score / 100.0, 1.0)
    diversity_bonus = min(indicator_count * 0.05, 0.2)
    return round(min(base + diversity_bonus, 1.0), 3)


def _suggested_actions(risk_level: str, indicators: list[PhishingIndicator]) -> list[str]:
    actions: list[str] = []
    categories = {i.category for i in indicators}

    if risk_level == "phishing":
        actions.append("立即阻断该来源，标记为钓鱼攻击")
        actions.append("通知安全团队进行溯源分析")
        if "url" in categories:
            actions.append("将相关 URL/域名加入黑名单")
        if "sender" in categories:
            actions.append("封禁发件人地址并报告邮件服务商")
        if "extension" in categories or "magic" in categories or "macro" in categories:
            actions.append("隔离该附件并通知邮件网关拦截同类文件")
        if "payment" in categories:
            actions.append("冻结相关支付通道，通知财务部门核实交易")
        if "executive" in categories or "financial" in categories:
            actions.append("通知被仿冒高管及财务部门，启动 BEC 应急响应")
        if "shortener" in categories:
            actions.append("解析短链真实目标并加入封禁列表")
        # LLM 维度触发的特殊响应
        if "llm_semantic" in categories:
            actions.append("LLM 复核产出的语义判定需人工 review 后入库")
    elif risk_level == "suspicious":
        actions.append("标记为可疑，建议人工复核")
        actions.append("暂不阻断，持续监控后续行为")
        if "encryption" in categories:
            actions.append("要求发件人提供未加密版本或说明加密原因")
        if "secrecy" in categories:
            actions.append("提醒收件人核实发件人身份，勿绕过审批流程")
        if "context" in categories:
            actions.append("核实二维码来源是否被篡改")
        # LLM 维度触发的特殊响应
        if "llm_semantic" in categories:
            actions.append("LLM 复核产出的语义判定需人工 review 后入库")
    else:
        actions.append("未发现明显钓鱼特征，正常放行")
    return actions


def aggregate(
    detection_type: str,
    target: str,
    indicators: list[PhishingIndicator],
    summary: str = "",
) -> PhishingVerdict:
    """将指标列表聚合为最终裁决。

    同类（category）指标：取最高分 + 其余按 0.3 衰减叠加，
    不同类之间直接求和，最终 cap 到 100。
    """
    if not indicators:
        return PhishingVerdict(
            detection_type=detection_type,
            target=target,
            risk_level="safe",
            confidence=0.0,
            score=0.0,
            indicators=[],
            summary=summary or "未检测到钓鱼指标",
            suggested_actions=["未发现明显钓鱼特征，正常放行"],
        )

    # 按 category 分组
    by_cat: dict[str, list[float]] = {}
    for ind in indicators:
        base = SEVERITY_SCORE.get(ind.severity, 5.0)
        ind.score = base
        by_cat.setdefault(ind.category, []).append(base)

    total = 0.0
    for _cat, scores in by_cat.items():
        scores_sorted = sorted(scores, reverse=True)
        cat_score = scores_sorted[0]
        for extra in scores_sorted[1:]:
            cat_score += extra * 0.3  # 衰减叠加
        total += cat_score

    score = round(min(total, 100.0), 1)
    risk_level = _classify(score)
    confidence = _confidence(score, len(indicators))

    # 按 score 降序排列指标
    indicators_sorted = sorted(indicators, key=lambda i: i.score, reverse=True)

    return PhishingVerdict(
        detection_type=detection_type,
        target=target,
        risk_level=risk_level,
        confidence=confidence,
        score=score,
        indicators=indicators_sorted,
        summary=summary,
        suggested_actions=_suggested_actions(risk_level, indicators_sorted),
    )


# ── P0.S LLM 维度二次聚合 ──

def aggregate_with_llm(
    rule_verdict: PhishingVerdict,
    llm_indicator: Optional[PhishingIndicator],
) -> PhishingVerdict:
    """
    在规则 verdict 基础上,把 LLM 维度指标加入后二次聚合.
    返回新 verdict (规则原 verdict 不被修改,符合不可变语义).
    llm_indicator=None 时直接返回原 verdict (降级).
    """
    if llm_indicator is None:
        return rule_verdict

    # 合并指标列表 + 重新聚合
    merged_indicators = list(rule_verdict.indicators) + [llm_indicator]
    # 复用 aggregate 的打分逻辑
    by_cat: dict[str, list[float]] = {}
    for ind in merged_indicators:
        base = SEVERITY_SCORE.get(ind.severity, 5.0)
        # llm_semantic 维度保留原 score (LLM 已自评)
        if ind.category == "llm_semantic" and ind.score:
            base = ind.score
        else:
            ind.score = base
        by_cat.setdefault(ind.category, []).append(base)

    total = 0.0
    for _cat, scores in by_cat.items():
        scores_sorted = sorted(scores, reverse=True)
        cat_score = scores_sorted[0]
        for extra in scores_sorted[1:]:
            cat_score += extra * 0.3
        total += cat_score

    new_score = round(min(total, 100.0), 1)
    new_level = _classify(new_score)
    new_conf = _confidence(new_score, len(merged_indicators))

    indicators_sorted = sorted(merged_indicators, key=lambda i: i.score, reverse=True)

    return PhishingVerdict(
        detection_type=rule_verdict.detection_type,
        target=rule_verdict.target,
        risk_level=new_level,
        confidence=new_conf,
        score=new_score,
        indicators=indicators_sorted,
        # 追加 LLM 标记到 summary
        summary=rule_verdict.summary + " + LLM 复核" if llm_indicator else rule_verdict.summary,
        suggested_actions=_suggested_actions(new_level, indicators_sorted),
    )
