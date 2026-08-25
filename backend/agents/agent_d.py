"""
审查 Agent (Agent-D) — 安全审计的兜底机制

设计目的：
  Agent A/B/C 完成流水线审核后，Agent-D 独立运行，
  专门检查"被前序 Agent 忽略或低估的可疑事件"。

触发条件：
  1. 每次批量审核完成后自动触发
  2. 异常检测器标记了 anomaly 但前序 Agent 未告警的事件
  3. 攻击链关联引擎发现了新链但未被审核的事件

工作流程：
  1. 从 event_store 获取所有未审核或低分审核事件
  2. 从 anomaly_detector 获取异常检测报告
  3. 从 correlation_engine 获取攻击链
  4. 用 LLM 审查：是否遗漏了应该告警的事件
  5. 输出：遗漏列表 + 原因 + 建议处置

核心设计：
  - Agent-D 看到的是"前序 Agent 的输出 + 异常报告 + 原始事件"
  - 它不需要从头审核，只需要"找不同"——前序认为安全但实际危险的事件
"""
import json
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseAgent
from event_store import event_store, EventFilter
from anomaly_detector import anomaly_detector
from correlation_engine import correlation_engine
from sliding_window import sliding_window

logger = logging.getLogger(__name__)


class AgentD(BaseAgent):
    """审查 Agent：检查前序流水线是否遗漏了可疑事件"""

    def __init__(self):
        super().__init__(agent_id="agent_d", display_name="审查 Agent")

    async def process(
        self, session: AsyncSession, user_input: str, session_id: str,
        agent_context: Optional[dict] = None
    ) -> dict:
        logger.info(f"AgentD (审查) processing for {session_id}...")

        # 1. 获取异常检测报告
        anomaly_events = await event_store.get_unreviewed_anomalies(
            session, session_id, min_score=0.5, limit=50
        )

        # 2. 获取攻击链
        corr_result = await correlation_engine.analyze(
            session, session_id, time_window_minutes=1440
        )

        # 3. 获取已审核事件的原始数据
        analyzed_events = await event_store.query(
            session, EventFilter(session_id=session_id, limit=200)
        )

        # 4. 获取窗口淘汰记录（可能包含被遗漏的重要事件）
        evicted = await sliding_window.get_evicted(session_id, limit=50)

        # 5. 构建审查上下文
        context_parts = []

        context_parts.append(f"## 待复查事件（异常标记）")
        context_parts.append(f"共 {len(anomaly_events)} 条被异常检测器标记但尚未审核的事件:")
        for evt in anomaly_events[:20]:
            context_parts.append(
                f"  [#{evt.id}] [{evt.severity.upper()}] {evt.event_type} "
                f"score={evt.anomaly_score:.3f} {evt.message[:100]}"
            )
        context_parts.append("")

        if corr_result.chains:
            context_parts.append("## 未审核攻击链")
            for chain in corr_result.chains:
                context_parts.append(
                    f"  🔗 [{chain.pattern_name}] "
                    f"置信度={chain.confidence:.2f} "
                    f"({len(chain.events)}步, {chain.time_span_minutes:.0f}分钟)"
                )
                for evt in chain.events:
                    context_parts.append(
                        f"    [{evt['severity'].upper()}] {evt['event_type']} "
                        f"#{evt['id']} {evt['message'][:80]}"
                    )
            context_parts.append("")

        if evicted:
            suspicious_evicted = [
                m for m in evicted
                if any(kw in m.get("content", "").upper()
                       for kw in ["C2", "MALWARE", "EXFIL", "BEACON",
                                   "RANSOM", "ATTACK", "BRUTE", "ANOMALY"])
            ]
            if suspicious_evicted:
                context_parts.append(
                    f"## 窗口淘汰事件中的可疑项 ({len(suspicious_evicted)} 条)"
                )
                for m in suspicious_evicted[:10]:
                    context_parts.append(f"  {m.get('content', '')[:150]}")
                context_parts.append("")

        # 6. 前序审核结果
        ctx = agent_context or {}
        prev_analysis = ctx.get("analysis", "")
        prev_decision = ctx.get("decision", "")
        prev_report = ctx.get("report", "")
        context_parts.append("## 前序审核结果")
        context_parts.append(f"分析: {prev_analysis[:300]}" if prev_analysis else "分析: (无)")
        context_parts.append(f"决策: {prev_decision[:300]}" if prev_decision else "决策: (无)")
        context_parts.append(f"报告: {prev_report[:300]}" if prev_report else "报告: (无)")
        context_parts.append("")

        context_parts.append(f"## 审查指令")
        context_parts.append(
            "请严格审查以上所有信息，回答以下问题：\n"
            "1. 前序 Agent 是否遗漏了任何应该告警的事件？\n"
            "2. 异常检测器标记的事件中，有哪些是真的威胁？\n"
            "3. 攻击链是否完整？是否有更多未被关联的事件？\n"
            "4. 窗口淘汰事件中是否可能有被忽略的攻击信号？\n\n"
            "请输出 JSON 格式，包含：\n"
            "- missed_events: 遗漏的事件列表（含ID、原因、建议操作）\n"
            "- false_positives: 被异常标记但实际无害的事件ID列表\n"
            "- new_chains: 发现的新攻击链\n"
            "- overall_assessment: 整体审核评估\n"
            "- confidence: 置信度(0-1)\n"
            "- action_required: 是否需要人工介入(true/false)"
        )

        context = "\n".join(context_parts)

        # 7. LLM 审查
        from prompts import render
        prompt = render("audit/agent_d_audit", context=context)

        result = await self.llm_chat([
            {
                "role": "system",
                "content": render("audit/agent_d_audit_system"),
            },
            {"role": "user", "content": prompt},
        ])

        # 8. 记录审查结果
        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[审查结果] {result}"
        )

        logger.info(f"AgentD review complete: {result[:100]}...")

        return {"agent": self.display_name, "result": result}
