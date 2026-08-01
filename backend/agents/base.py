"""
Agent 基类 — 安全审计版

提供安全审计上下文构建方法 build_security_context()。
"""
import logging
from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from vector_store import vector_store
from sliding_window import sliding_window
from summary_compression import embedder, summary
from event_store import event_store, EventFilter, StoredEvent

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    def __init__(self, agent_id: str, display_name: str):
        self.agent_id = agent_id
        self.display_name = display_name

    @abstractmethod
    async def process(
        self, session: AsyncSession, user_input: str, session_id: str,
        agent_context: Optional[dict] = None
    ) -> dict:
        ...

    async def build_security_context(
        self, session: AsyncSession, session_id: str, query: str = "",
        max_tokens: int = 4000,
        agent_context: Optional[dict] = None,
        include_anomaly: bool = True,
        include_correlation: bool = True,
        include_evicted: bool = True,
    ) -> str:
        """
        安全审计上下文构建

        数据来源:
        1. event_store — 全量原始日志
        2. anomaly_detector — 异常检测报告
        3. correlation_engine — 攻击链关联结果
        4. sliding_window — 近期窗口消息
        5. 前序 Agent 输出
        """
        parts = []

        if include_anomaly:
            try:
                events = await event_store.query(
                    session, EventFilter(
                        session_id=session_id, limit=50,
                    )
                )
                anomaly_lines = []
                for evt in events:
                    if evt.anomaly_score > 0.3:
                        anomaly_lines.append(
                            f"  [#{evt.id}] [{evt.severity.upper()}] "
                            f"{evt.event_type} score={evt.anomaly_score:.3f} "
                            f"corr={evt.correlation_id or 'none'}"
                        )
                if anomaly_lines:
                    parts.append("## 异常事件标记")
                    parts.append(f"共 {len(anomaly_lines)} 条事件被标记为异常:")
                    parts.extend(anomaly_lines)
                    parts.append("")
            except Exception as e:
                logger.warning(f"Anomaly context failed: {e}")

        if include_correlation:
            try:
                from correlation_engine import correlation_engine
                corr_result = await correlation_engine.analyze(
                    session, session_id, time_window_minutes=1440
                )
                if corr_result.chains:
                    parts.append("## 攻击链检测")
                    for chain in corr_result.chains:
                        event_ids = [e["id"] for e in chain.events]
                        parts.append(
                            f"  🔗 [{chain.pattern_name}] "
                            f"置信度={chain.confidence:.2f} "
                            f"事件ID={event_ids}"
                        )
                    parts.append("")
            except Exception as e:
                logger.warning(f"Correlation context failed: {e}")

        if agent_context:
            pipeline_parts = []
            for key, label in [("analysis", "分析"), ("decision", "决策")]:
                val = agent_context.get(key)
                if val:
                    pipeline_parts.append(f"[{label} Agent 输出] {val[:500]}")
            if pipeline_parts:
                parts.append("## 前序审核流水线输出")
                parts.extend(pipeline_parts)
                parts.append("")

        try:
            window_msgs = await sliding_window.get_window(session_id)
            if window_msgs:
                parts.append("## 近期上下文（窗口内）")
                for m in window_msgs[-15:]:
                    role = m.get("role", "?")
                    content = m.get("content", "")[:200]
                    parts.append(f"  [{role}] {content}")
                parts.append("")
        except Exception as e:
            logger.warning(f"Window context failed: {e}")

        if include_evicted:
            try:
                evicted = await sliding_window.get_evicted(session_id, limit=20)
                if evicted:
                    parts.append(f"## 窗口已淘汰历史 ({len(evicted)} 条)")
                    for m in evicted[-5:]:
                        content = m.get("content", "")[:100]
                        parts.append(f"  {content}")
                    parts.append("")
            except Exception as e:
                logger.warning(f"Evicted context failed: {e}")

        parts.append(f"## 当前待审核事件\n{query}\n")

        result = "\n".join(parts)
        max_chars = max_tokens * 2
        if len(result) > max_chars:
            result = result[:max_chars] + (
                f"\n\n[上下文截断] 已达 token 上限({max_tokens})。"
                f"请通过 event_store.query() 获取完整原始日志。"
            )
        return result

    async def llm_chat(self, messages: list[dict]) -> str:
        from trace_hook import set_trace_context
        set_trace_context(operation="agent_chat", caller=self.agent_id)
        return await summary.llm.chat(messages)
