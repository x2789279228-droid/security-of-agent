import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseAgent
from sliding_window import sliding_window
from summary_compression import embedder, summary
from vector_store import vector_store

logger = logging.getLogger(__name__)

class AgentC(BaseAgent):
    """报告 Agent（安全审计版）：汇总完整审核流水线 + 生成综合报告"""

    def __init__(self):
        super().__init__(agent_id="agent_c", display_name="报告 Agent")

    async def process(
        self, session: AsyncSession, user_input: str, session_id: str,
        agent_context: Optional[dict] = None
    ) -> dict:
        logger.info(f"AgentC processing: {user_input[:50]}...")

        ctx = agent_context or {}
        analysis_result = ctx.get("analysis", "（无）")
        decision_result = ctx.get("decision", "（无）")

        # 安全审计上下文（完整流水线 + 关联结果）
        security_context = await self.build_security_context(
            session, session_id, query=user_input,
            max_tokens=3000,
            agent_context=agent_context,
            include_anomaly=True,
            include_correlation=True,
        )

        from prompts import render
        prompt = render("audit/agent_c_report",
                        analysis_result=analysis_result,
                        decision_result=decision_result,
                        security_context=security_context,
                        user_input=user_input)

        result = await self.llm_chat([
            {
                "role": "system",
                "content": render("audit/agent_c_report_system"),
            },
            {"role": "user", "content": prompt},
        ])

        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[最终报告] {result}"
        )

        from memory_guard import structured_memory_content
        mem_text = structured_memory_content(
            "report", result[:200], provenance_id=session_id,
        )
        embedding = await embedder.embed(mem_text)
        await vector_store.store_memory(
            session, mem_text, embedding,
            agent_id=self.agent_id, metadata={"type": "report"},
            source_type="agent_output", provenance_id=session_id,
        )

        return {"agent": self.display_name, "result": result}
