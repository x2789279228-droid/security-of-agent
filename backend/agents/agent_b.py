import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseAgent
from sliding_window import sliding_window
from summary_compression import embedder
from vector_store import vector_store

logger = logging.getLogger(__name__)

class AgentB(BaseAgent):
    """决策 Agent（安全审计版）：基于分析结果 + 完整上下文做处置决策"""

    def __init__(self):
        super().__init__(agent_id="agent_b", display_name="决策 Agent")

    async def process(
        self, session: AsyncSession, user_input: str, session_id: str,
        agent_context: Optional[dict] = None
    ) -> dict:
        logger.info(f"AgentB processing: {user_input[:50]}...")

        analysis_result = (agent_context or {}).get("analysis", "（无）")

        # 安全审计上下文（含前序Agent输出）
        security_context = await self.build_security_context(
            session, session_id, query=user_input,
            max_tokens=3000,
            agent_context=agent_context,
            include_anomaly=True,
            include_correlation=True,
        )

        from prompts import render
        prompt = render("audit/agent_b_decision",
                        analysis_result=analysis_result,
                        security_context=security_context,
                        user_input=user_input)

        result = await self.llm_chat([
            {
                "role": "system",
                "content": render("audit/agent_b_decision_system"),
            },
            {"role": "user", "content": prompt},
        ])

        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[决策结果] {result}"
        )

        from memory_guard import structured_memory_content
        mem_text = structured_memory_content(
            "decision", result[:200], provenance_id=session_id,
        )
        embedding = await embedder.embed(mem_text)
        await vector_store.store_memory(
            session, mem_text, embedding,
            agent_id=self.agent_id, metadata={"type": "decision"},
            source_type="agent_output", provenance_id=session_id,
        )

        return {"agent": self.display_name, "result": result}
