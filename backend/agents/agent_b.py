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

        prompt = f"""你是安全决策专家。基于分析结果和完整上下文做出处置决策。

## 前一阶段分析结果
{analysis_result}

## 安全上下文
{security_context if security_context else '（无）'}

## 当前待决策事件
{user_input}

## 决策要求
1. 确认分析阶段的威胁判定是否完整
2. 如果分析Agent遗漏了威胁，需在决策中补充
3. 给出具体处置方案和优先级

{{"处置方案":[{{"操作":"阻断IP/隔离主机/告警升级/...","目标":"...","理由":"...","紧急度":"立即/小时内/当天"}}],"推荐方案":"...","风险提示":"...","优先级":"紧急/高/中/低","是否需要人工介入":true/false,"补充发现":"分析阶段遗漏的威胁...","决策依据":"..."}}"""

        result = await self.llm_chat([
            {
                "role": "system",
                "content": (
                    "你是一个理性的安全决策专家。如果你发现分析阶段遗漏了威胁，"
                    "必须在决策中补充。宁可升级不可降级。严格按照 JSON 格式输出。"
                ),
            },
            {"role": "user", "content": prompt},
        ])

        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[决策结果] {result}"
        )

        embedding = await embedder.embed(user_input)
        await vector_store.store_memory(
            session, f"决策Agent处理: {user_input[:100]}", embedding,
            agent_id=self.agent_id, metadata={"type": "decision"}
        )

        return {"agent": self.display_name, "result": result}
