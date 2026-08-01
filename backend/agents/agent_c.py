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

        prompt = f"""你是安全报告专家。基于完整的审核流水线生成综合安全报告。

## 分析阶段结论
{analysis_result}

## 决策阶段结论
{decision_result}

## 安全上下文
{security_context if security_context else '无'}

## 原始输入
{user_input}

## 处理流水线
分析 Agent → 决策 Agent → 报告 Agent → 审查 Agent(后续)

## 报告要求
1. 汇总分析、决策阶段的完整结论
2. 如果发现前序阶段的遗漏，在报告中明确指出
3. 提供可供安全运维人员直接执行的行动项
4. 时间线和攻击链重建

{{"报告标题":"...","执行摘要":"...","威胁概述":{{"威胁列表":[],"最高严重度":"...","是否遗漏":true/false}},"攻击链重建":{{"时间线":[],"涉及IP":[],"攻击路径":"..."}},"处置建议":[],"待审查项目":["审查Agent需要关注的点..."],"报告完整内容":"..."}}"""

        result = await self.llm_chat([
            {
                "role": "system",
                "content": (
                    "你是一个专业的安全报告撰写专家。报告必须包含完整的威胁分析、"
                    "攻击链重建和处置建议。如果前序阶段有遗漏，必须在报告中指出。"
                    "严格按照 JSON 格式输出。"
                ),
            },
            {"role": "user", "content": prompt},
        ])

        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[最终报告] {result}"
        )

        embedding = await embedder.embed(user_input)
        await vector_store.store_memory(
            session, f"报告Agent生成: {user_input[:100]}", embedding,
            agent_id=self.agent_id, metadata={"type": "report"}
        )

        return {"agent": self.display_name, "result": result}
