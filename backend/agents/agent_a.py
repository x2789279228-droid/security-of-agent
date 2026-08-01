import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseAgent
from sliding_window import sliding_window
from summary_compression import embedder
from vector_store import vector_store

logger = logging.getLogger(__name__)

class AgentA(BaseAgent):
    """分析 Agent（安全审计版）：基于完整上下文 + 异常报告做分析"""

    def __init__(self):
        super().__init__(agent_id="agent_a", display_name="分析 Agent")

    async def process(
        self, session: AsyncSession, user_input: str, session_id: str,
        agent_context: Optional[dict] = None
    ) -> dict:
        logger.info(f"AgentA processing: {user_input[:50]}...")

        # 使用安全审计上下文（完整原始数据 + 异常检测 + 关联引擎）
        security_context = await self.build_security_context(
            session, session_id, query=user_input,
            max_tokens=4000,
            agent_context=agent_context,
            include_anomaly=True,
            include_correlation=True,
        )

        prompt = f"""你是安全分析专家。请基于完整的上下文信息分析安全事件，输出 JSON 格式的分析结果。

## 安全上下文（完整事件 + 异常标记 + 攻击链）
{security_context if security_context else '（无）'}

## 当前待分析事件
{user_input}

## 分析要求
1. 仔细查看异常检测标记的事件
2. 确认攻击链的完整性
3. 注意低严重度事件的组合风险
4. 如果发现被遗漏的威胁，务必标记

{{"威胁判定":"是/否/疑似","威胁类型":"C2/DDoS/数据外泄/横向移动/勒索软件/其他","影响评估":"...","涉及实体":{{"src_ip":"...","dst_ip":"..."}},"置信度":0.0-1.0,"分析摘要":"...","需要紧急处理":true/false,"遗漏告警":["之前未识别的事件描述..."]}}"""

        result = await self.llm_chat([
            {
                "role": "system",
                "content": (
                    "你是一个严谨的安全分析专家。分析时必须基于完整上下文，"
                    "注意低严重度事件的组合风险。宁可误报不可漏报。"
                    "严格按照 JSON 格式输出。"
                ),
            },
            {"role": "user", "content": prompt},
        ])

        await sliding_window.add_message(
            session_id, self.agent_id, "assistant",
            f"[分析结果] {result}"
        )

        embedding = await embedder.embed(user_input)
        await vector_store.store_memory(
            session, f"分析Agent处理: {user_input[:100]}", embedding,
            agent_id=self.agent_id, metadata={"type": "analysis"}
        )

        return {"agent": self.display_name, "result": result}
