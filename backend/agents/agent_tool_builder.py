"""
工具构建者 (Tool Builder) — Audit-LLM 第二层

职责：
  将 Decomposer 输出的抽象子任务(SubTask) 映射为具体可执行的工具调用(ToolCall)

设计原则：
  - 子任务→工具的映射是**确定性的**，用代码逻辑而非 LLM
  - 每个子任务类型对应固定的工具名称和参数构造规则
  - 模糊参数（如"相关IP"）由 Decomposer 或 LLM 解析

输入：list[SubTask]
输出：list[ToolCall]
"""
import logging

from audit_types import (
    SubTask, ToolCall,
    SUBTASK_QUERY_EVENTS, SUBTASK_ANALYZE_IP, SUBTASK_FIND_CHAINS,
    SUBTASK_CHECK_MEMORY, SUBTASK_KNOWLEDGE_SEARCH,
    SUBTASK_DEEP_ANALYZE, SUBTASK_RECHECK,
    SUBTASK_GET_WINDOW, SUBTASK_ENTITY_LINK,
    TOOL_EVENT_STORE_QUERY, TOOL_ANOMALY_BASELINE,
    TOOL_CORRELATION_CHAINS, TOOL_CORRELATION_TEMPORAL,
    TOOL_CORRELATION_ENTITY_LINK, TOOL_VECTOR_SEARCH,
    TOOL_KNOWLEDGE_SEARCH,
    TOOL_MEMORY_TREE_RELATED, TOOL_SLIDING_WINDOW, TOOL_SLIDING_EVICTED,
)

logger = logging.getLogger(__name__)


class ToolBuilder:
    """
    工具构建者

    build(sub_tasks, session_id, db_session) → list[ToolCall]
    """

    def __init__(self):
        # 子任务类型 → (工具名, 参数构造函数) 映射表
        self._mapping = {
            SUBTASK_QUERY_EVENTS: (TOOL_EVENT_STORE_QUERY, self._build_query_params),
            SUBTASK_ANALYZE_IP: (TOOL_ANOMALY_BASELINE, self._build_baseline_params),
            SUBTASK_FIND_CHAINS: (TOOL_CORRELATION_CHAINS, self._build_chain_params),
            SUBTASK_ENTITY_LINK: (TOOL_CORRELATION_ENTITY_LINK, self._build_entity_params),
            SUBTASK_CHECK_MEMORY: (TOOL_VECTOR_SEARCH, self._build_memory_params),
            SUBTASK_KNOWLEDGE_SEARCH: (TOOL_KNOWLEDGE_SEARCH, self._build_knowledge_params),
            SUBTASK_GET_WINDOW: (TOOL_SLIDING_WINDOW, self._build_window_params),
        }

    def build(
        self,
        sub_tasks: list[dict],
        session_id: str,
    ) -> list[ToolCall]:
        """
        将子任务列表构建为工具调用列表

        Args:
            sub_tasks: Decomposer 输出的子任务列表
            session_id: 会话ID

        Returns:
            list[ToolCall]
        """
        tool_calls = []
        call_idx = 0

        for st_dict in sub_tasks:
            st = SubTask(**st_dict)
            mapping = self._mapping.get(st.type)

            if mapping:
                tool_name, param_fn = mapping
                call_idx += 1
                args = param_fn(st.params, session_id)
                tool_calls.append(ToolCall(
                    call_id=f"c{call_idx}",
                    task_id=st.task_id,
                    tool=tool_name,
                    args=args,
                    priority=st.priority,
                ))
            elif st.type == SUBTASK_DEEP_ANALYZE:
                # 深度分析：这是一个特殊的"工具"，由 Executor 用 LLM 执行
                call_idx += 1
                event = st.params.get("event", {})
                tool_calls.append(ToolCall(
                    call_id=f"c{call_idx}",
                    task_id=st.task_id,
                    tool="llm.deep_analyze",
                    args={"event": event},
                    priority=st.priority,
                ))
            elif st.type == SUBTASK_RECHECK:
                # 复核：Executor 执行最后一步
                call_idx += 1
                tool_calls.append(ToolCall(
                    call_id=f"c{call_idx}",
                    task_id=st.task_id,
                    tool="llm.recheck",
                    args={},
                    priority=st.priority,
                ))
            else:
                logger.warning(f"Unknown sub-task type: {st.type}, skipping")

        # 记录依赖关系：task_id → 工具名称
        logger.info(
            f"ToolBuilder: built {len(tool_calls)} tool calls "
            f"from {len(sub_tasks)} sub-tasks"
        )
        for tc in tool_calls:
            logger.debug(f"  {tc.call_id}: {tc.tool} <- task {tc.task_id}")

        return tool_calls

    def _build_query_params(self, params: dict, session_id: str) -> dict:
        """构造事件查询参数"""
        return {
            "session_id": session_id,
            "src_ip": params.get("src_ip", ""),
            "dst_ip": params.get("dst_ip", ""),
            "event_type": params.get("event_type", ""),
            "severity": params.get("severity", ""),
            "event_ids": params.get("event_ids", []),
            "limit": params.get("limit", 100),
            "time_window_minutes": params.get("time_window_minutes", 60),
        }

    def _build_baseline_params(self, params: dict, session_id: str) -> dict:
        """构造IP基线查询参数"""
        return {
            "src_ip": params.get("src_ip", ""),
        }

    def _build_chain_params(self, params: dict, session_id: str) -> dict:
        """构造攻击链查询参数"""
        return {
            "session_id": session_id,
            "time_window_minutes": params.get("time_window_minutes", 1440),
        }

    def _build_entity_params(self, params: dict, session_id: str) -> dict:
        """构造实体关联参数"""
        return {
            "session_id": session_id,
            "time_window_minutes": params.get("time_window_minutes", 1440),
        }

    def _build_memory_params(self, params: dict, session_id: str) -> dict:
        """构造记忆检索参数"""
        return {
            "query": params.get("query", ""),
            "top_k": params.get("top_k", 5),
        }

    def _build_knowledge_params(self, params: dict, session_id: str) -> dict:
        """构造安全知识库检索参数（source 逗号分隔多库，由 decomposer 按威胁类型推荐）"""
        return {
            "query": params.get("query", ""),
            "threat_type": params.get("threat_type", ""),
            "severity": params.get("severity", ""),
            "source": params.get("source", ""),
            "top_k": params.get("top_k", 5),
        }

    def _build_window_params(self, params: dict, session_id: str) -> dict:
        """构造窗口查询参数"""
        return {
            "session_id": session_id,
        }


tool_builder = ToolBuilder()
