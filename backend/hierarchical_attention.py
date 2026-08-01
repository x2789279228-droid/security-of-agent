"""
层级化上下文组织 — 安全审计改造版

核心变更：
  - 去掉"注意力预算分配"（按重要性分配token是信息丢失的根源）
  - 改为"完整事件列表 + 关联标记"
  - 所有事件平铺展示，不做截断
  - 保留 tree 结构仅用于展示关联关系

设计原则：
  Agent 应该看到所有事件，自行判断哪些重要。
  系统不替 Agent 做"重要性过滤"。
"""
import logging
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ContextItem:
    """上下文条目"""
    def __init__(self, level: str, content: str, importance: float = 1.0,
                 source: str = "", group_key: str = "",
                 event_type: str = "", severity: str = ""):
        self.level = level
        self.content = content
        self.importance = 1.0          # 所有条目同等重要
        self.source = source
        self.group_key = group_key
        self.event_type = event_type
        self.severity = severity
        self.token_estimate = max(1, len(content) // 2)

    def __repr__(self):
        return f"[{self.level}][{self.source}] {self.content[:40]}"


class HierarchicalAttention:
    """
    层级化上下文组织器 — 安全审计版
    
    不再模拟 Transformer 注意力。
    改为按实际层级组织事件列表：
    
    📋 会话全景
    ━━━━━━━━━━━━━━━━━━
    🎯 关联组 1: 时间窗口关联 (IP: 10.0.0.5)
      ├─ [CRITICAL] C2_BEACON (原始)
      ├─ [HIGH] BRUTE_FORCE (原始)
      └─ [INFO] DNS_QUERY (原始)
    ━━━━━━━━━━━━━━━━━━
    🎯 关联组 2: 攻击链
      ├─ [CRITICAL] DATA_EXFIL (原始)
    ━━━━━━━━━━━━━━━━━━
    📄 独立事件
      ├─ [INFO] USER_LOGIN (原始)
    """
    def __init__(self, max_tokens: int = 4000):
        self.max_tokens = max_tokens

    def collect(self, tree_nodes: list[dict] = None,
                window_msgs: list[dict] = None,
                memories: list[str] = None,
                session_summary: str = None) -> dict:
        """收集所有上下文条目 — 不做重要性过滤"""
        result = {
            "summary": [],
            "groups": [],      # 关联分组
            "events": [],      # 独立事件
            "memories": [],    # 向量检索记忆
        }

        # 1. 会话摘要（如果有）
        if session_summary:
            result["summary"].append(
                ContextItem("SUMMARY", session_summary[:500],
                            source="session_summary")
            )

        # 2. 树节点 — 按关联分组组织
        if tree_nodes:
            groups = {}
            for n in tree_nodes:
                cg = n.get("correlation_group", n.get("route", "independent"))
                if cg and cg != "independent":
                    if cg not in groups:
                        groups[cg] = []
                    groups[cg].append(n)
                else:
                    result["events"].append(n)

            for group_key, nodes in groups.items():
                result["groups"].append({
                    "key": group_key,
                    "nodes": nodes,
                })

        # 3. 窗口消息
        if window_msgs:
            for m in window_msgs[-10:]:
                role = m.get("role", "?")
                content = m.get("content", "")[:300]
                result["events"].append({
                    "role": "event",
                    "depth": 0,
                    "content": f"[{role}] {content}",
                    "importance": 1.0,
                    "route": "window",
                })

        # 4. 向量记忆
        if memories:
            for i, mem in enumerate(memories[:5]):
                result["memories"].append(
                    ContextItem("MEMORY", mem[:300],
                                source=f"memory_{i}")
                )

        logger.info(f"Collected {len(result['summary'])} summaries, "
                    f"{len(result['groups'])} groups, "
                    f"{len(result['events'])} events, "
                    f"{len(result['memories'])} memories")
        return result

    def linearize(self, collected: dict) -> str:
        """
        线性化为 prompt 文本。
        按"关联分组 → 独立事件 → 记忆"组织，不截断。
        """
        parts = ["## 完整安全事件上下文（全部保留，无过滤）\n"]

        # 会话摘要
        if collected["summary"]:
            parts.append("### 会话摘要")
            for s in collected["summary"]:
                parts.append(f"> {s.content}")
            parts.append("")

        # 关联分组（攻击链）
        if collected["groups"]:
            parts.append("### 攻击链 / 事件关联分组")
            for g in collected["groups"]:
                group_key = g["key"]
                nodes = g["nodes"]
                severities = [n.get("severity", "?") for n in nodes]
                types = [n.get("event_type", "?") for n in nodes]
                parts.append(f"**分组: {group_key}** ({', '.join(types)})")
                for n in nodes:
                    sev = n.get("severity", "").upper()
                    et = n.get("event_type", "")
                    content = n.get("content", n.get("summary", ""))[:300]
                    parts.append(f"  [{sev}] [{et}] {content}")
            parts.append("")

        # 独立事件
        if collected["events"]:
            parts.append("### 独立事件")
            for evt in collected["events"]:
                if isinstance(evt, dict):
                    sev = evt.get("severity", "").upper()
                    et = evt.get("event_type", "")
                    content = evt.get("content", "")[:300]
                    parts.append(f"  [{sev}] [{et}] {content}")
                else:
                    parts.append(f"  {str(evt)[:300]}")
            parts.append("")

        # 记忆
        if collected["memories"]:
            parts.append("### 相关记忆")
            for m in collected["memories"]:
                parts.append(f"  - {m.content[:200]}")
            parts.append("")

        result = "\n".join(parts)
        total_chars = len(result)
        logger.info(f"Linearized context: {total_chars} chars, "
                    f"~{total_chars // 2} estimated tokens")
        return result

    def build_prompt_context(self, tree_nodes: list[dict] = None,
                             window_msgs: list[dict] = None,
                             memories: list[str] = None,
                             session_summary: str = None) -> str:
        """完整流水线：收集 → 线性化"""
        collected = self.collect(tree_nodes, window_msgs, memories, session_summary)
        return self.linearize(collected)


hierarchical_attention = HierarchicalAttention(max_tokens=4000)
