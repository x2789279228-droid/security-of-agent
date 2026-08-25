"""
记忆树 (Memory Tree) — 安全审计改造版

核心变更：
  - 去掉所有有损压缩：叶子节点永远保留原始日志全文
  - 去掉重要性评分：改为关联分组（correlation_group）
  - 去掉合并摘要：改为建立关联关系
  - 上下文重建：返回所有节点，不做重要性过滤

设计原则：
  原始日志 = 证据（永不丢失）
  记忆树   = 索引（只建关联不压缩）
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select, desc, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models import MemoryTreeNode, SecurityEvent

logger = logging.getLogger(__name__)

# ── 关联分组类型 ──

class CorrelationGroup:
    """关联分组 — 替代原来的压缩路由"""
    TEMPORAL = "temporal"       # 时间窗口关联（同一源IP短时内多个事件）
    ATTACK_CHAIN = "chain"      # 攻击链关联（PORT_SCAN→BRUTE_FORCE→C2）
    SAME_ENTITY = "entity"      # 同一实体关联（同IP/同用户）
    ANOMALY_CLUSTER = "cluster" # 异常聚类

# ── 记忆树节点管理 ──

class MemoryTree:
    """
    记忆树 — 纯索引结构，不压缩内容。
    
    树结构用于表示事件之间的关联关系：
      root (session)
      ├── group: temporal_20260728_10.0.0.5
      │   ├── leaf: raw event 1 (PORT_SCAN)
      │   ├── leaf: raw event 2 (BRUTE_FORCE)
      │   └── leaf: raw event 3 (C2_BEACON)
      ├── group: anomaly_high_dns_traffic
      │   └── leaf: raw event 4 (DNS_QUERY × 1000)
      └── leaf: raw event 5 (standalone, no correlation yet)
    """

    async def add_leaf(
        self, session: AsyncSession, session_id: str,
        event: dict, event_text: str, token_count: int = 0,
        correlation_group: str = "",
    ) -> MemoryTreeNode:
        """添加事件叶子节点 — 永远保留原始内容"""
        node = MemoryTreeNode(
            session_id=session_id,
            parent_id=None,
            depth=0,
            node_type="leaf",
            content=event_text,                # 永远保留原始内容
            summary=None,                      # 不再需要摘要
            importance=1.0,                    # 所有节点同等重要
            compression_route=correlation_group or "independent",
            token_count=token_count or len(event_text),
            metadata_={
                "event": event.get("event"),
                "severity": event.get("severity"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "correlation_group": correlation_group,
                "original_severity": event.get("severity"),
            },
        )
        session.add(node)
        await session.commit()
        await session.refresh(node)
        logger.info(f"Added leaf node {node.id} for {session_id}: "
                    f"{event.get('event','?')} ({event.get('severity','?')})")
        return node

    async def link_to_group(
        self, session: AsyncSession, session_id: str,
        leaf_ids: list[int], group_type: str, group_label: str,
    ) -> MemoryTreeNode:
        """将多个叶子节点关联到一个分组节点下 — 替代原来的合并压缩"""
        group_node = MemoryTreeNode(
            session_id=session_id,
            parent_id=None,
            depth=0,
            node_type="summary",       # 复用 summary 类型，但性质变为"分组"
            content=None,
            summary=f"[{group_type}] {group_label}",
            importance=1.0,
            compression_route=group_type,
            token_count=len(group_label),
            metadata_={
                "type": "correlation_group",
                "group_type": group_type,
                "child_count": len(leaf_ids),
                "child_ids": leaf_ids,
            },
        )
        session.add(group_node)
        await session.commit()
        await session.refresh(group_node)

        for leaf_id in leaf_ids:
            leaf = await session.get(MemoryTreeNode, leaf_id)
            if leaf:
                leaf.parent_id = group_node.id
        await session.commit()

        logger.info(f"Linked {len(leaf_ids)} leaves to group {group_node.id} "
                    f"({group_type}: {group_label})")
        return group_node

    async def reconstruct_context(
        self, session: AsyncSession, session_id: str,
        query: str = "", max_tokens: int = 2000,
        for_llm: bool = False,
    ) -> list[dict]:
        """
        重建上下文 — 返回所有节点，不做重要性过滤。
        
        与改造前的关键区别：
        - 不按 importance 剪枝
        - 不返回压缩摘要替换原始内容
        - 所有 leaf 节点都返回完整 content
        """
        context: list[dict] = []
        tokens_used = [0]

        # 1. 获取所有顶级节点
        stmt = (
            select(MemoryTreeNode)
            .where(
                MemoryTreeNode.session_id == session_id,
                MemoryTreeNode.parent_id.is_(None),
            )
            .order_by(MemoryTreeNode.created_at)
        )
        result = await session.execute(stmt)
        top_nodes = result.scalars().all()

        # 2. 递归展开 — 全部展开，不做重要性过滤
        for node in top_nodes:
            if tokens_used[0] >= max_tokens:
                logger.warning(f"Context reconstruction hit max_tokens={max_tokens} for {session_id}")
                context.append({
                    "role": "truncated",
                    "depth": 0,
                    "content": f"[截断] 上下文已达上限({max_tokens}tokens)，部分事件未包含",
                    "importance": 1.0,
                    "route": "truncated",
                })
                break
            await self._expand_node(
                session, node, context, tokens_used, max_tokens, for_llm=for_llm,
            )

        return context

    async def _expand_node(
        self, session: AsyncSession, node: MemoryTreeNode,
        context: list[dict], tokens_used: list[int], max_tokens: int,
        for_llm: bool = False,
    ):
        if tokens_used[0] >= max_tokens:
            return

        # 获取子节点
        stmt = (
            select(MemoryTreeNode)
            .where(MemoryTreeNode.parent_id == node.id)
            .order_by(MemoryTreeNode.created_at)
        )
        result = await session.execute(stmt)
        children = result.scalars().all()

        if not children:
            # 叶子节点 → 返回完整原始内容
            content = node.content or ""
            if content:
                if for_llm:
                    from memory_guard import sanitize_untrusted_text
                    content = sanitize_untrusted_text(content, max_len=1500)
                meta = node.metadata_ or {}
                context.append({
                    "role": node.node_type,
                    "depth": node.depth,
                    "content": content,
                    "importance": 1.0,
                    "route": node.compression_route,
                    "event_type": meta.get("event", ""),
                    "severity": meta.get("severity", ""),
                    "correlation_group": meta.get("correlation_group", ""),
                    "node_id": node.id,
                })
                tokens_used[0] += len(content)
            return

        # 有子节点 → 分组节点，展开所有子节点
        for child in children:
            if tokens_used[0] >= max_tokens:
                break
            await self._expand_node(
                session, child, context, tokens_used, max_tokens, for_llm=for_llm,
            )

    async def find_related(
        self, session: AsyncSession, session_id: str,
        src_ip: str = "", event_type: str = "",
        time_window_minutes: int = 60,
    ) -> list[dict]:
        """
        查找关联事件 — 用于 Agent 回溯攻击链
        
        支持：
        - 同 IP 在时间窗口内的所有事件
        - 同类型事件在所有 IP 上的分布
        """
        stmt = (
            select(MemoryTreeNode)
            .where(
                MemoryTreeNode.session_id == session_id,
                MemoryTreeNode.node_type == "leaf",
            )
        )
        if src_ip:
            stmt = stmt.where(
                MemoryTreeNode.metadata_["src_ip"].as_string() == src_ip
            )
        result = await session.execute(stmt)
        nodes = result.scalars().all()

        if time_window_minutes:
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
            nodes = [n for n in nodes if n.created_at >= cutoff]

        return [
            {
                "id": n.id,
                "content": n.content or "",
                "event_type": (n.metadata_ or {}).get("event", ""),
                "severity": (n.metadata_ or {}).get("severity", ""),
                "src_ip": (n.metadata_ or {}).get("src_ip", ""),
                "created_at": n.created_at.isoformat(),
                "correlation_group": n.compression_route,
            }
            for n in nodes
        ]

    async def get_tree_stats(
        self, session: AsyncSession, session_id: str
    ) -> dict:
        """记忆树统计"""
        total = await session.execute(
            select(func.count(MemoryTreeNode.id)).where(
                MemoryTreeNode.session_id == session_id
            )
        )
        leaves = await session.execute(
            select(func.count(MemoryTreeNode.id)).where(
                MemoryTreeNode.session_id == session_id,
                MemoryTreeNode.node_type == "leaf",
            )
        )
        groups = await session.execute(
            select(func.count(MemoryTreeNode.id)).where(
                MemoryTreeNode.session_id == session_id,
                MemoryTreeNode.node_type == "summary",
            )
        )
        return {
            "total_nodes": total.scalar() or 0,
            "leaves": leaves.scalar() or 0,
            "groups": groups.scalar() or 0,
        }

    async def get_unlinked_leaves(
        self, session: AsyncSession, session_id: str
    ) -> list[MemoryTreeNode]:
        """获取未关联到任何分组的独立叶子节点 — 候选关联对象"""
        stmt = (
            select(MemoryTreeNode)
            .where(
                MemoryTreeNode.session_id == session_id,
                MemoryTreeNode.node_type == "leaf",
                MemoryTreeNode.parent_id.is_(None),
                MemoryTreeNode.compression_route == "independent",
            )
            .order_by(MemoryTreeNode.created_at)
        )
        result = await session.execute(stmt)
        return result.scalars().all()


memory_tree = MemoryTree()
