"""
统一工具注册入口 (ToolRegistry)

为 Audit-LLM 的 Tool Builder 和 Executor 提供统一工具接口。
所有工具函数在此注册，Tool Builder 通过工具名称查找，Executor 通过名称调用。

设计原则：
  - 每个工具是一个异步函数，接收 **kwargs
  - 工具注册时附带元信息（参数描述、返回类型、预估耗时）
  - Executor 根据工具信息做并行调度决策

初始化策略:
  - D2 改造：模块加载时仍自动调 init_tool_registry() 保持向后兼容
  - 加 _initialized 守门防止重复注册与日志噪音
  - 显式 init_tool_registry() 调用幂等（多次调用只首次注册）
"""
import logging
import time
from typing import Any, Callable, Coroutine, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from event_store import event_store, EventFilter
from anomaly_detector import anomaly_detector
from correlation_engine import correlation_engine
from vector_store import vector_store
from memory_tree import memory_tree
from sliding_window import sliding_window
from summary_compression import embedder

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    工具注册表

    用法:
        registry = ToolRegistry()
        result = await registry.execute("event_store.query",
                                         session=session,
                                         session_id="xxx",
                                         src_ip="10.0.0.5")
    """

    def __init__(self):
        self._tools: dict[str, dict] = {}
        # D2: 守门标志 — init_tool_registry() 只首次生效，幂等
        self._initialized = False

    def register(
        self,
        name: str,
        fn: Callable[..., Coroutine],
        description: str = "",
        category: str = "data",
        estimated_ms: int = 100,
        timeout_ms: int = 30000,
    ):
        """注册一个工具"""
        self._tools[name] = {
            "fn": fn,
            "description": description,
            "category": category,   # "data" | "analysis" | "search"
            "estimated_ms": estimated_ms,
            "timeout_ms": timeout_ms,
        }
        logger.info(f"Registered tool: {name} ({category})")

    async def execute(self, name: str, **kwargs) -> Any:
        """执行工具调用"""
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")

        start = time.time()
        try:
            result = await tool["fn"](**kwargs)
            duration = (time.time() - start) * 1000
            logger.info(f"Tool {name} completed in {duration:.0f}ms")
            return result
        except Exception as e:
            duration = (time.time() - start) * 1000
            logger.error(f"Tool {name} failed after {duration:.0f}ms: {e}")
            raise

    def get_info(self, name: str) -> Optional[dict]:
        """获取工具元信息"""
        return self._tools.get(name)

    def list_tools(self, category: str = "") -> list[str]:
        """列出所有工具，可选按类别筛选"""
        if category:
            return [
                n for n, t in self._tools.items()
                if t["category"] == category
            ]
        return list(self._tools.keys())

    def estimate_duration(self, names: list[str]) -> int:
        """估算一组工具的总执行时间（用于并行调度决策）"""
        total = 0
        for name in names:
            tool = self._tools.get(name)
            if tool:
                total += tool["estimated_ms"]
        return total


# ── 全局单例 ──

tool_registry = ToolRegistry()


# ── 工具实现（注册到 registry） ──

async def _event_store_query(
    session: AsyncSession,
    session_id: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    event_type: str = "",
    severity: str = "",
    event_ids: list[int] = None,
    limit: int = 100,
    time_window_minutes: int = 0,
) -> list[dict]:
    """查询完整原始事件"""
    from datetime import datetime, timezone, timedelta

    # 如果传入了 event_ids，按 ID 精确查询
    if event_ids:
        from sqlalchemy import select
        from models import SecurityEvent
        stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        result = await session.execute(stmt)
        events = result.scalars().all()
        return [
            {
                "id": e.id, "event_type": e.event_type,
                "severity": e.severity, "src_ip": e.src_ip or "",
                "dst_ip": e.dst_ip or "", "message": (e.message or "")[:200],
                "anomaly_score": (e.raw_data or {}).get("_anomaly_score", 0.0),
                "created_at": e.created_at.isoformat() if e.created_at else "",
            }
            for e in events
        ]

    time_start = None
    if time_window_minutes > 0:
        time_start = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    events = await event_store.query(
        session, EventFilter(
            session_id=session_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type,
            severity=severity,
            time_start=time_start,
            limit=limit,
        )
    )
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "message": e.message[:200],
            "anomaly_score": e.anomaly_score,
            "created_at": e.created_at,
        }
        for e in events
    ]


async def _anomaly_baseline(session_id: str = "", src_ip: str = "", **kwargs) -> dict:
    """获取实体的异常检测基线"""
    # anomaly_detector 维护着内存基线，直接查询
    bl = anomaly_detector.baselines.get("src_ip", {}).get(src_ip)
    if not bl:
        return {"src_ip": src_ip, "status": "no_baseline"}
    return {
        "src_ip": src_ip,
        "total_count": bl.total_count,
        "first_seen": bl.first_seen,
        "last_seen": bl.last_seen,
        "hourly_distribution": bl.hourly_counts,
        "event_types": list(bl.event_types),
    }


async def _correlation_chains(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 1440,
) -> list[dict]:
    """获取攻击链"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=time_window_minutes
    )
    return [
        {
            "chain_id": c.chain_id,
            "pattern_name": c.pattern_name,
            "confidence": c.confidence,
            "event_ids": [e["id"] for e in c.events],
            "time_span_minutes": c.time_span_minutes,
            "alert": c.alert,
        }
        for c in result.chains
    ]


async def _correlation_temporal(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 60,
) -> list[dict]:
    """获取时间窗口事件分组"""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select
    from models import SecurityEvent

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.session_id == session_id,
            SecurityEvent.created_at >= cutoff,
        )
        .order_by(SecurityEvent.created_at)
    )
    result = await session.execute(stmt)
    events = result.scalars().all()

    # 按 IP 分组
    from collections import defaultdict
    by_ip = defaultdict(list)
    for evt in events:
        by_ip[evt.src_ip or "unknown"].append({
            "id": evt.id, "type": evt.event_type, "severity": evt.severity,
            "src_ip": evt.src_ip, "created_at": evt.created_at.isoformat(),
        })

    groups = []
    for ip, ip_events in by_ip.items():
        if len(ip_events) >= 2:
            groups.append({
                "src_ip": ip,
                "count": len(ip_events),
                "types": list(set(e["type"] for e in ip_events)),
                "events": ip_events,
            })

    return groups[:20]


async def _correlation_entity_link(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 1440,
) -> list[dict]:
    """获取实体图关联"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=time_window_minutes
    )
    return result.entity_links


async def _vector_search(
    session: AsyncSession,
    query: str = "",
    top_k: int = 5,
) -> list[dict]:
    """向量检索语义相关记忆（memories 表，通用记忆）

    note: agent 记忆是自指语义(doc 与 query 同源), 保持 db-db 对称编码, 与写入端一致;
    不对称检索(query vs db)仅适用于 knowledge 知识库这类"文档↔自然语言问题"场景。"""
    embedding = await embedder.embed(query)
    memories = await vector_store.search_similar(
        session, embedding, top_k=top_k, for_llm=True,
    )
    from memory_guard import memory_trust_value
    return [
        {"id": m.id, "content": m.content[:200], "agent_id": m.agent_id,
         "created_at": m.created_at.isoformat(),
         "trust": memory_trust_value(m),
         "source_type": getattr(m, "source_type", "") or "",
         }
        for m in memories
    ]


async def _knowledge_search(
    session: AsyncSession,
    query: str = "",
    threat_type: str = "",
    severity: str = "",
    top_k: int = 5,
    **kwargs,
) -> list[dict]:
    """检索安全知识库（knowledge_chunks 表，MITRE ATT&CK / CAPEC / 预置知识）"""
    from rag import retriever as rag_retriever

    query_embedding = None
    if query:
        query_embedding = await embedder.embed(query, type_="query")  # 不对称检索: 查询查库

    result = await rag_retriever.retrieve(
        session,
        query=query,
        query_embedding=query_embedding,
        threat_type=threat_type,
        severity=severity,
        top_k=top_k,
        min_score=0.4,
    )

    # LLM 重排（当结果 > 2 条时）
    if len(result.chunks) > 2 and query:
        result.chunks = await rag_retriever.rerank(query, result.chunks, top_k=top_k)

    return [
        {
            "id": c["id"],
            "title": c.get("title", ""),
            "content": c.get("content", ""),
            "source": c.get("source", ""),
            "threat_types": c.get("threat_types", []),
            "severity": c.get("severity", ""),
            "score": c.get("score", 0),
            "strategy": c.get("strategy", ""),
        }
        for c in result.chunks
    ]


async def _memory_tree_related(
    session: AsyncSession,
    session_id: str = "",
    src_ip: str = "",
    event_type: str = "",
    time_window_minutes: int = 60,
) -> list[dict]:
    """获取记忆树关联事件"""
    return await memory_tree.find_related(
        session, session_id,
        src_ip=src_ip, event_type=event_type,
        time_window_minutes=time_window_minutes,
    )


async def _sliding_window_get(session_id: str = "", **kwargs) -> list[dict]:
    """获取滑动窗口近期上下文"""
    return await sliding_window.get_window(session_id)


async def _sliding_window_evicted(session_id: str = "", limit: int = 50, **kwargs) -> list[dict]:
    """获取被滑窗淘汰的历史消息"""
    return await sliding_window.get_evicted(session_id, limit=limit)


# ── 注册所有工具 ──

def init_tool_registry():
    """初始化并注册所有可用工具

    D2 改造：加 _initialized 守门，使该函数幂等
    - 多次调用只首次注册，避免日志噪音和重复覆盖
    - reload 时仍可强制触发：手动重置 tool_registry._initialized = False 后再调
    """
    if tool_registry._initialized:
        logger.debug(
            f"Tool registry already initialized "
            f"({len(tool_registry._tools)} tools) — skipping re-registration"
        )
        return

    tool_registry.register(
        "event_store.query", _event_store_query,
        description="查询完整原始事件（支持按IP/类型/严重度/时间窗口筛选）",
        category="data", estimated_ms=50,
    )
    tool_registry.register(
        "anomaly.baseline", _anomaly_baseline,
        description="获取源IP的异常检测基线（历史行为统计）",
        category="data", estimated_ms=10,
    )
    tool_registry.register(
        "correlation.chains", _correlation_chains,
        description="攻击链模式匹配（检测已知攻击路径）",
        category="analysis", estimated_ms=200,
    )
    tool_registry.register(
        "correlation.temporal", _correlation_temporal,
        description="时间窗口事件分组（同IP短时内事件聚合）",
        category="analysis", estimated_ms=100,
    )
    tool_registry.register(
        "correlation.entity_link", _correlation_entity_link,
        description="实体图关联（通过共同目标发现关联源IP）",
        category="analysis", estimated_ms=200,
    )
    tool_registry.register(
        "vector.search", _vector_search,
        description="向量检索语义相关的历史记忆（memories 表）",
        category="search", estimated_ms=300,
    )
    tool_registry.register(
        "knowledge.search", _knowledge_search,
        description="检索安全知识库（MITRE ATT&CK / CAPEC / 威胁情报），支持按威胁类型过滤 + LLM 重排",
        category="search", estimated_ms=500,
    )
    tool_registry.register(
        "memory_tree.related", _memory_tree_related,
        description="查找与事件关联的记忆树节点（同IP/同类型）",
        category="search", estimated_ms=50,
    )
    tool_registry.register(
        "sliding_window.get", _sliding_window_get,
        description="获取滑动窗口内的近期上下文",
        category="data", estimated_ms=10,
    )
    tool_registry.register(
        "sliding_window.evicted", _sliding_window_evicted,
        description="获取被窗口淘汰的历史消息",
        category="data", estimated_ms=10,
    )
    logger.info(f"Tool registry initialized with {len(tool_registry._tools)} tools")
    tool_registry._initialized = True


# 模块加载时自动初始化（保持向后兼容）。
# 应用启动入口（app.py）若已 import 本模块则自动完成注册；
# 若运行时新工具需要 reload，可手动 tool_registry._initialized = False 后再调 init。
init_tool_registry()
