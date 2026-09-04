"""
对话/记忆树/实时事件路由 — 聊天流水线/SSE 事件流/记忆树/统计

端点前缀: /api
"""
import asyncio
import json
import logging
import time
import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from config import settings
from models import get_session, Conversation, SecurityEvent, Memory, MemoryTreeNode
from sliding_window import sliding_window
from memory_tree import memory_tree, MemoryTreeNode
from context_stream import context_stream
from event_bus import BOOT_TS, event_bus
from agents import AgentA, AgentB, AgentC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["chat"])

# 旧流水线 Agent 实例（兼容旧端点）
agent_a = AgentA()
agent_b = AgentB()
agent_c = AgentC()


# ── 请求模型 ──

class ChatRequest(BaseModel):
    query: str
    session_id: str = ""


# ── SSE 实时事件流 ──

@router.get("/events/stream")
async def events_stream(request: Request):
    """SSE 实时事件流 — 推送安全事件、审计结果、响应动作

    浏览器 EventSource 断线自动重连时会携带 Last-Event-ID 请求头，
    此处先按序号补发历史中错过的事件再进入实时循环，消除断线窗口的数据空洞；
    订阅队列先于历史快照建立，重复投递由客户端按 _seq 去重兜底。
    """
    q = event_bus.subscribe()
    if q is None:
        # 订阅槽满员：拒绝而非踢出老订阅者（踢出会造成客户端无法感知的僵尸流）
        return JSONResponse(
            status_code=503,
            headers={"Retry-After": "3"},
            content={"detail": "event stream subscriber slots full, retry later"},
        )
    # 浏览器自动重连经 Last-Event-ID 头携带断点；手动重建连接无法设头，允许用同名查询参数兜底
    last_id_raw = (
        request.headers.get("last-event-id")
        or request.query_params.get("last_event_id")
        or ""
    )
    resume_from = int(last_id_raw) if last_id_raw.isdigit() else 0

    async def generator():
        try:
            missed = event_bus.recent(limit=200, since_seq=resume_from)
            # complete=False 表示断点已超出服务端历史窗口（或服务端重启），客户端将标记数据空洞
            no_history = event_bus.oldest_seq == 0
            window_intact = event_bus.oldest_seq <= resume_from + 1
            complete = resume_from == 0 or (len(missed) == 0 and no_history) or window_intact
            yield {"event": "connected", "data": json.dumps({
                "subscribers": event_bus.subscriber_count,
                "server_time": time.time(),
                "epoch": BOOT_TS,
                "resumed": bool(resume_from),
                "replayed": len(missed),
                "complete": bool(complete),
            })}
            for item in missed:
                yield {"event": item["event"], "id": str(item["seq"]), "data": item["data"]}
            while True:
                try:
                    # ping 周期 15s：既保活，又让客户端能通过 id 行(last_seq)检测
                    # "订阅被挤出"型僵尸流（连接存活但收不到数据）
                    evt = await asyncio.wait_for(q.get(), timeout=15)
                    if evt.seq <= resume_from:
                        continue
                    yield evt.to_sse()
                except asyncio.TimeoutError:
                    yield {
                        "event": "ping",
                        "id": str(event_bus.last_seq),
                        "data": json.dumps({"ts": time.time()}),
                    }
        finally:
            event_bus.unsubscribe(q)

    return EventSourceResponse(generator())

@router.get("/events/recent")
async def events_recent(
    limit: int = Query(50, ge=1, le=200),
    since_seq: int = Query(0, ge=0),
):
    """获取最近的实时事件（用于页面刷新后恢复/断线回放），按 seq 升序"""
    return event_bus.recent(limit, since_seq=since_seq)


# ── 对话端点 ──

@router.post("/chat")
async def chat(req: ChatRequest, session: AsyncSession = Depends(get_session)):
    session_id = str(uuid.uuid4())

    await sliding_window.add_message(session_id, "user", "user", req.query)
    session_obj = Conversation(
        session_id=session_id, agent_id="user", role="user", content=req.query
    )
    session.add(session_obj)
    await session.commit()

    agent_ctx = {}
    analysis = await agent_a.process(session, req.query, session_id, agent_ctx)
    agent_ctx["analysis"] = analysis.get("result", "")
    decision = await agent_b.process(session, req.query, session_id, agent_ctx)
    agent_ctx["decision"] = decision.get("result", "")
    report = await agent_c.process(session, req.query, session_id, agent_ctx)

    return {
        "session_id": session_id,
        "pipeline": [analysis, decision, report],
    }

@router.post("/chat/stream")
async def chat_stream(req: ChatRequest, session: AsyncSession = Depends(get_session)):
    session_id = req.session_id or str(uuid.uuid4())

    await sliding_window.add_message(session_id, "user", "user", req.query)
    session_obj = Conversation(
        session_id=session_id, agent_id="user", role="user", content=req.query
    )
    session.add(session_obj)
    await session.commit()

    async def event_generator():
        agent_ctx = {}
        yield {"event": "session", "data": json.dumps({"session_id": session_id})}

        yield {"event": "agent_start", "data": json.dumps({"agent": "分析 Agent", "step": "analysis"})}
        analysis = await agent_a.process(session, req.query, session_id, agent_ctx)
        agent_ctx["analysis"] = analysis.get("result", "")
        yield {"event": "agent_done", "data": json.dumps({"agent": "分析 Agent", "result": analysis["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_a", role="assistant", content=analysis["result"]))

        yield {"event": "agent_start", "data": json.dumps({"agent": "决策 Agent", "step": "decision"})}
        decision = await agent_b.process(session, req.query, session_id, agent_ctx)
        agent_ctx["decision"] = decision.get("result", "")
        yield {"event": "agent_done", "data": json.dumps({"agent": "决策 Agent", "result": decision["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_b", role="assistant", content=decision["result"]))

        yield {"event": "agent_start", "data": json.dumps({"agent": "报告 Agent", "step": "report"})}
        report = await agent_c.process(session, req.query, session_id, agent_ctx)
        yield {"event": "agent_done", "data": json.dumps({"agent": "报告 Agent", "result": report["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_c", role="assistant", content=report["result"]))

        await session.commit()

        yield {"event": "done", "data": json.dumps({
            "pipeline": [analysis, decision, report],
        })}

    return EventSourceResponse(event_generator())


# ── 记忆树端点 ──

@router.get("/tree/stats")
async def tree_stats(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """记忆树统计"""
    return await memory_tree.get_tree_stats(session, session_id)

@router.get("/tree/context")
async def tree_context(
    session_id: str = Query(..., description="会话ID"),
    query: str = Query("", description="查询内容"),
    max_tokens: int = Query(1000, description="最大token数"),
    session: AsyncSession = Depends(get_session)
):
    """从记忆树重建上下文"""
    ctx = await memory_tree.reconstruct_context(session, session_id, query, max_tokens)
    return {"session_id": session_id, "context": ctx, "node_count": len(ctx)}

@router.get("/tree/nodes")
async def tree_nodes(
    session_id: str = Query(..., description="会话ID"),
    limit: int = 50,
    session: AsyncSession = Depends(get_session)
):
    """查看记忆树节点"""
    stmt = (
        select(MemoryTreeNode)
        .where(MemoryTreeNode.session_id == session_id)
        .order_by(MemoryTreeNode.created_at)
        .limit(limit)
    )
    result = await session.execute(stmt)
    nodes = result.scalars().all()
    return [
        {
            "id": n.id, "parent_id": n.parent_id,
            "depth": n.depth, "node_type": n.node_type,
            "importance": n.importance, "route": n.compression_route,
            "summary": (n.summary or n.content or "")[:100],
            "created_at": n.created_at.isoformat(),
        }
        for n in nodes
    ]

@router.get("/tree/consolidate")
async def tree_consolidate(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """获取记忆树统计（改造后记忆树为纯索引结构，无需手动合并）"""
    stats = await memory_tree.get_tree_stats(session, session_id)
    return {"status": "ok", "session_id": session_id, "stats": stats}


# ── 会话/窗口/上下文端点 ──

@router.get("/chat/history/{session_id}")
async def get_chat_history(session_id: str, session: AsyncSession = Depends(get_session)):
    stmt = select(Conversation).where(Conversation.session_id == session_id).order_by(Conversation.created_at)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": c.id, "agent_id": c.agent_id, "role": c.role,
            "content": c.content, "created_at": c.created_at.isoformat(),
        }
        for c in rows
    ]

@router.get("/window/{session_id}")
async def get_window(session_id: str):
    items = await sliding_window.get_window(session_id)
    return {"session_id": session_id, "messages": items}

@router.get("/context/stream/{session_id}")
async def get_context_stream(session_id: str):
    """查看当前上下文流状态"""
    loaded = await context_stream.load(session_id)
    if not loaded:
        return {"session_id": session_id, "active": False, "fragments": []}
    return {
        "session_id": session_id,
        "active": True,
        "stats": context_stream.stats(),
        "fragments": [
            {
                "source": f.source,
                "importance": f.importance,
                "tokens": f.tokens,
                "preview": f.content[:80],
            }
            for f in context_stream.fragments
        ],
    }

@router.get("/summary/{session_id}")
async def get_summary(session_id: str):
    s = await sliding_window.get_summary(session_id)
    return {"session_id": session_id, "summary": s or ""}


# ── 全局统计 ──

# /api/stats 高压下被前端以秒级频率轮询，6 个全表 COUNT 逐条执行会拖垮 DB。
# 合并为单条 SELECT（标量子查询一次往返）+ 5s 进程内 TTL 缓存。
STATS_TTL_S = 5.0
_stats_cache: dict = {"data": None, "ts": 0.0}


@router.get("/stats")
async def stats(session: AsyncSession = Depends(get_session)):
    now = time.monotonic()
    if _stats_cache["data"] is not None and now - _stats_cache["ts"] < STATS_TTL_S:
        return _stats_cache["data"]

    row = (await session.execute(
        select(
            select(func.count(Memory.id)).scalar_subquery(),
            select(func.count(Conversation.id)).scalar_subquery(),
            select(func.count(SecurityEvent.id)).scalar_subquery(),
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.analyzed == False
            ).scalar_subquery(),
            select(func.count(MemoryTreeNode.id)).scalar_subquery(),
            select(func.count(MemoryTreeNode.id)).where(
                MemoryTreeNode.node_type == "leaf"
            ).scalar_subquery(),
        )
    )).one()
    mem_count, conv_count, evt_count, evt_pending, tree_total, tree_leaves = row
    redis_keys = await sliding_window.dbsize()

    # Audit-LLM 统计（使用 analyzed 字段代替 JSON 内嵌判断）
    audit_total = evt_count
    audit_done = evt_count - evt_pending

    payload = {
        "memories_count": mem_count,
        "conversations_count": conv_count,
        "security_events": evt_count,
        "security_pending": evt_pending,
        "tree_nodes": tree_total,
        "tree_leaves": tree_leaves,
        "redis_keys": redis_keys,
        "audit_llm": {
            "total": audit_total,
            "completed": audit_done,
            "pending": evt_pending,
        },
        "services": {
            "pgvector": "active",
            "redis": "active",
            "llm": settings.llm_model,
            "embedding": settings.embedding_model,
        },
    }
    _stats_cache["data"] = payload
    _stats_cache["ts"] = now
    return payload
