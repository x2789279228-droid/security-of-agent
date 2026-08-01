import asyncio
import logging
import json
import uuid
from contextlib import asynccontextmanager

import time
from collections import defaultdict

from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from config import settings
from auth import create_access_token, get_current_user, RequireRole, UserInfo
from models import init_db, get_session, async_session, Memory, Conversation, SecurityEvent, PhishingRecord
from vector_store import vector_store
from sliding_window import sliding_window
from summary_compression import summary, embedder
from agents import (
    AgentA, AgentB, AgentC, AgentD,
    decomposer, tool_builder, executor, reviewer,
)
from log_ingestion import log_ingestor
from memory_tree import memory_tree, MemoryTreeNode
from context_stream import context_stream, ContextFragment
from anomaly_detector import anomaly_detector
from correlation_engine import correlation_engine
from event_store import event_store, EventFilter, StoredEvent
from audit_types import FinalVerdict
from scheduler import scheduler
from event_bus import event_bus
from agents.agent_cad import cad_agent
from cad import circuit_breaker
from rag import (
    kb_manager, retriever, security_chunker, seed_knowledge_base,
    evidence_verifier, RAGContextBuilder,
    import_enterprise_attack, import_capec,
    get_import_status, set_import_status, ImportStatus,
)
from response_engine import (
    get_orchestrator, get_response_logger,
    response_executor,
    approval_queue, policy_engine, response_registry,
    ApprovalStatus, ssh_transport,
)
from source_registry import source_registry
from kafka_consumer import kafka_consumer_manager
from kafka_producer import kafka_producer

response_orchestrator = get_orchestrator()
response_logger = get_response_logger()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# 旧流水线 Agent 实例（兼容旧端点）
agent_a = AgentA()
agent_b = AgentB()
agent_c = AgentC()
agent_d = AgentD()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    await init_db()
    await sliding_window.connect()
    await summary.ensure_client()
    await embedder.ensure_client()
    # Connect Redis for context_stream
    redis_client = await sliding_window.get_redis()
    if redis_client:
        embedder.set_redis(redis_client)
        context_stream.set_redis(redis_client)
        # 异常检测基线持久化
        anomaly_detector.set_redis(redis_client)
        await anomaly_detector.load_baselines_from_redis()
    logger.info("安全审计模式: 所有事件全量存储，无有损压缩 + 异常基线持久化")
    if not settings.llm_api_key:
        logger.warning("LLM API key not set — LLM calls will return fallback responses")
    if not settings.embedding_api_key:
        logger.warning("Embedding API key not set — embeddings will return zero vectors")
    logger.info(f"LLM: {settings.llm_model} @ {settings.llm_base_url}")
    logger.info(f"Embedding: {settings.embedding_model} @ {settings.embedding_base_url}")
    # 配置响应引擎传输层
    if settings.response_ssh_host:
        ssh_transport.configure(
            host=settings.response_ssh_host,
            port=settings.response_ssh_port,
            user=settings.response_ssh_user,
            key_file=settings.response_ssh_key_file,
        )
        logger.info(f"Response SSH transport configured: {settings.response_ssh_user}@{settings.response_ssh_host}:{settings.response_ssh_port}")
    else:
        logger.info("Response transport mode: stub (set RESPONSE_SSH_HOST to enable real execution)")

    # 播种安全知识库
    try:
        async with async_session() as rag_session:
            await seed_knowledge_base(rag_session)
    except Exception as e:
        logger.warning(f"Knowledge base seeding failed (will retry): {e}")

    # 数据源注册表初始化
    source_registry.load_from_config()

    # SSH 防火墙适配器初始化（可选）
    if settings.fw_ssh_host:
        from response_engine.ssh_firewall import ssh_firewall
        ssh_firewall.configure(
            host=settings.fw_ssh_host,
            port=settings.fw_ssh_port,
            username=settings.fw_ssh_user,
            password=settings.fw_ssh_password,
            use_sudo=settings.fw_use_sudo,
        )
        logger.info(f"SSH firewall adapter configured: {settings.fw_ssh_user}@{settings.fw_ssh_host}")

    # Sigma 检测引擎
    from sigma_detector import sigma_detector
    logger.info(f"Sigma detector: {sigma_detector.stats()['rules_count']} rules loaded")

    # Kafka 消息总线（可选，kafka_enabled=True 时启用）
    if settings.kafka_enabled:
        await kafka_producer.start()
        await kafka_consumer_manager.start()
        logger.info("Kafka 模式已启用: 数据通过 Kafka + Flink 流水线处理")
    else:
        logger.info("HTTP 直连模式: 设置 SHARED_MEMORY_KAFKA_ENABLED=true 启用 Kafka")

    # 启动定时调度器
    await scheduler.start(async_session)
    logger.info("Scheduler started")

    yield

    # 停止 Kafka
    if settings.kafka_enabled:
        await kafka_consumer_manager.stop()
        await kafka_producer.stop()

    await scheduler.stop()
    await summary.close()
    await embedder.close()
    logger.info("Shutdown complete")

app = FastAPI(title="共享记忆服务层", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=eval(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 速率限制中间件 ──

_rate_limit_store: dict[str, list[float]] = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if settings.rate_limit_per_minute <= 0:
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = 60.0
    timestamps = _rate_limit_store[client_ip]
    cutoff = now - window
    _rate_limit_store[client_ip] = [t for t in timestamps if t > cutoff]
    if len(_rate_limit_store[client_ip]) >= settings.rate_limit_per_minute:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    _rate_limit_store[client_ip].append(now)
    return await call_next(request)

class ChatRequest(BaseModel):
    query: str
    session_id: str = ""

# ── REST Endpoints ──

@app.post("/api/auth/login")
async def login(username: str = Query(...), password: str = Query(...)):
    """登录获取 JWT token（生产环境应接入真实认证源）"""
    from auth import create_access_token
    if username == settings.admin_user and password == settings.admin_password:
        token = create_access_token(username, role="admin")
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/health")
async def health():
    return {"status": "ok", "services": {
        "llm": settings.llm_model,
        "embedding": settings.embedding_model,
        "kafka": "enabled" if settings.kafka_enabled else "disabled",
        "kafka_bootstrap": settings.kafka_bootstrap if settings.kafka_enabled else "",
    }}

# ── 数据源管理端点 ──

@app.get("/api/sources")
async def list_sources(
    user: UserInfo = Depends(RequireRole("operator")),
):
    """列出所有已注册的数据源"""
    return {
        "sources": source_registry.list_sources(),
        "stats": source_registry.stats(),
    }

class SourceRegisterRequest(BaseModel):
    api_key: str
    name: str
    source_type: str = "generic"

@app.post("/api/sources/register")
async def register_source(
    req: SourceRegisterRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """注册新数据源"""
    source = source_registry.register(req.api_key, req.name, req.source_type)
    return {"status": "registered", "name": source.name, "source_type": source.source_type}

@app.post("/api/sources/revoke")
async def revoke_source(
    api_key: str = Query(..., description="要吊销的 API Key"),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """吊销数据源"""
    ok = source_registry.revoke(api_key)
    if not ok:
        raise HTTPException(404, "Source not found")
    return {"status": "revoked"}

@app.get("/api/sources/rejections")
async def source_rejections(
    limit: int = Query(50, description="返回条数"),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """查看未认证访问的拒绝记录（安全审计）"""
    return {
        "rejections": source_registry.get_rejection_log(limit),
        "total": len(source_registry.get_rejection_log(limit)),
    }

# ── Kafka 状态端点 ──

@app.get("/api/kafka/status")
async def kafka_status():
    """Kafka 消息总线状态"""
    return {
        "enabled": settings.kafka_enabled,
        "bootstrap": settings.kafka_bootstrap,
        "topics": {
            "raw": settings.kafka_topic_raw,
            "validated": settings.kafka_topic_validated,
            "rejected": settings.kafka_topic_rejected,
            "enriched": settings.kafka_topic_enriched,
            "alerts": settings.kafka_topic_alerts,
            "audit_queue": settings.kafka_topic_audit_queue,
            "audit_results": settings.kafka_topic_audit_results,
        },
        "consumer_stats": kafka_consumer_manager.stats(),
        "producer_active": kafka_producer.is_active,
    }

# ── Sigma 检测引擎端点 ──

@app.get("/api/sigma/stats")
async def sigma_stats():
    """Sigma 检测引擎状态"""
    from sigma_detector import sigma_detector
    return sigma_detector.stats()

class SigmaDetectRequest(BaseModel):
    events: list[dict]

@app.post("/api/sigma/detect")
async def sigma_detect(req: SigmaDetectRequest):
    """批量 Sigma 规则检测"""
    from sigma_detector import sigma_detector
    return sigma_detector.detect_batch(req.events)

# ── MCP Guard 网关端点 ──

@app.get("/api/guard/status")
async def guard_status():
    """MCP Guard 网关状态"""
    try:
        from mcp_guard import mcp_guard
        return {
            "enabled": settings.mcp_guard_enabled,
            "tools": mcp_guard.list_tools(),
            "recent_calls": mcp_guard.logger.recent(20) if hasattr(mcp_guard, 'logger') else [],
        }
    except ImportError:
        return {"enabled": False, "error": "mcp_guard module not available"}

class GuardCallRequest(BaseModel):
    tool_name: str
    arguments: dict = {}
    user_role: str = "security_operator"
    reason: str = ""

@app.post("/api/guard/call")
async def guard_call(req: GuardCallRequest):
    """通过 MCP Guard 网关调用安全工具（4 层检查）"""
    if not settings.mcp_guard_enabled:
        raise HTTPException(400, "MCP Guard is disabled")
    try:
        from mcp_guard import mcp_guard
        from mcp_guard.guard_server import ToolCallRequest as GuardReq
        result = await asyncio.to_thread(
            mcp_guard.call_tool,
            GuardReq(
                tool_name=req.tool_name,
                arguments=req.arguments,
                user_role=req.user_role,
                reason=req.reason,
            )
        )
        return result
    except ImportError:
        raise HTTPException(500, "mcp_guard module not available")

# ── SSH 防火墙端点 ──

@app.get("/api/firewall/status")
async def firewall_status():
    """SSH 防火墙适配器状态"""
    from response_engine.ssh_firewall import ssh_firewall
    return {
        "enabled": ssh_firewall.enabled,
        "connected": ssh_firewall._connected,
        "host": settings.fw_ssh_host,
        "active_rules": ssh_firewall.get_active_rules(),
    }

@app.post("/api/firewall/connect")
async def firewall_connect(user: UserInfo = Depends(RequireRole("admin"))):
    """连接 SSH 防火墙虚拟机"""
    from response_engine.ssh_firewall import ssh_firewall
    if not settings.fw_ssh_host:
        raise HTTPException(400, "FW_SSH_HOST not configured")
    ssh_firewall.configure(
        host=settings.fw_ssh_host,
        port=settings.fw_ssh_port,
        username=settings.fw_ssh_user,
        password=settings.fw_ssh_password,
        use_sudo=settings.fw_use_sudo,
    )
    try:
        info = await asyncio.to_thread(ssh_firewall.connect)
        return {"status": "connected", "info": info}
    except Exception as e:
        raise HTTPException(500, f"SSH connection failed: {e}")

@app.get("/api/firewall/rules")
async def firewall_rules(user: UserInfo = Depends(RequireRole("operator"))):
    """查询 iptables 规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    return await asyncio.to_thread(ssh_firewall.list_rules)

@app.post("/api/firewall/rollback-all")
async def firewall_rollback_all(user: UserInfo = Depends(RequireRole("admin"))):
    """回滚所有防火墙规则"""
    from response_engine.ssh_firewall import ssh_firewall
    if not ssh_firewall._connected:
        raise HTTPException(400, "Firewall not connected")
    return await asyncio.to_thread(ssh_firewall.rollback_all)

# ── SecurityGuard 端点 ──

@app.get("/api/security-guard/status")
async def security_guard_status():
    """SecurityGuard 状态"""
    try:
        from security_guard import security_guard
        return {
            "enabled": settings.security_guard_enabled,
            "rate_limiter": security_guard.rate_limiter.get_stats() if hasattr(security_guard, 'rate_limiter') else {},
        }
    except ImportError:
        return {"enabled": False, "error": "security_guard module not available"}

@app.get("/api/events/stream")
async def events_stream():
    """SSE 实时事件流 — 推送安全事件、审计结果、响应动作"""
    q = event_bus.subscribe()

    async def generator():
        try:
            yield {"event": "connected", "data": json.dumps({
                "subscribers": event_bus.subscriber_count,
            })}
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=30)
                    yield evt.to_sse()
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            event_bus.unsubscribe(q)

    return EventSourceResponse(generator())

@app.get("/api/events/recent")
async def events_recent(limit: int = Query(50, ge=1, le=200)):
    """获取最近的实时事件（用于页面刷新后恢复）"""
    return event_bus.recent(limit)

@app.post("/api/chat")
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

@app.post("/api/chat/stream")
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

# ── Log Ingestion Endpoints ──

class LogIngestRequest(BaseModel):
    message: str | dict
    session_id: str = ""

class LogBatchRequest(BaseModel):
    logs: list[str | dict]
    session_id: str = ""

@app.post("/api/logs/ingest")
async def ingest_log(
    req: LogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """
    接入单条安全日志

    安全增强: 支持 X-API-Key 头认证。
    - Kafka 模式下: 此端点仅用于兼容测试，生产数据应走 Kafka
    - HTTP 模式下: 建议携带 X-API-Key 头
    """
    # 数据源认证检查
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        source = source_registry.authenticate(api_key)
        if not source:
            raise HTTPException(403, "Invalid or revoked API key")
    elif settings.kafka_enabled:
        logger.warning("[Security] HTTP ingest without API key in Kafka mode — should use Kafka pipeline")

    session_id = str(uuid.uuid4())
    log_data = req.message if isinstance(req.message, dict) else json.loads(req.message)
    result = await log_ingestor.ingest(session, session_id, log_data)
    return {"session_id": session_id, **result}

@app.post("/api/logs/ingest/batch")
async def ingest_log_batch(
    req: LogBatchRequest,
    session: AsyncSession = Depends(get_session)
):
    """Fast Path: 批量接入安全日志"""
    session_id = str(uuid.uuid4())
    parsed = [d if isinstance(d, dict) else json.loads(d) for d in req.logs]
    result = await log_ingestor.ingest_batch(session, session_id, parsed)
    return result

@app.post("/api/logs/analyze")
async def trigger_analysis(
    session_id: str = Query(..., description="会话ID"),
):
    """手动触发未分析日志的批量分析"""
    asyncio.create_task(log_ingestor._run_batch_analysis(session_id))
    return {"status": "analysis_triggered", "session_id": session_id}

@app.get("/api/logs/status")
async def log_status(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """查询日志接入状态"""
    return await log_ingestor.get_status(session, session_id)

@app.get("/api/logs/review")
async def review_status(
    session_id: str = Query(..., description="会话ID"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询每条日志的审核状态"""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.session_id == session_id)
        .order_by(desc(SecurityEvent.created_at))
        .limit(limit)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    reviewed = sum(1 for r in rows if r.analyzed)
    return {
        "session_id": session_id,
        "total": len(rows),
        "reviewed": reviewed,
        "pending": len(rows) - reviewed,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "message": e.message[:80],
                "analyzed": e.analyzed,
                "result": (e.raw_data or {}).get("_review", {}),
                "created_at": e.created_at.isoformat(),
            }
            for e in rows
        ],
    }

@app.get("/api/logs/stuck")
async def stuck_events(
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session)
):
    """诊断: 查找卡在审核中的事件"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
        .order_by(SecurityEvent.created_at)
        .limit(100)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return {
        "stuck_count": len(rows),
        "cutoff_minutes": minutes,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "created_at": e.created_at.isoformat(),
                "has_error": bool((e.raw_data or {}).get("_audit_llm_error")),
                "error": (e.raw_data or {}).get("_audit_llm_error", ""),
            }
            for e in rows
        ],
    }

@app.post("/api/logs/reset-stuck")
async def reset_stuck(
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session)
):
    """将所有卡住的事件标记为已分析（含错误标记），释放管道"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    count = 0
    for e in rows:
        e.analyzed = True
        e.raw_data["_audit_llm_error"] = "reset_by_admin"
        count += 1
    await session.commit()
    return {"reset_count": count}

@app.get("/api/logs/events")
async def list_events(
    session_id: str = Query("", description="会话ID"),
    severity: str = Query("", description="按严重度筛选"),
    limit: int = 50, offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    """查询已接入的安全事件"""
    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at))
    if session_id:
        stmt = stmt.where(SecurityEvent.session_id == session_id)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": e.id, "session_id": e.session_id,
            "event_type": e.event_type, "severity": e.severity,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip,
            "message": e.message, "analyzed": e.analyzed,
            "created_at": e.created_at.isoformat(),
        }
        for e in rows
    ]

# ── Original Endpoints ──

@app.get("/api/memories")
async def list_memories(
    limit: int = 20, offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    stmt = select(Memory).order_by(desc(Memory.created_at)).limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": m.id, "agent_id": m.agent_id, "content": m.content[:200],
            "metadata": m.metadata_, "created_at": m.created_at.isoformat()
        }
        for m in rows
    ]

# ── Memory Tree Endpoints ──

@app.get("/api/tree/stats")
async def tree_stats(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """记忆树统计"""
    return await memory_tree.get_tree_stats(session, session_id)

@app.get("/api/tree/context")
async def tree_context(
    session_id: str = Query(..., description="会话ID"),
    query: str = Query("", description="查询内容"),
    max_tokens: int = Query(1000, description="最大token数"),
    session: AsyncSession = Depends(get_session)
):
    """从记忆树重建上下文"""
    ctx = await memory_tree.reconstruct_context(session, session_id, query, max_tokens)
    return {"session_id": session_id, "context": ctx, "node_count": len(ctx)}

@app.get("/api/tree/nodes")
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

@app.get("/api/tree/consolidate")
async def tree_consolidate(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """获取记忆树统计（改造后记忆树为纯索引结构，无需手动合并）"""
    stats = await memory_tree.get_tree_stats(session, session_id)
    return {"status": "ok", "session_id": session_id, "stats": stats}

# ── Original Endpoints ──

@app.get("/api/chat/history/{session_id}")
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

@app.get("/api/window/{session_id}")
async def get_window(session_id: str):
    items = await sliding_window.get_window(session_id)
    return {"session_id": session_id, "messages": items}

@app.get("/api/context/stream/{session_id}")
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

@app.get("/api/summary/{session_id}")
async def get_summary(session_id: str):
    s = await sliding_window.get_summary(session_id)
    return {"session_id": session_id, "summary": s or ""}

@app.get("/api/stats")
async def stats(session: AsyncSession = Depends(get_session)):
    mem_count = (await session.execute(select(func.count(Memory.id)))).scalar()
    conv_count = (await session.execute(select(func.count(Conversation.id)))).scalar()
    evt_count = (await session.execute(select(func.count(SecurityEvent.id)))).scalar()
    evt_pending = (await session.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.analyzed == False)
    )).scalar()
    tree_total = (await session.execute(
        select(func.count(MemoryTreeNode.id))
    )).scalar()
    tree_leaves = (await session.execute(
        select(func.count(MemoryTreeNode.id)).where(MemoryTreeNode.node_type == "leaf")
    )).scalar()
    redis_keys = await sliding_window.dbsize()

    # Audit-LLM 统计（使用 analyzed 字段代替 JSON 内嵌判断）
    audit_total = evt_count
    audit_done = evt_count - evt_pending

    return {
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

@app.delete("/api/memories/{memory_id}")
async def delete_memory(
    memory_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    ok = await vector_store.delete_memory(session, memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"deleted": True}

# ── 安全审计专用端点 ──

@app.get("/api/security/anomalies")
async def list_anomalies(
    session_id: str = Query(..., description="会话ID"),
    min_score: float = Query(0.5, description="最低异常分数"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """获取异常检测标记的事件"""
    events = await event_store.get_unreviewed_anomalies(
        session, session_id, min_score=min_score, limit=limit
    )
    return [
        {
            "id": evt.id,
            "event_type": evt.event_type,
            "severity": evt.severity,
            "message": evt.message[:200],
            "anomaly_score": evt.anomaly_score,
            "correlation_id": evt.correlation_id,
            "src_ip": evt.src_ip,
            "created_at": evt.created_at,
        }
        for evt in events
    ]

@app.get("/api/security/chains")
async def list_chains(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """获取攻击链关联结果"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=1440
    )
    return {
        "session_id": session_id,
        "chains": [
            {
                "chain_id": c.chain_id,
                "pattern_name": c.pattern_name,
                "confidence": c.confidence,
                "event_ids": [e["id"] for e in c.events],
                "src_ips": list(c.src_ips),
                "dst_ips": list(c.dst_ips),
                "time_span_minutes": c.time_span_minutes,
                "alert": c.alert,
            }
            for c in result.chains
        ],
        "temporal_groups": [
            {
                "src_ip": g["src_ip"],
                "event_count": g["count"],
                "types": g["types"],
                "start": g["start"],
                "end": g["end"],
            }
            for g in result.temporal_groups[:20]
        ],
        "total_events_analyzed": result.total_events_analyzed,
    }

@app.get("/api/security/events")
async def query_events(
    session_id: str = Query("", description="会话ID"),
    src_ip: str = Query("", description="源IP"),
    event_type: str = Query("", description="事件类型"),
    severity: str = Query("", description="严重度"),
    limit: int = Query(100, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询完整原始事件（EventStore 溯源）"""
    events = await event_store.query(
        session, EventFilter(
            session_id=session_id,
            src_ip=src_ip,
            event_type=event_type,
            severity=severity,
            limit=limit,
        )
    )
    return [
        {
            "id": evt.id,
            "event_type": evt.event_type,
            "severity": evt.severity,
            "src_ip": evt.src_ip,
            "dst_ip": evt.dst_ip,
            "message": evt.message,
            "anomaly_score": evt.anomaly_score,
            "correlation_id": evt.correlation_id,
            "created_at": evt.created_at,
        }
        for evt in events
    ]

@app.get("/api/security/events/{event_id}")
async def get_event_detail(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取单条事件的完整原始数据"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")
    return {
        "id": evt.id,
        "session_id": evt.session_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "src_ip": evt.src_ip,
        "dst_ip": evt.dst_ip,
        "message": evt.message,
        "raw_data": evt.raw_data,
        "anomaly_score": evt.anomaly_score,
        "correlation_id": evt.correlation_id,
        "created_at": evt.created_at,
    }

@app.post("/api/security/review")
async def trigger_agent_d_review(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """手动触发 Agent-D 审查（检查已审核事件中是否有遗漏）"""
    asyncio.create_task(_run_agent_d_review(session_id))
    return {"status": "agent_d_review_triggered", "session_id": session_id}

async def _run_agent_d_review(session_id: str):
    """后台运行 Agent-D 审查"""
    from agents import AgentD
    from models import async_session as db_session

    agent_d = AgentD()
    async with db_session() as session:
        try:
            result = await agent_d.process(session, "", session_id, {})
            logger.info(f"Agent-D review completed for {session_id}: {result.get('result', '')[:100]}")
        except Exception as e:
            logger.error(f"Agent-D review failed: {e}")

# ── Audit-LLM 端点 ──

class AuditLLMRequest(BaseModel):
    event: dict
    session_id: str = ""

@app.post("/api/audit-llm/run")
async def run_audit_llm_pipeline(
    req: AuditLLMRequest,
    session: AsyncSession = Depends(get_session)
):
    """手动触发 Audit-LLM 四层流水线"""
    from anomaly_detector import anomaly_detector as ad

    session_id = str(uuid.uuid4())

    # 异常检测
    anomaly_report = await ad.analyze(req.event)

    # Decomposer
    decomp_output = await decomposer.decompose(
        event=req.event,
        session_id=session_id,
        anomaly_score=anomaly_report.anomaly_score,
        anomaly_reasons=anomaly_report.reasons,
    )

    # Tool Builder
    tool_calls = tool_builder.build(
        decomp_output["sub_tasks"], session_id
    )

    # Executor
    audit_result = await executor.execute(
        tool_calls=tool_calls,
        session=session,
        session_id=session_id,
        raw_event=req.event,
        depth=decomp_output["audit_depth"],
    )

    # Reviewer
    tool_data = "\n".join(
        f"[{tr.tool}] {str(tr.data)[:200]}"
        for tr in audit_result.tool_results
    )
    verdict = await reviewer.review(
        raw_event=req.event,
        decomposer_output=decomp_output,
        audit_result=audit_result,
        tool_data_raw=tool_data,
    )

    return {
        "session_id": session_id,
        "depth": decomp_output["audit_depth"],
        "audit_result": audit_result.to_dict(),
        "verdict": verdict.to_dict(),
        "pipeline_steps": {
            "decomposer": {
                "sub_tasks": len(decomp_output["sub_tasks"]),
                "depth": decomp_output["audit_depth"],
            },
            "tool_builder": {
                "tool_calls": len(tool_calls),
            },
            "executor": {
                "tool_results": len(audit_result.tool_results),
                "threat_detected": audit_result.threat_detected,
                "confidence": audit_result.confidence,
            },
            "reviewer": {
                "conclusion": verdict.conclusion,
                "human_intervention": verdict.human_intervention,
            },
        },
    }

@app.get("/api/audit-llm/pipeline/{event_id}")
async def get_pipeline_result(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取 Audit-LLM 流水线的审核结果"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")

    raw = evt.raw_data or {}
    pipeline = raw.get("_audit_llm", {})
    error = raw.get("_audit_llm_error", "")

    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "analyzed": evt.analyzed,
        "pipeline_result": pipeline,
        "error": error or None,
    }

@app.get("/api/audit-llm/stats")
async def audit_llm_stats(
    session_id: str = Query("", description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """Audit-LLM 流水线统计"""
    from sqlalchemy import select, func

    total_val = (await session.execute(
        select(func.count(SecurityEvent.id))
    )).scalar() or 0
    analyzed_val = (await session.execute(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.analyzed == True)
    )).scalar() or 0
    return {
        "total_events": total_val,
        "analyzed": analyzed_val,
        "pending": total_val - analyzed_val,
    }

@app.get("/api/audit-llm/evidence/{event_id}")
async def get_evidence_trail(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取审计全链路证据追溯（断言↔事件ID映射）"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")

    raw = evt.raw_data or {}
    audit = raw.get("_audit_llm", {})

    evidence_trail = audit.get("evidence_trail", [])
    hallucination = audit.get("hallucination", {})

    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "evidence_trail": evidence_trail,
        "hallucination_risk": hallucination,
        "executor_summary": audit.get("executor", {}),
        "reviewer_verdict": audit.get("reviewer", {}),
        "pipeline_duration_s": audit.get("pipeline_duration_s"),
        "completed_at": audit.get("completed_at"),
    }

# ── CAD 审计角色端点 ──

@app.get("/api/cad/status")
async def cad_status():
    """获取 CAD 审计角色状态（含熔断器）"""
    cb_status = circuit_breaker.get_status()
    return {
        "circuit_breaker": cb_status,
        "context_audit_interval_s": 3600,
    }

@app.post("/api/cad/audit-context")
async def trigger_context_audit():
    """手动触发上下文审计"""
    report = await cad_agent.audit_context()
    return report

@app.get("/api/cad/circuit-breaker")
async def get_circuit_breaker():
    """查询熔断器状态"""
    return circuit_breaker.get_status()

@app.post("/api/cad/circuit-breaker/reset")
async def reset_circuit_breaker():
    """人工重置熔断器"""
    return circuit_breaker.reset()

@app.get("/api/cad/verification/{event_id}")
async def get_cad_verification(
    event_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取指定事件的 CAD 穿透验证结果"""
    evt = await event_store.get_by_id(session, event_id)
    if not evt:
        raise HTTPException(404, "Event not found")
    raw = evt.raw_data or {}
    cad_data = raw.get("_cad_audit", {})
    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "cad_audit": cad_data,
    }

# ── 响应引擎端点 ──

class SimulateThreatRequest(BaseModel):
    threat_type: str = "C2_BEACON"
    confidence: float = 0.85
    severity: str = "critical"
    src_ip: str = "192.168.1.100"
    dst_ip: str = ""
    message: str = ""
    session_id: str = ""
    event_id: int = 0

@app.post("/api/response/simulate")
async def simulate_threat(
    req: SimulateThreatRequest,
    session: AsyncSession = Depends(get_session)
):
    """模拟威胁事件，触发响应引擎"""
    threat_info = {
        "threat_type": req.threat_type,
        "confidence": req.confidence,
        "severity": req.severity,
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "message": req.message or f"模拟{req.threat_type}攻击",
        "session_id": req.session_id or str(uuid.uuid4()),
        "event_id": req.event_id,
    }
    result = await response_orchestrator.on_threat_detected(
        session=session,
        threat_info=threat_info,
        event_id=req.event_id if req.event_id else None,
        session_id=threat_info["session_id"],
    )
    return result

@app.get("/api/response/policies")
async def list_response_policies():
    """查看所有响应策略"""
    policies = policy_engine.get_policies()
    return [
        {
            "name": p.name,
            "threat_type": p.threat_type,
            "actions": p.actions,
            "min_confidence": p.min_confidence,
            "min_severity": p.min_severity,
            "auto_execute": p.auto_execute,
            "require_approval": p.require_approval,
            "cooldown_minutes": p.cooldown_minutes,
            "description": p.description,
        }
        for p in policies
    ]

class PolicyUpdateRequest(BaseModel):
    name: str
    auto_execute: bool | None = None
    require_approval: bool | None = None
    cooldown_minutes: int | None = None
    min_confidence: float | None = None

@app.put("/api/response/policies")
async def update_response_policy(
    req: PolicyUpdateRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """更新响应策略"""
    policy = policy_engine.get_policy(req.name)
    if not policy:
        raise HTTPException(404, f"Policy not found: {req.name}")
    if req.auto_execute is not None:
        policy.auto_execute = req.auto_execute
    if req.require_approval is not None:
        policy.require_approval = req.require_approval
    if req.cooldown_minutes is not None:
        policy.cooldown_minutes = req.cooldown_minutes
    if req.min_confidence is not None:
        policy.min_confidence = req.min_confidence
    return {"status": "updated", "name": req.name}

@app.get("/api/response/actions")
async def list_response_actions():
    """列出所有可用的响应动作"""
    actions = response_registry.list_actions()
    return [
        {
            "name": a.name,
            "description": a.description,
            "severity": a.severity,
            "category": a.category,
            "reversible": a.reversible,
            "params_schema": a.params_schema,
        }
        for a in actions
    ]

@app.post("/api/response/execute")
async def execute_response(
    action_name: str = Query(..., description="动作名称"),
    src_ip: str = Query("", description="目标IP"),
    reason: str = Query("", description="原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """手动执行响应动作"""
    threat_info = {"src_ip": src_ip, "threat_type": "manual", "confidence": 1.0, "severity": "high"}
    actions = [{"name": action_name, "params": {"src_ip": src_ip, "reason": reason}}]
    result = await response_executor.execute_actions(actions, threat_info)
    return {
        "action": action_name,
        "target": src_ip,
        "success": result.succeeded > 0,
        "rollback_token": result.batch_rollback_token,
        "detail": [r.to_dict() if hasattr(r, 'to_dict') else {"success": r.success, "error": r.error} for r in result.results],
    }

@app.post("/api/response/rollback")
async def rollback_response(
    rollback_token: str = Query(..., description="回滚令牌"),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """回滚响应动作"""
    result = await response_executor.rollback_batch(rollback_token)
    return {
        "rollback_token": rollback_token,
        "succeeded": result.succeeded,
        "failed": result.failed,
    }

@app.get("/api/response/approvals")
async def list_approvals(
    pending_only: bool = Query(False, description="仅待审批"),
):
    """查看审批队列"""
    if pending_only:
        tickets = approval_queue.list_pending()
    else:
        tickets = approval_queue.list_all()
    return [
        {
            "id": t.id[:8],
            "policy_name": t.policy_name,
            "threat_type": t.threat_info.get("threat_type", ""),
            "severity": t.threat_info.get("severity", ""),
            "src_ip": t.threat_info.get("src_ip", ""),
            "confidence": t.threat_info.get("confidence", 0),
            "actions": t.actions,
            "status": t.status.value,
            "created_at": t.created_at,
            "expires_at": t.expires_at,
        }
        for t in tickets
    ]

@app.post("/api/response/approvals/{ticket_id}/approve")
async def approve_action(
    ticket_id: str,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """批准审批工单"""
    ticket = approval_queue.approve(ticket_id, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    # 触发执行
    result = await response_orchestrator.execute_approved_action(ticket_id)
    return {
        "status": "approved",
        "ticket_id": ticket_id,
        "execution_result": {
            "succeeded": result.succeeded if result else 0,
            "failed": result.failed if result else 0,
        } if result else None,
    }

@app.post("/api/response/approvals/{ticket_id}/reject")
async def reject_action(
    ticket_id: str,
    reason: str = Query("", description="拒绝原因"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """拒绝审批工单"""
    ticket = approval_queue.reject(ticket_id, reason, user.username)
    if not ticket:
        raise HTTPException(404, f"Ticket not found or already processed: {ticket_id}")
    return {"status": "rejected", "ticket_id": ticket_id, "reason": reason}

@app.get("/api/response/logs")
async def query_response_logs(
    session_id: str = Query("", description="会话ID"),
    threat_type: str = Query("", description="威胁类型"),
    src_ip: str = Query("", description="源IP"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询响应日志"""
    logs = await response_logger.query_logs(
        session,
        session_id=session_id,
        threat_type=threat_type,
        src_ip=src_ip,
        limit=limit,
    )
    return [log.to_dict() for log in logs]

@app.post("/api/response/clear-cooldowns")
async def clear_cooldowns(
    user: UserInfo = Depends(RequireRole("admin")),
):
    """清除所有策略冷却状态（人工干预用）"""
    policy_engine.clear_cooldowns()
    return {"status": "cooldowns_cleared"}

# ── RAG 知识库端点 ──

class RAGSearchRequest(BaseModel):
    query: str = ""
    threat_type: str = ""
    severity: str = ""
    source: str = ""
    top_k: int = 5
    min_score: float = 0.0

@app.post("/api/rag/search")
async def rag_search(
    req: RAGSearchRequest,
    session: AsyncSession = Depends(get_session)
):
    """检索安全知识库"""
    query_embedding = None
    if req.query:
        query_embedding = await embedder.embed(req.query)
    result = await retriever.retrieve(
        session,
        query=req.query,
        query_embedding=query_embedding,
        threat_type=req.threat_type,
        severity=req.severity,
        source=req.source,
        top_k=req.top_k,
        min_score=req.min_score,
    )
    return {
        "total": result.total_found,
        "strategy": result.strategy_used,
        "chunks": result.chunks,
    }

@app.get("/api/rag/documents")
async def rag_list_documents(
    threat_type: str = Query(""),
    source: str = Query(""),
    limit: int = Query(20),
    offset: int = Query(0),
    session: AsyncSession = Depends(get_session)
):
    """列出知识库文档"""
    docs = await kb_manager.search_documents(
        session,
        threat_type=threat_type,
        source=source,
        limit=limit,
        offset=offset,
    )
    return {"documents": docs, "total": len(docs)}

@app.get("/api/rag/documents/{doc_id}")
async def rag_get_document(
    doc_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取单个知识文档"""
    doc = await kb_manager.get_document(session, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    return doc

@app.delete("/api/rag/documents/{doc_id}")
async def rag_delete_document(
    doc_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """删除知识文档"""
    ok = await kb_manager.delete_document(session, doc_id)
    if not ok:
        raise HTTPException(404, "Document not found")
    return {"deleted": True}

class RAGAddDocumentRequest(BaseModel):
    title: str = "未命名"
    content: str = ""
    source: str = "internal"
    threat_types: list[str] = []
    severity: str = "medium"
    tags: list[str] = []

@app.post("/api/rag/documents")
async def rag_add_document(
    req: RAGAddDocumentRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """添加知识文档（自动分块+向量化）"""
    from models import KnowledgeChunk

    title = req.title
    content = req.content
    source = req.source
    threat_types = req.threat_types
    severity = req.severity
    tags = req.tags

    # 添加文档
    doc = await kb_manager.add_document(
        session, title, content, source, threat_types, severity, tags,
    )
    doc_id = doc["id"]

    # 分块
    chunks = security_chunker.chunk_document(
        doc_id, title, content, source, threat_types, severity, tags,
    )

    # 计算向量并写入
    total_chunks = 0
    for chunk_data in chunks:
        vec = await embedder.embed(chunk_data["content"][:1000])
        chunk = KnowledgeChunk(
            doc_id=chunk_data["doc_id"],
            chunk_id=chunk_data["chunk_id"],
            content=chunk_data["content"],
            title=title,
            source=source,
            threat_types=threat_types,
            severity=severity,
            tags=tags,
            embedding=vec,
            token_count=chunk_data["token_count"],
        )
        session.add(chunk)
        total_chunks += 1

    await session.commit()

    return {
        "doc_id": doc_id,
        "title": title,
        "chunks_created": total_chunks,
    }

class RAGVerifyRequest(BaseModel):
    claim: str = ""
    threat_type: str = ""
    severity: str = ""

@app.post("/api/rag/verify")
async def rag_verify_claim(
    req: RAGVerifyRequest,
    session: AsyncSession = Depends(get_session)
):
    """验证断言是否被知识库支撑（减少幻觉的核心功能）"""
    claim = req.claim
    threat_type = req.threat_type
    severity = req.severity

    query_embedding = None
    if claim:
        query_embedding = await embedder.embed(claim)

    report = await evidence_verifier.verify_claim(
        session, claim, threat_type, severity, query_embedding,
    )
    return {
        "claim": claim,
        "verdict": report.verdict,
        "confidence": report.confidence,
        "supporting_evidence": report.supporting_evidence,
        "suggestion": report.suggestion,
    }

@app.get("/api/rag/stats")
async def rag_stats(
    session: AsyncSession = Depends(get_session)
):
    """知识库统计"""
    stats = await kb_manager.get_stats(session)
    return stats

@app.post("/api/rag/reseed")
async def rag_reseed(
    session: AsyncSession = Depends(get_session)
):
    """重新播种知识库"""
    await seed_knowledge_base(session)
    return {"status": "reseeded"}

@app.get("/api/rag/import/status")
async def rag_import_status():
    """查询当前导入进度"""
    status = get_import_status()
    if not status:
        return {"running": False, "message": "No import in progress"}
    return status.to_dict()

@app.post("/api/rag/import/mitre")
async def rag_import_mitre(
    limit: int = Query(0, description="最大导入数(0=全部)"),
    session: AsyncSession = Depends(get_session),
):
    """从 MITRE ATT&CK 官方数据源导入完整攻击技术库"""
    s = ImportStatus()
    s.start("mitre-attack")
    set_import_status(s)
    try:
        result = await import_enterprise_attack(session, limit=limit)
        s.finish(result.imported, result.skipped, result.errors, result.error_details)
        return {"status": "ok" if result.errors == 0 else "partial", "source": "mitre-attack", **result.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

@app.post("/api/rag/import/capec")
async def rag_import_capec(
    limit: int = Query(0, description="最大导入数(0=全部)"),
    session: AsyncSession = Depends(get_session),
):
    """从 MITRE CAPEC 官方数据源导入完整攻击模式库"""
    s = ImportStatus()
    s.start("capec")
    set_import_status(s)
    try:
        result = await import_capec(session, limit=limit)
        s.finish(result.imported, result.skipped, result.errors, result.error_details)
        return {"status": "ok" if result.errors == 0 else "partial", "source": "capec", **result.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

@app.post("/api/rag/import/all")
async def rag_import_all(
    session: AsyncSession = Depends(get_session),
):
    """导入所有 MITRE 知识库 (ATT&CK + CAPEC + 预置知识)"""
    s = ImportStatus()
    s.start("all")
    set_import_status(s)
    try:
        await seed_knowledge_base(session)
        mitre = await import_enterprise_attack(session)
        capec = await import_capec(session)
        total = mitre.imported + capec.imported
        s.finish(total, mitre.skipped + capec.skipped, mitre.errors + capec.errors)
        return {"status": "ok", "seed": {"status": "done"}, "mitre_attack": mitre.to_dict(), "capec": capec.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

# ── 质量评估端点 ──

async def _embed_contexts(contexts: list[dict]) -> list[list[float]]:
    """为评估上下文批量计算 embedding（并发，失败返回空列表）"""
    if not contexts:
        return []
    sem = asyncio.Semaphore(5)

    async def embed_one(ctx: dict):
        async with sem:
            try:
                return await embedder.embed(str(ctx.get("content", ""))[:2000])
            except Exception:
                return None

    vectors = await asyncio.gather(*[embed_one(c) for c in contexts])
    return [v for v in vectors if v]

class RAGEvalRequest(BaseModel):
    query: str
    contexts: list[dict] = []
    ground_truth: str = ""
    retrieval_strategy: str = ""

class RAGEvalAutoRequest(BaseModel):
    query: str
    threat_type: str = ""
    severity: str = ""
    top_k: int = 5
    ground_truth: str = ""

class FaithfulnessEvalRequest(BaseModel):
    answer: str
    contexts: list[dict] = []
    query: str = ""
    prompt_version: str = ""

@app.post("/api/eval/rag")
async def eval_rag(
    req: RAGEvalRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估一次 RAG 检索质量（传入查询与检索上下文）"""
    from eval_service import evaluate_rag_retrieval
    return await evaluate_rag_retrieval(
        query=req.query,
        contexts=req.contexts,
        ground_truth=req.ground_truth,
        retrieval_strategy=req.retrieval_strategy,
    )

@app.post("/api/eval/rag/auto")
async def eval_rag_auto(
    req: RAGEvalAutoRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """对真实知识库检索做自动质量评估（检索 + 评估一体化）"""
    from rag.retriever import retriever
    from eval_service import evaluate_rag_retrieval

    query_embedding = None
    try:
        query_embedding = await embedder.embed(req.query)
    except Exception:
        pass
    result = await retriever.retrieve(
        session,
        query=req.query,
        query_embedding=query_embedding,
        threat_type=req.threat_type,
        severity=req.severity,
        top_k=req.top_k,
    )
    contexts = [
        {"title": c["title"], "content": c["content"], "source": c["source"], "score": c.get("score", 0)}
        for c in result.chunks
    ]
    context_embeddings = await _embed_contexts(contexts)
    run = await evaluate_rag_retrieval(
        query=req.query,
        contexts=contexts,
        ground_truth=req.ground_truth,
        retrieval_strategy=f"{result.strategy_used}:top{req.top_k}",
        answer_embedding=query_embedding,
        context_embeddings=context_embeddings,
    )
    return {"search": {"total": result.total_found, "strategy": result.strategy_used, "chunks": result.chunks}, "eval": run}

@app.post("/api/eval/faithfulness")
async def eval_faithfulness(
    req: FaithfulnessEvalRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估回答对上下文的忠实度（防幻觉）"""
    from eval_service import evaluate_faithfulness
    context_embeddings = await _embed_contexts(req.contexts)
    return await evaluate_faithfulness(
        answer=req.answer,
        contexts=req.contexts,
        query=req.query,
        prompt_version=req.prompt_version,
        context_embeddings=context_embeddings,
    )

@app.get("/api/eval/runs")
async def eval_runs(
    run_type: str = Query("", description="rag | faithfulness"),
    limit: int = Query(50, ge=1, le=200),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """列出评估运行记录"""
    from eval_repository import list_evaluation_runs
    return await list_evaluation_runs(run_type=run_type, limit=limit)

@app.get("/api/eval/runs/{run_id}")
async def eval_run_detail(
    run_id: str,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估运行详情"""
    from eval_repository import get_evaluation_run
    run = await get_evaluation_run(run_id)
    if not run:
        raise HTTPException(404, "Evaluation run not found")
    return run

@app.get("/api/eval/report")
async def eval_report(
    run_type: str = Query("", description="rag | faithfulness"),
    limit: int = Query(200, ge=1, le=1000),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """质量评估聚合报告（指标均值/通过率）"""
    from eval_repository import evaluation_report
    return await evaluation_report(run_type=run_type, limit=limit)

# ── Agent 轨迹端点 ──

@app.get("/api/agent-traces")
async def agent_traces(
    caller: str = Query("", description="调用方"),
    operation: str = Query("", description="操作"),
    status: str = Query("", description="success | error"),
    event_id: int = Query(0),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """查询 Agent LLM 轨迹（分页 + 过滤）"""
    from eval_repository import get_traces
    return await get_traces(
        caller=caller, operation=operation, status=status,
        event_id=event_id, limit=limit, offset=offset,
    )

@app.get("/api/agent-traces/stats")
async def agent_trace_stats(
    caller: str = Query("", description="调用方"),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """Agent 轨迹聚合统计"""
    from eval_repository import get_trace_stats
    return await get_trace_stats(caller=caller)

# ── 钓鱼检测端点 ──

from phishing_guard import phishing_guard
from phishing_guard.models import (
    EmailPhishingRequest,
    WebPhishingRequest,
    DomainPhishingRequest,
    AttachmentPhishingRequest,
    SmsPhishingRequest,
    QrCodePhishingRequest,
    BecPhishingRequest,
)
from phishing_guard.drill_manager import drill_manager
from models import PhishingDrill, PhishingDrillRecord

@app.post("/api/phishing/detect/email")
async def phishing_detect_email(
    req: EmailPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """邮件钓鱼检测"""
    verdict = phishing_guard.detect_email(req)
    record = PhishingRecord(
        detection_type="email",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/web")
async def phishing_detect_web(
    req: WebPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """网页钓鱼检测"""
    verdict = phishing_guard.detect_web(req)
    record = PhishingRecord(
        detection_type="web",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/domain")
async def phishing_detect_domain(
    req: DomainPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """域名访问钓鱼检测"""
    verdict = phishing_guard.detect_domain(req)
    record = PhishingRecord(
        detection_type="domain",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/attachment")
async def phishing_detect_attachment(
    req: AttachmentPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """附件钓鱼检测"""
    verdict = phishing_guard.detect_attachment(req)
    record = PhishingRecord(
        detection_type="attachment",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/sms")
async def phishing_detect_sms(
    req: SmsPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """短信钓鱼检测"""
    verdict = phishing_guard.detect_sms(req)
    record = PhishingRecord(
        detection_type="sms",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/qrcode")
async def phishing_detect_qrcode(
    req: QrCodePhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """二维码钓鱼检测"""
    verdict = phishing_guard.detect_qrcode(req)
    record = PhishingRecord(
        detection_type="qrcode",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.post("/api/phishing/detect/bec")
async def phishing_detect_bec(
    req: BecPhishingRequest,
    session: AsyncSession = Depends(get_session),
):
    """商务诈骗 (BEC) 检测"""
    verdict = phishing_guard.detect_bec(req)
    record = PhishingRecord(
        detection_type="bec",
        target=verdict.target,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        score=verdict.score,
        indicators=[i.model_dump() for i in verdict.indicators],
        summary=verdict.summary,
        suggested_actions=verdict.suggested_actions,
        raw_input=req.model_dump(),
    )
    session.add(record)
    await session.commit()
    return verdict.to_dict()

@app.get("/api/phishing/stats")
async def phishing_stats(session: AsyncSession = Depends(get_session)):
    """钓鱼检测统计"""
    total = (await session.execute(
        select(func.count(PhishingRecord.id))
    )).scalar() or 0
    phishing_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "phishing")
    )).scalar() or 0
    suspicious_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "suspicious")
    )).scalar() or 0
    safe_count = (await session.execute(
        select(func.count(PhishingRecord.id)).where(PhishingRecord.risk_level == "safe")
    )).scalar() or 0

    by_type = {}
    for dtype in ("email", "web", "domain", "attachment", "sms", "qrcode", "bec"):
        cnt = (await session.execute(
            select(func.count(PhishingRecord.id)).where(PhishingRecord.detection_type == dtype)
        )).scalar() or 0
        by_type[dtype] = cnt

    return {
        "total": total,
        "phishing": phishing_count,
        "suspicious": suspicious_count,
        "safe": safe_count,
        "by_type": by_type,
    }

@app.get("/api/phishing/history")
async def phishing_history(
    limit: int = Query(20, ge=1, le=100),
    detection_type: str = Query("", description="email / web / domain"),
    session: AsyncSession = Depends(get_session),
):
    """钓鱼检测历史记录"""
    stmt = select(PhishingRecord).order_by(desc(PhishingRecord.created_at))
    if detection_type:
        stmt = stmt.where(PhishingRecord.detection_type == detection_type)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "detection_type": r.detection_type,
            "target": r.target,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "score": r.score,
            "summary": r.summary,
            "indicator_count": len(r.indicators or []),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]

# ── 钓鱼演练管理端点 ──

class DrillCreateRequest(BaseModel):
    name: str
    drill_type: str = "email"
    template_subject: str = ""
    template_body: str = ""

class DrillLaunchRequest(BaseModel):
    targets: list[str]

class DrillRecordRequest(BaseModel):
    target_identifier: str
    event_type: str  # opened / clicked / reported

@app.post("/api/phishing/drill")
async def create_drill(
    req: DrillCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    """创建钓鱼演练"""
    return await drill_manager.create_drill(
        session, req.name, req.drill_type,
        req.template_subject, req.template_body,
    )

@app.get("/api/phishing/drill")
async def list_drills(
    status: str = Query("", description="draft / running / completed"),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    """演练列表"""
    return await drill_manager.list_drills(session, status=status, limit=limit)

@app.get("/api/phishing/drill/{drill_id}")
async def get_drill(
    drill_id: int,
    session: AsyncSession = Depends(get_session),
):
    """演练详情 + 统计"""
    result = await drill_manager.get_drill(session, drill_id)
    if not result:
        raise HTTPException(404, "Drill not found")
    return result

@app.delete("/api/phishing/drill/{drill_id}")
async def delete_drill(
    drill_id: int,
    session: AsyncSession = Depends(get_session),
):
    """删除演练"""
    ok = await drill_manager.delete_drill(session, drill_id)
    if not ok:
        raise HTTPException(404, "Drill not found")
    return {"deleted": True}

@app.post("/api/phishing/drill/{drill_id}/launch")
async def launch_drill(
    drill_id: int,
    req: DrillLaunchRequest,
    session: AsyncSession = Depends(get_session),
):
    """发起演练（批量生成目标记录）"""
    result = await drill_manager.launch_drill(session, drill_id, req.targets)
    if not result:
        raise HTTPException(404, "Drill not found")
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@app.post("/api/phishing/drill/{drill_id}/record")
async def record_drill_event(
    drill_id: int,
    req: DrillRecordRequest,
    session: AsyncSession = Depends(get_session),
):
    """记录演练目标事件（opened / clicked / reported）"""
    result = await drill_manager.record_event(
        session, drill_id, req.target_identifier, req.event_type,
    )
    if not result:
        raise HTTPException(404, "Drill record not found")
    return result
