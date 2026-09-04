# -*- coding: utf-8 -*-
"""
共享记忆安全审计 Agent 平台 — FastAPI 主入口

职责:
  - 应用生命周期管理 (lifespan: 初始化 / 关闭)
  - 中间件注册 (CORS / 速率限制)
  - 路由挂载 (13 个业务域 Router)

所有 API 端点已拆分到 routers/ 子模块，本文件不再定义端点。
"""

import asyncio
import logging
import json
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from models import init_db, async_session, NetworkFlow, PcapFile
from sliding_window import sliding_window
from summary_compression import summary, embedder
from context_stream import context_stream
from anomaly_detector import anomaly_detector
from scheduler import scheduler
from source_registry import source_registry
from kafka_consumer import kafka_consumer_manager
from kafka_producer import kafka_producer
from response_engine import ssh_transport
from rag import seed_knowledge_base

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    await init_db()
    # 成本控制: 从 llm_traces 重建今日用量, 保证预算门禁不因重启失效
    try:
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import select, func
        from models import AgentTrace, async_session as db_session
        from summary_compression import cost_tracker
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        async with db_session() as _s:
            used, prompt, completion = (await _s.execute(
                select(
                    func.coalesce(func.sum(AgentTrace.total_tokens), 0),
                    func.coalesce(func.sum(AgentTrace.prompt_tokens), 0),
                    func.coalesce(func.sum(AgentTrace.completion_tokens), 0),
                ).where(AgentTrace.created_at >= today_start)
            )).one()
            calls = (await _s.execute(
                select(func.count(AgentTrace.id)).where(AgentTrace.created_at >= today_start)
            )).scalar() or 0
        cost_tracker.restore_today_usage(
            tokens=int(used), calls=int(calls),
            prompt_tokens=int(prompt), completion_tokens=int(completion),
        )
        logger.info(
            f"CostControl: restored today usage={used} tokens / {calls} calls, "
            f"budget={cost_tracker.daily_budget}, over_budget={cost_tracker.is_over_budget()}"
        )
    except Exception as e:
        logger.warning(f"CostControl: failed to restore today usage (will start from zero): {e}")
    await sliding_window.connect()
    await summary.ensure_client()
    await embedder.ensure_client()
    # Connect Redis for context_stream
    redis_client = await sliding_window.get_redis()
    if redis_client:
        embedder.set_redis(redis_client)
        # v6: LLM 响应缓存接入同一 Redis(跨重启/跨容器共享), 替代原纯进程内缓存
        summary.llm.set_redis(redis_client)
        context_stream.set_redis(redis_client)
        anomaly_detector.set_redis(redis_client)
        # 回滚记录双写 Redis：进程重启后已执行动作仍可回滚
        from response_engine.response_executor import rollback_store
        rollback_store.set_redis(redis_client)
        # v6: Temporal worker 跨进程写回后,需 Redis 广播才能:
        #   1) 丢弃本进程 event_store 热缓存(否则 pipeline API 永远 pending)
        #   2) 把 audit_complete 注入本进程 SSE(否则 Monitor 看不到报告)
        from event_store import event_store as _event_store
        from event_bus import event_bus as _event_bus
        from temporal import client as _temporal_client
        from audit_pq import audit_pq as _audit_pq
        _event_store.set_redis(redis_client)
        _event_bus.set_redis(redis_client)
        _temporal_client.set_redis(redis_client)
        _audit_pq.set_redis(redis_client)
        await _event_store.start_invalidate_listener()
        await _event_bus.start_redis_bridge()
        await anomaly_detector.load_baselines_from_redis()
    logger.info("安全审计模式: 所有事件全量存储，无有损压缩 + 异常基线持久化")
    if not settings.llm_api_key:
        logger.warning("LLM API key not set — LLM calls will return fallback responses")
    if not settings.embedding_api_key:
        logger.warning("Embedding API key not set — embeddings will return zero vectors")
    logger.info(f"LLM: {settings.llm_model} @ {settings.llm_base_url}")
    logger.info(f"Embedding: {settings.embedding_model} @ {settings.embedding_base_url}")
    logger.info(f"Embedding dim: {settings.embedding_dim}")

    # Qdrant 知识库 / 记忆集合就绪（缺失则创建，避免检索 404）
    try:
        from qdrant_store import qdrant_store
        from vector_store import vector_store as _mem_vs
        ok = await qdrant_store.ensure_collection()
        logger.info(
            f"Qdrant knowledge collection ready={ok} "
            f"name={settings.qdrant_collection} "
            f"size={settings.qdrant_vector_size or settings.embedding_dim}"
        )
        await _mem_vs._ensure_memories_collection()
    except Exception as e:
        logger.warning(f"Qdrant ensure_collection skipped: {e}")

    # 配置响应引擎传输层
    if settings.response_ssh_host:
        # v4 修复(2026-09-01):key_file 解析顺序:
        #   1. settings.response_ssh_key_file (env 显式配置)
        #   2. /tmp/ssh-keys/id_rsa (entrypoint 期望路径)
        #   3. /root/.ssh/id_rsa (兼容旧配置,entrypoint 也会 cp 到这里)
        import os as _os
        key_candidates = [
            settings.response_ssh_key_file,
            "/tmp/ssh-keys/id_rsa",
            "/root/.ssh/id_rsa",
        ]
        _key_file = next((p for p in key_candidates if p and _os.path.isfile(p)), settings.response_ssh_key_file)
        if not _os.path.isfile(_key_file):
            logger.warning(f"Response SSH key not found at any candidate: {key_candidates}; transport will be stub")
        ssh_transport.configure(
            host=settings.response_ssh_host,
            port=settings.response_ssh_port,
            user=settings.response_ssh_user,
            key_file=_key_file,
        )
        logger.info(f"Response SSH transport configured: {settings.response_ssh_user}@{settings.response_ssh_host}:{settings.response_ssh_port} key={_key_file}")
    else:
        logger.info("Response transport mode: stub (set RESPONSE_SSH_HOST to enable real execution)")

    # 播种安全知识库
    try:
        async with async_session() as rag_session:
            await seed_knowledge_base(rag_session)
    except Exception as e:
        logger.warning(f"Knowledge base seeding failed (will retry): {e}")

    # 启动时后台回填缺失 embedding(幂等, 独立 session; seed 因 count>10 skip 时也照常触发)
    try:
        from rag.seeder import launch_embedding_backfill
        launch_embedding_backfill(scope="chunks")
        launch_embedding_backfill(scope="memories")
    except Exception as e:
        logger.warning(f"Startup embedding backfill launch failed: {e}")

    # 数据源注册表初始化
    source_registry.load_from_config()
    try:
        await source_registry.load_from_db(async_session)
        await source_registry._backfill_pending(async_session)
    except Exception as e:
        logger.warning(f"SourceRegistry DB load failed: {e}; 继续使用 config 缓存")

    # 资产管理 — 从 DB 重建内存缓存
    try:
        from routers.assets import refresh_asset_cache
        await refresh_asset_cache()
    except Exception as e:
        logger.warning(f"[Assets] cache init failed: {e}")

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

    # ── NDR 模块初始化（按配置按需启用） ──
    if settings.capture_enabled:
        from traffic_capture.capture_engine import capture_engine
        from traffic_capture.flow_aggregator import flow_aggregator
        from traffic_capture.pcap_store import pcap_store

        # 流持久化回调: FlowRecord → network_flows 表
        # (缺此接线时聚合结果会被直接丢弃, /api/ndr/flows 恒为空)
        async def _persist_flow(record):
            from datetime import datetime as _dt, timezone as _tz
            async with async_session() as session:
                session.add(NetworkFlow(
                    src_ip=record.src_ip, dst_ip=record.dst_ip,
                    src_port=record.src_port, dst_port=record.dst_port,
                    protocol=record.protocol, direction=record.direction,
                    bytes_in=record.bytes_in, bytes_out=record.bytes_out,
                    packets_in=record.packets_in, packets_out=record.packets_out,
                    duration_ms=record.duration_ms, tcp_flags=record.tcp_flags,
                    app_protocol=record.app_protocol, sensor_id=record.sensor_id,
                    flow_start=_dt.fromtimestamp(record.flow_start, tz=_tz.utc) if record.flow_start else None,
                    flow_end=_dt.fromtimestamp(record.flow_end, tz=_tz.utc) if record.flow_end else None,
                    raw_data={"packet_count": record.packet_count},
                ))
                await session.commit()

        flow_aggregator.on_flow_complete(_persist_flow)

        # PCAP 元数据持久化回调: 轮转关闭文件时写入 pcap_files 表
        async def _persist_pcap_meta(meta):
            from datetime import datetime as _dt
            async with async_session() as session:
                session.add(PcapFile(
                    file_path=meta["file_path"],
                    file_size=meta.get("file_size", 0),
                    sensor_id=meta.get("sensor_id", ""),
                    interface=meta.get("interface", ""),
                    packet_count=meta.get("packet_count", 0),
                    capture_start=_dt.fromisoformat(meta["capture_start"]) if meta.get("capture_start") else None,
                    capture_end=_dt.fromisoformat(meta["capture_end"]) if meta.get("capture_end") else None,
                    bpf_filter=settings.capture_bpf_filter,
                    status=meta.get("status", "closed"),
                    storage_tier=meta.get("storage_tier", "hot"),
                ))
                await session.commit()

        pcap_store.set_db_callback(_persist_pcap_meta)

        # 协议解析层: dissector 识别协议 → 各解析器 → TLS 会话关联落库
        # (缺此接线时 /api/ndr/tls 恒为空)
        from protocol_parser.dissector import dissector
        from protocol_parser.tls_parser import tls_parser
        from protocol_parser.http_parser import http_parser
        from protocol_parser.dns_parser import dns_parser
        from protocol_parser.smb_parser import smb_parser
        from encrypted_traffic.session_collector import tls_session_collector
        dissector.register_parser("TLS", tls_parser)
        dissector.register_parser("HTTP", http_parser)
        dissector.register_parser("DNS", dns_parser)
        dissector.register_parser("SMB", smb_parser)
        dissector.on_message(tls_session_collector.on_message)

        capture_engine.register_handler(dissector.on_packet)
        capture_engine.register_handler(flow_aggregator.on_packet)
        capture_engine.register_handler(pcap_store.on_packet)
        await flow_aggregator.start()
        await pcap_store.start()
        await capture_engine.start()
        logger.info("NDR 流量采集引擎已启动")

    if settings.edr_enabled:
        from edr_fusion.edr_adapter import edr_adapter
        await edr_adapter.start()
        logger.info("EDR 融合适配器已启动")

    if settings.intel_enabled:
        from threat_intel.ioc_matcher import ioc_matcher
        await ioc_matcher.refresh_cache()
        logger.info("威胁情报 IOC 缓存已加载")

    if settings.sandbox_enabled:
        from zeroday_detect.sandbox_connector import sandbox
        logger.info(f"沙箱连接器就绪: {sandbox.sandbox_type} @ {sandbox.api_url}")

    # Kafka 消息总线（可选）
    if settings.kafka_enabled:
        # 注册 Flink↔Python 跨运行时 Schema 契约 (best-effort, 失败不影响消费)
        from schema_registry import schema_registry
        await schema_registry.register_all()
        await kafka_producer.start()
        await kafka_consumer_manager.start()
        logger.info("Kafka 模式已启用: 数据通过 Kafka + Flink 流水线处理 (Python 为薄消费者)")
    else:
        logger.info("HTTP 直连模式: 设置 SHARED_MEMORY_KAFKA_ENABLED=true 启用 Kafka")

    # 启动定时调度器
    await scheduler.start(async_session)
    logger.info("Scheduler started")

    # 可观测性
    from observability.health_monitor import health_monitor
    from observability.watchdog import watchdog
    from observability.pipeline_tracer import pipeline_tracer
    health_monitor.set_diagnose_callback(watchdog.diagnose)
    pipeline_tracer.enable_persist()
    logger.info("Observability: health monitor + watchdog + pipeline tracer initialized")

    # 启动时清理长期 stuck 未分析事件，避免积压拖垮队列
    if settings.stuck_auto_reset_minutes and settings.stuck_auto_reset_minutes > 0:
        try:
            from datetime import datetime, timezone, timedelta
            from sqlalchemy import select
            from models import SecurityEvent
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.stuck_auto_reset_minutes)
            async with async_session() as _s:
                rows = (await _s.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.analyzed == False,
                        SecurityEvent.created_at < cutoff,
                    ).limit(500)
                )).scalars().all()
                n = 0
                for e in rows:
                    e.analyzed = True
                    raw = dict(e.raw_data or {})
                    raw["_audit_llm_error"] = "auto_reset_stuck_on_startup"
                    audit = dict(raw.get("_audit_llm") or {})
                    audit.update({
                        "status": "failed",
                        "error": "auto_reset_stuck_on_startup",
                        "note": "cleared on backend startup",
                    })
                    raw["_audit_llm"] = audit
                    e.raw_data = raw
                    n += 1
                if n:
                    await _s.commit()
                    logger.warning(f"Cleared {n} stuck unanalyzed events older than {settings.stuck_auto_reset_minutes}m")
        except Exception as e:
            logger.warning(f"Stuck auto-reset skipped: {e}")

    yield

    # ── Shutdown ──
    if settings.kafka_enabled:
        await kafka_consumer_manager.stop()
        await kafka_producer.stop()

    await scheduler.stop()
    await summary.close()
    await embedder.close()
    logger.info("Shutdown complete")


# ════════════════════════════════════════════
# 应用实例 + 中间件
# ════════════════════════════════════════════

import os
_is_prod = os.environ.get("SHARED_MEMORY_ENV_NAME", settings.env_name) == "prod"

app = FastAPI(
    title="共享记忆服务层",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=json.loads(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# ── 全局认证中间件 ──
# 所有 /api/* 端点默认需要 JWT 认证 (Bearer header 或 ?token= query param)
# 白名单路径无需认证

_PUBLIC_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/register",
    "/api/health",
    "/docs", "/redoc", "/openapi.json",
    "/metrics",
})


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in _PUBLIC_PATHS:
        # 支持 Authorization header 和 query param (SSE EventSource 不支持自定义 header)
        token = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif "token" in request.query_params:
            token = request.query_params["token"]

        if not token:
            return JSONResponse(status_code=401, content={"detail": "Missing authorization"})

        try:
            import jwt as _jwt
            payload = _jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
            request.state.user = payload
        except _jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"detail": "Token expired"})
        except _jwt.InvalidTokenError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})

    response = await call_next(request)
    # 移除 Server 版本头 (starlette MutableHeaders 无 dict.pop, 用 del + 存在性检查)
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ── 速率限制中间件 ──

_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_CLEANUP_INTERVAL = 300
_last_rate_limit_cleanup = 0.0

# 限流白名单 — 这些路径高频访问或本身已有限流, 不计入全局限流
#   /api/health         — K8s liveness/readiness probe + 前端轮询
#   /api/llm/cost       — LLM 成本只读查询, O(1) 内存读取, 不应限流
#   /api/feedback/*     — feedback 统计/建议, 只读
#   /api/auth/*         — 登录/注册, auth.py 已有自己的 brute force 429
#   /api/logs/ingest    — 真实日志源入站(2026-09-01 v4 复现:同机 ingest 被打 429)
#   /api/logs/events    — 监控查询(Monitor 页 SSE/轮询,被打 429 会断流)
#   /api/firewall/*     — 防火墙状态查询(只读,被限会让 SOC 失去态势感知)
#   /api/response/*     — 响应引擎状态/动作查询(只读,被限会让响应链断)
_RATE_LIMIT_WHITELIST = (
    "/api/health",
    "/api/llm/cost",
    "/api/feedback",
    "/api/auth",
    "/api/logs/ingest",
    "/api/logs/events",
    "/api/firewall",
    "/api/response",
)


def _is_rate_limit_whitelisted(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _RATE_LIMIT_WHITELIST)


def _resolve_rate_limit_key(request: Request) -> str:
    """v4 修复(2026-09-01):按 (api_key | X-Forwarded-For | client_ip) 分桶,避免 127.0.0.1 共桶

    优先级:
      1. X-API-Key 头(真实数据源)→ key:<truncated>
      2. Authorization Bearer token  → key:<truncated>
      3. X-Forwarded-For 第一项      → ip:<xff>
      4. request.client.host         → ip:<host>

    桶 key 截断到 32 字符,防止恶意长 header 撑爆 _rate_limit_store 内存
    """
    # 1. X-API-Key
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return f"key:{api_key[:32]}"
    # 2. Authorization Bearer
    auth = request.headers.get("Authorization", "").strip()
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return f"key:{token[:32]}"
    # 3. X-Forwarded-For(取第一项 = 真实客户端 IP)
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        first_ip = xff.split(",")[0].strip()
        if first_ip:
            return f"ip:{first_ip[:64]}"
    # 4. client.host
    return f"ip:{request.client.host if request.client else 'unknown'}"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _last_rate_limit_cleanup
    # 白名单路径直接 pass, 不计入限流
    if _is_rate_limit_whitelisted(request.url.path):
        return await call_next(request)
    if settings.rate_limit_per_minute <= 0:
        return await call_next(request)
    # v4 修复:按 (api_key | xff | client_ip) 分桶,而非纯 client_ip
    rate_key = _resolve_rate_limit_key(request)
    now = time.time()
    window = 60.0
    if now - _last_rate_limit_cleanup > _RATE_LIMIT_CLEANUP_INTERVAL:
        _last_rate_limit_cleanup = now
        stale_keys = [k for k, ts in _rate_limit_store.items() if not ts or ts[-1] < now - window]
        for k in stale_keys:
            del _rate_limit_store[k]
    timestamps = _rate_limit_store[rate_key]
    cutoff = now - window
    _rate_limit_store[rate_key] = [t for t in timestamps if t > cutoff]
    if len(_rate_limit_store[rate_key]) >= settings.rate_limit_per_minute:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    _rate_limit_store[rate_key].append(now)
    return await call_next(request)


# ════════════════════════════════════════════
# 路由挂载 — 13 个业务域 Router
# ════════════════════════════════════════════

from routers.auth import router as auth_router
from routers.sources import router as sources_router
from routers.kafka import router as kafka_router
from routers.assets import router as assets_router
from routers.logs import router as logs_router
from routers.chat import router as chat_router
from routers.audit import router as audit_router
from routers.response import router as response_router
from routers.rag import router as rag_router
from routers.phishing import router as phishing_router
from routers.ndr import router as ndr_router
from routers.edr_intel import router as edr_intel_router
from routers.ops import router as ops_router
from routers.capabilities import router as capabilities_router

app.include_router(auth_router)
app.include_router(sources_router)
app.include_router(kafka_router)
app.include_router(assets_router)
app.include_router(logs_router)
app.include_router(chat_router)
app.include_router(audit_router)
app.include_router(response_router)
app.include_router(rag_router)
app.include_router(phishing_router)
app.include_router(ndr_router)
app.include_router(capabilities_router)
app.include_router(edr_intel_router)
app.include_router(ops_router)

logger.info(f"Mounted 13 routers — {len(app.routes)} routes total")

# ── OpenTelemetry 标准 trace (→ otel-collector → Tempo) ──
try:
    from otel_setup import setup_otel
    setup_otel(app=app)
except Exception as e:
    logger.warning(f"OTel setup failed: {e}")

# ── Prometheus 指标出口 (Python 侧; 与 Flink 9250 对齐, 统一可观测) ──
# 注: 用轻量 metrics.py (兼容 FastAPI 0.14x _IncludedRouter), 替代
# prometheus-fastapi-instrumentator (其内省 route.path 与新版 FastAPI 不兼容 → 全请求 500)
from metrics import metrics_endpoint, MetricsMiddleware

app.add_middleware(MetricsMiddleware)
app.add_api_route("/metrics", metrics_endpoint, include_in_schema=False, methods=["GET"])
logger.info("Prometheus /metrics enabled (metrics.py)")
