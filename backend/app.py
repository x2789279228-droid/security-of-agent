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
        context_stream.set_redis(redis_client)
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
        await kafka_producer.start()
        await kafka_consumer_manager.start()
        logger.info("Kafka 模式已启用: 数据通过 Kafka + Flink 流水线处理")
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

app = FastAPI(title="共享记忆服务层", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=json.loads(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 速率限制中间件 ──

_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_CLEANUP_INTERVAL = 300
_last_rate_limit_cleanup = 0.0

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _last_rate_limit_cleanup
    if settings.rate_limit_per_minute <= 0:
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = 60.0
    if now - _last_rate_limit_cleanup > _RATE_LIMIT_CLEANUP_INTERVAL:
        _last_rate_limit_cleanup = now
        stale_ips = [ip for ip, ts in _rate_limit_store.items() if not ts or ts[-1] < now - window]
        for ip in stale_ips:
            del _rate_limit_store[ip]
    timestamps = _rate_limit_store[client_ip]
    cutoff = now - window
    _rate_limit_store[client_ip] = [t for t in timestamps if t > cutoff]
    if len(_rate_limit_store[client_ip]) >= settings.rate_limit_per_minute:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    _rate_limit_store[client_ip].append(now)
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
app.include_router(edr_intel_router)
app.include_router(ops_router)

logger.info(f"Mounted 13 routers — {len(app.routes)} routes total")
