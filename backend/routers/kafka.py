"""Kafka 消息总线与 CEP 攻击链管理路由"""
import logging

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session
from auth import UserInfo, get_current_user
from audit_trail import log_from_request
from kafka_consumer import kafka_consumer_manager
from kafka_producer import kafka_producer
from schema_registry import schema_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["kafka"])

# ── CEP 模式管理（热更新 + 灰度）──

# 默认 CEP 模式（内存缓存，通过 Kafka Broadcast 同步到 Flink）
_CEP_PATTERNS_CACHE: dict[str, dict] = {
    "port_scan_to_c2": {
        "patternId": "port_scan_to_c2", "name": "端口扫描→暴力破解→C2",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
        "withinMinutes": 30, "enabled": True, "shadowMode": False, "version": 1,
    },
    "lateral_movement": {
        "patternId": "lateral_movement", "name": "可疑登录→文件访问→横向移动",
        "steps": ["SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE"],
        "withinMinutes": 60, "enabled": True, "shadowMode": False, "version": 1,
    },
    "data_exfil": {
        "patternId": "data_exfil", "name": "文件访问→数据外泄",
        "steps": ["FILE_ACCESS", "DATA_EXFIL"],
        "withinMinutes": 15, "enabled": True, "shadowMode": False, "version": 1,
    },
}


async def _broadcast_pattern(pattern: dict):
    """将模式配置发布到 Kafka Broadcast topic"""
    if kafka_producer.is_active:
        try:
            await kafka_producer._producer.send(
                settings.kafka_topic_cep_patterns,
                key=pattern["patternId"],
                value=pattern,
            )
            logger.info(f"[CEP] Broadcast pattern: {pattern['patternId']} v{pattern['version']}")
        except Exception as e:
            logger.warning(f"[CEP] Broadcast failed: {e}")


async def _flink_overview() -> dict:
    """聚合 Flink JobManager 状态 (REST API) — 单一管道状态视图"""
    import httpx

    base = settings.flink_jobmanager_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            overview = (await client.get(f"{base}/overview")).json()
            jobs = (await client.get(f"{base}/jobs/overview")).json().get("jobs", [])
            return {
                "reachable": True,
                "taskmanagers": overview.get("taskmanagers", 0),
                "slots_total": overview.get("slots-total", 0),
                "slots_available": overview.get("slots-available", 0),
                "running_jobs": overview.get("jobs-running", 0),
                "finished_jobs": overview.get("jobs-finished", 0),
                "jobs": [
                    {
                        "id": j.get("jid"),
                        "name": j.get("name"),
                        "state": j.get("state"),
                        "start_ts": j.get("start-time"),
                        "end_ts": j.get("end-time"),
                        "duration_ms": j.get("duration"),
                    }
                    for j in jobs
                ],
            }
    except Exception as e:
        logger.warning(f"[Flink] JobManager 不可达: {e}")
        return {"reachable": False, "error": str(e)}


@router.get("/kafka/status")
async def kafka_status():
    """Kafka 消息总线 + Flink 管道聚合状态 (单一状态视图)"""
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
        "flink": await _flink_overview(),
        "schema_registry": {
            "configured": bool(schema_registry._registry_base),
            "schemas": list(schema_registry._schemas.keys()),
        },
    }


async def _trace_backend_health() -> dict:
    """trace 后端健康: otel-collector + Grafana Tempo 可达性"""
    import httpx

    result = {"tempo": {"reachable": False}, "otel_collector": {"reachable": False}}
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get("http://tempo:3200/ready")
            result["tempo"] = {"reachable": True, "status_code": r.status_code}
    except Exception as e:
        result["tempo"]["error"] = str(e)
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            # OTLP HTTP 接收端探测 (401/400 均说明服务可达)
            r = await client.post(
                "http://otel-collector:4318/v1/traces", json={"resourceSpans": []}
            )
            result["otel_collector"] = {"reachable": True, "status_code": r.status_code}
    except Exception as e:
        result["otel_collector"]["error"] = str(e)
    return result


@router.get("/pipeline/status")
async def pipeline_status():
    """全管道拓扑状态 — 一次调用看穿 Flink→Kafka→Python→Trace 每一环"""
    return {
        "source": {"kafka_enabled": settings.kafka_enabled},
        "flink": await _flink_overview(),
        "kafka_consumers": kafka_consumer_manager.stats(),
        "kafka_rejections": kafka_consumer_manager.rejection_stats(),
        "schema_registry": {
            "configured": bool(schema_registry._registry_base),
            "schemas": list(schema_registry._schemas.keys()),
        },
        "tracing": await _trace_backend_health(),
    }


@router.get("/kafka/rejections")
async def kafka_rejections():
    """Kafka 拒绝原因统计（数据质量可观测）"""
    return kafka_consumer_manager.rejection_stats()


@router.get("/cep/partial-matches")
async def cep_partial_matches():
    """CEP 攻击链部分匹配状态（实时可视化）"""
    return {"matches": kafka_consumer_manager.cep_partial_matches()}


@router.get("/cep/patterns")
async def cep_patterns_list():
    """列出所有 CEP 攻击链模式"""
    return {"patterns": list(_CEP_PATTERNS_CACHE.values())}


@router.post("/cep/patterns/{pattern_id}/toggle")
async def cep_pattern_toggle(
    pattern_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """启用/禁用 CEP 模式（通过 Kafka Broadcast 热更新到 Flink）"""
    if pattern_id not in _CEP_PATTERNS_CACHE:
        return {"success": False, "error": f"模式 {pattern_id} 不存在"}
    p = _CEP_PATTERNS_CACHE[pattern_id]
    before_enabled = p["enabled"]
    p["enabled"] = not p["enabled"]
    p["version"] += 1
    await _broadcast_pattern(p)
    await log_from_request(
        session, request, user, action="cep.pattern_toggle",
        target_type="cep_pattern", target_id=pattern_id,
        before={"enabled": before_enabled},
        after={"enabled": p["enabled"], "version": p["version"]},
    )
    return {"success": True, "pattern": p}


@router.post("/cep/patterns/{pattern_id}/shadow")
async def cep_pattern_shadow(
    pattern_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """切换灰度模式（shadow mode: 仅记录不告警）"""
    if pattern_id not in _CEP_PATTERNS_CACHE:
        return {"success": False, "error": f"模式 {pattern_id} 不存在"}
    p = _CEP_PATTERNS_CACHE[pattern_id]
    before_shadow = p["shadowMode"]
    p["shadowMode"] = not p["shadowMode"]
    p["version"] += 1
    await _broadcast_pattern(p)
    await log_from_request(
        session, request, user, action="cep.pattern_toggle",
        target_type="cep_pattern", target_id=pattern_id,
        before={"shadowMode": before_shadow},
        after={"shadowMode": p["shadowMode"], "version": p["version"]},
    )
    return {"success": True, "pattern": p}


@router.post("/cep/replay")
async def cep_replay(limit: int = 200, src_ip: str = ""):
    """CEP 回放验证：用历史事件回测攻击链模式命中率"""
    from models import async_session as db_session, SecurityEvent
    from sqlalchemy import select, desc

    patterns = {k: v["steps"] for k, v in _CEP_PATTERNS_CACHE.items() if v["enabled"]}

    async with db_session() as session:
        stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
        if src_ip:
            stmt = stmt.where(SecurityEvent.src_ip == src_ip)
        result = await session.execute(stmt)
        events = result.scalars().all()

    # 按 src_ip 分组，时间正序回放
    from collections import defaultdict
    by_ip: dict[str, list] = defaultdict(list)
    for evt in reversed(events):
        by_ip[evt.src_ip or "unknown"].append(evt)

    hits = []
    for ip, ip_events in by_ip.items():
        for pname, steps in patterns.items():
            matched = []
            step_idx = 0
            for evt in ip_events:
                if step_idx < len(steps) and evt.event_type == steps[step_idx]:
                    matched.append({"event_id": evt.id, "event_type": evt.event_type,
                                    "step": steps[step_idx], "at": str(evt.created_at)})
                    step_idx += 1
                    if step_idx >= len(steps):
                        hits.append({"pattern": pname, "src_ip": ip,
                                     "events": matched, "status": "completed"})
                        step_idx = 0
                        matched = []
            if matched:
                hits.append({"pattern": pname, "src_ip": ip,
                             "events": matched, "status": "partial",
                             "progress": f"{len(matched)}/{len(steps)}"})

    return {
        "total_events": len(events),
        "total_ips": len(by_ip),
        "patterns_tested": list(patterns.keys()),
        "hits": hits,
        "hit_count": sum(1 for h in hits if h["status"] == "completed"),
        "partial_count": sum(1 for h in hits if h["status"] == "partial"),
    }
