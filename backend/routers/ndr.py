"""NDR 流量采集与协议解析 — 路由模块"""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session
from auth import get_current_user, UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ndr", tags=["ndr"])


@router.get("/flows")
async def ndr_list_flows(
    limit: int = Query(100, le=500),
    src_ip: str = "",
    dst_ip: str = "",
    protocol: str = "",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询网络流记录"""
    from models import NetworkFlow
    q = select(NetworkFlow).order_by(desc(NetworkFlow.created_at)).limit(limit)
    if src_ip:
        q = q.where(NetworkFlow.src_ip == src_ip)
    if dst_ip:
        q = q.where(NetworkFlow.dst_ip == dst_ip)
    if protocol:
        q = q.where(NetworkFlow.app_protocol == protocol)
    result = await session.execute(q)
    flows = result.scalars().all()
    return [
        {
            "id": f.id, "src_ip": f.src_ip, "dst_ip": f.dst_ip,
            "src_port": f.src_port, "dst_port": f.dst_port,
            "protocol": f.protocol, "app_protocol": f.app_protocol,
            "direction": f.direction, "bytes_in": f.bytes_in, "bytes_out": f.bytes_out,
            "packets_in": f.packets_in, "packets_out": f.packets_out,
            "duration_ms": f.duration_ms, "sensor_id": f.sensor_id,
            "flow_start": f.flow_start.isoformat() if f.flow_start else None,
        }
        for f in flows
    ]


@router.get("/capture/stats")
async def ndr_capture_stats(user: UserInfo = Depends(get_current_user)):
    """采集引擎统计"""
    if not settings.capture_enabled:
        return {"enabled": False, "message": "流量采集未启用"}
    from traffic_capture.capture_engine import capture_engine
    from traffic_capture.flow_aggregator import flow_aggregator
    from traffic_capture.pcap_store import pcap_store
    stats = capture_engine.get_stats()
    stats["active_flows"] = flow_aggregator.active_flow_count
    stats["pcap"] = pcap_store.get_disk_usage()
    stats["enabled"] = True
    return stats


@router.get("/tls")
async def ndr_list_tls(
    limit: int = Query(100, le=500),
    sni: str = "",
    risk_min: float = 0.0,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询 TLS 会话"""
    from models import TlsSession
    q = select(TlsSession).order_by(desc(TlsSession.created_at)).limit(limit)
    if sni:
        q = q.where(TlsSession.sni.contains(sni))
    if risk_min > 0:
        q = q.where(TlsSession.risk_score >= risk_min)
    result = await session.execute(q)
    sessions = result.scalars().all()
    return [
        {
            "id": s.id, "src_ip": s.src_ip, "dst_ip": s.dst_ip, "dst_port": s.dst_port,
            "sni": s.sni, "ja3_hash": s.ja3_hash, "ja3s_hash": s.ja3s_hash,
            "ja4_hash": s.ja4_hash, "tls_version": s.tls_version,
            "cipher_suite": s.cipher_suite, "alpn": s.alpn,
            "cert_subject": s.cert_subject, "cert_issuer": s.cert_issuer,
            "cert_is_self_signed": s.cert_is_self_signed, "is_expired": s.is_expired,
            "risk_score": s.risk_score, "risk_reasons": s.risk_reasons or [],
            "session_start": s.session_start.isoformat() if s.session_start else None,
        }
        for s in sessions
    ]


@router.get("/pcap")
async def ndr_list_pcap(user: UserInfo = Depends(get_current_user)):
    """PCAP 文件列表"""
    if not settings.capture_enabled:
        return {"files": [], "disk": {}}
    from traffic_capture.pcap_store import pcap_store
    return {"files": pcap_store.list_files(), "disk": pcap_store.get_disk_usage()}
