"""
session_collector.py — TLS 握手消息关联器

将 protocol_parser.dissector 产出的 ClientHello / ServerHello / Certificate
消息按流 (src_ip, dst_ip, dst_port) 关联为完整会话，经 tls_metadata 聚合与
风险评分后持久化到 tls_sessions 表；高分会话触发 LLM 语义判定（主路径不等待）。

用法 (在 capture_enabled 初始化时接线):
    from encrypted_traffic.session_collector import tls_session_collector
    dissector.on_message(tls_session_collector.on_message)
"""
import logging
import time

logger = logging.getLogger(__name__)

_SESSION_TIMEOUT = 30.0   # 握手消息等待超时（秒）
_MAX_PENDING = 2000       # 挂起会话上限（防内存膨胀）
_SWEEP_INTERVAL = 10.0    # 惰性清理间隔（秒）


class TlsSessionCollector:
    """按五元组关联 TLS 握手三消息并落库"""

    def __init__(self):
        self._pending: dict[tuple, dict] = {}
        self._last_sweep = 0.0
        self._stats = {"sessions": 0, "expired": 0}

    @property
    def stats(self) -> dict:
        return {**self._stats, "pending": len(self._pending)}

    async def on_message(self, msg) -> None:
        """dissector 消息回调 — 仅处理 TLS 握手消息"""
        if getattr(msg, "protocol", "") != "TLS":
            return

        now = msg.timestamp or time.time()
        if now - self._last_sweep > _SWEEP_INTERVAL:
            self._last_sweep = now
            await self._sweep_expired(now)

        key = (msg.src_ip, msg.dst_ip, msg.dst_port)
        entry = self._pending.get(key)

        if msg.method == "ClientHello":
            if entry is not None and entry["client"] is not None:
                # 上一条握手尚未收齐即开始新握手 → 先 flush 旧会话
                await self._flush(key)
            if len(self._pending) >= _MAX_PENDING:
                self._evict_oldest()
            entry = {"client": msg, "server": None, "cert": None, "first_seen": now}
            self._pending[key] = entry
            return

        if entry is None:
            return  # 没有对应 ClientHello 的孤立消息, 忽略
        if msg.method == "ServerHello":
            entry["server"] = msg
        elif msg.method == "Certificate":
            entry["cert"] = msg
            # 证书到达即视为握手信息齐备（ClientHello 必有）
            if entry["client"] is not None:
                await self._flush(key)

    async def _sweep_expired(self, now: float):
        expired = [k for k, v in self._pending.items()
                   if now - v["first_seen"] > _SESSION_TIMEOUT]
        for key in expired:
            self._stats["expired"] += 1
            await self._flush(key)  # 仅有 ClientHello 也落库（SNI/JA3 仍有价值）

    def _evict_oldest(self):
        try:
            oldest = min(self._pending.items(), key=lambda kv: kv[1]["first_seen"])[0]
            self._pending.pop(oldest, None)
        except ValueError:
            pass

    async def _flush(self, key: tuple):
        entry = self._pending.pop(key, None)
        if entry is None or entry["client"] is None:
            return

        from encrypted_traffic.tls_metadata import tls_metadata
        src_ip, dst_ip, dst_port = key
        session = tls_metadata.build_session(
            client_hello_msg=entry["client"],
            server_hello_msg=entry["server"],
            cert_msg=entry["cert"],
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            timestamp=entry["first_seen"],
        )
        session = tls_metadata.score_session(session)
        self._stats["sessions"] += 1
        await self._persist(session)

        # 高分会话触发 LLM 语义判定（fire-and-forget, 不阻塞主路径）
        from encrypted_traffic.llm_tls_analyzer import (
            should_trigger_llm, llm_analyze_tls_session,
        )
        if should_trigger_llm(session):
            from llm_enhancer import safe_dispatch
            safe_dispatch(
                llm_analyze_tls_session(
                    src_ip=session.src_ip, dst_ip=session.dst_ip,
                    sni=session.sni, ja3_hash=session.ja3_hash,
                    tls_version=session.tls_version, cipher_suite=session.cipher_suite,
                    cert_subject=session.cert_subject, cert_issuer=session.cert_issuer,
                    cert_is_self_signed=session.cert_is_self_signed,
                    risk_score=session.risk_score, risk_reasons=session.risk_reasons,
                ),
                log_label="encrypted_traffic",
            )

    async def _persist(self, session):
        """TlsSessionData → tls_sessions 表"""
        from datetime import datetime
        from models import async_session as db_session, TlsSession

        def _parse_dt(s: str):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s)
            except (ValueError, TypeError):
                return None

        try:
            async with db_session() as db:
                db.add(TlsSession(
                    src_ip=session.src_ip, dst_ip=session.dst_ip,
                    dst_port=session.dst_port, sni=session.sni,
                    ja3_hash=session.ja3_hash, ja3s_hash=session.ja3s_hash,
                    ja4_hash=session.ja4_hash, tls_version=session.tls_version,
                    cipher_suite=session.cipher_suite, alpn=session.alpn,
                    cert_subject=session.cert_subject, cert_issuer=session.cert_issuer,
                    cert_serial=session.cert_serial,
                    cert_not_before=_parse_dt(session.cert_not_before),
                    cert_not_after=_parse_dt(session.cert_not_after),
                    cert_san=session.cert_san,
                    cert_is_self_signed=session.cert_is_self_signed,
                    risk_score=session.risk_score, risk_reasons=session.risk_reasons,
                    sensor_id=session.sensor_id,
                    session_start=datetime.fromtimestamp(session.timestamp) if session.timestamp else None,
                ))
                await db.commit()
        except Exception as e:
            logger.warning("TLS 会话持久化失败: %s", e)


# ── 全局单例 ──
tls_session_collector = TlsSessionCollector()
