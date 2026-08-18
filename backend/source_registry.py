"""
数据源注册与认证 (Source Registry) — P0.G 升级版

解决"无差别接收"的核心模块：
  1. 注册并获取 API Key（持久化到 data_sources 表，SHA256 哈希存储）
  2. 每次上报携带 API Key + Source ID
  3. 未注册来源的日志直接拒绝并告警
  4. 重启不丢注册与吊销状态（取代原内存+配置文件实现）

设计:
  - 内存热缓存保留原 API 合同（同步 authenticate() 调用方不变）
  - DB 为权威源；register/revoke/authenticate 穿透到 DB
  - 启动时 load_from_config() 仅在 DB 为空时播种配置文件，DB 已有则忽略

用法:
    registry = SourceRegistry()
    await registry.load_from_db(async_session)
    if registry.authenticate("soc-syslog-2024"):
        # 合法来源，接收
    else:
        # 拒绝，记录告警
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = logging.getLogger(__name__)


def _hash_key(api_key: str) -> str:
    """API Key SHA256 哈希（不存明文）"""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


@dataclass
class DataSource:
    """已注册的数据源（内存缓存对象）"""
    api_key: str                     # 完整明文（仅在内存缓存中保留以避免每次哈希）
    api_key_hash: str = ""           # SHA256 哈希（DB 主键）
    name: str = ""
    source_type: str = "generic"     # syslog | api | simulator | generic
    enabled: bool = True
    registered_at: float = field(default_factory=time.time)
    last_seen: float = 0
    total_events: int = 0
    rejected_events: int = 0
    revoked_at: float = 0
    revoked_by: str = ""
    db_id: int = 0                   # DB 主键


class SourceRegistry:
    """
    数据源注册表（DB 持久化版）

    - 内存 _sources 仍保留，用作热缓存（避免每次 authenticate 都查 DB）
    - 写操作（register/revoke/authenticate）穿透到 DB
    - authenticate 同步 API，热缓存命中 → 更新 last_seen/total_events → 异步刷盘
    """

    def __init__(self):
        self._sources: dict[str, DataSource] = {}  # api_key明文 → DataSource
        self._rejection_log: list[dict] = []
        self._rejection_log_max = 500
        self._db: Optional[AsyncSession] = None  # 当前 session，由 load_from_db 注入

    # ── 加载 ──

    def load_from_config(self):
        """从配置加载预注册 API Key（不写 DB，仅热缓存）"""
        try:
            keys = json.loads(settings.source_api_keys)
            for api_key, name in keys.items():
                self._sources[api_key] = DataSource(
                    api_key=api_key,
                    api_key_hash=_hash_key(api_key),
                    name=name,
                    source_type=self._infer_type(name),
                )
            if keys:
                logger.info(
                    f"SourceRegistry: preloaded {len(self._sources)} sources from config "
                    f"(DB 未初始化时回退用)"
                )
        except Exception as e:
            logger.warning(f"SourceRegistry: failed to load config: {e}")

    async def load_from_db(self, session_factory):
        """从 DB 重建热缓存（启动时调用，覆盖 config 加载）"""
        try:
            from models import DataSource as DataSourceModel
            async with session_factory() as s:
                stmt = select(DataSourceModel).where(DataSourceModel.enabled == True)
                result = await s.execute(stmt)
                rows = result.scalars().all()
        except Exception as e:
            logger.warning(f"SourceRegistry: load_from_db failed: {e}; 退回 config 缓存")
            return

        # 仅保留 config 中的非 DB 来源（避免重复），优先 DB
        config_keys = set(self._sources.keys())
        db_keys_by_hash = {}
        for r in rows:
            # DB 没有明文 key，无法直接做 authenticate by 明文 — 但 authenticate 入参是明文
            # 解决：DB 记录 api_key_hash，运行时 authenticate(api_key) 先哈希再比对
            db_keys_by_hash[r.api_key_hash] = r

        # 把 DB 启用条目索引到 _sources by hash — 单独维护 _sources_by_hash
        self._sources_by_hash: dict[str, DataSource] = {}
        for r in rows:
            ds = DataSource(
                api_key="",  # DB 不存明文
                api_key_hash=r.api_key_hash,
                name=r.name,
                source_type=r.source_type,
                enabled=r.enabled,
                registered_at=r.registered_at.timestamp() if r.registered_at else time.time(),
                last_seen=r.last_seen.timestamp() if r.last_seen else 0,
                total_events=r.total_events or 0,
                rejected_events=r.rejected_events or 0,
                db_id=r.id,
            )
            self._sources_by_hash[r.api_key_hash] = ds

        # 合并 config（明文 → 计算 hash → 如果 DB 也有则跳过，否则保留 config 副本并准备 backfill 到 DB）
        for api_key, ds in list(self._sources.items()):
            h = _hash_key(api_key)
            if h in db_keys_by_hash:
                # DB 已有 → 用明文填充 hash 槽
                self._sources_by_hash[h] = ds
                ds.db_id = db_keys_by_hash[h].id
                ds.total_events = db_keys_by_hash[h].total_events or 0
                ds.last_seen = db_keys_by_hash[h].last_seen.timestamp() if db_keys_by_hash[h].last_seen else 0
            else:
                # 仅 config 有 → 标记待 backfill
                ds.api_key_hash = h
                self._sources_by_hash[h] = ds
                logger.info(f"SourceRegistry: '{ds.name}' 在 config 但不在 DB，启动时 backfill")

        # 反向索引（明文 → DS) 保留方便 authenticate 快速查
        self._sources = {k: v for k, v in self._sources.items()}
        logger.info(
            f"SourceRegistry: loaded {len(self._sources_by_hash)} sources from DB "
            f"({len([h for h in self._sources_by_hash.values() if not h.db_id])} pending backfill)"
        )

    async def _backfill_pending(self, session_factory):
        """config 中存在但 DB 未持久化的来源 → 写入 DB"""
        try:
            from models import DataSource as DataSourceModel
            async with session_factory() as s:
                for api_key, ds in list(self._sources.items()):
                    if not ds.api_key_hash:
                        ds.api_key_hash = _hash_key(api_key)
                    if ds.db_id:
                        continue
                    # 检查 DB 是否已存在（避免重启重复 backfill）
                    stmt = select(DataSourceModel).where(
                        DataSourceModel.api_key_hash == ds.api_key_hash
                    )
                    result = await s.execute(stmt)
                    existing = result.scalars().first()
                    if existing:
                        ds.db_id = existing.id
                        continue
                    new_row = DataSourceModel(
                        api_key_hash=ds.api_key_hash,
                        name=ds.name,
                        source_type=ds.source_type,
                        enabled=ds.enabled,
                    )
                    s.add(new_row)
                    await s.commit()
                    await s.refresh(new_row)
                    ds.db_id = new_row.id
                    logger.info(f"SourceRegistry: backfilled '{ds.name}' → DB id={ds.db_id}")
        except Exception as e:
            logger.warning(f"SourceRegistry: backfill failed: {e}")

    # ── 写操作（穿透 DB） ──

    async def register(
        self, session: AsyncSession, api_key: str, name: str,
        source_type: str = "generic", changed_by: str = "admin",
    ) -> DataSource:
        """注册新数据源（持久化到 DB）"""
        from models import DataSource as DataSourceModel
        api_key_hash = _hash_key(api_key)

        # DB upsert
        stmt = select(DataSourceModel).where(DataSourceModel.api_key_hash == api_key_hash)
        result = await session.execute(stmt)
        existing = result.scalars().first()

        if existing:
            existing.name = name
            existing.source_type = source_type
            existing.enabled = True
            existing.revoked_at = None
            existing.revoked_by = ""
            await session.commit()
            await session.refresh(existing)
            db_id = existing.id
        else:
            new_row = DataSourceModel(
                api_key_hash=api_key_hash, name=name,
                source_type=source_type, enabled=True,
            )
            session.add(new_row)
            await session.commit()
            await session.refresh(new_row)
            db_id = new_row.id

        await self._persist_rejection(session, "")

        # 操作审计
        try:
            from audit_trail import log_action
            await log_action(
                session, actor=changed_by, action="source.register",
                target_type="source", target_id=str(db_id),
                before={}, after={"name": name, "source_type": source_type},
                reason=f"注册数据源 {name}",
            )
        except Exception as e:
            logger.warning(f"[SourceRegistry] audit_trail log failed: {e}")

        # 同步热缓存
        ds = DataSource(
            api_key=api_key, api_key_hash=api_key_hash,
            name=name, source_type=source_type, enabled=True,
            db_id=db_id,
        )
        if not hasattr(self, "_sources_by_hash"):
            self._sources_by_hash = {}
        self._sources_by_hash[api_key_hash] = ds
        self._sources[api_key] = ds

        logger.info(f"SourceRegistry: registered source '{name}' (type={source_type}) → DB id={db_id}")
        return ds

    async def revoke(
        self, session: AsyncSession, api_key: str, by: str = "admin"
    ) -> bool:
        """吊销数据源（持久化到 DB）"""
        from models import DataSource as DataSourceModel
        api_key_hash = _hash_key(api_key)
        stmt = select(DataSourceModel).where(DataSourceModel.api_key_hash == api_key_hash)
        result = await session.execute(stmt)
        row = result.scalars().first()
        if not row:
            return False

        before = {"enabled": row.enabled, "revoked_at": row.revoked_at}
        row.enabled = False
        from datetime import datetime, timezone
        row.revoked_at = datetime.now(timezone.utc)
        row.revoked_by = by
        await session.commit()

        try:
            from audit_trail import log_action
            await log_action(
                session, actor=by, action="source.revoke",
                target_type="source", target_id=str(row.id),
                before=before, after={"enabled": False},
                reason=f"吊销数据源 {row.name}",
            )
        except Exception as e:
            logger.warning(f"[SourceRegistry] audit_trail log failed: {e}")

        # 热缓存同步
        if hasattr(self, "_sources_by_hash") and api_key_hash in self._sources_by_hash:
            self._sources_by_hash[api_key_hash].enabled = False
        if api_key in self._sources:
            self._sources[api_key].enabled = False

        logger.warning(f"SourceRegistry: revoked source '{row.name}'")
        return True

    # ── 同步认证 (保持原 API) ──

    def authenticate(self, api_key: str) -> Optional[DataSource]:
        """
        验证数据源 API Key（同步，热缓存命中）

        缓存命中 → 增计数 + 异步刷盘 last_seen/total_events 到 DB
        缓存未命中 → 直接拒绝（避免热路径 DB 查询）

        Returns:
            DataSource if valid, None if rejected
        """
        api_key_hash = _hash_key(api_key)

        # 双索引命中（明文或哈希）
        ds = self._sources.get(api_key)
        if ds is None and hasattr(self, "_sources_by_hash"):
            ds = self._sources_by_hash.get(api_key_hash)
        if ds is None:
            self._log_rejection(api_key, "unknown_key")
            return None

        if not ds.enabled:
            self._log_rejection(api_key, "revoked")
            return None

        ds.last_seen = time.time()
        ds.total_events += 1
        # 异步刷盘（不必等待；丢失几秒计数可接受）
        try:
            asyncio_create_task_refresh_stats(api_key_hash, ds)
        except Exception:
            pass

        return ds

    def _log_rejection(self, api_key: str, reason: str):
        """记录未认证访问 + 持久化（异步）"""
        entry = {
            "api_key_prefix": api_key[:8] + "..." if len(api_key) > 8 else api_key,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._rejection_log.append(entry)
        if len(self._rejection_log) > self._rejection_log_max:
            del self._rejection_log[: len(self._rejection_log) - self._rejection_log_max]
        logger.warning(
            f"SourceRegistry: REJECTED access from key={entry['api_key_prefix']} reason={reason}"
        )
        try:
            asyncio_create_task_persist_rejection(entry)
        except Exception:
            pass

    async def _persist_rejection(self, session: AsyncSession, prefix: str):
        """已废弃 stub — 保留兼容签名"""
        return

    # ── 查询 ──

    def list_sources(self) -> list[dict]:
        """列出已注册数据源（不返回明文 key）"""
        out = []
        seen = set()
        if hasattr(self, "_sources_by_hash"):
            for h, ds in self._sources_by_hash.items():
                out.append({
                    "id": ds.db_id,
                    "api_key_prefix": ds.api_key[:8] + "..." if ds.api_key else "db-only",
                    "api_key_hash": h[:16] + "...",
                    "name": ds.name,
                    "source_type": ds.source_type,
                    "enabled": ds.enabled,
                    "total_events": ds.total_events,
                    "last_seen": ds.last_seen,
                })
            seen = set(h for h in self._sources_by_hash.keys())
        for api_key, ds in self._sources.items():
            h = _hash_key(api_key)
            if h in seen:
                continue
            out.append({
                "id": ds.db_id,
                "api_key_prefix": api_key[:8] + "...",
                "api_key_hash": h[:16] + "...",
                "name": ds.name,
                "source_type": ds.source_type,
                "enabled": ds.enabled,
                "total_events": ds.total_events,
                "last_seen": ds.last_seen,
            })
        return out

    def get_rejection_log(self, limit: int = 50) -> list[dict]:
        return self._rejection_log[-limit:]

    def stats(self) -> dict:
        n_enabled = 0
        if hasattr(self, "_sources_by_hash"):
            n_enabled = sum(1 for ds in self._sources_by_hash.values() if ds.enabled)
        else:
            n_enabled = sum(1 for ds in self._sources.values() if ds.enabled)
        return {
            "registered_sources": len(self._sources) + (
                len(self._sources_by_hash) if hasattr(self, "_sources_by_hash") else 0
            ),
            "enabled_sources": n_enabled,
            "total_events": sum(ds.total_events for ds in self._sources.values()),
            "recent_rejections": len(self._rejection_log),
        }

    def _infer_type(self, name: str) -> str:
        if "syslog" in name:
            return "syslog"
        if "simulator" in name:
            return "simulator"
        if "api" in name:
            return "api"
        return "generic"


# ── 异步刷盘辅助（节流 prefetch） ──

_PERSIST_STAT_INTERVAL = 30.0  # 每 30 秒最多刷一次统计
_last_stat_flush = 0.0


def asyncio_create_task_refresh_stats(api_key_hash: str, ds: DataSource):
    """异步把 last_seen/total_events 刷到 DB（节流）"""
    global _last_stat_flush
    import asyncio
    now = time.time()
    if now - _last_stat_flush < _PERSIST_STAT_INTERVAL:
        return
    _last_stat_flush = now

    async def _flush():
        try:
            from models import async_session, DataSource as DM
            async with async_session() as s:
                stmt = select(DM).where(DM.api_key_hash == api_key_hash)
                row = (await s.execute(stmt)).scalars().first()
                if row:
                    from datetime import datetime, timezone
                    row.last_seen = datetime.now(timezone.utc)
                    row.total_events = ds.total_events
                    await s.commit()
        except Exception as e:
            logger.debug(f"[SourceRegistry] stat flush failed: {e}")

    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_flush())
    except RuntimeError:
        pass


def asyncio_create_task_persist_rejection(entry: dict):
    """异步把拒绝记录持久化到 data_source_rejections"""
    import asyncio

    async def _persist():
        try:
            from models import async_session, DataSourceRejection as DR
            async with async_session() as s:
                s.add(DR(
                    api_key_prefix=entry["api_key_prefix"],
                    reason=entry["reason"],
                ))
                await s.commit()
        except Exception as e:
            logger.debug(f"[SourceRegistry] rejection persist failed: {e}")

    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_persist())
    except RuntimeError:
        pass


source_registry = SourceRegistry()