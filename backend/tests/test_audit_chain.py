"""
审计哈希链 (PR1 控制面安全): audit_trail 行级 prev_hash / row_hash + verify_chain

- 每次落库(在线 _persist_entry / 离线 flush_fallback)计算
    row_hash = hmac_sha256(canonical_json{actor, action, target_type, target_id,
                                          before, after, reason, prev_hash, created_at_iso})
  prev_hash = 上一条 row_hash; 首条用 64 个 '0'(genesis)。
- verify_chain 按 id 升序全表重算比对, 首个不匹配行记为 first_break_id。

运行: python -m pytest tests/test_audit_chain.py -q --tb=short (cwd=backend)
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import audit_trail
from models import AuditTrail, Base

GENESIS = "0" * 64


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _db():
    """每个测试一个独立内存库引擎 — StaticPool 单连接保证同 loop 内读写一致
    (见 test_learn_loop 同款防 :memory: flake)。"""
    eng = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return eng, async_sessionmaker(eng, expire_on_commit=False)


async def _write_two_rows():
    """在线路径(log_action → _persist_entry)写两条记录。"""
    eng, Session = await _db()
    async with Session() as s:
        await audit_trail.log_action(
            s, actor="alice", action="case.transition",
            target_type="case", target_id="7",
            before={"status": "open"}, after={"status": "investigating"},
            reason="start investigation",
        )
        await audit_trail.log_action(
            s, actor="bob", action="rule.publish",
            target_type="rule", target_id="r-100",
            after={"enabled": True}, reason="publish rule",
        )
    return eng, Session


class TestAuditChain:
    def test_two_log_actions_then_verify_ok(self):
        async def t():
            eng, Session = await _write_two_rows()
            async with Session() as s:
                res = await audit_trail.verify_chain(s)
            assert res == {"ok": True, "checked": 2, "first_break_id": None}
        _run(t())

    def test_empty_table_verifies_ok(self):
        async def t():
            eng, Session = await _db()
            async with Session() as s:
                res = await audit_trail.verify_chain(s)
            assert res == {"ok": True, "checked": 0, "first_break_id": None}
        _run(t())

    def test_rows_linked_prev_hash_row_hash(self):
        """首行 prev=genesis; 次行 prev=首行 row_hash; 两行哈希不同。"""
        async def t():
            eng, Session = await _write_two_rows()
            async with Session() as s:
                rows = (await s.execute(
                    select(AuditTrail).order_by(AuditTrail.id)
                )).scalars().all()
            assert len(rows) == 2
            r1, r2 = rows
            assert r1.prev_hash == GENESIS
            assert len(r1.row_hash) == 64 and len(r2.row_hash) == 64
            assert r1.row_hash != r2.row_hash
            assert r2.prev_hash == r1.row_hash
        _run(t())

    def test_tampered_second_row_hash_detected(self):
        """改第二条 row_hash → verify 首个断点即该行。"""
        async def t():
            eng, Session = await _write_two_rows()
            async with Session() as s:
                rows = (await s.execute(
                    select(AuditTrail).order_by(AuditTrail.id)
                )).scalars().all()
                second = rows[1]
                second.row_hash = "f" * 64
                await s.commit()
                res = await audit_trail.verify_chain(s)
            assert res["ok"] is False
            assert res["first_break_id"] == second.id
            assert res["checked"] == 1  # 断点前通过 1 行
        _run(t())

    def test_tampered_field_detected(self):
        """改第二条内容字段(不碰 row_hash) → 重算不一致, 断点即该行。"""
        async def t():
            eng, Session = await _write_two_rows()
            async with Session() as s:
                rows = (await s.execute(
                    select(AuditTrail).order_by(AuditTrail.id)
                )).scalars().all()
                second = rows[1]
                second.actor = "mallory"
                await s.commit()
                res = await audit_trail.verify_chain(s)
            assert res["ok"] is False
            assert res["first_break_id"] == second.id
        _run(t())


class TestFlushFallbackChain:
    def test_flush_fallback_writes_hashes_and_verifies(self):
        """离线缓冲冲刷(flush_fallback)也必须写链哈希, 且同批内逐条成链。"""
        async def t():
            eng, Session = await _db()
            audit_trail._fallback_buffer.clear()
            audit_trail._enqueue_fallback(audit_trail._build_entry(
                actor="system", action="order.approve",
                target_type="work_order", target_id="wo-1",
                reason="offline queue",
            ))
            audit_trail._enqueue_fallback(audit_trail._build_entry(
                actor="system", action="asset.update",
                target_type="asset", target_id="a-9",
                after={"owner": "soc"},
            ))
            async with Session() as s:
                n = await audit_trail.flush_fallback(s)
                assert n == 2
                res = await audit_trail.verify_chain(s)
                rows = (await s.execute(
                    select(AuditTrail).order_by(AuditTrail.id)
                )).scalars().all()
            audit_trail._fallback_buffer.clear()
            assert res == {"ok": True, "checked": 2, "first_break_id": None}
            assert rows[0].prev_hash == GENESIS
            assert rows[1].prev_hash == rows[0].row_hash
        _run(t())

    def test_flush_chains_after_existing_rows(self):
        """flush 追加到已有链尾: 首条 flush 行的 prev = 在线末行 row_hash。"""
        async def t():
            eng, Session = await _write_two_rows()
            audit_trail._fallback_buffer.clear()
            audit_trail._enqueue_fallback(audit_trail._build_entry(
                actor="carol", action="source.revoke",
                target_type="source", target_id="src-1",
                reason="compromised key",
            ))
            async with Session() as s:
                n = await audit_trail.flush_fallback(s)
                assert n == 1
                res = await audit_trail.verify_chain(s)
                rows = (await s.execute(
                    select(AuditTrail).order_by(AuditTrail.id)
                )).scalars().all()
            audit_trail._fallback_buffer.clear()
            assert res == {"ok": True, "checked": 3, "first_break_id": None}
            assert len(rows) == 3
            assert rows[2].prev_hash == rows[1].row_hash, "flush 行必须挂在在线链尾"
        _run(t())
