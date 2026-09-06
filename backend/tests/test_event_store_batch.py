"""event_store.store_batch 单测 (P1-E / P1-F)。

覆盖:
  - 空列表 → [] 且无 commit;
  - N 条全新事件 → 一次 commit, 落库 N 行, 返回等长同序;
  - 同一 eventId 重复 (跨批次 / 批内重复) → 只一行 (幂等, IntegrityError 回退逐条 store);
  - 混合 新+重复 → 一次 commit, 重复行返回旧 id。

跟随 tests/conftest + test_arch_unification 模式: sqlite 内存库 + pytest-asyncio。
"""
import pytest

from sqlalchemy import select, func


async def _reset_db():
    from models import Base, engine, _migrate_existing_tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await _migrate_existing_tables(conn)


def _evt(event_id: str, event: str = "LOGIN", severity: str = "info", src_ip: str = "10.0.0.1"):
    return {
        "eventId": event_id, "event": event, "severity": severity,
        "src_ip": src_ip, "message": f"msg-{event_id}",
    }


@pytest.mark.asyncio
async def test_store_batch_empty_list():
    from models import async_session
    from event_store import event_store

    await _reset_db()
    async with async_session() as s:
        out = await event_store.store_batch(s, [])
        assert out == []


@pytest.mark.asyncio
async def test_store_batch_n_new_one_commit(monkeypatch):
    from models import async_session, SecurityEvent
    from event_store import event_store

    await _reset_db()
    rows = [
        (_evt("a-1"), "sess-1", 0.1, ""),
        (_evt("a-2", event="SCAN", severity="medium"), "sess-1", 0.55, ""),
        (_evt("a-3", event="EXPLOIT", severity="critical", src_ip="8.8.8.8"), "sess-2", 0.9, ""),
    ]
    async with async_session() as s:
        commits = []

        async def _counting_commit(*a, **k):
            commits.append(1)
            return await orig_commit(*a, **k)

        orig_commit = s.commit
        s.commit = _counting_commit
        out = await event_store.store_batch(s, rows)

        assert len(out) == 3
        assert commits == [1], "N 条新事件必须恰好一次 commit"
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 3
        # 等长同序
        assert out[0].event_type == "LOGIN"
        assert out[2].anomaly_score == 0.9
        # 字段映射与 store() 一致: eventId / raw_data._anomaly_score / analyzed=False
        db_evt = (await s.execute(
            select(SecurityEvent).where(SecurityEvent.event_id == "a-1")
        )).scalars().first()
        assert db_evt is not None
        assert db_evt.raw_data["_anomaly_score"] == 0.1
        assert db_evt.analyzed is False
        assert db_evt.anomaly_score == 0.1


@pytest.mark.asyncio
async def test_store_batch_duplicate_event_id_single_row():
    """同一 eventId 跨批次重复 / 批内重复 → 只一行 (与 store() 幂等一致)。"""
    from models import async_session, SecurityEvent
    from event_store import event_store

    await _reset_db()
    async with async_session() as s:
        # 第一批: 两条新
        first = await event_store.store_batch(s, [
            (_evt("dup-1"), "sess-1", 0.5, ""),
            (_evt("dup-2"), "sess-1", 0.5, ""),
        ])
        # 第二批: 重复 dup-1 + 全新 dup-3
        second = await event_store.store_batch(s, [
            (_evt("dup-1"), "sess-2", 0.9, ""),
            (_evt("dup-3"), "sess-2", 0.9, ""),
        ])
        assert len(second) == 2
        assert second[0].id == first[0].id, "重复 eventId 必须返回已存在行"
        assert second[1].id > first[1].id
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 3

    # 批内重复 eventId (不在库里) → IntegrityError 回退逐条 store → 收敛一行
    await _reset_db()
    async with async_session() as s:
        out = await event_store.store_batch(s, [
            (_evt("inner-dup"), "sess-1", 0.5, ""),
            (_evt("inner-dup"), "sess-1", 0.5, ""),
        ])
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 1, "批内重复 eventId 只能落一行"
        assert len(out) == 2 and out[0].id == out[1].id


@pytest.mark.asyncio
async def test_store_batch_mixed_new_and_duplicate():
    from models import async_session, SecurityEvent
    from event_store import event_store

    await _reset_db()
    async with async_session() as s:
        await event_store.store(s, _evt("m-1"), "sess-1", anomaly_score=0.5)
        commits = []

        async def _counting_commit(*a, **k):
            commits.append(1)
            return await orig_commit(*a, **k)

        orig_commit = s.commit
        s.commit = _counting_commit
        rows = [
            (_evt("m-1"), "sess-2", 0.9, ""),          # 已存在 → 复用
            (_evt("m-2", event="SCAN"), "sess-2", 0.7, ""),   # 新
            (_evt("m-3", event="EXPLOIT", severity="critical"), "sess-2", 0.8, ""),  # 新
        ]
        out = await event_store.store_batch(s, rows)

        assert len(out) == 3
        assert commits == [1], "混合批次 (仅新行 insert) 一次 commit"
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 3
        assert out[0].event_type == "LOGIN"      # 已存在行的旧字段
        assert out[1].event_type == "SCAN"
        assert out[2].event_type == "EXPLOIT"
        assert out[0].anomaly_score == 0.5       # 旧行分数不被覆盖


@pytest.mark.asyncio
async def test_store_batch_rows_without_event_id_insert_always():
    """无 eventId 的行跳过幂等检查, 每次都是新行 (与 store() 一致)。"""
    from models import async_session, SecurityEvent
    from event_store import event_store

    await _reset_db()
    async with async_session() as s:
        no_eid = {"event": "LOGIN", "severity": "info", "message": "no-id"}
        out = await event_store.store_batch(s, [
            (dict(no_eid), "sess-1", 0.1, ""),
            (dict(no_eid), "sess-1", 0.1, ""),
        ])
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 2
        assert len(out) == 2 and out[0].id != out[1].id
