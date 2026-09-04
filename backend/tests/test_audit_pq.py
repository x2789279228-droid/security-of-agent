"""审计优先级队列 + P0 预留槽。"""
import pytest

from audit_pq import AuditPriorityQueue
from temporal.client import _reserved_p0_slots


def test_reserved_p0_slots():
    # monkeypatch via settings is heavy; test pure math helper with patched settings
    from config import settings
    old = getattr(settings, "audit_p0_reserve_pct", 0.25)
    try:
        settings.audit_p0_reserve_pct = 0.25
        assert _reserved_p0_slots(30) == 8  # ceil(7.5)=8
        assert _reserved_p0_slots(4) == 1  # pct>0 and limit>=? 4 < 5 → ceil(1)=1 but limit>=5 check
        # limit 4: code says if limit >= 5 ... else just ceil
        n4 = _reserved_p0_slots(4)
        assert 0 <= n4 <= 4
        settings.audit_p0_reserve_pct = 0.0
        assert _reserved_p0_slots(30) == 0
    finally:
        settings.audit_p0_reserve_pct = old


@pytest.mark.asyncio
async def test_pq_enqueue_pop_order():
    class FakeRedis:
        def __init__(self):
            self.kv = {}
            self.z = {}  # member -> score
            self._buf = []

        async def set(self, k, v, ex=None):
            self.kv[k] = v

        async def get(self, k):
            return self.kv.get(k)

        async def delete(self, *keys):
            for k in keys:
                self.kv.pop(k, None)

        async def exists(self, k):
            return 1 if k in self.kv else 0

        def pipeline(self):
            self._buf = []
            return self

        def set(self, k, v, ex=None):  # noqa: F811 — sync buffer for pipeline
            self._buf.append(("set", k, v))
            return self

        def zadd(self, key, mapping):
            self._buf.append(("zadd", mapping))
            return self

        def expire(self, *a, **k):
            self._buf.append(("expire",))
            return self

        async def execute(self):
            for op in self._buf:
                if op[0] == "set":
                    self.kv[op[1]] = op[2]
                elif op[0] == "zadd":
                    self.z.update(op[1])
            self._buf = []
            return []

        async def zpopmin(self, key, count=1):
            if not self.z:
                return []
            items = sorted(self.z.items(), key=lambda x: x[1])[:count]
            for m, _ in items:
                self.z.pop(m, None)
            return items

        async def zcard(self, key):
            return len(self.z)

        async def zrange(self, key, a, b):
            return list(self.z.keys())

        async def zrem(self, key, member):
            self.z.pop(member, None)

    pq = AuditPriorityQueue()
    pq.set_redis(FakeRedis())
    await pq.enqueue(
        event_id=1, session_id="s", log_data={"e": 1},
        anomaly_score=0.2, anomaly_reasons=[], priority=40, tier="P2",
    )
    await pq.enqueue(
        event_id=2, session_id="s", log_data={"e": 2},
        anomaly_score=0.9, anomaly_reasons=[], priority=90, tier="P0",
    )
    await pq.enqueue(
        event_id=3, session_id="s", log_data={"e": 3},
        anomaly_score=0.5, anomaly_reasons=[], priority=70, tier="P1",
    )
    first = await pq.pop_highest()
    assert first["event_id"] == 2  # P0 highest
    second = await pq.pop_highest()
    assert second["event_id"] == 3
    third = await pq.pop_highest()
    assert third["event_id"] == 1
    assert await pq.pop_highest() is None
