"""P3 下游容量: PQ drain 公平性 (2026-q3 D-A..D-G)。

- pop_first_runnable: Agent 槽满时跳过队头 P0 agent, 弹出可运行的 P1 llm_single
- start_audit_workflow: start 墙钟超时 → 返回 False 且 inflight 不卡死
- drain: P1 dequeue > 0; Temporal shed 仅 P0 agent 重入队, P1 不回 PQ 空转
"""
import asyncio

import pytest
from prometheus_client import REGISTRY, generate_latest

from audit_pq import AuditPriorityQueue
from audit_triage import score_event, uses_llm_single, uses_temporal


# ── 内存 fake redis (覆盖 audit_pq / temporal.client 用到的子集) ──

class _FakePipe:
    def __init__(self, r):
        self.r = r
        self.ops = []

    def set(self, k, v, ex=None):
        self.ops.append(("set", k, v))
        return self

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping))
        return self

    def expire(self, *a, **k):
        return self

    def incr(self, k):
        self.ops.append(("incr", k))
        return self

    async def execute(self):
        out = []
        for op in self.ops:
            if op[0] == "set":
                await self.r.set(op[1], op[2])
                out.append(True)
            elif op[0] == "zadd":
                await self.r.zadd(op[1], op[2])
                out.append(True)
            elif op[0] == "incr":
                out.append(await self.r.incr(op[1]))
        self.ops = []
        return out


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.z = {}  # key -> {member: score}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v, ex=None):
        self.kv[k] = v

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    async def exists(self, k):
        return 1 if k in self.kv else 0

    async def incr(self, k):
        v = int(self.kv.get(k) or 0) + 1
        self.kv[k] = v
        return v

    async def decr(self, k):
        v = int(self.kv.get(k) or 0) - 1
        self.kv[k] = v
        return v

    def _z(self, key):
        return self.z.setdefault(key, {})

    def pipeline(self):
        return _FakePipe(self)

    async def zadd(self, key, mapping):
        self._z(key).update(mapping)

    async def zpopmin(self, key, count=1):
        z = self._z(key)
        items = sorted(z.items(), key=lambda x: x[1])[:count]
        for m, _ in items:
            z.pop(m, None)
        return items

    async def zrange(self, key, a, b, withscores=False):
        items = sorted(self._z(key).items(), key=lambda x: x[1])
        if b < 0:
            b = len(items) - 1
        items = items[a:b + 1]
        if withscores:
            return items
        return [m for m, _ in items]

    async def zrem(self, key, member):
        return 1 if self._z(key).pop(member, None) is not None else 0

    async def zcard(self, key):
        return len(self._z(key))

    async def expire(self, key, ttl):
        return True


# ── 真实 score_event 造出的 P0-agent / P1-single 事件体 ──

P0_AGENT_LOG = {
    "severity": "critical",
    "event": "C2_BEACON",
    "threat_type": "C2_BEACON",
    "_sigma": {"detected": True, "max_severity": "critical"},
}
P1_SINGLE_LOG = {
    "severity": "high",
    "event": "C2_BEACON",
    "threat_type": "C2_BEACON",
    "_sigma": {"detected": True, "max_severity": "medium",
               "hits": [{"confidence": "medium"}]},
}


def _counter_value(name: str) -> float:
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if sample.name == name:
                return float(sample.value)
    return 0.0


def _make_pq() -> tuple:
    fake = FakeRedis()
    pq = AuditPriorityQueue()
    pq.set_redis(fake)
    return pq, fake


async def _seed_two_jobs(pq: AuditPriorityQueue, *, p0_eid: int, p1_eid: int):
    t0 = score_event(P0_AGENT_LOG, 0.9)
    assert t0.tier == "P0" and uses_temporal(t0.lane)
    t1 = score_event(P1_SINGLE_LOG, 0.4)
    assert t1.tier == "P1" and uses_llm_single(t1.lane) and not uses_temporal(t1.lane)
    await pq.enqueue(
        event_id=p0_eid, session_id="s", log_data=dict(P0_AGENT_LOG),
        anomaly_score=0.9, anomaly_reasons=[], priority=t0.priority, tier="P0",
    )
    await pq.enqueue(
        event_id=p1_eid, session_id="s", log_data=dict(P1_SINGLE_LOG),
        anomaly_score=0.4, anomaly_reasons=[], priority=t1.priority, tier="P1",
    )


# ── pop_first_runnable / peek_highest ──

@pytest.mark.asyncio
async def test_pop_first_runnable_skips_blocked_p0_agent():
    pq, _fake = _make_pq()
    await _seed_two_jobs(pq, p0_eid=101, p1_eid=102)

    # peek 不弹出
    head = await pq.peek_highest()
    assert head is not None and head["event_id"] == 101
    assert await pq.depth() == 2

    # Agent 槽满 → 跳过队头 P0, 弹出 P1 llm_single
    job = await pq.pop_first_runnable(agent_full=True)
    assert job is not None and job["event_id"] == 102
    assert await pq.depth() == 1
    head = await pq.peek_highest()
    assert head is not None and head["event_id"] == 101  # P0 留在 zset

    # 槽不满 → 正常按优先级弹出 P0
    job = await pq.pop_first_runnable(agent_full=False)
    assert job is not None and job["event_id"] == 101
    assert await pq.pop_highest() is None


@pytest.mark.asyncio
async def test_pop_first_runnable_returns_none_when_only_p0_agent():
    pq, _fake = _make_pq()
    t0 = score_event(P0_AGENT_LOG, 0.9)
    await pq.enqueue(
        event_id=201, session_id="s", log_data=dict(P0_AGENT_LOG),
        anomaly_score=0.9, anomaly_reasons=[], priority=t0.priority, tier="P0",
    )
    job = await pq.pop_first_runnable(agent_full=True)
    assert job is None                      # 不弹被阻塞的 P0
    assert await pq.depth() == 1
    job = await pq.pop_first_runnable(agent_full=False)
    assert job is not None and job["event_id"] == 201


@pytest.mark.asyncio
async def test_pop_first_runnable_dequeue_metric_p1():
    pq, _fake = _make_pq()
    await _seed_two_jobs(pq, p0_eid=111, p1_eid=112)
    await pq.pop_first_runnable(agent_full=True)  # 弹 P1
    text = generate_latest()
    assert b'soc_audit_pq_dequeue_total{tier="P1"}' in text


# ── start_audit_workflow 超时 (D-A) ──

@pytest.mark.asyncio
async def test_start_audit_workflow_timeout_releases_inflight(monkeypatch):
    import temporal.client as tc
    from config import settings

    monkeypatch.setattr(settings, "audit_temporal_start_timeout_s", 0.05)
    fake = FakeRedis()
    monkeypatch.setattr(tc, "_redis", fake)

    class _SlowClient:
        def __init__(self):
            self.calls = 0

        async def start_workflow(self, *a, **k):
            self.calls += 1
            await asyncio.sleep(30)  # 模拟 Temporal 分发卡死

    slow = _SlowClient()

    async def fake_get_client():
        return slow

    monkeypatch.setattr(tc, "get_client", fake_get_client)

    before = _counter_value("soc_audit_temporal_start_timeout_total")
    result = await tc.start_audit_workflow(
        session_id="s", event_id=301, log_data=dict(P0_AGENT_LOG),
        anomaly_score=0.9, anomaly_reasons=[], max_rounds=1, tier="P0",
    )
    assert result is False
    assert slow.calls == 1
    # inflight acquire 后已归还, 不卡死
    assert int(fake.kv.get(tc._INFLIGHT_KEY) or 0) == 0
    assert int(fake.kv.get(tc._INFLIGHT_P0_KEY) or 0) == 0
    assert _counter_value("soc_audit_temporal_start_timeout_total") == before + 1


@pytest.mark.asyncio
async def test_start_audit_workflow_success_keeps_inflight(monkeypatch):
    """超时路径之外: start 成功不归还 inflight(由 workflow 收尾归还)。"""
    import temporal.client as tc

    fake = FakeRedis()
    monkeypatch.setattr(tc, "_redis", fake)

    class _OkClient:
        async def start_workflow(self, *a, **k):
            return "handle"

    async def fake_get_client():
        return _OkClient()

    monkeypatch.setattr(tc, "get_client", fake_get_client)
    result = await tc.start_audit_workflow(
        session_id="s", event_id=302, log_data=dict(P0_AGENT_LOG),
        anomaly_score=0.9, anomaly_reasons=[], max_rounds=1, tier="P0",
    )
    assert result is True
    assert int(fake.kv.get(tc._INFLIGHT_KEY) or 0) == 1


# ── scheduler._drain_audit_pq_once 公平性 (D-C/D-D/D-E/D-F) ──

@pytest.mark.asyncio
async def test_drain_dequeues_p1_while_agent_full(monkeypatch):
    """Agent 槽满: P0 agent 被跳过留在 PQ, P1 走 audit_worker(llm_single), 不 start Temporal。"""
    import temporal.client as tc
    import audit_worker as aw_mod
    from audit_pq import audit_pq
    from scheduler import scheduler

    fake = FakeRedis()
    monkeypatch.setattr(audit_pq, "_redis", fake)
    await _seed_two_jobs(audit_pq, p0_eid=401, p1_eid=402)

    async def full_stats():
        return {"total": 12, "p0": 12, "limit": 4, "reserved_p0": 1}

    monkeypatch.setattr(tc, "inflight_stats", full_stats)

    started_calls = []

    async def must_not_start(**kw):
        started_calls.append(kw.get("event_id"))
        return True

    monkeypatch.setattr(tc, "start_audit_workflow", must_not_start)

    submitted = []

    async def fake_submit(**kw):
        submitted.append(kw.get("event_id"))
        return "queued"

    monkeypatch.setattr(aw_mod.audit_worker, "submit", fake_submit)

    n = await scheduler._drain_audit_pq_once()

    assert submitted == [402]           # D-D: P1 dequeue > 0
    assert started_calls == []          # D-E: llm_single 不 start Temporal
    assert n == 1
    assert await audit_pq.depth() == 1  # P0 留在 PQ
    head = await audit_pq.peek_highest()
    assert head is not None and head["event_id"] == 401


@pytest.mark.asyncio
async def test_drain_p0_shed_reenqueues_only_agent(monkeypatch):
    """Temporal shed: P0 agent 允许重入队一次; 之后槽满时 P1 仍可出队。"""
    import temporal.client as tc
    import audit_worker as aw_mod
    from audit_pq import audit_pq
    from scheduler import scheduler

    fake = FakeRedis()
    monkeypatch.setattr(audit_pq, "_redis", fake)
    await _seed_two_jobs(audit_pq, p0_eid=501, p1_eid=502)

    async def empty_stats():
        return {"total": 0, "p0": 0, "limit": 4, "reserved_p0": 1}

    monkeypatch.setattr(tc, "inflight_stats", empty_stats)

    started_calls = []

    async def shed_start(**kw):
        started_calls.append(kw.get("event_id"))
        return "shed"

    monkeypatch.setattr(tc, "start_audit_workflow", shed_start)

    n1 = await scheduler._drain_audit_pq_once()
    assert n1 == 0
    assert started_calls == [501]       # P0 尝试 start → shed
    assert await audit_pq.depth() == 2  # P0 重入队 + P1 未动

    # 第二轮: 槽满 → 跳过 P0, P1 出队进 worker (不再被 shed 空转)
    async def full_stats():
        return {"total": 12, "p0": 12, "limit": 4, "reserved_p0": 1}

    monkeypatch.setattr(tc, "inflight_stats", full_stats)
    monkeypatch.setattr(tc, "start_audit_workflow", must_not_start_helper)

    submitted = []

    async def fake_submit(**kw):
        submitted.append(kw.get("event_id"))
        return "queued"

    monkeypatch.setattr(aw_mod.audit_worker, "submit", fake_submit)

    n2 = await scheduler._drain_audit_pq_once()
    assert submitted == [502]
    assert n2 == 1
    assert await audit_pq.depth() == 1
    head = await audit_pq.peek_highest()
    assert head is not None and head["event_id"] == 501


async def must_not_start_helper(**kw):  # pragma: no cover - 经 monkeypatch 注入
    raise AssertionError("P1/llm_single must not start Temporal workflow")


@pytest.mark.asyncio
async def test_drain_start_false_falls_back_to_worker(monkeypatch):
    """Temporal 不可用/start 超时返回 False → P0 agent 落 audit_worker, 不假完成。"""
    import temporal.client as tc
    import audit_worker as aw_mod
    from audit_pq import audit_pq
    from scheduler import scheduler

    fake = FakeRedis()
    monkeypatch.setattr(audit_pq, "_redis", fake)
    await _seed_two_jobs(audit_pq, p0_eid=601, p1_eid=602)

    async def empty_stats():
        return {"total": 0, "p0": 0, "limit": 4, "reserved_p0": 1}

    monkeypatch.setattr(tc, "inflight_stats", empty_stats)

    async def fail_start(**kw):
        return False

    monkeypatch.setattr(tc, "start_audit_workflow", fail_start)

    submitted = []

    async def fake_submit(**kw):
        submitted.append(kw.get("event_id"))
        return "queued"

    monkeypatch.setattr(aw_mod.audit_worker, "submit", fake_submit)

    n = await scheduler._drain_audit_pq_once()
    assert n == 2                        # P0(False→worker) + P1(llm_single→worker)
    assert submitted == [601, 602]       # P0 优先级高, 先出队
    assert await audit_pq.depth() == 0


@pytest.mark.asyncio
async def test_drain_worker_backpressure_reenqueues(monkeypatch):
    """worker 内存队列接近满 → 回 PQ 背压, 不塞爆 drain。"""
    import temporal.client as tc
    import audit_worker as aw_mod
    from audit_pq import audit_pq
    from config import settings
    from scheduler import scheduler

    fake = FakeRedis()
    monkeypatch.setattr(audit_pq, "_redis", fake)
    t1 = score_event(P1_SINGLE_LOG, 0.4)
    await audit_pq.enqueue(
        event_id=701, session_id="s", log_data=dict(P1_SINGLE_LOG),
        anomaly_score=0.4, anomaly_reasons=[], priority=t1.priority, tier="P1",
    )

    async def empty_stats():
        return {"total": 0, "p0": 0, "limit": 4, "reserved_p0": 1}

    monkeypatch.setattr(tc, "inflight_stats", empty_stats)

    class _FullWorker:
        def queue_depth(self):
            return 95

        def _queue_max(self):
            return 100

    monkeypatch.setattr(aw_mod, "audit_worker", _FullWorker())
    monkeypatch.setattr(settings, "audit_pq_drain_batch", 20)

    n = await scheduler._drain_audit_pq_once()
    assert n == 0
    assert await audit_pq.depth() == 1   # 回队, 未丢
    head = await audit_pq.peek_highest()
    assert head is not None and head["event_id"] == 701


# ── 指标 (D-G) ──

def test_metrics_counters_exist():
    import metrics
    metrics.inc_audit_cache_hit()
    metrics.inc_temporal_start_timeout()
    metrics.inc_audit_pq_dequeue("P1")
    text = generate_latest()
    assert b"soc_audit_cache_hit_total" in text
    assert b"soc_audit_temporal_start_timeout_total" in text
    assert b'soc_audit_pq_dequeue_total{tier="P1"}' in text
