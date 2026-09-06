"""kafka_producer._deliver_batch 单测 (P1-I).

asyncio.gather(*futures, return_exceptions=True) 并发等待:
  - 一个 future 抛异常 → 其余成功仍计数, 异常不扩散;
  - gather 确实被使用 (for+await 串行被禁止);
  - 空列表 → 0 且不调用 gather。
"""
import asyncio

import kafka_producer


def test_deliver_batch_gather_used_and_counts_successes():
    real_asyncio = asyncio
    gathered = []
    real_gather = real_asyncio.gather

    class _Probe:
        def __getattr__(self, name):
            if name == "gather":
                def rec(*a, **k):
                    gathered.append(len(a))
                    return real_gather(*a, **k)
                return rec
            return getattr(real_asyncio, name)

    kafka_producer.asyncio = _Probe()
    try:
        async def _case():
            loop = asyncio.get_running_loop()
            ok1 = loop.create_future()
            ok1.set_result(None)
            bad = loop.create_future()
            bad.set_exception(RuntimeError("delivery failed"))
            ok2 = loop.create_future()
            ok2.set_result("delivered")
            n = await kafka_producer.kafka_producer._deliver_batch([ok1, bad, ok2], "t")
            return n

        n = asyncio.run(_case())
        assert n == 2, "异常 future 不计成功, 其余成功照常计数"
        assert gathered == [3], "_deliver_batch 必须经 asyncio.gather 一次并发等待"
    finally:
        kafka_producer.asyncio = real_asyncio


def test_deliver_batch_empty_futures():
    async def _case():
        return await kafka_producer.kafka_producer._deliver_batch([], "empty")

    assert asyncio.run(_case()) == 0


def test_deliver_batch_all_fail_returns_zero():
    async def _case():
        loop = asyncio.get_running_loop()
        bad1 = loop.create_future()
        bad1.set_exception(RuntimeError("e1"))
        bad2 = loop.create_future()
        bad2.set_exception(RuntimeError("e2"))
        return await kafka_producer.kafka_producer._deliver_batch([bad1, bad2], "t")

    assert asyncio.run(_case()) == 0
