"""慢消费者丢最旧事件,不踢订阅者。"""
import asyncio

from event_bus import EventBus


def test_slow_consumer_stays_subscribed():
    bus = EventBus(max_subscribers=4)
    bus._queue_max = 2
    q = bus.subscribe()
    assert q is not None
    bus.publish("a", {"event_id": 1})
    bus.publish("a", {"event_id": 2})
    bus.publish("a", {"event_id": 3})  # overflow → drop oldest
    assert q in bus._subscribers
    assert bus.subscriber_count == 1
    # queue still has ≤ maxsize items
    assert q.qsize() <= 2


def test_full_slots_reject_new():
    bus = EventBus(max_subscribers=1)
    q1 = bus.subscribe()
    q2 = bus.subscribe()
    assert q1 is not None
    assert q2 is None
    assert bus.max_subscribers == 1


def test_redis_dedup_lru():
    bus = EventBus()
    assert bus._redis_recently_seen("o|t|1") is False
    assert bus._redis_recently_seen("o|t|1") is True
    assert bus._redis_recently_seen("o|t|2") is False
