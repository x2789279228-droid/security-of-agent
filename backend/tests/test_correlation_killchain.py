"""PR-C: 跨主机杀伤链 / 可跳过中间步匹配。"""
from datetime import datetime, timezone, timedelta

from correlation_engine import CorrelationEngine


def _evt(i, etype, src, dst, minutes=0):
    return {
        "id": i,
        "event_type": etype,
        "severity": "high" if etype != "PORT_SCAN" else "medium",
        "src_ip": src,
        "dst_ip": dst,
        "message": etype,
        "created_at": datetime.now(timezone.utc) + timedelta(minutes=minutes),
    }


def test_external_compromise_exfil_pattern_on_hub_timeline():
    engine = CorrelationEngine()
    hub = "192.168.1.100"
    attacker = "45.33.32.156"
    c2 = "23.129.64.33"
    events = [
        _evt(1, "PORT_SCAN", attacker, hub, 0),
        _evt(2, "BRUTE_FORCE", attacker, hub, 1),
        _evt(3, "C2_BEACON", hub, c2, 2),
        _evt(4, "DATA_EXFIL", hub, c2, 3),
    ]
    # 直接测 hub matcher（接受 ORM-like 对象或用简单 namespace）
    class E:
        def __init__(self, d):
            self.__dict__.update(d)

    chains = engine._match_hub_hosts([E(e) for e in events])
    assert chains, "expected at least one hub killchain"
    assert len(chains[0].events) >= 3


def test_match_pattern_skips_lateral_move():
    engine = CorrelationEngine()
    hub = "192.168.1.100"
    events = [
        _evt(1, "PORT_SCAN", "1.1.1.1", hub, 0),
        _evt(2, "BRUTE_FORCE", "1.1.1.1", hub, 1),
        _evt(3, "C2_BEACON", hub, "9.9.9.9", 2),
        _evt(4, "DATA_EXFIL", hub, "9.9.9.9", 3),
    ]
    pattern = {
        "name": "经典杀伤链",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "min_match": 3,
        "skippable": ["LATERAL_MOVE"],
        "allow_skip_missing": True,
    }
    chain = engine._match_pattern("classic", pattern, hub, events)
    assert chain is not None
    assert len(chain.events) >= 3
