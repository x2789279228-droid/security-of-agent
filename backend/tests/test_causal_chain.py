"""因果链 PC/GES + 后门 do:合成 SCM 可证伪。"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from causal_chain.compare import annotate_chain
from causal_chain.do_calculus import intervene
from causal_chain.learn import learn_from_events, learn_from_matrix
from causal_chain.pc import pc_learn
from causal_chain.variables import events_to_matrix


def _true_chain_matrix(n=700, seed=0):
    rng = np.random.default_rng(seed)
    night = rng.random(n) < 0.35
    ps = np.where(night, rng.random(n) < 0.78, rng.random(n) < 0.12).astype(np.uint8)
    bf = np.where(ps == 1, rng.random(n) < 0.84, rng.random(n) < 0.05).astype(np.uint8)
    c2 = np.where(
        bf == 1,
        rng.random(n) < 0.82,
        np.where(night, rng.random(n) < 0.22, rng.random(n) < 0.04),
    ).astype(np.uint8)
    fa = (rng.random(n) < 0.07).astype(np.uint8)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "FILE_ACCESS", "HOUR_NIGHT"]
    X = np.stack([ps, bf, c2, fa, night.astype(np.uint8)], axis=1)
    return X, names


def _spurious_night_matrix(n=700, seed=1):
    """夜间同时抬升扫描/爆破/C2,无真链。CEP 仍会因共现命中。"""
    rng = np.random.default_rng(seed)
    night = rng.random(n) < 0.40
    ps = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    bf = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    c2 = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    fa = (rng.random(n) < 0.06).astype(np.uint8)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "FILE_ACCESS", "HOUR_NIGHT"]
    X = np.stack([ps, bf, c2, fa, night.astype(np.uint8)], axis=1)
    return X, names


def _edge_set(result) -> set:
    return {(e["cause"], e["effect"]) for e in result.get("edges") or []
            if e.get("confidence") in ("high_confidence", "oriented_by_one")}


def test_pc_recovers_true_chain_skeleton():
    X, names = _true_chain_matrix()
    pc = pc_learn(X, names, alpha=0.05)
    sk = {tuple(sorted(e)) for e in pc["skeleton"]}
    true_sk = {tuple(sorted(e)) for e in [
        ("PORT_SCAN", "BRUTE_FORCE"),
        ("BRUTE_FORCE", "C2_BEACON"),
    ]}
    assert true_sk <= sk, f"missing true skeleton {true_sk - sk}; got {sk}"


def test_learn_recalls_true_chain_and_do_port_scan_drops_c2():
    X, names = _true_chain_matrix()
    result = learn_from_matrix(X, names, alpha=0.05)
    assert result["ok"]
    directed = result["directed"]
    true_edges = {("PORT_SCAN", "BRUTE_FORCE"), ("BRUTE_FORCE", "C2_BEACON")}
    got = set(map(tuple, directed))
    recall = len(true_edges & got) / len(true_edges)
    assert recall >= 2 / 3, f"recall={recall} directed={got}"
    q_ps = intervene(X, names, directed, "PORT_SCAN", "C2_BEACON", do_value=0)
    q_fa = intervene(X, names, directed, "FILE_ACCESS", "C2_BEACON", do_value=0)
    assert q_ps.get("identifiable"), q_ps
    assert q_ps.get("ace") is not None and q_ps["ace"] > 0.15, q_ps
    if q_fa.get("identifiable") and q_fa.get("ace") is not None:
        assert abs(q_fa["ace"]) < q_ps["ace"], (q_fa, q_ps)


def test_night_confounder_marks_cep_chain_spurious():
    X, names = _spurious_night_matrix()
    result = learn_from_matrix(X, names, alpha=0.05)
    directed = result["directed"]
    chain = {
        "pattern_id": "port_scan_to_c2",
        "pattern_name": "端口扫描→暴力破解→C2",
        "events": [
            {"event_type": "PORT_SCAN"},
            {"event_type": "BRUTE_FORCE"},
            {"event_type": "C2_BEACON"},
        ],
    }
    annotated = annotate_chain(chain, directed=directed, names=names, data=X)
    q = intervene(X, names, directed, "PORT_SCAN", "C2_BEACON", do_value=0)
    if q.get("identifiable") and q.get("ace") is not None:
        assert abs(q["ace"]) < 0.15, q
        assert annotated["causal_verdict"] in ("spurious", "unknown")
    else:
        assert annotated["causal_verdict"] in ("spurious", "unknown")


def test_insufficient_windows_returns_empty():
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "PORT_SCAN",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.0.0.1",
            "created_at": now + timedelta(minutes=i),
            "anomaly_score": 0.1,
        }
        for i in range(5)
    ]
    result = learn_from_events(events, min_windows=40)
    assert result["ok"] is False
    assert result["reason"] == "insufficient_data"
    assert result["edges"] == []


def test_events_to_matrix_bins_and_night_flag():
    from datetime import datetime, timezone
    events = []
    base = datetime(2026, 9, 5, 2, 0, tzinfo=timezone.utc)
    for i in range(80):
        src = f"10.0.0.{i % 8}"
        ts = base.replace(minute=(i * 7) % 60, hour=1 + (i // 15) % 6)
        if i % 2 == 0:
            events.append({
                "event_type": "PORT_SCAN",
                "src_ip": src, "dst_ip": "192.168.1.1",
                "created_at": ts, "anomaly_score": 0.7 if i % 7 == 0 else 0.1,
            })
        if i % 3 == 0:
            events.append({
                "event_type": "C2_BEACON",
                "src_ip": src, "dst_ip": "8.8.8.8",
                "created_at": ts, "anomaly_score": 0.2,
            })
    mat = events_to_matrix(events, bin_minutes=30, min_windows=10)
    assert mat["ok"] is True
    assert "HOUR_NIGHT" in mat["names"]
    assert "PORT_SCAN" in mat["names"]
    assert mat["X"].shape[0] >= 10
