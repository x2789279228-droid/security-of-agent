# ── CAD / 上游证据规范化 回归测试 ──
# 覆盖 executor._normalize_event / _extract_events 对落入审计块事件的 id 规范性:
#   保证每条事件都有可被 CAD evidence_ids 引用的 int `id`, 并补 event_id/metadata,
#   否则无 id 事件(无法穿透验证)不得静默进入审计块造成 CAD 0-0/1.0 误判。

import pytest

from agents.agent_executor import Executor
from agents.agent_executor import ToolResult


@pytest.fixture
def exec_agent():
    return Executor()


# ── _normalize_event ──

def test_normalize_keeps_int_id(exec_agent):
    evt = exec_agent._normalize_event(
        {"id": 2653, "type": "SANGFOR_ALERT", "severity": "high"}
    )
    assert evt is not None
    assert evt["id"] == 2653
    assert evt["event_id"] == 2653 or evt["event_id"] is not None
    assert evt["event_type"] == "SANGFOR_ALERT"   # setdefault 自 type


def test_normalize_backfills_id_from_event_id(exec_agent):
    evt = exec_agent._normalize_event({"event_id": "1234", "type": "SANGFOR_ALERT"})
    assert evt is not None
    assert evt["id"] == 1234
    assert evt["event_id"] == "1234"


def test_normalize_drops_event_without_any_id(exec_agent):
    """无可用 id 事件不能静默进审计块 → 返回 None(避免 CAD 空/伪造 evidence)."""
    assert exec_agent._normalize_event({"type": "SANGFOR_ALERT"}) is None
    assert exec_agent._normalize_event({"type": "SANGFOR_ALERT", "id": "#bad"}) is None
    assert exec_agent._normalize_event(None) is None


def test_normalize_backfills_meta(exec_agent):
    evt = exec_agent._normalize_event({"id": 7, "event_type": "scan"})
    assert evt["event_type"] == "scan"
    assert evt["severity"] in ("info",)        # setdefault 缺省 info
    assert "created_at" in evt


def test_normalize_is_non_mutating(exec_agent):
    src = {"id": 42, "type": "SANGFOR_ALERT"}
    out = exec_agent._normalize_event(src)
    assert "severity" not in src            # 原 dict 未被改
    assert src["id"] == 42
    assert out["severity"] == "info"


# ── _extract_events(含 normalize 接线) ──

def test_extract_events_keeps_ids_from_query(exec_agent):
    from agents.agent_executor import ToolResult
    results = [
        ToolResult(
            call_id="c1", task_id="t1", tool="event_store.query", success=True,
            data=[{"id": 100, "type": "SANGFOR_ALERT", "severity": "high"},
                  {"event_id": "200", "type": "SANGFOR_ALERT"}],
        ),
    ]
    events, chain_ids = exec_agent._extract_events(results)
    ids = {e["id"] for e in events}
    assert ids == {100, 200}
    # 确保子审计可用规范 int id
    assert all(isinstance(e["id"], int) for e in events)


def test_extract_events_drops_idless(exec_agent):
    from agents.agent_executor import ToolResult
    results = [
        ToolResult(
            call_id="c1", task_id="t1", tool="event_store.query", success=True,
            data=[{"type": "SANGFOR_ALERT", "severity": "info"}]   # 无 id
        ),
    ]
    events, _ = exec_agent._extract_events(results)
    assert events == []
