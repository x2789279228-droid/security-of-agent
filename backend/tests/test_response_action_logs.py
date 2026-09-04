"""响应动作日志：逐条展开 BatchActionResult，API 带 execution_mode。"""
import os
import sys
from pathlib import Path

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from response_engine.response_executor import ActionResult, BatchActionResult
from response_engine.response_log import ResponseLogEntry
from response_engine.response_orchestrator import action_rows_from_batch


def test_action_rows_from_batch_exposes_block_ip_mode():
    batch = BatchActionResult(
        total=2, succeeded=2, failed=0,
        batch_rollback_token="batch_abc",
        results=[
            ActionResult(
                action_name="block_ip",
                success=True,
                result={"mode": "stub", "src_ip": "45.33.32.156", "_stub": True},
                rollback_token="rb_1",
            ),
            ActionResult(
                action_name="send_alert",
                success=True,
                result={"mode": "log", "title": "安全告警"},
            ),
        ],
    )
    rows = action_rows_from_batch(
        batch,
        {"session_id": "demo_1", "event_id": 556, "threat_type": "PORT_SCAN"},
        "端口扫描限速",
        auto_execute=True,
        approval_status="approved",
    )
    names = [r["action_name"] for r in rows]
    assert names == ["block_ip", "send_alert"]
    assert rows[0]["action_params"]["execution_mode"] == "stub"
    assert rows[1]["result"]["mode"] == "log"
    assert rows[0]["session_id"] == "demo_1"
    assert rows[0]["event_id"] == 556


def test_response_log_entry_to_dict_includes_mode():
    entry = ResponseLogEntry(
        id=1,
        session_id="demo_1",
        event_id=556,
        threat_type="BRUTE_FORCE",
        policy_name="暴力破解自动阻断",
        action_name="block_ip",
        action_success=True,
        action_params={"execution_mode": "stub"},
        action_result={"mode": "stub", "src_ip": "1.2.3.4", "verified": False},
        auto_execute=True,
    )
    d = entry.to_dict()
    assert d["action_name"] == "block_ip"
    assert d["execution_mode"] == "stub"
    assert d["verified"] is False
    assert d["action_result"]["src_ip"] == "1.2.3.4"
