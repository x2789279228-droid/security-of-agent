"""思维链发布器 / 缓冲 / 存量投影 单测。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from observability.thought_events import (
    ThoughtChainBuffer,
    assemble_thought_chain,
    attach_to_audit,
    compact_step,
    emit_executor,
    emit_plan,
    emit_rag_chunks,
    emit_review,
    emit_signals,
    emit_tool_map,
    emit_tool_result,
    project_from_audit_llm,
    publish_thought_batch,
    thought_buffer,
)


class TestCompact:
    def setup_method(self):
        thought_buffer.clear()

    def test_drops_without_event_id(self):
        assert compact_step({"kind": "plan", "title": "x"}) is None

    def test_clips_summary_and_quotes(self):
        step = compact_step({
            "event_id": 7,
            "kind": "claim",
            "stage": "executor",
            "title": "A" * 200,
            "summary": "B" * 500,
            "evidence_quotes": ["Q" * 200, "second", "third"],
            "evidence_ids": ["#12", 13, "nope"],
            "status": "weird",
        })
        assert step["event_id"] == 7
        assert len(step["title"]) <= 80
        assert len(step["summary"]) <= 240
        assert len(step["evidence_quotes"]) == 2
        assert len(step["evidence_quotes"][0]) <= 80
        assert step["evidence_ids"] == [12, 13]
        assert step["status"] == "success"
        assert step["step_id"].startswith("e7-")

    def test_unknown_kind_falls_back(self):
        step = compact_step({"event_id": 1, "kind": "magic", "stage": "nope"})
        assert step["kind"] == "hop"
        assert step["stage"] == "executor"

    def test_signature_fields_on_tool_step(self):
        step = compact_step({
            "event_id": 3,
            "kind": "tool",
            "stage": "executor",
            "tool_name": "block_ip",
            "signature_score": 0.91,
            "signature_reasons": ["block_ip.ip 类别 rfc1918,基线未见"],
        })
        assert step["signature_score"] == 0.91
        assert step["signature_reasons"]
        assert "rfc1918" in step["signature_reasons"][0]


class TestBuffer:
    def setup_method(self):
        thought_buffer.clear()

    def test_ring_per_event_and_evicts_old_events(self):
        buf = ThoughtChainBuffer(max_events=3, max_steps=4)
        for eid in (1, 2, 3, 4):
            buf.add({"event_id": eid, "kind": "plan", "stage": "decomposer", "title": str(eid)})
        assert buf.get(1) == []
        assert len(buf.get(4)) == 1

    def test_caps_steps_and_dedupes_step_id(self):
        buf = ThoughtChainBuffer(max_events=5, max_steps=3)
        for i in range(5):
            buf.add({
                "event_id": 9,
                "step_id": f"e9-plan-{i}",
                "kind": "plan",
                "stage": "decomposer",
                "title": str(i),
            })
        steps = buf.get(9)
        assert len(steps) == 3
        buf.add({
            "event_id": 9,
            "step_id": steps[-1]["step_id"],
            "kind": "plan",
            "stage": "decomposer",
            "title": "updated",
        })
        assert buf.get(9)[-1]["title"] == "updated"


class TestPublish:
    def setup_method(self):
        thought_buffer.clear()

    def test_batch_writes_buffer_and_returns_compacted(self):
        out = publish_thought_batch([
            {"event_id": 42, "kind": "plan", "stage": "decomposer", "title": "deep"},
            {"event_id": 42, "kind": "claim", "stage": "executor", "title": "C2", "confidence": 0.86},
        ], stage="executor")
        assert len(out) == 2
        assert thought_buffer.get(42)[0]["title"] == "deep"


class TestEmit:
    def setup_method(self):
        thought_buffer.clear()

    def test_emit_signals_sigma_and_anomaly(self):
        steps = emit_signals(
            {
                "_sigma": {"detected": True, "hits": [{"name": "c2_beacon"}]},
                "_anomaly": {"score": 0.81, "reasons": ["rare dest"]},
                "_chain": {"id": 1},
            },
            event_id=5,
            session_id="s",
        )
        kinds = [s["kind"] for s in steps]
        assert kinds == ["signal", "signal", "signal"]
        assert any("Sigma" in s["title"] for s in steps)

    def test_emit_plan_and_tool_map(self):
        plan = emit_plan(
            {
                "audit_depth": "deep",
                "sub_tasks": [{"task_id": "t1", "type": "query_events"}],
                "depth_reason": "critical",
                "mode": "full",
            },
            event_id=5,
        )
        assert plan[0]["kind"] == "plan"
        assert "deep" in plan[0]["title"]
        mapped = emit_tool_map(
            [{"task_id": "t1", "type": "query_events"}],
            [{"task_id": "t1", "tool": "event_store.query"}],
            event_id=5,
        )
        assert mapped[0]["kind"] == "tool_map"
        assert "event_store.query" in mapped[0]["summary"]
        tools = [s for s in mapped if s["kind"] == "tool"]
        assert len(tools) == 1
        assert tools[0]["tool_name"] == "event_store.query"
        assert mapped[0]["step_id"] in tools[0]["parent_ids"]

    def test_emit_tool_result_carries_signature(self):
        class R:
            anomaly_score = 0.88
            is_anomaly = True
            reasons = ["caller=ops 在 alert_only 后直接 isolate_host"]
        steps = emit_tool_result(
            "isolate_host", success=True, duration_ms=8,
            report=R(), event_id=5,
        )
        assert steps[0]["kind"] == "tool"
        assert steps[0]["signature_score"] == 0.88
        assert steps[0]["status"] == "error"
        assert steps[0]["tool_ok"] is False

    def test_emit_executor_claims_hops_verdict_gate(self):
        class AR:
            evidence = [{
                "threat_claims": [{
                    "type": "C2",
                    "confidence": 0.9,
                    "summary": "beacon",
                    "evidence_ids": [5, 6],
                    "evidence_quotes": ["dst=1.2.3.4"],
                }],
            }]
            discarded_claims = [{"type": "XSS", "summary": "无证据"}]
            hop_trace = [
                {"hop": "sub_auditor", "avg_grounding": 0.8},
                {"hop": "synthesize", "verdict": "confirmed", "reason": "sigma+claim"},
            ]
            verdict = "confirmed"
            summary = "C2 confirmed"
            confidence = 0.88
            threat_detected = True
            grounding_score = 0.8

        steps = emit_executor(AR(), event_id=5, round_num=1)
        kinds = [s["kind"] for s in steps]
        assert "claim" in kinds
        assert "discard" in kinds
        assert "hop" in kinds
        assert "verdict" in kinds
        assert "gate" in kinds
        claim = next(s for s in steps if s["kind"] == "claim")
        assert claim["evidence_ids"] == [5, 6]

    def test_emit_rag_chunks_and_claim_parents(self):
        emit_tool_map(
            [{"task_id": "t1", "type": "kb"}],
            [{"task_id": "t1", "tool": "knowledge.search"}],
            event_id=9,
        )
        class TR:
            tool = "knowledge.search"
            success = True
            task_id = "t1"
            data = [{
                "id": 42,
                "title": "C2 beacon pattern",
                "content": "beacon every 60s",
                "score": 0.91,
                "source": "mitre-attack",
            }]

        class AR:
            tool_results = [TR()]
            evidence = [{
                "threat_claims": [{
                    "type": "C2", "confidence": 0.9, "summary": "beacon",
                    "evidence_ids": [9],
                }],
            }]
            discarded_claims = []
            hop_trace = []
            verdict = "confirmed"
            summary = "ok"
            confidence = 0.9
            threat_detected = True
            grounding_score = 0.8

        rag = emit_rag_chunks(AR(), event_id=9)
        assert rag and rag[0]["kind"] == "rag"
        assert rag[0]["chunk_id"] == "42"
        assert rag[0]["rag_score"] == 0.91
        exec_steps = emit_executor(AR(), event_id=9)
        claim = next(s for s in exec_steps if s["kind"] == "claim")
        assert rag[0]["step_id"] in claim["parent_ids"]
        assembled = assemble_thought_chain(9, status="running")
        assert any(n["kind"] == "rag" for n in assembled["nodes"])
        assert any(
            e["from"] == rag[0]["step_id"] or e["to"] == rag[0]["step_id"]
            for e in assembled["edges"]
        )

    def test_emit_review_abstain(self):
        class V:
            conclusion = "insufficient_evidence"
            confidence = 0.2
            final_summary = "证据不足"
            reviewer_notes = ""
            evidence_chain = ["no quote match"]
            abstain = True
            human_intervention = True
            missed_threats = []

        steps = emit_review(V(), event_id=5)
        assert steps[0]["status"] == "abstain"
        assert steps[0]["kind"] == "review"


class TestAssemble:
    def setup_method(self):
        thought_buffer.clear()

    def test_project_old_audit_without_thought_chain(self):
        audit = {
            "status": "completed",
            "rounds_detail": [{"round": 1, "mode": "full", "threat_detected": True, "confidence": 0.8}],
            "evidence_trail": [{
                "claim": "C2 beacon",
                "type": "C2",
                "confidence": 0.86,
                "evidence_ids": [11],
                "evidence_quotes": ["23.129.64.33"],
                "round": 1,
            }],
            "hop_trace": [{"hop": "synthesize", "verdict": "confirmed", "reason": "sigma"}],
            "merged": {
                "verdict": "confirmed",
                "threat_detected": True,
                "confidence": 0.8,
                "summary": "C2",
                "response_blocked": True,
            },
            "reviewer": {
                "conclusion": "threat_confirmed",
                "confidence": 0.82,
                "final_summary": "确认",
                "evidence_chain": ["同源 beacon"],
            },
            "grounding": {"score": 0.91},
        }
        nodes = project_from_audit_llm(audit, 11)
        kinds = {n["kind"] for n in nodes}
        assert "plan" in kinds
        assert "claim" in kinds
        assert "verdict" in kinds
        assert "review" in kinds
        assert "response" in kinds
        assembled = assemble_thought_chain(11, audit=audit, status="completed")
        assert assembled["source"] == "projected"
        assert assembled["event_id"] == 11
        assert assembled["grounding"]["score"] == 0.91
        assert 11 in assembled["grounding"]["cited_event_ids"]
        assert any(e["rel"] == "evidences" for e in assembled["edges"])

    def test_live_buffer_preferred(self):
        publish_thought_batch([{
            "event_id": 3, "kind": "plan", "stage": "decomposer", "title": "live",
        }])
        assembled = assemble_thought_chain(3, audit={"thought_chain": [{
            "event_id": 3, "kind": "plan", "stage": "decomposer",
            "step_id": "other", "title": "persisted",
        }]}, status="running")
        assert assembled["source"] == "live"
        titles = {n["title"] for n in assembled["nodes"]}
        assert "live" in titles
        assert "persisted" in titles

    def test_attach_to_audit(self):
        publish_thought_batch([{
            "event_id": 8, "kind": "plan", "stage": "decomposer", "title": "p",
        }])
        payload = attach_to_audit({"status": "completed"}, 8)
        assert payload["thought_chain"][0]["title"] == "p"
