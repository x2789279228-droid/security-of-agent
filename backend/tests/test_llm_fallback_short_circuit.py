"""r6: LLM fallback / 预算门禁 — 禁止 schema-retry 空转占槽。"""
import json
import pytest

from agents.llm_fallback import is_llm_fallback, parse_llm_json, budget_exhausted


def test_is_llm_fallback_budget_json():
    text = json.dumps({"error": "每日 LLM 预算已用尽", "fallback": True}, ensure_ascii=False)
    ok, reason = is_llm_fallback(text)
    assert ok is True
    assert reason == "budget_exhausted"


def test_is_llm_fallback_call_failed():
    text = json.dumps({"error": "LLM调用失败", "fallback": True}, ensure_ascii=False)
    ok, reason = is_llm_fallback(text)
    assert ok is True
    assert reason == "llm_call_failed"


def test_is_llm_fallback_normal_json():
    text = json.dumps({"threat_detected": True, "confidence": 0.8, "summary": "x"})
    ok, reason = is_llm_fallback(text)
    assert ok is False
    assert reason == ""


def test_parse_llm_json_fenced():
    raw = '```json\n{"fallback": true, "error": "每日 LLM 预算已用尽"}\n```'
    obj = parse_llm_json(raw)
    assert obj and obj.get("fallback") is True


@pytest.mark.asyncio
async def test_sub_auditor_no_retry_on_budget(monkeypatch):
    """预算降级响应只调用一次 llm_chat,不进入 MAX_RETRIES。"""
    from agents.sub_auditor import SubAuditor, ChunkVerdict
    from agents.chunker import AuditChunk

    calls = {"n": 0}

    async def fake_chat(messages):
        calls["n"] += 1
        return json.dumps({"error": "每日 LLM 预算已用尽", "fallback": True}, ensure_ascii=False)

    sa = SubAuditor()
    monkeypatch.setattr(sa, "llm_chat", fake_chat)

    chunk = AuditChunk(
        chunk_id="c1",
        strategy="by_ip",
        label="IP 1.2.3.4",
        events=[{"id": 1, "message": "ssh fail", "src_ip": "1.2.3.4"}],
    )

    verdict = await sa.audit(chunk)
    assert isinstance(verdict, ChunkVerdict)
    assert verdict.schema_valid is False
    assert "budget_exhausted" in (verdict.schema_errors[0] if verdict.schema_errors else "")
    assert calls["n"] == 1  # 无第二次 retry


def test_budget_exhausted_reads_tracker(monkeypatch):
    class Fake:
        def is_over_budget(self):
            return True

    import agents.llm_fallback as mod
    import summary_compression as sc
    monkeypatch.setattr(sc, "cost_tracker", Fake())
    assert budget_exhausted() is True
