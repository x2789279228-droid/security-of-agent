"""P2 HTTP 网关: producer 活跃 → 202 queued 且不借 OLTP session;
producer 关闭 → 同步 ingest, HTTP 200, dummy 结果合并。
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import models
import routers.logs as logs_router
from routers.logs import router


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _no_get_session():
    raise AssertionError("get_session must not be called when producer active")


async def _fake_session():
    yield None


@pytest.fixture()
def client():
    with TestClient(_app()) as c:
        yield c


def test_ingest_202_queued_and_no_session(monkeypatch, client):
    from config import settings

    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"session_id": session_id, "api_key": api_key, "events": list(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_producer_active", lambda: True)
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    # producer 活跃时 get_session 绝不能被调用
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "BRUTE_FORCE", "message": "<b>hi</b>", "severity": "high"},
        "session_id": "s1",
    })

    assert resp.status_code == int(settings.ingest_http_queued_status or 202)
    body = resp.json()
    assert body["status"] == "queued"
    assert body["session_id"] == "s1"
    assert body["produced"] == 1
    # sanitize 仍然生效
    assert captured[0]["api_key"] == ""
    assert captured[0]["events"][0]["message"] == "hi"


def test_batch_202_forwards_api_key(monkeypatch, client):
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"session_id": session_id, "api_key": api_key, "events": list(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_producer_active", lambda: True)
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "PORT_SCAN"}, {"event": "C2_BEACON"}], "session_id": "sb"},
        headers={"X-API-Key": "abc"},
    )

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["count"] == 2
    assert body["produced"] == 2
    assert captured[0]["api_key"] == "abc"
    assert captured[0]["session_id"] == "sb"
    assert len(captured[0]["events"]) == 2


def test_batch_202_without_api_key_header(monkeypatch, client):
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"api_key": api_key, "n": len(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_producer_active", lambda: True)
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post("/api/logs/ingest/batch", json={"logs": ["{\"event\": \"X\"}"]})

    assert resp.status_code == 202
    assert captured[0]["api_key"] == ""


def test_ingest_falls_back_to_sync_200(monkeypatch, client):
    async def dummy_ingest(session, session_id, log_data):
        return {"status": "review_queued", "event_id": 7, "event_type": "REQ"}

    async def dummy_ingest_batch(session, session_id, parsed):
        return {"status": "review_queued", "count": len(parsed)}

    class _Stub:
        ingest = staticmethod(dummy_ingest)
        ingest_batch = staticmethod(dummy_ingest_batch)

    monkeypatch.setattr(logs_router, "_ingest_producer_active", lambda: False)
    monkeypatch.setattr(models, "get_session", _fake_session)
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "REQ", "message": "m", "severity": "info"},
        "session_id": "s2",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review_queued"
    assert body["event_id"] == 7
    assert body["session_id"] == "s2"


def test_batch_falls_back_to_sync_200(monkeypatch, client):
    async def dummy_ingest_batch(session, session_id, parsed):
        return {"status": "review_queued", "count": len(parsed)}

    class _Stub:
        ingest = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("no single ingest")))
        ingest_batch = staticmethod(dummy_ingest_batch)

    monkeypatch.setattr(logs_router, "_ingest_producer_active", lambda: False)
    monkeypatch.setattr(models, "get_session", _fake_session)
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "A"}, {"event": "B"}], "session_id": "sb2"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review_queued"
    assert body["count"] == 2
    assert body["session_id"] == "sb2"
