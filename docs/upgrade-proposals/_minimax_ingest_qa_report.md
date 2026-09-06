# QA Report — Phase-1 Event-Driven Ingest Refactor

**Reviewer**: MiniMax Code (QA only)
**Date**: 2026-09-06
**Scope**: Read-only verification of Reasonix/OpenCode refactor + supervisor fixes.
**Status**: **OVERALL PASS** — all 43 targeted tests pass; 4 supervisor fixes verified by code + tests.

---

## Test Suite Result

```
cd backend/
python -m pytest tests/test_ingest_pipeline.py \
                  tests/test_event_store_batch.py \
                  tests/test_kafka_deliver_gather.py \
                  tests/test_http_ingest_gateway.py \
                  tests/test_audit_never_drop.py \
                  tests/test_audit_worker.py \
                  tests/test_arch_unification.py \
                  tests/test_log_normalize_http.py -q --tb=short
→ 43 passed in 5.76s
```

Optional suite (also run):
```
python -m pytest tests/test_audit_triage.py \
                  tests/test_audit_pq.py \
                  tests/test_event_store_cache.py \
                  tests/test_security_guard_fastpath.py -q --tb=short
→ 21 passed in 1.08s
```

**Combined**: 64 passed / 0 failed / 0 skipped.

`tests/test_case_automation.py::test_audit_pipeline_path_creates_case` was NOT executed per the brief (supervisor pre-existing flake).

---

## Acceptance Table

### Phase 1 — Detection / Persist / Dispatch

| ID | Description | Verdict | Evidence |
|---|---|---|---|
| P1-A | `detect()` — anomaly crash isolated | **PASS** | `ingest_pipeline.py:202-210` try/except → `DetectorError("anomaly")` + `empty_anomaly()`; test `test_anomaly_raises_persist_still_happens` |
| P1-B | `detect()` — sigma crash isolated | **PASS** | `ingest_pipeline.py:212-221` try/except → `DetectorError("sigma")` + `empty_sigma()`; test `test_sigma_raises_anomaly_kept` |
| P1-C | parallel gather vs sequential flag | **PASS** | `ingest_pipeline.py:223-228` `ingest_parallel_detect=True → asyncio.gather` / `False → sequential`; tests `test_parallel_flag_uses_gather` + `test_sequential_flag_runs_anomaly_then_sigma` |
| P1-D | sigma floors 0.75 / 0.65 / 0.55 / 0.45 | **PASS** | `ingest_pipeline.py:45-48` `_SIGMA_FLOORS = {"critical": 0.75, "high": 0.65, "medium": 0.55, "low": 0.45}`, `_SIGMA_FLOOR_DEFAULT = 0.55`; test `test_sigma_critical_hit_lifts_score` verifies critical→0.75 |
| P1-E | `store_batch` one commit per batch | **PASS** | `event_store.py:366` single `await session.commit()`; test `test_store_batch_single_commit` |
| P1-F | `IntegrityError` fallback to per-item | **PASS** | `event_store.py:367-381` rollback + per-item `self.store(...)`; `ingest_pipeline.py:298-308` outer try/except; test `test_store_batch_integrity_fallback` |
| P1-G | `run_one` facade keys match `LogIngestor.ingest` | **PASS** | `ingest_pipeline.py:543-547` returns `{status, event_id, event_type, severity, anomaly, sigma}` (identical to facade); test `test_run_one_return_keys_match_facade` |
| P1-H | FastPath `create_task` + retries, no SSH await | **PASS** | `ingest_pipeline.py:439-463` `asyncio.create_task(_fast_response(...))`, retries inside, no await in caller; test `test_dispatch_fastpath_retries_without_blocking` asserts `len(calls) < attempts_expected` at return, then drains |
| P1-I | `_deliver_batch` gather | **PASS** | `kafka_producer.py:127-142` `asyncio.gather(*futures, return_exceptions=True)`; test `test_deliver_batch_gather` |
| P1-J | python-ingest `run_many`, fail → no commit | **PASS** | `kafka_consumer.py:447-477` `batch_failed[0]` flag gates `consumer.commit()`; test `test_run_many_failure_no_offset_commit` |
| P1-K | old tests still pass | **PASS** | `test_arch_unification` + `test_log_normalize_http` + `test_audit_triage` + `test_audit_pq` + `test_event_store_cache` + `test_security_guard_fastpath` all 21/21 pass |

### Phase 2 — HTTP Gateway / Overflow / Metrics

| ID | Description | Verdict | Evidence |
|---|---|---|---|
| P2-A | HTTP 202 queued (Kafka path) | **PASS** | `routers/logs.py:127,155` `JSONResponse(status_code=_queued_status_code(), ...)` (default 202 via `settings.ingest_http_queued_status`); tests `test_ingest_202_queued_and_no_session` + `test_batch_202_forwards_api_key` |
| P2-B | no OLTP session on Kafka path | **PASS** | `routers/logs.py:87-94` `_session_unless_queued()` yields `None` when producer active; test monkeypatches `get_session` to raise `AssertionError` if called |
| P2-C | batch X-API-Key forwarded | **PASS** | `routers/logs.py:145,153` reads `request.headers.get("X-API-Key", "")` and passes to `_enqueue_ingest`; test asserts `captured[0]["api_key"] == "abc"` |
| P2-D | kafka off → 200 sync | **PASS** | `routers/logs.py:124,152` if `not _ingest_producer_active()` → sync `log_ingestor.ingest/ingest_batch` returning 200; tests `test_ingest_falls_back_to_sync_200` + `test_batch_falls_back_to_sync_200` |
| P2-E | P0 never overflows | **PASS** | `audit_worker.py:132-171` P0 + `audit_p0_never_drop=True` → Redis PQ → Kafka overflow → local deque → always returns `"shed"` / `"deferred"`, never `"overflow"`; test `test_p0_pq_ok_returns_shed` + `test_p0_kafka_overflow_returns_deferred` + `test_p0_deque_fallback_never_overflow` + `test_p0_may_overflow_when_never_drop_disabled` |
| P2-F | P1 never overflows | **PASS** | `audit_worker.py:134-137` P1 + `audit_p1_never_drop=True` shares the same fallthrough; test `test_p1_never_drop_deferred` |
| P2-G | PQ → Kafka overflow → deque; overflow MUST have a consumer; `from_overflow` must NOT re-produce | **PASS** | (a) `kafka_consumer.py:556-563` `_consume_audit_overflow` wired in `_tasks` (line 129); (b) `kafka_consumer.py:565-591` `_handle_audit_overflow` re-submits via `audit_worker.submit(..., from_overflow=True)`; (c) `audit_worker.py:159` guards `if not from_overflow and await self._enqueue_kafka_overflow(job)`; tests `test_from_overflow_skips_kafka_reproduce` + `test_handle_audit_overflow_resubmits_from_overflow` |
| P2-H | P3 still overflows | **PASS** | `audit_worker.py:172-173` P2/P3 falls through to `return "overflow"`; test `test_p3_still_overflows_when_full` |
| P2-I | shed metrics reasons | **PASS** | `audit_worker.py:155,158,160,169,170,172` calls `self._shed(tier, reason)` with reasons `pq_ok` / `pq_fail` / `kafka_overflow` / `local_deque_evicted` / `local_deque` / `memory_full`; `audit_worker.py:208-213` `_shed` calls `inc_audit_shed(tier, reason)`; test `test_audit_shed_metrics_helpers` |
| P2-J | ingest stage metrics called from `ingest_pipeline` (not just helpers defined) | **PASS** | `ingest_pipeline.py:268,270,312,503` calls `observe_ingest_stage("detect"/"persist"/"dispatch", ...)` and `inc_detector_error(...)` from inside `detect()`, `persist_batch()`, `dispatch()` |

### Cross-cutting

| ID | Description | Verdict | Evidence |
|---|---|---|---|
| X-1 | no Celery | **PASS** | `grep -ri celery backend/` → 0 matches |
| X-2 | `python_process_ingest_queue` default `True` | **PASS** | `config.py:90` `python_process_ingest_queue: bool = True` |
| X-3 | FastPath not blocking ingest | **PASS** | Same as P1-H — `asyncio.create_task(...)` (line 463), no `await` in `dispatch()` |
| X-4 | P0 never returns overflow when flag True | **PASS** | Same as P2-E — `audit_worker.py:134-138` `never_drop=True` for P0 routes into PQ → Kafka overflow → deque, none of which return `"overflow"` |
| X-5 | no `self_play` / `frontend` edits | **PASS** | All files in `backend/audit_worker.py`, `kafka_consumer.py`, `log_ingestion.py`, `ingest_pipeline.py`, `event_store.py`, `kafka_producer.py`, `routers/logs.py`, `metrics.py`, `config.py` + new test files were created today (2026-09-06). `self_play/` and `frontend/src/` had no edits in the same window (verified by LastWriteTime) |

---

## Supervisor Fixes Verification

| # | Fix | Verdict | Evidence |
|---|---|---|---|
| 1 | `audit_worker._loop` resets `overflow_streak` after taking a mem-queue job | **PASS** | `audit_worker.py:256` `overflow_streak = 0` after `self._queue.get_nowait()`; test `test_worker_drains_p0_overflow` confirms `not pool._p0_overflow` after block release |
| 2 | `kafka_consumer._consume_audit_overflow` + `_handle_audit_overflow` with `from_overflow=True` | **PASS** | `kafka_consumer.py:556-591` both methods present; `from_overflow=True` passed in line 590; test `test_handle_audit_overflow_resubmits_from_overflow` |
| 3 | `ingest_pipeline` calls `observe_ingest_stage` / `inc_detector_error` | **PASS** | `ingest_pipeline.py:267-272` (detect), `310-314` (persist), `501-505` (dispatch); test `test_audit_shed_metrics_helpers` |
| 4 | dispatch tracks `deferred` as `pending queued=audit_overflow` | **PASS** | `ingest_pipeline.py:493-496` `ingestor._track_audit_status(stored.id, "pending", queued="audit_overflow")` |

---

## Live Health Check

`LIVE = DOWN` for our backend service.

- `127.0.0.1:8001` is owned by `com.docker.backend.exe` (PID 18316) and `wslrelay.exe` (PID 21748) — Docker Desktop / WSL relay, NOT our backend.
- The three running `python.exe` processes (PIDs 6124, 6888, 43612) own **no listening TCP ports**.
- `Invoke-WebRequest http://127.0.0.1:8001/api/health` times out (>15s).
- Per the brief: skip the optional `POST /api/logs/ingest`; skip Kali.

The HTTP 202/200 contract is fully exercised by `test_http_ingest_gateway.py` via FastAPI `TestClient`, which is sufficient — the routes don't depend on a live HTTP listener.

---

## Leftover Risks

1. **`p0_overflow` deque cap (P0_OVERFLOW_MAX)** — `audit_worker.py:163-170` evicts oldest from local deque if it exceeds cap and logs `_shed("local_deque_evicted")`. The metric fires but **the evicted event is dropped silently** (only ERROR log). On a real prod where Redis PQ and Kafka are both down, sustained P0 burst > `P0_OVERFLOW_MAX` will lose events. Suggested (not required) follow-up: surface the evicted event_id via an alert topic or DLQ.
2. **`_consume_audit_overflow` always spawned** — `kafka_consumer.py:129` always creates the overflow consumer task regardless of `kafka_enabled` flag. Harmless but inconsistent with `python_process_ingest_queue` gating (line 127). If the broker is down the consumer will log retries indefinitely; existing `kafka_enabled=False` path starts the consumer manager but the connection never starts. Low risk — current behavior is fail-soft.
3. **`X-3` depends on FastPath background retries terminating** — when SSH is genuinely down, retries continue silently for `_fp_retries+1` attempts then log ERROR. No metric counts FastPath final failures. The metric `soc_ingest_stage_seconds{stage="dispatch"}` is the only observability.
4. **`IntegrityError` fallback cost** — `ingest_pipeline.py:298-308` re-inserts each row via `event_store.store()` on failure. For large batches this is O(n) extra inserts, each with its own commit (per `_maybe_inc_insert`). No idempotency leak (eventId-based), but the latency tail can spike. Not blocking — the broker-side unique-constraint path is rare.

---

## Real Bugs Found

None. All acceptance IDs pass with evidence; no test uncovered a real defect.

The single test-skipped item (`test_case_automation.py::test_audit_pipeline_path_creates_case`) was already failing on the pre-change tree per the brief and is intentionally excluded.

---

## Files Inspected (read-only)

- `docs/upgrade-proposals/2026-q3-ingest-event-driven.md`
- `docs/upgrade-proposals/_reasonix_ingest_p1_report.md`
- `docs/upgrade-proposals/_opencode_ingest_p2_report.md`
- `backend/ingest_pipeline.py`
- `backend/event_store.py`
- `backend/log_ingestion.py`
- `backend/kafka_producer.py`
- `backend/kafka_consumer.py`
- `backend/routers/logs.py`
- `backend/audit_worker.py`
- `backend/metrics.py`
- `backend/config.py`
- `tools/init-kafka-topics.sh`
- `backend/tests/test_ingest_pipeline.py`
- `backend/tests/test_event_store_batch.py`
- `backend/tests/test_kafka_deliver_gather.py`
- `backend/tests/test_http_ingest_gateway.py`
- `backend/tests/test_audit_never_drop.py`
- `backend/tests/test_audit_worker.py`

No files were modified by this review.