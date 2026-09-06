# P1 接入流水线 — Reasonix 实现报告

> 日期：2026-09-06
> 切片：`docs/upgrade-proposals/2026-q3-ingest-event-driven.md` P1 全部 (P1-A..P1-K)
> 实现者：Reasonix（不触碰 OpenCode 所有权：routers/logs.py、audit_worker.py、metrics.py、config.py、frontend、flink-jobs、self_play、anomaly_detector.py、sigma_detector.py）

## 1. 目标

把 `log_ingestion.LogIngestor.ingest()` 的串行关键路径收敛成同进程事件驱动流水线：

```
detect(anomaly ∥ sigma, 失败隔离) → persist_batch(单 commit) → dispatch(FastPath create_task + 重试 / audit_worker.submit / event_bus)
```

`ingest()` 降级为 facade（归一化 + 数字 severity 映射 + `run_one(...).as_http_dict()`），
Kafka python-ingest 消费走 `run_many`（整批解析 → 单个 session → 单/分块 commit，失败整批不 commit）。

## 2. 改动文件清单

| 文件 | 改动 |
|---|---|
| `backend/ingest_pipeline.py` | **实现** contract 全部函数体（签名/dataclass 未动）：`detect`（异常隔离、`ingest_parallel_detect` 并行、Sigma 融合抬分、`_anomaly`/`_sigma` in-place 写回）、`persist_batch`（store_batch 单事务 + IntegrityError 双保险回退）、`dispatch`（FastPath 迁移 + `ingest_fastpath_retries` 重试 + 审计 + 总线广播）、`run_one`、`run_many` |
| `backend/event_store.py` | **只加** `store_batch()` + `_maybe_inc_insert()`；`store()` 逐条 commit 语义不变（既有单测依赖） |
| `backend/log_ingestion.py` | `ingest()` 改为 facade（保留 `_normalize_fields` + 数字 severity 映射，删除整段 detect/store/FastPath/submit 复制体）；`ingest_batch` 非 sqlite 多事件分支改调 `run_many`（sqlite / len≤1 仍串行 `ingest`） |
| `backend/kafka_producer.py` | `_deliver_batch` → `asyncio.gather(*futures, return_exceptions=True)`，非异常计成功、异常记日志（删除 for+await 串行）；补 `import asyncio` |
| `backend/kafka_consumer.py` | `_consume_python_ingest` 整批解析 → 单 `async_session` → `run_many`（按 `ingest_store_batch_size` 分块）；任一 persist/run_many 抛错 → `batch_failed` → 本批不 commit（现无丢失语义）；`_handle_python_ingest` 保留（wrapper.body/session_id 提取不变）；其他 topic handler 未动 |
| `backend/tests/test_ingest_pipeline.py` | 新建（6 个用例，覆盖 P1-A/B/C/D/G/H） |
| `backend/tests/test_event_store_batch.py` | 新建（5 个用例：空 / N 新一次 commit / 跨批+批内重复幂等 / 混合 / 无 eventId） |
| `backend/tests/test_kafka_deliver_gather.py` | 新建（3 个用例：gather 使用 + 异常计数 / 空 / 全失败） |
| `docs/upgrade-proposals/_reasonix_ingest_p1_report.md` | 本报告 |

未触碰：`routers/logs.py`、`audit_worker.py`、`metrics.py`、`config.py`、`event_bus.py`、`models.py`、`tests/conftest.py`、frontend、flink-jobs、self_play、两个检测器模块。

## 3. 验收对照（P1-A..P1-K）

| ID | 结论 | 说明 |
|---|---|---|
| P1-A | ✅ | anomaly 抛异常 → `empty_anomaly(reasons=["anomaly_error"])` + `DetectorError(detector="anomaly")`；sigma 继续跑；persist 不中断（`test_anomaly_raises_persist_still_happens`） |
| P1-B | ✅ | sigma 抛异常 → `empty_sigma()` + `DetectorError(detector="sigma")`，anomaly 结果保留（`test_sigma_raises_anomaly_kept`） |
| P1-C | ✅ | `ingest_parallel_detect=True` 经 `asyncio.gather`（probe 断言）；False 时 anomaly→sigma 顺序（两个用例） |
| P1-D | ✅ | Sigma 抬分 floor 与旧 `log_ingestion.ingest` EXACT 同源（critical 0.75 / high 0.65 / medium 0.55 / low 0.45，默认 0.55）；`is_anomaly=True`；reasons 追加 `Sigma命中:<types>`；`test_sigma_critical_hit_lifts_score` 断言 0.75 |
| P1-E | ✅ | `store_batch(n)` 一次 commit（counting-commit 断言 ==1）；同 eventId 重复 → 单行（跨批 & 批内）；等长同序返回 |
| P1-F | ✅ | 批内重复触发 IntegrityError → rollback + 逐条 `store()` 回退，收敛一行且不丢已成功行 |
| P1-G | ✅ | facade 返回 key 集合 = `{status, event_id, event_type, severity, anomaly, sigma}`（`as_http_dict` 契约；facade 直测） |
| P1-H | ✅ | FastPath 仍是 `create_task`（不 await SSH/编排）；失败按 `ingest_fastpath_retries`(2) 重试后打 error 日志（后台任务尝试 3 次后终局） |
| P1-I | ✅ | `_deliver_batch` 单次 `asyncio.gather(*futures, return_exceptions=True)`；单条异常不计成功、其余照常计数（probe + 混异常 futures） |
| P1-J | ✅ | python-ingest 批 → `run_many`；任一 persist/run_many 抛错 → `batch_failed` → 整批不 commit（offset 不推进，回放不丢） |
| P1-K | ✅ | `test_arch_unification.py`、`test_log_normalize_http.py`、`test_audit_worker.py` 全绿 |

### 反例核对（明确不做）
- X-1..X-5：未新增 Celery/Redis broker 依赖；`python_process_ingest_queue` 默认值未动；FastPath 未改回 await；submit() 溢出语义未改（P2 OpenCode 负责 never-drop 链）；self_play/前端/flink 零改动。

## 4. 测试执行

命令（规格要求，`backend/` 下）：
```
python -m pytest tests/test_ingest_pipeline.py tests/test_event_store_batch.py tests/test_kafka_deliver_gather.py tests/test_arch_unification.py tests/test_log_normalize_http.py tests/test_audit_worker.py -q
```
结果：**27 passed**（P1 新文件 14 + P1-K 旧测 13）。

额外回归（相邻被改模块的调用面）：
```
test_fallback_quality.py test_threat_type_inference.py test_event_store_cache.py
test_event_bus_slow_consumer.py test_security_guard_fastpath.py
test_response_dedup_dual_track.py test_security_audit_fixes.py
```
结果：**64 passed, 2 skipped**（skip 为 Redis/Temporal 环境用例，与本次改动无关）。

> 环境备注：`config.py` 的 `env_file=".env"` 相对 CWD 解析；本沙箱从仓库根运行 pytest 时会把根目录 docker-compose `.env` 的裸变量读成 pydantic extra 而崩。为跑测试临时把根 `.env` 移开、跑完已恢复原位（零代码改动）。规格里的 `cd backend && pytest` 流程无此问题。

## 5. 残留风险 / 已知取舍

1. **观测埋点丢失**：旧 `ingest()` 里 `pipeline_tracer.span("anomaly_detect")` 随迁移删除，未在 `ingest_pipeline` 重建。规则 11 的指标为可选项（`soc_ingest_*` 属 OpenCode P2-J），本切片未加任何 metrics；建议 P2 与 OpenCode 一起按 stage（detect/persist/dispatch）补 span + 指标，保持单方所有权。
2. **`ingest_batch` 非 sqlite 路径行为变化**：原实现按 `BATCH_INGEST_CONCURRENCY`(12) 每条独立 session 并发 commit；现改单 session + `store_batch` 单事务（P1 设计本意：detect 并行、落库批量单 commit）。`BATCH_INGEST_CONCURRENCY` 环境变量不再生效——吞吐模型从"并行 commit"变为"并行 detect + 串行批量 commit"。若 HTTP /batch 大请求实测变慢需在 P2 复核分块。
3. **store_batch 重复行的 `analyzed` 状态**：幂等返回用 `_to_stored`（携带 DB 真实 `analyzed`），而 `store()` 重复路径的 StoredEvent 默认 `analyzed=False`——热缓存内容更准确，但两路径返回的 analyzed 语义有细微差别；目前无消费方依赖此字段做决策。
4. **FastPath 重试节奏**：后台任务失败重试间 `sleep(0.2)`，最坏在打最终 error 前多花 ~0.4s（纯后台，不阻塞 ingest/run_many 返回）。
5. **correlation_id 透传**：pipeline 从 `log_data.get("correlation_id")` 取值；现上游（HTTP/检测）从未写入该键，实际恒为 `""`，与旧 ingest（store 不传 correlation_id）行为一致。若未来网关要在 wrapper 透传 correlation，需在 run_many 入参侧加通道（P1 契约外）。
6. **`log_ingestion` 顶部 `from anomaly_detector import anomaly_detector` 现仅被旧 ingest 使用，已成死 import**——保留以兼容测试 monkeypatch 面，P2 可清理。
7. **`_safe_py_handle` / `_handle_python_ingest` 保留**（`_consume_python_ingest` 主循环已不再调用），供其他调用方兼容；kafka 批路径的 parse 失败仍走"整批不 commit → 回放"，毒消息语义与旧版一致（非本次引入）。

## 6. 跳过的内容（有意为之）

- 指标/观测埋点（规则 11 可选；`metrics.py` 为 OpenCode P2 所有权）。
- HTTP 网关 202 / API key / batch 透传、audit never-drop 链、overflow/shed 指标 → 全部 P2（OpenCode 切片），未越界实现。
- Celery / ProcessPool / ClickHouse / `python_process_ingest_queue` 翻转（X-1/X-2，明确不做）。
- store() 逐条 commit 语义、audit_worker / audit_triage / FastPath 双轨判定逻辑本体：零改动（dispatch 逐行迁移，仅加重试壳）。
