# OpenCode — P2 网关 / 审计不丢 / 指标 实施报告

> 日期：2026-09-06
> 执行者：OpenCode（glm-5.3-flash）
> 依据：`docs/upgrade-proposals/2026-q3-ingest-event-driven.md` §2 P2 / §3 P2-A..P2-J
> 范围承诺：仅改 `routers/logs.py`、`audit_worker.py`、`metrics.py` + 两个新测试文件 + 本报告。未实现 detect/store 流水线（Reasonix P1 已实现并全绿）。

---

## 1. 文件变更

| 文件 | 变更 |
|---|---|
| `backend/routers/logs.py` | ① 新增 FastAPI yield 依赖 `_session_unless_queued()`：producer 活跃 → `yield None`（不 checkout OLTP session）；否则动态 `from models import get_session` 透传（动态解析使测试可 patch `models.get_session`）。② `/logs/ingest` 与 `/logs/ingest/batch` 改用该依赖。③ producer 活跃路径返回 `JSONResponse(status_code=int(settings.ingest_http_queued_status or 202), content=...)`，body 含 `session_id/status='queued'/produced` + 既有字段（单条 `event_type/severity`，批量 `count`），**不调用** `log_ingestor.ingest`。④ `ingest_log_batch` 增加 `request: Request`，读 `X-API-Key` 传入 `_enqueue_ingest`（原硬编码 `""`）。⑤ sanitize / batch 1000 上限 / 其他端点未动。 |
| `backend/audit_worker.py` | ① `submit()` 队列满分支重构：`(tier=='P0' and audit_p0_never_drop) or (tier=='P1' and audit_p1_never_drop)` 时走链 `Redis PQ 成功 → 'shed'`；`PQ 失败 → Kafka overflow 成功 → 'deferred'`；`Kafka 也失败 → 进程内 `_p0_overflow` deque（容量 10000，FIFO 淘汰）→ 'deferred'`。never_drop 关闭时 P0/P1 与 P2/P3 一样记 `memory_full` 返回 `'overflow'`。② 新增 `_enqueue_kafka_overflow(job)`：producer `is_active` 检查 + `kafka_producer.produce_raw(payload, topic=settings.kafka_topic_audit_overflow, key_field="event_id")`，payload 为 JSON 化 `{event_id, session_id, log_data, anomaly_score, reasons, tier, priority}`（producer 未启动/投递失败/异常 → `False`）。③ 新增 `_shed(tier, reason)` 记 `soc_audit_shed_total`。④ `_loop()`：本地 deque 非空时 FIFO 优先 drain（每 3 个穿插 1 个普通队列任务防饿死 P2/P3），否则照旧阻塞 `queue.get()`；cancel/inflight/busy 语义不变。⑤ P2/P3 overflow 路径语义不变。返回值仍只有 `queued/shed/overflow/deferred/direct`。 |
| `backend/metrics.py` | 新增（纯增量，未改名/未动现有指标）：`soc_audit_shed_total{tier,reason}` Counter、`soc_ingest_stage_seconds{stage}` Histogram（buckets 至 30s）、`soc_ingest_detector_errors_total{detector}` Counter；助手 `inc_audit_shed(tier,reason)`、`observe_ingest_stage(stage,seconds)`、`inc_detector_error(detector)`，全部 try/except 包裹，与现有 helper 风格一致，模块级创建。 |
| `backend/tests/test_http_ingest_gateway.py` | 新建。TestClient 直连 `routers.logs.router`。覆盖：producer 活跃单条/批量 → 202 + `status=queued` + `produced`；`models.get_session` 被 patch 为「调用即 raise」仍成功（证明不借 session）；batch 带 `X-API-Key: abc` → `_enqueue_ingest(..., api_key='abc')`；无头 batch → `api_key=''`；sanitize 仍生效；producer 关闭 → 同步路径 200 + stub 结果合并（单条 + 批量）。 |
| `backend/tests/test_audit_never_drop.py` | 新建。复用 `test_audit_worker.py` 模式（假 `_audit_pipeline` 挂起、workers=1、queue_max=1）。覆盖：P0 满载 PQ ok→`shed`；PQ fail+Kafka ok→`deferred`；两者都 fail→`deferred` 且 job 在 `_p0_overflow`（`tier=='P0'`）；释放 pipeline 后 worker drain deque，calls==[1,2,3] 不丢；P1 never-drop 同链路；P3 满载仍 `overflow`（且断言 P3 不触碰 PQ/Kafka）；`audit_p0_never_drop=False` 时 P0 可 `overflow`；`_enqueue_kafka_overflow` 单测（produce_raw 参数/topic/key_field + producer 未启动→False）；metrics 助手冒烟（`generate_latest` 含三个新指标名）。 |

## 2. 测试运行与结果

命令（`cd backend`）：

```
python -m pytest tests/test_http_ingest_gateway.py tests/test_audit_never_drop.py tests/test_audit_worker.py -q
→ 17 passed in 2.26s
```

- `test_queue_overflow_p3` 保持通过（P2/P3 仍 overflow）。
- 邻接回归（P1-K 及 P1 新文件，确认未破坏 Reasonix 切片）：

```
python -m pytest tests/test_arch_unification.py tests/test_log_normalize_http.py tests/test_ingest_pipeline.py tests/test_event_store_batch.py tests/test_kafka_deliver_gather.py -q
→ 24 passed in 4.31s
```

- `tests/test_case_automation.py::TestAutoDispatch::test_audit_pipeline_path_creates_case` 失败 —— **已实证为存量问题，与本切片无关**：把 `metrics.py/audit_worker.py/routers/logs.py` 临时还原到 P2 前状态后单跑该测试，同样失败（`log_ingestion.py:422` `asyncio.wait_for` 收到测试自身 stub 的非 awaitable `lambda` 返回 `None` → TypeError → case/工单断言失败）。涉及文件 `log_ingestion.py`（Reasonix 锁定）与 `tests/test_case_automation.py`（不在本切片允许清单）。已恢复 P2 文件并复跑本切片全部测试确认仍 17 passed。

## 3. 验收对照（P2-A..P2-J）

| ID | 结果 | 证据 |
|---|---|---|
| P2-A | ✅ | `routers/logs.py` 两端点 producer 活跃时返回 `JSONResponse(status_code=settings.ingest_http_queued_status=202)`，body `status=queued`、`produced` 为成功条数；`test_ingest_202_queued_and_no_session` / `test_batch_202_forwards_api_key` |
| P2-B | ✅ | 依赖 `_session_unless_queued` 活跃时 `yield None`；测试把 `models.get_session` patch 为 raise 仍 202；不调 `log_ingestor.ingest`（stub 即 raise） |
| P2-C | ✅ | `ingest_log_batch` 读 `X-API-Key` 传 `_enqueue_ingest`（wrapper 内写入 `source_key`），与单条一致 |
| P2-D | ✅ | producer 关闭走同步 `log_ingestor.ingest/ingest_batch`，HTTP 200，`status=review_queued` |
| P2-E | ✅ | P0 满载：`shed`（PQ ok）/ `deferred`（Kafka 或 deque），测试断言 `!= "overflow"` |
| P2-F | ✅ | P1 同链路（`audit_p1_never_drop=True`），`test_p1_never_drop_deferred` |
| P2-G | ✅ | PQ fail → `produce_raw` → `security-audit-overflow`；Kafka fail → `_p0_overflow` deque；worker 空时就地 drain（测试 calls==[1,2,3]） |
| P2-H | ✅ | P2/P3 满载仍 `overflow`；`test_queue_overflow_p3` 绿 |
| P2-I | ✅ | `soc_audit_shed_total{tier,reason}`，reason ∈ `memory_full,pq_ok,pq_fail,kafka_overflow,local_deque` |
| P2-J | ✅ | `soc_ingest_stage_seconds{stage}`（detect/persist/dispatch 可用）、`soc_ingest_detector_errors_total{detector}` 助手已就绪 |
| X-4 | ✅ 未出现 | never_drop=True 时 P0/P1 永不 `overflow`（deque 兜底后仍返回 `deferred`） |

## 4. 遗留风险

1. **`_p0_overflow` 仅进程内**：Redis 与 Kafka 双失败时兜底在内存（上限 10000，FIFO 淘汰最旧）。进程崩溃即丢 —— 这是验收允许的最后一级兜底，但如果要跨重启持久化需后续把 deque 也落盘（未做，超出本轮）。
2. **Kafka overflow topic 的消费侧**：`security-audit-overflow` 目前只有生产侧；没有 consumer 把它回灌审计管道。事件不丢（在 Kafka 里），但也不会自动被审计 —— 需登记后续接线（属 Phase 2 topic 扇出范围）。
3. **deque 优先 drain 的公平性**：worker 每 3 个 overflow 兜底任务穿插 1 个普通队列任务；极端兜底洪峰下 P2/P3 深度审计会延后（不丢、但可能慢）。文档认可该取舍。
4. **PQ 失败会同时记 `pq_fail` 与下一跳 reason**（如 `kafka_overflow`/`local_deque`）：单事件可能贡献两条 counter —— 属预期（计数器语义为累计原因），如需「每事件一条」需改成单一终态 reason。
5. **`test_case_automation` 存量失败**（见 §2）：需 Reasonix/测试 owner 处理，不在本切片。
6. `produce_raw` 的 `value_serializer` 用 `json.dumps` 无 `default=str`；若 `log_data` 内含不可序列化对象，send 入队失败会被 `produce_raw_batch` 捕获记日志并返回 0 → `_enqueue_kafka_overflow` 返回 False → 落 deque，不会崩 submit。

## 5. 明确未做（按指示）

- 未实现 detect/store 流水线（`ingest_pipeline.py` 等，Reasonix P1 已完成且全绿）。
- 未在 ingest 阶段（detect/persist/dispatch）实际打点 `observe_ingest_stage`/`inc_detector_error` —— 打点位置在 `ingest_pipeline.py`（禁止触碰），本切片只交付指标与助手。
- 未改 `config.py`（旋钮只读使用）、未上 Celery、未改 `python_process_ingest_queue`、未动 FastPath/前端/Flink/self_play、未触碰 `test_audit_worker.py` 与 `test_case_automation.py`。
- 未 commit（未获授权）。
