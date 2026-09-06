# 安全审计接入链路 — 事件驱动解耦 Phase 1

> 日期：2026-09-06
> 范围：`shared-memory-platform/backend/` 接入 / 检测 / 落库 / 审计调度
> 角色：Grok 定标准与验收；Reasonix / OpenCode 按文件切片实现；MiniMax 只做 QA
> 目标：把「HTTP 线程里串行跑完检测+写库+派审计」收敛成「入队即返 + 同进程分层流水线」
> 非目标：本轮不拆独立微服务、不上 Celery、不换 ClickHouse、不把 HTTP 权威检测交回 Flink

---

## 0. 现状核对（相对用户给出的框架图）

用户给出的现状图**大体正确**，但有三处已经过时、一处被 profile 证伪。实现必须对着代码而不是对着旧图。

### 0.1 已经成立的部分

```
外部源 ─HTTP─► FastAPI ─┐
                       ├─► log_ingestion.ingest()   ← 同步关键路径（仅 kafka_enabled=False）
       ─Kafka─► 6+1 薄消费 ─┘
                                    ├─► anomaly_detector  (sync, 实测极轻)
                                    ├─► sigma_detector    (sync, 轻)
                                    ├─► event_store.store (sync, 重: 每条 commit PG)
                                    ├─► _index_background (async)
                                    ├─► FastPath 双轨门槛 (async create_task)
                                    └─► audit_worker.submit
                                              │
                                              ▼
                                  AuditWorkerPool(12) + PriorityQueue(2000)
                                              │ 满载: P0/P1 → Redis PQ; P2/P3 overflow 规则收口
                                              ▼
                                  4-Layer Pipeline → ResponseOrchestrator → SSH/iptables
```

证据：

| 环节 | 文件 | 事实 |
|---|---|---|
| HTTP 网关 | `routers/logs.py:109-112` | `kafka_enabled` 且 producer 已 start → produce `security-events-ingest` 后立即返回 `{status:queued}`（**HTTP 状态码仍是 200，不是 202**） |
| HTTP 回退 | 同上 `else` | Kafka 关时仍同步 `log_ingestor.ingest()` |
| 薄消费 | `kafka_consumer.py:117-127` | 6+1 topic；python-ingest 在 `python_process_ingest_queue=True` 时启动 |
| 权威处理 | `kafka_consumer.py:466-474` | python-ingest **仍然调用完整** `log_ingestor.ingest()`（检测+写库+FastPath+审计提交） |
| 检测串行 | `log_ingestion.py:197-243` | anomaly → sigma → `event_store.store` 顺序；sigma 有 try/except，**anomaly 没有** |
| 写库 | `event_store.py:187-240` | 每条 `commit()`；eventId 唯一索引幂等 |
| FastPath | `log_ingestion.py:252-355` | `create_task`，不阻塞 ingest 返回；失败只打日志，无重试 |
| 审计池 | `audit_worker.py:44-48,121-131` | 12 worker / 队列 2000；满载 P0/P1 进 Redis PQ（失败则 overflow），P2/P3 直接 overflow |
| 审计分流 | `audit_triage.py` | 已有 P0–P3 与 lane（llm_deep / tools_only / rule_close） |
| 背压 | `kafka_consumer.py` | 手动 commit、`max_poll_records=50`、audit-queue semaphore=12；python-ingest 整批失败不 commit |
| Flink | `r12_executive_summary.md` | HTTP 路径上 Flink 闲置，因为 `python_process_ingest_queue=True`（**这是 2026-09-04 的有意决策**：保住 Python sigma+anomaly+FastPath，避免双 LLM） |

### 0.2 用户诊断 vs 代码/数据

| 诊断 | 判定 | 本轮动作 |
|---|---|---|
| 1. HTTP 同步关键路径过重 | **生产 Kafka 模式已解耦入口**；瓶颈下移到 Python consumer 内的 `ingest()`。HTTP 仍 `Depends(get_session)` 白借连接；返回码 200 不是 202 | 修网关：无 DB session、202、batch 透传 API key |
| 2. 检测器串行、未并行 | 串行为真。**但 2026-09-04 profile：anomaly ≈5µs、sigma ≈0.71ms，合计 <4% 墙钟**。主成本是 PG 逐条 commit | 并行+隔离（正确性）；**禁止**为本项上 ProcessPool |
| 3. LLM 审计慢、满载 shed | 为真。已有 triage / PQ / timeout 配置，但 P0 在 Redis PQ 失败时仍可能 `overflow` | P0/P1 永不 overflow：PQ → Kafka overflow topic → 进程内 deque |
| 4. DB 逐条写入 | 为真，这是 consumer 12 ev/s 的主因之一 | `store_batch` 单事务 |
| 5. GIL / 线程模型 | anomaly 非 CPU 瓶颈（profile 证伪）。Audit 线程池对 LLM IO 够用 | **不做** Celery / ProcessPool / 换语言 |
| 6. 缺全链路背压 | 半真：Kafka offset 已手动；审计满载会丢 P2/P3 深度审计；缺阶段耗时指标 | 指标 + P0 不丢；不改 Kafka 语义 |
| 7. 可靠性：检测异常拖垮 ingest、响应无重试 | 为真（anomaly 未隔离；FastPath 无重试） | 检测隔离 + FastPath 有限重试 |

### 0.3 明确拒绝（本轮与北星都不要做）

1. **不要**把 HTTP 权威检测改回 Flink（`python_process_ingest_queue=False`）。r12 吞吐数字诱人，但会丢掉 Python sigma / FastPath 双轨 / audit_triage，与 2026-09-04 决策冲突。
2. **不要**为 anomaly 上 `ProcessPoolExecutor`。数据不支持。
3. **不要**本轮引入 Celery、ClickHouse、独立检测微服务。同进程 + 已有 Kafka topic 就能实现用户目标拓扑。
4. **不要**让 HTTP 同步返回封禁决策。封禁继续走 FastPath 异步；查询走已有 `/api/logs/status`。

---

## 1. 目标拓扑（本轮落地形态）

```
外部源 ──HTTP──► FastAPI 轻量接收（sanitize + 可选 API key）
                       │
                       ├─ kafka_enabled ──► Kafka(security-events-ingest) ──► 202 {status:queued}
                       └─ kafka 关      ──► ingest_pipeline.run_one()     ──► 200 {status:review_queued}

Kafka ingest ──► python-ingest consumer（批 poll）
                       │
                       ▼
              ingest_pipeline.run_many()
                       │
         detect(anomaly ∥ sigma, 失败隔离)
                       │
         event_store.store_batch（单 commit）
                       │
         ┌─────────────┼──────────────┐
         ▼             ▼              ▼
    FastPath(async)  AuditWorker   event_bus
    可重试 2 次      P0/P1 永不丢
         │             │
         └──────► ResponseOrchestrator
```

关键特性（对应用户「优化后理论框架」，本轮可验收的子集）：

- HTTP 层无检测、无写库、无 LLM。
- 检测模块逻辑独立、异常互不影响；同进程并行，不独立部署。
- 高优先级审计永不因内存队列满而 `overflow`。
- 写库批量 + 异步索引（索引已在后台）。
- 每阶段耗时 / 错误 / shed 原因可观测。

---

## 2. 切片与文件锁

### P1 接入流水线（Reasonix）

| 文件 | 允许改什么 |
|---|---|
| `backend/ingest_pipeline.py` | **实现** contract 中全部函数（文件已有类型与签名，禁止改签名） |
| `backend/event_store.py` | **只加** `store_batch()`；`store()` 行为不变 |
| `backend/kafka_producer.py` | `_deliver_batch` 改为 `asyncio.gather`；其余 API 不变 |
| `backend/log_ingestion.py` | `ingest()` 改为 facade：normalize + severity map 后调用 `run_one`；删掉复制的 detect/store/fastpath/submit 体。`ingest_batch` 在非 sqlite 路径改为 `run_many` |
| `backend/kafka_consumer.py` | `_handle_python_ingest` / 批处理循环改为 `run_many`（仍整批失败不 commit） |
| `backend/tests/test_ingest_pipeline.py` | 新建 |
| `backend/tests/test_event_store_batch.py` | 新建 |
| `backend/tests/test_kafka_deliver_gather.py` | 新建 |
| `docs/upgrade-proposals/_reasonix_ingest_p1_report.md` | 报告 |

禁止改：`routers/logs.py`、`audit_worker.py`、`metrics.py`、`config.py`、前端、Flink、self_play。

### P2 网关 / 审计不丢 / 指标（OpenCode）

| 文件 | 允许改什么 |
|---|---|
| `backend/routers/logs.py` | Kafka 路径 202、不借 DB session、batch 读 `X-API-Key`；同步路径保持 200 |
| `backend/audit_worker.py` | P0/P1 never-drop 链；P2/P3 overflow 语义不变（`test_queue_overflow_p3` 必须继续过） |
| `backend/metrics.py` | 增加 pipeline / shed 指标与 inc_* 助手 |
| `backend/tests/test_http_ingest_gateway.py` | 新建 |
| `backend/tests/test_audit_never_drop.py` | 新建 |
| `docs/upgrade-proposals/_opencode_ingest_p2_report.md` | 报告 |

禁止改：`ingest_pipeline.py` 签名、`event_store.py`、`kafka_producer.py`、`log_ingestion.py`、`kafka_consumer.py`、`config.py`（旋钮已由主管写入）。

`config.py` 已落地的旋钮（只读使用，不要改名）：

- `ingest_http_queued_status` (202)
- `ingest_parallel_detect`
- `ingest_store_batch_size` / `ingest_store_batch_flush_ms`
- `ingest_fastpath_retries`
- `audit_p0_never_drop` / `audit_p1_never_drop`
- `kafka_topic_audit_overflow`

---

## 3. 验收标准

### P1 流水线

| ID | 标准 |
|---|---|
| P1-A | `detect()` 中 anomaly 抛异常 → 返回 `empty_anomaly(reasons=["anomaly_error"])` + `DetectorError`，**不**阻止 sigma 与后续 persist |
| P1-B | sigma 抛异常 → `empty_sigma()` + error，不阻止 anomaly 结果与 persist |
| P1-C | `ingest_parallel_detect=True` 时 anomaly 与 sigma 经 `asyncio.gather`；False 时保持先 anomaly 后 sigma（顺序可测） |
| P1-D | Sigma 命中抬分规则与当前 `log_ingestion.ingest` 完全一致（critical 0.75 / high 0.65 / medium 0.55 / low 0.45，`is_anomaly=True`，reasons 含 `Sigma命中:`） |
| P1-E | `store_batch(n)` 一次 `commit`；同一 `eventId` 重复 → 只一行（与 `store()` 幂等一致） |
| P1-F | `store_batch` 遇 `IntegrityError` 回退逐条 `store()`，不丢已成功行 |
| P1-G | `LogIngestor.ingest` 对外返回字段仍含 `status/event_id/event_type/severity/anomaly/sigma`，旧调用方不断 |
| P1-H | FastPath 仍 `create_task`，ingest/run_many **不等待** SSH；失败按 `ingest_fastpath_retries` 重试后打日志 |
| P1-I | `_deliver_batch` 用 `asyncio.gather(*futures, return_exceptions=True)` 计成功数，禁止 for+await 串行 |
| P1-J | python-ingest 一批消息走 `run_many`；任一条 persist 失败 → 整批不 commit（现有语义） |
| P1-K | 现有 `tests/test_arch_unification.py`、`tests/test_log_normalize_http.py`、`tests/test_audit_worker.py` 全绿 |

### P2 网关与审计

| ID | 标准 |
|---|---|
| P2-A | Kafka producer active 时 `POST /api/logs/ingest` 与 `/batch` 返回 **HTTP 202**，body `status=queued`，`produced` 为成功条数 |
| P2-B | 该路径 **不** 进入 `log_ingestor.ingest`，**不** checkout OLTP session（dependency yield None） |
| P2-C | `/batch` 读取 `X-API-Key` 并写入 enqueue wrapper 的 `source_key`（与单条一致） |
| P2-D | Kafka 关闭时行为与现在一致：同步 ingest，HTTP 200，`status=review_queued` |
| P2-E | 审计队列满 + `audit_p0_never_drop`：P0 返回 `deferred`（或 `shed` 若已进 Redis PQ），**永不** `overflow` |
| P2-F | P1 同样 never-drop（`audit_p1_never_drop=True`） |
| P2-G | Redis PQ 失败 → produce `settings.kafka_topic_audit_overflow`；Kafka 也失败 → 进程内 `_p0_overflow` deque，仍不 `overflow` |
| P2-H | P2/P3 队列满仍 `overflow`（`test_queue_overflow_p3` 保持） |
| P2-I | overflow/shed/deferred 记 `soc_audit_shed_total{tier,reason}`；reason ∈ `memory_full,pq_ok,pq_fail,kafka_overflow,local_deque` |
| P2-J | 指标：`soc_ingest_stage_seconds{stage}`（detect/persist/dispatch）、`soc_ingest_detector_errors_total{detector}` |

### 明确不做（验收反例）

| ID | 不要出现 |
|---|---|
| X-1 | 新增 Celery/Redis broker 依赖 |
| X-2 | 改 `python_process_ingest_queue` 默认值 |
| X-3 | 把 FastPath 改回 await 阻塞 consumer |
| X-4 | 高优先级事件在 submit() 返回 `overflow` |
| X-5 | 修改 Self-Play / RAG / 前端 |

---

## 4. 实现要点（给执行者，不要发明第二种语义）

### 4.1 `event_store.store_batch`

```
async def store_batch(self, session, rows: list[tuple[dict, str, float, str]]) -> list[StoredEvent]:
    # rows: (event_data, session_id, anomaly_score, correlation_id)
```

- 先把带 `eventId` 的收集起来，一次 `SELECT WHERE event_id IN (...)` 找出已存在行。
- 只 insert 新行，**一次 commit**。
- 返回与输入等长的 `StoredEvent` 列表（已存在的用旧行，idempotent=True 由 pipeline 标记）。
- `inc_insert` 按真正 insert 条数调用（或循环 n 次，保持计数器语义）。
- 热缓存对每条 `_cache_put`。
- 单测必须覆盖：空列表、全新、全重复、混合、无 eventId。

### 4.2 `log_ingestion.ingest` facade

保留：

- `_normalize_fields`
- 数字 severity → 枚举
- 返回 dict 的 key 集合

删除（移到 pipeline，禁止两份 FastPath 逻辑）：

- 直接调 `anomaly_detector.analyze` / `sigma_detector.detect_for_event`
- 直接 `event_store.store`
- FastPath 大段 / `audit_worker.submit`

`ingest_batch`：sqlite 或 len<=1 仍串行 `ingest`（测试语义）；否则 `run_many`。

### 4.3 审计 never-drop 链（伪代码）

```
if queue_depth >= queue_max:
    if tier in (P0, P1) and corresponding never_drop flag:
        if await _enqueue_pq(...): return "shed"          # 已持久化 Redis
        if await _enqueue_kafka_overflow(...): return "deferred"
        self._p0_overflow.append(job)                     # 内存最后兜底
        return "deferred"
    return "overflow"   # P2/P3 only
```

worker loop 在内存 queue 空时，从 `_p0_overflow` 取（P0 优先于普通队列也可，但不要饿死 P2：每处理 3 个 overflow 抽 1 个普通；若实现复杂，FIFO 处理 overflow 即可，测试只要求不丢）。

`_enqueue_kafka_overflow` 用已有 `kafka_producer`；producer 未启动视为失败，走 deque。

### 4.4 HTTP 网关

```
async def _session_unless_queued():
    if _ingest_producer_active():
        yield None
        return
    async for s in get_session():
        yield s
```

202 用 `JSONResponse(status_code=settings.ingest_http_queued_status, content=...)`。

batch 必须 `request: Request` 才能读 header。

---

## 5. 测试命令（执行者本地必须跑）

```
cd backend
python -m pytest tests/test_ingest_pipeline.py tests/test_event_store_batch.py tests/test_kafka_deliver_gather.py tests/test_http_ingest_gateway.py tests/test_audit_never_drop.py tests/test_audit_worker.py tests/test_arch_unification.py tests/test_log_normalize_http.py -q
```

Reasonix 只保证自己那三个新文件 + P1-K 旧测。OpenCode 只保证自己两个新文件 + `test_audit_worker.py`。

---

## 6. 后续阶段（本轮不实现，只登记）

- Phase 2：检测/落库/审计分 Kafka topic 真扇出（alerts vs audit-queue 由 Python produce，而不是 Flink）。
- Phase 3：LLM 批量 prompt、模型级联、独立审计进程水平扩展。
- Phase 4：热数据 Timescale/列存评估（需单独容量与查询语义评审）。
