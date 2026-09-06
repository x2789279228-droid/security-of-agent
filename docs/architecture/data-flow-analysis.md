# SOC 安全运营平台：数据流与框架剖析

> 路径：`D:/揭榜挂帅/shared-memory-platform`
> 范围：`backend/` 源码（`.tmp_*.py` 忽略）+ `docker-compose.yml` + `config.py`
> 方法：read-only 证据级逐文件阅读 + grep 交叉验证

---

## 0. 顶层概览

```
                   ┌──────────────────────────────────────────────────┐
                   │                 外部数据源                       │
                   │ syslog / api / simulator / EDR (sysmon/winevent) │
                   │ 流量探针 (libpcap) / Taxii / MISP / 沙箱          │
                   └────────┬────────────────────────┬────────────────┘
                            │ HTTP                   │ Kafka / Syslog
                            ▼                        ▼
              ┌───────────────────────┐    ┌──────────────────────────┐
              │ FastAPI /api/*        │    │ KafkaConsumerManager     │
              │  routers/logs.py      │    │  (7 个 topic,薄消费)     │
              │  ingest → log_        │    └────────────┬─────────────┘
              │  ingestor.ingest()    │                 │
              └───────────┬───────────┘                 │
                          │                             │
                          └──────────┬──────────────────┘
                                     ▼
                  ┌──────────────────────────────────────┐
                  │  log_ingestion.ingest()              │  ← 同步关键路径
                  │   ① anomaly_detector.analyze        │   (重)
                  │   ② sigma_detector.detect_for_event  │   (轻)
                  │   ③ event_store.store                │   (重:PG)
                  │   ④ _index_background asyncio.task   │   (轻:后台)
                  │   ⑤ FastPath: response_orchestrator  │   (重→轻)
                  │   ⑥ audit_worker.submit (有界)       │
                  └──────────┬──────────────┬────────────┘
                             │              │
                ┌────────────▼──┐    ┌──────▼─────────────┐
                │  AuditWorker  │    │  FastPath (直接)   │
                │   Pool (12)   │    │   强信号→封禁      │
                │   PriorityQueue│    │   弱信号→告警      │
                └────────┬──────┘    └──────┬─────────────┘
                         │ Temporal (可)    │
                         ▼ 或 async 降级   │
                  ┌──────────────────────────▼────────┐
                  │  4-Layer Audit-LLM Pipeline       │
                  │   Decomposer → ToolBuilder →     │
                  │   Executor(SubAuditor) → Reviewer│
                  └──────────┬───────────────────────┘
                             │ merged verdict
                             ▼
              ┌──────────────────────────────┐
              │  Response Orchestrator        │
              │   policy_engine.match         │
              │   security_guard.inspect (4子检)│
              │   approval_queue 或 auto_exec  │
              │   response_executor.execute    │
              │   rollback (Redis + 内存)     │
              └──────────┬───────────────────┘
                         ▼
                ┌──────────────────────┐
                │  SSH/Windows 防火墙   │   物理响应
                │  iptables / WAF ACL  │
                │  SIEM / Slack / Alert │
                └──────────────────────┘

        ┌────────────────────────────────────────────────────┐
        │         横切: EventBus(SSE) / PipelineTracer       │
        │         / Watchdog / HealthMonitor / Scheduler     │
        │         / LlmLimiter / SourceRegistry              │
        └────────────────────────────────────────────────────┘
```

核心事实：
- **3 个解耦边界**：HTTP 网关 ↔ Kafka ↔ Python 消费；Python ↔ Temporal Workflow；EventBus 本进程 ↔ Redis 桥。
- **2 套真理源**：PG（事件权威）、Redis（PQ/限频/失效广播/基线）。
- **2 个主键索引**：`SecurityEvent.event_id` 唯一（kafka_consumer 重放幂等）、`SecurityEvent.anomaly_score` B-tree（reaper 查 stuck）。

---

## 1. 入口层（外部→系统）

### 1.1 HTTP 网关

| 端点 | 文件:行 | payload | 行为 |
|------|---------|---------|------|
| `POST /api/logs/ingest` | `routers/logs.py:82-115` | `LogIngestRequest{message, session_id}` | `source_registry.authenticate(X-API-Key)` → Kafka produce OR 直接 `log_ingestor.ingest()` |
| `POST /api/logs/ingest/batch` | `routers/logs.py:117-137` | `LogBatchRequest{logs[]}` | 限 ≤1000；同上分支 |
| `POST /api/auth/login` | `routers/auth.py`（仅导入） | JWT 颁发 | 全局中间件白名单 |
| `POST /api/guard/call` | `routers/audit.py:191` | `ToolCallRequest` | 走 McpGuardServer 4 层（见 §5.4） |

**核心分支**：`routers/logs.py:109` 处的 `_ingest_producer_active()` 决定走 Kafka 模式（`kafka_topic_ingest_process`）还是直连 Python；生产默认 Kafka 模式（`SHARED_MEMORY_KAFKA_ENABLED=true`）。

**认证链**：
1. 全局中间件 `auth_middleware` (`app.py:403-431`) — 验证 JWT，过滤 `_PUBLIC_PATHS`
2. `source_registry.authenticate(api_key)` (`routers/logs.py:96-100`) — SHA256 哈希比对，DB 权威 + 内存热缓存（`source_registry.py:38-41`）
3. 速率限制中间件 `rate_limit_middleware` (`app.py:496-519`) — 按 `X-API-Key > Bearer > X-Forwarded-For > client_ip` 分桶（`_resolve_rate_limit_key` at `app.py:465-493`）

### 1.2 Kafka 消费（薄消费者）

`kafka_consumer.py` 启动 6+1 个并行 consumer 任务（`kafka_consumer.py:117-127`）：

| Topic（settings 默认） | Consumer 入口 | handler | 下游 | 幂等 |
|---|---|---|---|---|
| `security-events-ingest` (新网关) | `_consume_python_ingest` (l.396) | `_handle_python_ingest` → `log_ingestor.ingest` | ingest 全流程 | PG `event_id` 唯一 |
| `security-events-enriched` | `_consume_enriched` (l.477) | `_handle_enriched` | event_store.store + memory_tree + (告警)→audit_worker.submit | PG `event_id` 唯一 |
| `security-audit-queue` | `_consume_audit_queue` (l.486) | `_handle_audit_with_backpressure` → `_handle_audit` | event_store + audit_worker.submit | PG `event_id` 唯一 |
| `security-alerts` | `_consume_alerts` (l.495) | `_handle_alert` | response_orchestrator.on_threat_detected | event_bus.publish 幂等 |
| `security-behavior-alerts` | `_consume_behavior_alerts` (l.504) | `_handle_behavior_alert`（固定 `BEHAVIOR_ANOMALY`） | response_orchestrator | event_bus.publish 幂等 |
| `security-logs-rejected` | `_consume_rejected` (l.513) | `_handle_rejected` | 内存 ring log | 无（只统计） |
| `security-cep-partial` | `_consume_cep_partial` (l.522) | 仅 append 到 ring | UI 展示 | 无（最近 100） |

**通用解耦模式** (`kafka_consumer.py:259-332`)：
- 手动 offset 提交 (`enable_auto_commit=False`)
- Schema Registry 校验 → 失败直接 DLQ（`security-logs-dlq`，`kafka_consumer.py:49`）
- 3 次重试（`MAX_RETRY=3`，`kafka_consumer.py:50`），再失败→DLQ
- W3C traceparent 从 header 提取，贯穿 OTel root span
- 整批失败→不 commit → 重放（`_consume_python_ingest` `kafka_consumer.py:439-443`）

**背压**：
- `_audit_semaphore = asyncio.Semaphore(12)`（`kafka_consumer.py:75`，可由 env `KAFKA_AUDIT_STORE_CONCURRENCY` 覆盖）
- 仅限 audit-queue 的 store 并发；`max_poll_records=50`（`kafka_consumer.py:53`）
- `_consume_python_ingest` 还做了 8-worker 分片 + 批 commit（`kafka_consumer.py:402-446`）

**Python 权威检测开关**（`config.py:89-90`）：
- `python_process_ingest_queue=True`：HTTP 写入 `security-events-ingest`，Python 消费做权威检测（取代旧 Flink enriched/alerts 双路径）
- `kafka_flink_secondary_llm=False`（默认）：关闭 Flink 侧的二级 LLM 审计，避免双 LLM 成本

### 1.3 其它入口

| 入口 | 文件 | 启动条件 | 写入路径 |
|---|---|---|---|
| NDR 流量 | `traffic_capture/capture_engine.py` + `flow_aggregator.py` + `protocol_parser/dissector.py` | `settings.capture_enabled=True`（默认关） | `network_flows` 表 + pcap 文件 + `tls_session_collector` |
| EDR（Sysmon/WindowsEvent） | `edr_fusion/edr_adapter.py:198-240` | `settings.edr_enabled=True`（默认关） | Kafka topic `edr-sysmon` / `edr-winevent` |
| 威胁情报 | `threat_intel/ioc_matcher.py:62` | `settings.intel_enabled=True`（默认关） | `threat_iocs` 表 + 内存缓存 + CIDR/域名后缀 |
| 沙箱 | `zeroday_detect/sandbox_connector.py` | `settings.sandbox_enabled=True` | CAPE/Cuckoo API |
| Taxii/MISP | `threat_intel/stix_taxii.py` | 同 intel | IOC 库 |
| Flink → Python | `kafka_consumer.py` 多 topic | `kafka_enabled=True` | ingest pipeline |
| 自博弈注入 | `self_play/orchestrator.py` → `sim_env` | `self_play_enabled=True` + `self_play_inject=True` | 走 ingest 加 `_self_play` tag |

### 1.4 幂等机制

**主键幂等**：`SecurityEvent.event_id` String(64) UNIQUE INDEX（`models.py:86`），由 `event_store.store` 的 IntegrityError 兜底，**替换原 Redis 24h 去重**（`models.py:84-85` 注释、`event_store.py:203` 注释）。这意味着：
- 跨重放/双路径扇出同 `eventId` 只落库一次
- 无论 HTTP↔Kafka 双路、自博弈注入、Flink 重放都收敛到 PG

**FastPath 冷却**：`log_ingestor._fastpath_allow(key)`（`log_ingestion.py:69-80`），key = `src_ip|threat_type`，TTL=60s（`FASTPATH_COOLDOWN_S`），OrderedDict LRU 上限 5000。

---

## 2. 摄取 + 存储

### 2.1 `log_ingestor.ingest()` 完整流程（同步关键路径）

`log_ingestion.py:184-400`，按行号逐步：

| 步骤 | 行号 | 同步/异步 | 重/轻 | 写入目标 |
|---|---|---|---|---|
| `_normalize_fields` | 188 | sync | 轻 | 字段重命名+threat_type 推断 |
| `anomaly_detector.analyze` | 198-199 | **sync** | **重**（含 7d 滑窗） | 内存基线 + Redis 持久化（60s 节流） |
| `sigma_detector.detect_for_event` | 209-237 | sync | 轻（11 条规则、聚合窗口） | 抬升 anomaly_score 门槛 |
| `event_store.store` | 240-243 | **sync** | **重**（PG INSERT） | `security_events` 表 |
| `_index_background` | 248-250 | **async**（create_task） | 轻 | `memory_tree_nodes` + sliding_window |
| FastPath 冷却去重 | 264-268 | sync | 轻 | 仅 LRU |
| FastPath 触发 → `_fast_response` | 348 | **async** | 重（SSH/iptables） | 实际封禁 |
| `audit_worker.submit` | 360 | sync | 轻（仅入堆） | `audit_workers` PriorityQueue |
| `event_bus.publish("security_event")` | 378-387 | sync | 轻 | SSE + Redis bridge |

**异常检测维度**（`anomaly_detector.py:283-391`）：
- 统计偏离度（`src_ip` 当前小时 vs 其他 23h 均值，泊松近似 σ）权重 0.35
- 事件类型罕见度（全局类型分布的反比）权重 0.20
- 时序异常（凌晨 0-5h 0.4 / 22-23h 0.2）权重 0.15
- 严重度（critical=1.0, high=0.6, medium=0.3, low=0, info=-0.05）权重 0.25
- `is_anomaly = score > 0.6 or max_sigma > 3`

### 2.2 持久化层

| 组件 | 写入者 | 读者 | 容量/TTL |
|---|---|---|---|
| **PostgreSQL** | `event_store`, `memory_tree`, `audit_worker`, `response_engine`, `mcp_guard.call_logger`（异步 flush）, `self_play.store`, `rag.knowledge_base` | 全部业务 | 由 PG 决定（2 个 engine：OLTP 24+8、BG 8+4）`models.py:31-48` |
| **Redis** | `anomaly_detector`（基线 7d）、`audit_pq`（ZSET+payload）、`event_bus`（pub/sub）、`event_store`（invalidate 通道）、`event_bus._redis_seen` 去重、`rollback_store`（7d TTL）、`temporal.client._inflight` 计数 | `anomaly_detector.load_baselines_from_redis`, `audit_pq.pop_highest`, `event_bus.start_redis_bridge`, `rollback_store.get`, `temporal._inflight_try_acquire` | 见各模块 |
| **Qdrant** | `qdrant_store`（KB chunks）、`vector_store`（agent_memories collection） | `rag.retriever` 混合检索、`vector_store` 记忆检索 | 768 维（`embedding_dim` 默认） |
| **内存 LRU** | `log_ingestor._audit_status_cache` (10k)、`_fastpath_cooldown` (5k)、`event_store._hot_cache` (2k)、`event_bus._history` (500)、`sigma_detector._agg_windows`、`security_guard.rate_limiter` | 各对应模块 | 见左侧 |
| **冷热分层** | `event_store` 计划 parquet→S3（`event_store.py:78-87`），目前仅 `event_archive` 目录 | 未启用温/冷归档的写代码 | 设计存在，落地未完成 |

### 2.3 DB 双池

`models.py:31-48`：
- `engine_oltp`（24+8，超时 5s）— ingest/API/audit 短租 SQL
- `engine_bg`（8+4，超时 10s）— 索引/调度/embedding 回填
- 注释：避免 memory_tree 把 ingest 饿死

### 2.4 写时幂等的精妙处

`event_store.store`（`event_store.py`）依靠 PG 唯一索引捕获 `IntegrityError`，**不做去重预检**。代价：极少数重放事件会浪费一次 INSERT，收益：无状态、可水平扩展。这是关键的"重 vs 轻"权衡——把复杂度从 Redis 转移到 PG。

---

## 3. 检测 + 审计（核心）

### 3.1 审计分流（Triage）

`audit_triage.py` 是审计 LLM 通道分层的核心，**5 个车道**：

| 车道 | 含义 | 何时进入 | 补审轮次 | 单次超时 |
|---|---|---|---|---|
| `llm_deep` | 完整 4 层 + Reviewer | `score.critical` + 非 LLM 信号；fused≥0.85；`sigma_critical` | ≤2 | P0=90s |
| `llm_standard` | SubAuditor + synthesize | `severity in (critical,high)` 或 sigma hit | ≤1 | P1=45s |
| `llm_light` | 轻量 + 限 hop | 默认 P2 | ≤1 | P2=20s |
| `tools_only` | 仅工具/规则收口 | `soft_budget` 时 `light→tools_only`；`hard_budget` 时 P1 | 1 | — |
| `rule_close` | 强降级收口 | `hard_budget` 时 P2/P3 | 1 | P3=10s |

**打分逻辑**（`audit_triage.py:82-209`）综合：
- `severity`（critical +35 / high +25 / medium +12）
- `sigma hit`（critical +40 / 否则 +20）
- `anomaly_score`（≥0.7 +25 / ≥0.5 +15 / ≥0.3 +8）
- `non_llm_signal.has_signal`（+15）
- `event_type ∈ HIGH_RISK_EVENT_TYPES`（+10）
- `fused_confidence`（≥0.85 +15 / ≥0.7 +8）
- 资产关键性（critical/high +12）
- `fastpath_strong` 标记 → 强制降为 `llm_light`（除非 `sigma_critical or fused≥0.9`）

**`admit()` 闸门**（`audit_triage.py:221-294`）：
- normal + inflight 不满 → 原车道
- soft（70% budget）→ `llm_light` 降为 `tools_only`；P3 降为 `rule_close`
- **hard（95% budget）→ P0 仍走 `llm_deep` 但跳过 `_llm_pre_analyze`**（最小 LLM hop）
- over_budget + P1 → `tools_only`；P2/P3 → `rule_close`

### 3.2 有界审计 Worker

`audit_worker.py:17-208`：

```
┌──────────────────┐  PriorityQueue<(-priority, seq, job)>
│ AuditWorkerPool  │  queue_max=2000
│  workers=12      │  满载策略:
│  (asyncio.Task × 12)  P0/P1 → Redis ZSET(soc:audit:pq)
└────────┬─────────┘  P2/P3 → "overflow" → fallback
         │                (log_ingestor 收到 "overflow" → _fallback_analysis
         ▼                 + _mark_analyzed quality="shed")
   ┌────────────────────┐
   │  _run_job          │
   │  - 取出 job        │
   │  - busy++          │
   │  - asyncio.create_task(
   │      log_ingestor._audit_pipeline)
   │  - busy-- (finally)│
   └────────────────────┘
```

- `submit()` 返回 `"queued" | "shed" | "overflow" | "direct"`（`audit_worker.py:94-144`）
- `cancel(event_id)` 供 stuck reaper 回收槽
- `_publish_gauges()` 推 `set_audit_runtime(inflight, queue_depth, workers)` 到 Prometheus

### 3.3 4 层 Agent 编排（核心审计）

`log_ingestion.py:795-1049`：

```
   ┌──────────────────────────────────────────────────────────┐
   │   _audit_pipeline (tier-aware wrapper, l.467-644)        │
   │     ├─ _auto_create_case_bg (后台, l.482)                │
   │     ├─ score_event + admit → TriageResult               │
   │     ├─ needs_llm? → false: _fallback_analysis           │
   │     └─ needs_llm? → true:                                 │
   │         ├─ Temporal 优先 (start_audit_workflow)          │
   │         │   ├─ "shed" → PQ (P0/P1) or fallback           │
   │         │   └─ False   → _fallback_routed=True           │
   │         └─ async 兜底 (asyncio.wait_for timeout)         │
   │                                                            │
   │   _audit_pipeline_inner (l.795-1049)                     │
   │     for round in 1..max_rounds:                          │
   │       mode = "full" (r=1) | "supplement" (r>1)          │
   │       ┌────────────────────────────────────────────┐     │
   │       │ L1 Decomposer (decomposer.decompose)       │     │
   │       │   - 规则路径/无 LLM: 快速深度决策           │     │
   │       │   - LLM 路径: plan + sub_tasks              │     │
   │       │   输出: sub_tasks[], audit_depth, missed[]  │     │
   │       └────────────────────────────────────────────┘     │
   │       ┌────────────────────────────────────────────┐     │
   │       │ L2 Tool Builder (tool_builder.build)        │     │
   │       │   sub_tasks → tool_calls[]                 │     │
   │       └────────────────────────────────────────────┘     │
   │       ┌────────────────────────────────────────────┐     │
   │       │ L3 Executor (executor.execute)             │     │
   │       │   1) 并行 data tools                       │     │
   │       │   2) chunker.chunk()                       │     │
   │       │   3) skip_llm? _deterministic_from_non_llm │     │
   │       │   4) SubAuditor 并行每块                   │     │
   │       │   5) synthesize LLM                        │     │
   │       │   输出: AuditResult                        │     │
   │       └────────────────────────────────────────────┘     │
   │       ┌────────────────────────────────────────────┐     │
   │       │ L4 Reviewer (reviewer.review)              │     │
   │       │   - depth=="deep" → LLM review             │     │
   │       │   - 否则 → executor_conclusion_floor       │     │
   │       │   - clamp_reviewer_conclusion              │     │
   │       │   - filter_missed_threats                  │     │
   │       │   输出: FinalVerdict                        │     │
   │       └────────────────────────────────────────────┘     │
   │     - _merge_rounds (禁止 OR 合并,confirmed 需非 LLM)  │
   │     - apply_faithfulness_gate                           │
   │     - _persist_audit_result (l.1051-1268)               │
   │        ├─ 写 _audit_llm 到 SecurityEvent.raw_data       │
   │        ├─ cad_agent.audit_pipeline (CAD 验证)           │
   │        └─ merged.threat_detected AND verdict∈           │
   │           (confirmed,suspicious) AND conf≥0.4          │
   │           AND NOT response_blocked:                     │
   │           → asyncio.create_task(_audit_response)        │
   │            (response_orchestrator.on_threat_detected)   │
   └──────────────────────────────────────────────────────────┘
```

**关键 LLM 通道约束**：
- 任何 `llm_*` 路径都过 `llm_limiter`（`llm_limiter.py:24-122`），`acquire(tier=...)` 异步上下文，全平台 `llm_global_concurrency=8`、P0 reserve=2
- `acquire` 超时（`llm_slot_timeout_s=30`）抛 `LlmSlotTimeout` → 上层降级

**Temporal vs async 边界**：
- `temporal_enabled=True`（`docker-compose.yml:360`）→ `start_audit_workflow` 启动 `AuditPipelineWorkflow`（`workflows.py:29-152`）
- Workflow 内逐 round `audit_round` activity（300s 超时）→ 收尾 `save_result` (120s) → `trigger_response` (120s) → `cad_verify` (180s)
- 单 workflow execution timeout = 900s（`temporal_workflow_execution_timeout_s`）
- Temporal 失败/不可用 → `_fallback_routed=True` → async pipeline 走独立 fallback Semaphore
- P0/P1 优先占用 Temporal `audit_inflight_max=12` 名额（`temporal/client.py:42-76`），P0 享专用预留槽

### 3.4 CAD 监督 + 熔断器

- `agents/agent_cad.py`（独立类）
- `cad.py:358-460`：`CircuitBreaker` 状态机（CLOSED→OPEN→HALF_OPEN）
- `record_audit_result(hallucination_risk, evidence_completeness, anomaly_detected)` 滑动窗口（最近 100 条，异常率 = last 20 中 risk>0.3 占比）
- `_check_trip()` 触发熔断 → CAD 写 `_cad_audit.circuit_breaker.tripped=True`
- `record_na()`：无可验断言不计入趋势，避免误熔断（`cad.py:403-409`）

### 3.5 Sigma 规则引擎

`sigma_detector.py`：
- 11 条内置规则（SIG-001 → SIG-011），`sigma_detector.py:107-280`
- 字段映射 + URL/event 包含匹配；OR/AND 模式（v5 修复 SIG-007 SSH 误报，`sigma_detector.py:215`）
- 聚合窗口：count 5m/3m（`aggregation` 字段），内存 deque
- 惰性清理：`CLEANUP_INTERVAL_SEC=300`（`sigma_detector.py:100`）
- `cleanup_windows()` 显式清扫（`sigma_detector.py:425-451`）
- `detect_for_event(event)` 集成点（`log_ingestion.py:210`），命中时抬升 anomaly_score（`log_ingestion.py:218-234`）

### 3.6 记忆树 + 滑动窗口

- `memory_tree.add_leaf`（在 `_index_background` 后台任务中执行，`log_ingestion.py:90-98`）— 不做内容压缩
- `sliding_window.add_message`（同 l.99-102）— 短上下文（默认 15min / 500 条）

---

## 4. 响应 + 护栏

### 4.1 响应编排器

`response_engine/response_orchestrator.py:197-499`：

```
   threat_info
       │
       ▼
   normalize_threat_info_for_guard (l.59-66)
       │
       ▼
   _classify_from_name (自然语言 → leaf/category) (l.78-85)
       │
       ▼
   policy_engine.match (response_policies.py)
       │  返回 action_map {matched, match_status, actions, needs_approval, auto_execute}
       │
       ├── SKIPPED/NO_ACTION/FILTERED → 写 log, return (不执行)
       │
       ├── allow_blocking=False (双轨门槛):
       │     action_map.actions 过滤掉非 send_alert
       │     is_uncertain → needs_approval=True
       │
       ├── needs_approval=True AND auto_execute=True AND 无 CRITICAL 动作:
       │     _guarded_execute (先自动执行) → approval_queue.submit
       │     is_uncertain AND 未封成功 → 仍 PENDING (l.421-424)
       │     否则 AUTO_EXECUTED (事后审查)
       │
       ├── needs_approval=True ELSE:
       │     approval_queue.submit
       │     asyncio.create_task(_poll_approval) (5s 轮询)
       │
       └── auto_execute=True:
             _guarded_execute
```

**`_guarded_execute`**（l.137-195）4 子检：
```
   SecurityGuard.inspect(action, threat_info)
       ├── intent_checker.check    (意图审查)
       ├── sequence_guard.check    (调用序列管控)
       ├── rate_limiter.check      (频率控制 — check-then-act 占坑)
       └── context_manager.check   (上下文感知)
       任一失败 → 跳过该动作 + 写 telemetry
   response_executor.execute_actions (顺序/并行)
   SecurityGuard.record (按执行结果确认/释放预留)
```

**关键：`rate_limiter` 防 check-then-act 竞态**（`security_guard/rate_limiter.py:79-95`）——`check()` 通过时立即 `append(now)` 占坑，`record(success=False)` 调用 `release()` 弹回时间戳。注释明确"单实例进程；多实例需改 Redis INCR"（`rate_limiter.py:84`）。

### 4.2 频率限制（生产配置）

`security_guard/rate_limiter.py:17-27`：
- `block_ip`：10/min
- `isolate_host`：5/min
- `alert_only`：50/min
- **GLOBAL**：30/min

### 4.3 策略匹配引擎

`response_engine/response_policies.py`：
- YAML 加载 + 热重载
- 4 段匹配优先级：精确 threat_type → category → ANY（fallback）→ uncertain_template
- `MatchStatus` 枚举（l.37-45）：`MATCHED | MATCHED_CATEGORY | MATCHED_BEHAVIOR | UNCERTAIN | SKIPPED | FILTERED | NO_ACTION`
- `mark_executed(policy_name, src_ip)` 实现 cooldown（l.76, 80% 同源不同策略独立计时）

### 4.4 动作注册表

`response_engine/response_registry.py:646-714`：
| 动作 | 严重度 | 类别 | 可回滚 |
|---|---|---|---|
| `block_ip` | high | network | ✓ |
| `isolate_host` | critical | host | ✓ |
| `rate_limit` | medium | network | ✓ |
| `kill_session` | high | session | ✗ |
| `send_alert` | low | notification | ✗ |

执行传输：SSH 到 Windows 宿主机（`transport.ssh_transport`，docker-compose 通过 `RESPONSE_SSH_HOST=host.docker.internal` 注入）执行 PowerShell/iptables 命令；失败回退 stub 模式。

### 4.5 SSH 防火墙适配器

`response_engine/ssh_firewall.py`（独立类）：
- 连接 `settings.fw_ssh_host`（默认 `soc-firewall` 容器）
- `iptables` 规则管理：`block_ip` / `unblock_ip` / `list_rules` / `rollback_all`
- 仅在 `settings.fw_ssh_host` 非空时启用（`app.py:180-189`）

### 4.6 审批队列

`response_engine/human_approval.py:76-160`：
- `ApprovalTicket` 内存字典存储（重启丢失）
- 状态：`PENDING → APPROVED/REJECTED/EXPIRED/AUTO_APPROVED/AUTO_EXECUTED`
- `priority`: p0/p1/p2/p3
- `Orchestrator._poll_approval(ticket_id, threat_info)` 每 5s 轮询 → 批结果后 `_guarded_execute`

### 4.7 FastPath 双轨门槛

`log_ingestion.py:268-353`（FastPath 触发条件）：

| 触发 | `_strong_signal` | `allow_blocking` | 含义 |
|---|---|---|---|
| `severity=critical` 但无检测器佐证 | false | **False** | 仅告警 + 双轨过滤 |
| Sigma critical 命中 或 fused≥0.7 | true | True | 可封禁 |

**关键修复**（v5 A）：`log_ingestion.py:294-302` —— 此前 `severity=critical` 直接触发完整响应，152/152 事件绕过审计和 veto 门控（ANY 兜底封禁假事件）。

### 4.8 MCP Guard 4 层（Agent 工具调用）

`mcp_guard/guard_server.py:101-171`：

```
   Agent → ToolCallRequest
            │
            ▼
       ┌─────────────────────────────┐
       │  L1 registry.get_tool       │  未注册 → "deny 幻觉工具"
       ├─────────────────────────────┤
       │  L2 permission.check (RBAC) │  失败 → "deny"
       ├─────────────────────────────┤
       │  L3 validator.validate      │  Pydantic 强类型，失败 → "deny"
       ├─────────────────────────────┤
       │  L4 policy.evaluate         │  allow / require_confirmation / deny
       ├─────────────────────────────┤
       │  L4.5 behavior_detector     │  shadow/confirm/deny/enforce
       │     observe_pre_exec        │  (可升级 decision,只升不降)
       ├─────────────────────────────┤
       │  执行 / 拒绝 / 入审批工单   │
       │  observe_post_exec          │
       │  call_logger.log (PG flush) │
       └─────────────────────────────┘
```

- `_DECISION_RANK = {allow:0, require_confirmation:1, deny:2}`（`guard_server.py:35`）
- `_apply_enforcement` 只升不降（l.240-255）
- `mode` 由 `settings.tool_signature_mode`（confirm/enforce/deny/shadow）控制
- `approvals = ApprovalQueue()`（`guard_server.py:89`）—— 与响应引擎的 ApprovalQueue 独立（不同工单体系）

---

## 5. 框架横切

### 5.1 事件总线

`event_bus.py`：
- 进程内 `asyncio.Queue[maxsize=500]` per subscriber（`event_bus.py:194`）
- `subscribe()` 满员返回 None → SSE 端点 503 + Retry-After（`event_bus.py:188-193`），避免踢出既有连接变僵尸流
- `publish()` 满队列 → drop oldest（l.97-103）
- 跨进程：`set_redis()` + `start_redis_bridge()`（l.83-99, 138-178）→ 通过 Redis `soc:event_bus` 频道广播
- `_redis_seen` LRU 去重（4096, 60s TTL）防回环
- 事件类型：`security_event | audit_complete | response_action | alert | pipeline_health | audit_degraded | tool_signature_degraded`
- `event_bus._history` 500 条断线续传缓冲

### 5.2 配置分组（`config.py` 全部 320+ 行）

| 分组 | 关键字段 | 默认 |
|---|---|---|
| **DB/Redis** | `database_url`, `redis_url` | localhost |
| **LLM** | `llm_api_key/base_url/model`, `llm_reasoning_effort=none` | — |
| **Embedding** | `embedding_dim=768` | 768 |
| **存储** | `sliding_window_size=500/minutes=15`, `embedding_cache_ttl=3600`, `llm_cache_ttl=86400` | Redis 24h LLM 缓存跨进程 |
| **Qdrant** | `qdrant_url`, `qdrant_collection=soc_knowledge_chunks`, `qdrant_memories_collection=agent_memories`, `qdrant_vector_size=0→embedding_dim` | True |
| **RAG 混合** | `rag_hybrid_enabled=True`, `rag_rrf_k=60`, `rag_prefetch=20`, `rag_rerank_enabled=True` | dense+BM25+RRF+CE |
| **Kafka 主题** | 11 个 topic（raw/validated/rejected/enriched/alerts/audit_queue/audit_results/cep_*/sigma_hit/behavior_alerts/ingest_process） | 全部可改 |
| **Temporal** | `temporal_enabled`, `audit_inflight_max=12`, `audit_p0_reserve_pct=0.25`, `temporal_workflow_execution_timeout_s=900` | 12 inflight, 25% P0 预留 |
| **审计调度** | `audit_workers=12`, `audit_queue_max=2000`, 4 档 timeout (P0=90s/P1=45s/P2=20s/P3=10s), `audit_max_rounds_deep=2/standard=1` | 严格分档 |
| **DB 双池** | OLTP 24+8/5s, BG 8+4/10s | 隔离前后台 |
| **LLM 限流** | `llm_global_concurrency=8`, `llm_p0_reserve=2`, `llm_slot_timeout_s=30` | P0 永不被关死 |
| **EventBus** | `event_bus_max_subscribers=256`, `event_bus_queue_max=500` | SSE 上限 |
| **Sigma** | `sigma_engine="pySigma"` | 真 Sigma + SQLite |
| **MCP Guard** | `mcp_guard_enabled=True`, `security_guard_enabled=True` | 双开 |
| **Tool 行为签名** | `tool_signature_mode=confirm`, `min_samples=30`, 3 档阈值 (warn 0.6 / confirm 0.8 / deny 0.95), 权重 param:0.35,seq:0.25,time:0.15,caller:0.25 | UEBA-for-AI |
| **案例/工单** | `case_auto_order_priorities=high,critical`, `case_auto_close_hours=24`, `case_auto_resolve_idle_minutes=10` | 自动派单 |
| **LLM 增强器** | 7 模块开关 + 7 模块日预算 (钓鱼 75¥/天, 其余 3-5¥/天) | 默认全关 |
| **Self-Play** | `self_play_enabled=True`, `self_play_inject=False`, `self_play_use_llm=False`, `self_play_max_inflight=1` | 离线教学 |
| **因果链** | `causal_enabled=True`, `causal_learn_interval_s=900`, `causal_lookback_hours=48` | 批式 PC/GES |
| **LLM 成本** | `llm_daily_budget_tokens=0`(=无上限), `llm_budget_unlimited=True` | 永不降级审计 |

### 5.3 监控/可观测性

| 组件 | 文件 | 输出 | 启动 |
|---|---|---|---|
| `pipeline_tracer` | `observability/pipeline_tracer.py` | OTel + 内存 500 环形 + PG 落库 | `app.py:309-311` 启动 `enable_persist()` |
| `thought_events` | `observability/thought_events.py` | SSE + 事件总线 | 与 audit pipeline 集成（`log_ingestion.py:831-841`） |
| `watchdog` | `observability/watchdog.py` | LLM 根因分析 + diagnostic_reports 表 + EventBus | 冷却 120s |
| `health_monitor` | `observability/health_monitor.py` | 规则触发 watchdog.diagnose | `app.py:307-310` |
| `metrics.py` | `metrics.py`（Prometheus `/metrics`） | 25+ inc/set counter | `app.py:572-575` |
| `kpi_calculator` | `ops_metrics/kpi_calculator.py` | KPI 日快照 | scheduler 每日 02:05 |
| `sla_tracker` | `ops_metrics/sla_tracker.py` | SLA 违约 | scheduler 5min 巡检 |
| `stage_events` | `observability/stage_events.py` | 阶段事件 | audit pipeline |

### 5.4 Self-Play 红蓝对抗

`self_play/orchestrator.py`：
- 状态机：`_LIVE: dict[match_id, state]`, `_LOCK=asyncio.Lock()`, `_RUNNING=0`（l.22-25）
- `_new_match_id() = "sp-{uuid12}"`
- Round 流程：RedAgent（攻击）→ SimEnv 物化 → BlueObserver（观察）→ score_round → BlueLearner 更新 → 可能进 RAG/Overlay
- `outcome`：attacks=0 → decoy_only；fn>0 且 tp=0 → red_win；fn=0 且 tp>0 → blue_win；否则 mixed
- `winner`：recall≥0.7 且 asr≤0.35 → blue；asr≥0.5 → red；其它 draw
- `self_play_max_inflight=1`（`config.py:292`）—— 同时仅 1 场
- `reviewer.py` + `seed_global_overlay()`：每 24h 影子规则→提升（`config.py:299-301`）
- `overlay.py` 全局影子规则 seed（`app.py:194-199`）

### 5.5 RAG 检索

`rag/retriever.py` + `knowledge_base.py`：
- 三步：`query_transform`（rewrite/HyDE）→ `_hybrid_search`（dense+BM25+RRF）→ 可选 `rerank`（cross-encoder via Infinity）
- `chunker.py`：知识文档切片
- `evidence_verifier.py` + `grounding_verifier.py`：证据核验 + 引用检查
- `seeder.py` 启动时播种（`app.py:150-154`）+ 后台 embedding 回填
- `mitre_importer.py` + `capec_importer.py`：威胁知识导入
- `lexical.py`：BM25 内置（`rag_bm25_backend="builtin"`）或 fastembed

### 5.6 威胁情报 + MITRE + CAPEC

- `threat_intel/ioc_matcher.py`：内存精确/CIDR/域名后缀缓存，5min refresh（`config.py:238`）
- `threat_intel/stix_taxii.py`：TAXII 拉取（`taxii_url`）
- `threat_intel/intel_enricher.py`：上下文富化
- `rag/mitre_importer.py` + `rag/capec_importer.py`：通过 RAG 体系统一管理

### 5.7 调度器

`scheduler.py:37-90`：16 个后台任务：
| 间隔 | 任务 |
|---|---|
| 5min | baseline_snapshot、sla_check、case_sla、stuck_audit_reap、embed_backfill |
| 30min | long_chain_scan |
| 10min | watchdog_patrol |
| 1h | cad_context_audit、llm_budget_reset |
| 1h/24h | fp_analytics、kpi_daily、selfplay_review、audit_trail_flush、tool_call_log_flush、causal_learn、demo_traffic |
| 1s | audit_pq_drain（实时） |

### 5.8 时间预算 / Cost Tracker

- `summary_compression.cost_tracker`：LLM token 累计 + 跨重启恢复（`app.py:46-72`）
- `llm_daily_budget_tokens=0` + `llm_budget_unlimited=True`（`config.py:318-320`）—— 审计永不因预算降级
- `llm_limiter.acquire(tier, timeout)` —— LLM HTTP 实际并发上限
- 各模块 LLM 增强器日预算（`config.py:272-278`）—— 仅 enhancer 超限时该模块降级

---

## 6. 并发/限流模型

### 6.1 Semaphore / Pool / Queue 全景

| 位置 | 类型 | 默认 | 备注 |
|---|---|---|---|
| `audit_worker.py:19` | `asyncio.PriorityQueue` | 上限 2000 | 排序键 `-priority*1e12 - ts` |
| `audit_worker.py:21` | `dict[event_id, asyncio.Task]` | — | inflight 追踪 |
| `audit_worker.py:60` | `asyncio.Task` | 12 个 worker | 取代无界 create_task |
| `kafka_consumer.py:75` | `asyncio.Semaphore` | 12 (env `KAFKA_AUDIT_STORE_CONCURRENCY`) | audit-queue store 并发 |
| `llm_limiter.py:24` | `asyncio.Condition` + `_used/_p0_used/_waiters` | 8, P0 reserve 2 | 全平台 LLM HTTP |
| `log_ingestion.py:59` | `asyncio.Lock` | — | `_run_batch_analysis` 互斥 |
| `log_ingestion.py:1334` | `asyncio.Semaphore` | env `BATCH_INGEST_CONCURRENCY` | 批量 ingest |
| `event_bus.py:194` | `asyncio.Queue(maxsize=500)` | per subscriber | SSE 慢消费者保护 |
| `self_play/orchestrator.py:24` | `asyncio.Lock` | — | 状态机并发安全 |
| `qdrant_store.py:49` | `asyncio.Lock` | — | 客户端互斥 |
| `vector_store.py:37` | `asyncio.Lock` | — | pgvector 客户端 |
| `traffic_capture/pcap_store.py:69` | `asyncio.Lock` | — | 轮转互斥 |
| `traffic_capture/flow_aggregator.py:164` | `asyncio.Lock` | — | 流表互斥 |
| `temporal/client.py:135` | `asyncio.Lock` | — | 惰性连接 |
| `audit_pq.py` | Redis ZSET + 内存 dict | 跨进程 | `soc:audit:pq` |
| `routers/rag.py:370` | `asyncio.Semaphore` | 5 | KB 审批并发 |
| `security_guard/rate_limiter._global_calls` | list 滑窗 | 60s | check-then-act 占坑 |
| `event_bus._subscribers` | list of Queue | 256 上限 | 满员→503 |
| `models.py:31` | PG `QueuePool` | OLTP 24+8, BG 8+4 | 隔离前后台 |

### 6.2 shed 策略（满载降级）— 核心

```
   ingest
     │
     ▼
   audit_worker.submit
     │
     ├── queue_depth < 2000 → 入堆 ("queued")
     │
     └── queue_depth >= 2000:
           ├── tier ∈ {P0, P1}:
           │     _enqueue_pq → audit_pq.enqueue (Redis ZSET)
           │     成功 → "shed" (主路径等待 drain)
           │     失败 → "overflow" → fallback
           │
           └── tier ∈ {P2, P3}:
                 直接 "overflow" → 立即降级
                 ingest 收到 "overflow" → _fallback_analysis
                 + _mark_analyzed(quality="shed")
```

**Temporal 路径 shed 独立计数**：`temporal/client.py:42-76` 的 `_inflight_try_acquire` 用 Redis 计数 `_INFLIGHT_KEY=soc:audit:inflight` + P0 子键。`audit_inflight_max=12`（`config.py:114`），`_reserved_p0_slots(limit) = ceil(limit * 0.25)`。

### 6.3 backpressure 边界

1. **HTTP 网关**：`_rate_limit_store` 内存桶（`app.py:436-519`），按 (X-API-Key / XFF / client_ip) 分桶，每 5min 清理过期
2. **Kafka audit-queue**：`_audit_semaphore` (12) + `max_poll_records=50`
3. **LLM HTTP**：`llm_limiter` (8, P0 reserve 2) + `acquire timeout=30s`
4. **Audit worker**：`PriorityQueue` 上限 2000 + PQ 兜底
5. **SSE 订阅**：`event_bus` 满员拒绝新连接，慢消费者 drop oldest
6. **PG 连接池**：OLTP 5s timeout，BG 10s timeout —— 超时直接报错，不排队

### 6.4 fastpath

- 入口：`log_ingestion.py:268-353`
- 冷却去重：`_fastpath_allow(key)` LRU 60s
- 强信号（Sigma critical / fused≥0.7）→ `allow_blocking=True` 可封禁
- 弱信号（仅 severity=critical）→ `allow_blocking=False` 仅告警
- 双轨门槛过滤：封禁类动作（block_ip/isolate_host/rate_limit）被剔除，仅 `send_alert` 可执行
- 独立 session 后台执行（`log_ingestion.py:336-348`）：不与请求 session 冲突

### 6.5 temporal in-flight 限制

- `audit_inflight_max=12`（`config.py:114`）
- `_INFLIGHT_KEY` / `_INFLIGHT_P0_KEY` Redis 计数（`temporal/client.py:22-23`）
- P0 预留：`ceil(12*0.25) = 3` 槽
- 非 P0 最多占用 `12-3=9` 槽
- 满载 → `start_audit_workflow` 返回 `"shed"`（`temporal/client.py:172-177`）→ 调用方决定入 PQ / fallback
- workflow execution timeout=900s（`temporal_workflow_execution_timeout_s=900`）

### 6.6 PQ 入队/出队

`audit_pq.py`：
- `enqueue`：Redis pipeline `SET payload:ZSET:KEY + ZADD soc:audit:pq score + EXPIRE`
- `score = -priority * 1e12 - ts`（负分优先 = ZPOPMIN 拿最高优）
- `pop_highest`：ZPOPMIN + GET payload + DEL payload
- `purge_stale(max_age_s=900)`：扫 ZSET 头 200，删 payload 已过期的幽灵成员
- 分档 TTL：`pq_ttl_for_tier` P0=3600s / P1=1800s / P2=300s / P3=900s（默认）
- `audit_pq_drain_loop` 在 scheduler 中每 1s（`config.py:130`）拉取并重入 audit_worker

---

## 7. 关键边界条件与降级路径

### 7.1 ingest 入口降级

```
   HTTP /api/logs/ingest
     │
     ├── X-API-Key 校验失败 → 403 (routers/logs.py:99-100)
     │
     ├── kafka_enabled=True AND producer active:
     │     produce_raw_batch(topic=ingest_process) → "queued"
     │     (不调 Python ingest)
     │
     └── 否则:
           log_ingestor.ingest()
             │
             ├── anomaly_detector.analyze 失败 → AnomalyReport(score=0, ...)
             ├── sigma_detector.detect_for_event 失败 → log_data["_sigma"]={"detected":False}
             ├── event_store.store 失败 → 抛错,event_id=None (主路径上)
             │
             ├── FastPath:
             │     ├─ 强信号: _fast_response (asyncio.create_task)
             │     └─ 弱信号: 仅告警 (allow_blocking=False)
             │
             └── audit_worker.submit:
                   ├─ "queued"  → 等 worker 拉
                   ├─ "shed"    → PQ (P0/P1) 或 fallback (P2/P3)
                   └─ "overflow"→ _fallback_analysis(quality="shed")
```

### 7.2 审计流水线降级

```
   _audit_pipeline
     │
     ├─ triage.admit → needs_llm=False (tools_only/rule_close)
     │     └─ _fallback_analysis (统计+Sigma 收口, 不调 LLM)
     │
     ├─ Temporal start:
     │     ├─ "shed" → 入 PQ (P0/P1) 或 triage close (P2/P3)
     │     ├─ True   → 4 层活动全部走 Temporal activity (后台 worker)
     │     └─ False  → _fallback_routed=True → 走 async + 独立 fallback Semaphore
     │
     └─ asyncio.wait_for timeout (按 tier: P0=90s/P1=45s/P2=20s/P3=10s):
           ├─ TimeoutError → _mark_analyzed(quality="fallback", error="pipeline_timeout")
           └─ Exception    → _mark_analyzed(quality="fallback", error=str(e))
                              + _fallback_analysis
```

### 7.3 LLM 通道降级

```
   llm_limiter.acquire(tier)
     │
     ├─ 8 槽空闲 + is_p0 OR (非 P0 + 9 槽未满) → 进入
     │
     └─ 满载:
           ├─ acquire timeout=30s
           │     ├─ 30s 内释放 → 进入
           │     └─ 超时 → 抛 LlmSlotTimeout
           │            → 上层 _fallback_analysis (统计+Sigma 收口)
           │
           └─ 任意降级策略:
                 ├─ soft budget (70%)  → tools_only (P1+)
                 ├─ hard budget (95%)  → tools_only/rule_close (P1-P3)
                 │                       + P0 仍走 deep (skip pre_analyze)
                 └─ over_budget         → rule_close
```

### 7.4 审计上下文还原降级

- 4 层都跑通 → merged verdict
- 任一 hop 报 `skip_reasoning` → `hop-budget early-stop`（`log_ingestion.py:951-959`），清除 `missed_threats`，终止迭代
- `_merge_rounds` 禁止 OR 合并：`confirmed` 必须绑定非 LLM 信号（`veto_gates.merge_audit_rounds`）
- `apply_faithfulness_gate`：低置信度/无 grounding → 软降级

### 7.5 响应降级

- 双轨门槛：FastPath 弱信号时 `allow_blocking=False` → 过滤封禁/限速/隔离类
- `rate_limiter` 超限 → SecurityGuard deny
- 策略 `uncertain` → 走 `UNCERTAIN_POLICY_NAME` (短封 5min, P1 工单)
- `auto_execute` + 高危动作 (`isolate_host`) → 强制人工审批 (`has_critical_action` 检查)
- 审批超时（30min） → `EXPIRED`

### 7.6 关键启动顺序

`app.py:42-348` lifespan：
1. `init_db()` → `cost_tracker.restore_today_usage`（重启不丢预算计数）
2. `sliding_window.connect()` → `summary.ensure_client()` → `embedder.ensure_client()`
3. 注入 Redis 到 `embedder / summary.llm / context_stream / anomaly_detector / rollback_store / event_store / event_bus / temporal.client / audit_pq`
4. `event_store.start_invalidate_listener()` + `event_bus.start_redis_bridge()` + `anomaly_detector.load_baselines_from_redis()`
5. Qdrant 集合就绪
6. SSH 防火墙 / Sigma 规则 / self-play overlay seed
7. NDR / EDR / intel / sandbox 按需启动
8. Kafka producer + consumer manager 启动
9. `audit_worker.start()` （有界 worker）
10. `scheduler.start()` 16 个后台任务
11. HealthMonitor + Watchdog + PipelineTracer 启动
12. 启动时 stuck 事件清理（`stuck_auto_reset_minutes=30`）

---

## 8. 已知瓶颈与脆弱点（不修，只列）

> 来源：commit history / 注释（`# v4 fix` / `# v5 fix` / `# v6 fix` / `# r6 fix`）+ grep 标记 + `r*_report.md` 旁证

1. **HTTP ingest + Kafka 双路径扇出风险**：`eventId` 唯一索引兜底（`models.py:86`），但 FastPath 在两条路径都会触发——可能产生重复 response。`_fastpath_allow` 仅按 `src_ip|threat_type` 60s 窗口去重，不能完全防双触发。
2. **Temporal 容器不稳**：`log_ingestion.py:548-617` 注释"v4 复现：Temporal 容器持续 Restarting 时所有调用都走降级"——降级路径走独立 fallback Semaphore，但降级路径未持久化 workflow 状态。
3. **审计状态缓存 LRUCache 10000 上限**：`log_ingestion.py:62-67` —— 满容时优先淘汰 completed/failed 保留 pending/running，但 pending/running 也可能溢出被淘汰。
4. **`_fastpath_allow` key 碰撞**：`src_ip|threat_type` 60s 窗口——同 IP 同类型 60s 内多条只触发 1 次响应，但 attack 4 层 audit 是各自的（不冲突）。
5. **circuit_breaker 单进程**：`cad.py:358-460` 仅在内存；多副本不共享熔断状态。
6. **rate_limiter 单实例**：`security_guard/rate_limiter.py:84` 注释"多实例部署需改用 Redis INCR+EXPIRE"。
7. **PQ payload 内联 log_data**：`audit_pq.py:64` —— log_data 内联到 JSON 写入 Redis，单事件体大时占用 Redis 内存。
8. **审计工作流的 inflight 计数 = Temporal + async 共用**：`temporal/client.py:22-23` 是 Temporal 路径，`audit_worker.py` 是 async 路径，两边**独立计数**——真正的 inflight 可能 = 12(Temporal) + 12(worker) = 24 实际并发审计，违背 `audit_inflight_max=12` 语义。
9. **FastPath 信任 severity=critical 但无检测器佐证**（已修，但易回归）：v5 修复后需保证 `sigma_critical OR fused≥0.7` 才允许封禁，单纯 `severity=critical` 不应触发封禁类动作。
10. **Sigma `_agg_windows` 仅惰性清理**：`sigma_detector.py:453-462` 每 5min 才清扫一次，长期低频 src_ip 的过期事件可能滞留 5min。
11. **AnomalyDetector 基线单进程**：`anomaly_detector.py:65-78` 内存基线 + Redis 持久化（60s 节流）—— 多副本时各副本独立维护基线。
12. **`audit_pq_drain_loop` 1s 间隔**（`config.py:130`）—— 高 PQ 长度时可能积压。
13. **`event_store._hot_cache` 2000 上限**（`event_store.py:98`）—— 长跑 LRU 淘汰可能让 `get_by_id` 走 DB。
14. **Stuck event 重置定时器 30min**（`stuck_auto_reset_minutes`，`config.py:197`）—— 启动时清理（`app.py:316-346`），但运行时不自动清理，需 `audit_pq_drain_loop` 或 stuck_audit_reap 兜底。
15. **ApprovalQueue 内存字典**：`response_engine/human_approval.py` —— 进程重启即丢失未审批工单（无 DB 持久化）。
16. **`McpGuardServer.approvals` 独立 ApprovalQueue**（`mcp_guard/approval_queue.py:23-67`）—— 与响应引擎的 ApprovalQueue **不互通**，两套工单体系。
17. **PySigma 加载失败时静默回退**：`sigma_engine/engine.py` 未在本任务深入，但 config 设 `sigma_engine="pySigma"`，无 pySigma 时无显式告警。
18. **OTel 抽样全开**（`otel_sampling.md` 旁证）—— 生产环境未配置 tail-based sampling，所有 span 推 Tempo。
19. **`metrics.py` 是轻量替代 prometheus-fastapi-instrumentator**（`app.py:570-575`）—— 注释指明后者与 FastAPI 0.14x 不兼容。
20. **`audit_pq` 内的 `_redis_seen` 60s**（`event_bus.py:67-69`）—— 同 event_id 跨进程 publish 60s 内被去重，跨 60s 后会重复。

---

## 附：关键文件引用速查

| 概念 | 锚点 |
|---|---|
| 入口分流 | `routers/logs.py:82-137` |
| 4 层编排 | `log_ingestion.py:795-1049` |
| Triage | `audit_triage.py:1-336` |
| 优先级队列 | `audit_pq.py:23-156` |
| 有界 Worker | `audit_worker.py:17-208` |
| FastPath | `log_ingestion.py:268-353` |
| Kafka 薄消费 | `kafka_consumer.py:107-911` |
| 响应编排 | `response_engine/response_orchestrator.py:130-499` |
| 4 子检 | `security_guard/security_guard.py:30-161` |
| 频控占坑 | `security_guard/rate_limiter.py:79-95` |
| MCP Guard | `mcp_guard/guard_server.py:101-385` |
| Temporal 边界 | `temporal/client.py:151-212` + `temporal/workflows.py:29-152` |
| LLM 闸 | `llm_limiter.py:24-122` |
| EventBus | `event_bus.py:49-217` |
| PipelineTracer | `observability/pipeline_tracer.py` |
| Watchdog | `observability/watchdog.py:27-99` |
| 调度器 | `scheduler.py:37-475` |
| Self-Play | `self_play/orchestrator.py:68-300` |
| RAG 检索 | `rag/retriever.py:40-100` |
| 威胁情报 | `threat_intel/ioc_matcher.py:50-194` |
| DB 双池 | `models.py:15-48` |
| 幂等 PK | `models.py:86` |
| 启动顺序 | `app.py:42-348` |
| 配置总览 | `config.py:1-360` |
