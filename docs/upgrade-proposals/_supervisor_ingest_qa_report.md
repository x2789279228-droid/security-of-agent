# 主管审查 — 接入链路事件驱动 Phase 1

> 日期：2026-09-06
> 审查人：Grok（不采信代理报告，对照仓库 + 本地 pytest）
> 结论：**源码验收 PASS**；线上 Docker/backend **未恢复**，HTTP 202 与 Kali 压测未在活体上复跑。

## 1. 现状核对（对用户框架图）

用户图仍然描述「HTTP 线程里同步跑完 anomaly + sigma + PG + FastPath + 审计」。代码事实：

- Kafka 开着时，HTTP 早已只 produce `security-events-ingest` 后返回（以前是 200 queued）。瓶颈在 Python consumer 内的 `log_ingestor.ingest()`。
- anomaly/sigma **不是** CPU 主因（2026-09-04 profile：合计 <4% 墙钟）。主因是逐条 PG commit。
- 审计已有 triage / Redis PQ / 12 worker；但 P0 在 PQ 失败时仍可能 `overflow`。
- Flink 在 HTTP 路径上闲置是 **有意决策**（保住 Python 检测权威），本轮不翻转 `python_process_ingest_queue`。

## 2. 本轮落地（同进程事件驱动，不拆微服务）

```
HTTP ──sanitize──► Kafka ingest ──► 202
                      │
                      ▼
              detect (anomaly ∥ sigma, 隔离)
                      │
              store_batch (单 commit)
                      │
         FastPath(async, 可重试)  +  AuditWorker(P0/P1 永不 overflow)
```

| 切片 | 谁 | 结果 |
|---|---|---|
| P1 流水线 | Reasonix | detect/persist/dispatch、store_batch、gather 投递、ingest facade、python-ingest `run_many` |
| P2 网关/不丢/指标 | OpenCode | HTTP 202、不借 OLTP、batch API key、never-drop 链、Prometheus 助手 |
| 主管补洞 | Grok | overflow **消费者**、`from_overflow` 防环、worker streak 重置、阶段指标真正打点、P1-J 单测 |
| QA | MiniMax | 对照验收 PASS；误写了不存在的测试名 `test_run_many_failure_no_offset_commit`（主管已补真测试） |

## 3. 独立验收

本地（`cd backend`）：

```
python -m pytest tests/test_ingest_pipeline.py tests/test_event_store_batch.py
  tests/test_kafka_deliver_gather.py tests/test_http_ingest_gateway.py
  tests/test_audit_never_drop.py tests/test_audit_worker.py
  tests/test_arch_unification.py tests/test_log_normalize_http.py -q
→ 44 passed
```

邻接：`test_audit_triage` / `test_audit_pq` / `test_event_store_cache` / `test_security_guard_fastpath` 等 63 passed；`test_case_automation::test_audit_pipeline_path_creates_case` 为改前即失败（测试 stub 非 awaitable），不计入本轮。

`http://127.0.0.1:8001/api/health` 超时。活体 202 / Kali 仿真未跑。

## 4. 明确未做（对用户北星）

- 独立 Sigma / 异常检测 / 存储微服务
- Celery、ClickHouse、ProcessPool（profile 不支持）
- 把 HTTP 权威检测交回 Flink
- HTTP 同步返回封禁决策
- deque 满 10000 后的跨进程持久化（最后一级仍可能淘汰最旧 P0，记 `local_deque_evicted`）

## 5. 风险

1. 本地 deque 超容会驱逐最旧 P0（Redis+Kafka 双挂的极端情况）。
2. `security-audit-overflow` 需 broker 上有 topic（`tools/init-kafka-topics.sh` 已加）；旧集群要补建。
3. 非 sqlite 的 HTTP `/batch` 从「每条独立 session 并发 commit」改为 `run_many` 单事务，大 batch 尾延迟形态变了。
4. 线上镜像未重建，活体仍是旧行为。
