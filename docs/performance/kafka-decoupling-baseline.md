# Kafka 三解耦改造 — 改造前基线 (Baseline)

**日期**: 2026-09-04
**阶段**: 阶段1(基线固化与基准采集)
**目标**: 为 Kafka 时间/速度/故障三解耦改造固化可回溯的现状基线，供阶段5同口径对比。

## 1. 运行环境快照
- backend 容器 `shared-memory-backend` 运行中, `SHARED_MEMORY_KAFKA_ENABLED=true`
- `/api/kafka/status`(容器内 8000 端口探测):
  - `enabled=True`, `producer_active=True`(KafkaProducer), `consumer running:true`
  - consumer_stats: `enriched_consumed=0, audit_consumed=0, alerts_consumed=0,
    behavior_alerts_consumed=0, rejected_consumed=0, errors=0, last_message_at=0, lag={}`
- **结论(名实分离)**: backend 已配为 Kafka 模式,但全部 topic 消费计数为 0、无 lag,
  说明历史压测(r8 等 1980 events)与演示全部走 HTTP 同步入口 `/api/logs/ingest/batch`,
  绕过了 Kafka。时间/速度/故障三解耦实际未落实:Ingest HTTP 仍同步结算
  DB 落库+检测+响应编排+审计任务派发。

## 2. HTTP 同步 ingest wall 基准(改造前)
复用 `event=HTTP_ACCESS / severity=low` 良性事件批量注入,批量返回 wall 延迟(ms):

| 单批条数 | wall(ms) | 折算速率 |
|---|---|---|
| 5    | 140.6 | ~36/s |
| 50   | 973.7 | ~51/s |
| 200  | 3464.8 | ~57.7/s |

> 口径: 同 r8 批处理 wall-clock(HTTP POST→200 返回)。改造后此 wall 应显著下降至
> 网关级(<100ms),因为落库/检测/审计改由 Kafka 消费者异步、并发、批量消化。

## 3. 已知说明
- 此入口注入的是良性 low 事件,不走 Audit-LLM 主槽(budget/triage 关断),不产生实际 LLM 调用。
- 改造前审计完成率端到端口径将在阶段5以同规模 r8 攻击事件重压测对比。

## 4. 探针
探针脚本逻辑见会话/宿主临时目录 `kprobe.py`(login + batch ingest 计时),不入库。

## 5. pytest 基线快照(改造前)
一次性容器(ghcr.io/.../soc-backend:dev, root, mount backend 源码, sqlite in-memory,
KAFKA_ENABLED=false, pip+pytest-asyncio)运行 `python -m pytest tests/ -q`:

`463 passed, 4 failed, 1 warning in 28.85s`

既有失败(基线 commit 后未改动任何业务源码,判定为既有/环境性,非本改造引入):
- `tests/test_any_fallback_guard.py::test_natural_language_name_hits_c2_policy`
- `tests/test_audit_endpoints.py::TestPolicyUpdateAudit::test_policy_update_writes_audit_trail`
- `tests/test_case_lifecycle.py::TestRuleManager::test_update_response_policy`
- `tests/test_inc_edr.py::test_edr_adapter_ingest_normalizes` — RuntimeError:
  There is no current event loop(环境/测试耦合 py3.12 事件循环, 明显非业务)

> 验收口径:改造后同容器重跑不得新增失败(期望仍 463p/4f, 除非针对失败另行修复)。

## 6. 改造后对比(同机同口径, 2026-09-04)
| 单批注入 | HTTP 同步(改造前 §2) | HTTP 网关投递(改造后) | 加速 |
|---|---|---|---|
| 50 | 973.7 ms | 7.3 ms | ≈133× |
| 200 | 3464.8 ms | 249.2 ms | ≈14× |

- 改造后 `/api/logs/ingest/batch` 仅认证+sanitize+produce `security-events-ingest` 后返回 `{status:queued,produced:n}`;
- Python 权威消费者(`group soc-backend-ingestpy`, workers=8)批量并发 → 复跑 `log_ingestor.ingest` 全检测闭环;
  实测注入 255 条 `python_ingest_consumed=255, errors=0`。
- 处理浪响应(FastPath 响应编排与 Audit-LLM 均 create_task 派发, 非请求/消费循环内 await SSH/LLM) → 慢端不阻塞 batch 消费推进。
- 专项回归: `tests/test_arch_unification/test_response_dedup_dual_track/test_audit_pq/test_case_automation/test_trace_otel` → 38 passed(KAFKA=false 原同步路径不变)。


