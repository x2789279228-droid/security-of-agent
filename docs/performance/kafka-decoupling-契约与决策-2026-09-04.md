# Kafka 三解耦 — 契约核对与关键决策记录

**日期**: 2026-09-04 | **阶段**: 阶段2 Ingest 端解耦 | **作者**: execution

## 1. raw topic 契约（HTTP 网关 → Kafka 前置校验源）
消费者链事实源：`flink-jobs/schemas/security-event.avsc` + `LogValidationJob.java`。

网关 produce `security-logs-raw` 的消息字段须符合 avsc(JSON camelCase)：

| 字段 | 必需 | 约束 |
|---|---|---|
| eventId | 否(runtime 自动生成 UUID) | string |
| sourceId | 建议 | 提示来源标识 |
| **apiKey** | **必需(Flink 校验)** | 须 ∈ Flink 白名单 {soc-syslog-2024, soc-api-2024, soc-simulator-2024}，否则 AUTH authentication → rejected |
| eventType | **必需** | 非空，会规范为大写；未知类型放行但标记 |
| severity | **必需** | info/low/medium/high/critical（或 10/30/50/70/90，Flink 映射）|
| message | **必需** | 非空，≤500 字符（Flink 截断）|
| confidence | 可选 | [0,100]，默认 50 |
| srcIp / dstIp | 可选 | 非空时须合法 IPv4，否则 rejected |
| protocol | 可选 | 小写 |
| timestamp | 可选 | epoch ms；(Flink 会把 10 位数秒级自动 ×1000；0 则用 current)|
| traceId | 可选 | 默认=eventId |
| rawData | 可选 | 透传 map |

Flink 侧 60s 去重：key(srcIp+eventType+messageHash)，源 srcIp 相同、事件类型与 message 相同者仅 1 条过 →
**去重键为 srcIp|eventType|md5(message)**,message 相同会丢。对"批量重复 message"注入(压测同 message 同 src)会在 Flink 被去重。

schema/枚举/IP 不合格会被 Flink rejected 到 security-logs-rejected，不进 validated → 不进审计。

## 2. API Key 身份跨越（决策点）
- 历史 HTTP 压测用 **admin JWT(Bearer)** 而非数据源 X-API-Key；Flink 校验的是硬编码 apiKey 白名单。
- **决策**：网关把每条 HTTP ingest 归一化为标准 raw 事件，signature/source 身份用 Flink 白名单里的合法 apiKey 注入。
  具体映射：HTTP header `X-API-Key`(经 source_registry 认证) → 该源的 apiKey 字段；无 X-API-Key(admin JWT 场景)
  → 退回 `source_registry` 默认/兜底源，循环使用，避免整批被 Flink 认证拒 → rejected 丢弃，实现断点不是"丢"而是进审计闭环。
  若 source_registry 空 → produce 前按 Flink 白名单格式补充(保守：打 warn + 用兜底 apiKey "soc-api-2024")。
- 该决策使 Kafka 模式 HTTP 入口与既有数据源语义一致，且不会因认证失败丢数据(仍可由审计闭环捕获，与现 FastPath 一致)。

## 3. sanitize/归一化位置
- 保留 HTTP 层 HTML sanitize(防 XSS, independent of transport)。
- Flink 侧会做 severity/eventType/protocol/IP/timestamp 归一化；网关不重复,只负责字段存在与基本必填,符合"薄网关 + Flink 事实源"架构定位。

## 4. 解耦开关
- `settings.kafka_enabled=True + producer started` → HTTP ingest/batch 网关化(produce raw 后立即返回)。
- `settings.kafka_enabled=False` → 维持原同步 ingest(单机/无 Kafka 场景)，功能不缩水。

## 5. 检测引擎事实源（决策 2026-09-04 定稿/go）
采用「**Python 侧消费 Kafka 排队处理**」——保住 r8 python 全检测(sigma+anomaly+FastPath+审计+响应)能力，杜绝衰减。
**分区（single-owner）决策修正**：HTTP 网关只把事件投到 `security-events-ingest`（Python 处理权威队列），**不再跨喂 Flink raw**——
原因：既有 Flink 链路(raw→enriched/alerts)服务的是"外部 Kafka 直连来源"(syslog/simulator/NDR/EDR 等, 它们只写 Flink raw)。若 Python HTTP 事件也 feed raw，
同一物理事件会同时抵达 Flink(enriched→旧handler 补审计) 与 Python 处理通道 → 双 LLM/双审计(成本与语义歧义)。故**按来源分区**：
1. HTTP 网关/其它经 /api 注入 → `security-events-ingest`，由 Python 新消费者复跑 `log_ingestor.ingest`(全能力, 请求内同步→消息驱动异步)。上游永不阻塞。
2. 外部 Kafka 直连源(不经 HTTP) → Flink raw 原生链路 → 旧 `_handle_enriched/_handle_alert/.../audit-queue`, 维持原有 kafka-mode 行为不变。
两者 topic/来源互斥, 物理事件不重复, 单点审计调度无双跑。
- 消费者：`kafka_consumer` 新增 ingest-process consumer(独立 group `soc-backend-ingestpy`), 手动 commit+PG 幂等+DLQ/重试复用通用 `_consume_loop`。
- 开关：`settings.python_process_ingest_queue`(默认 true)不启用则 HTTP 回退原同步 ingest(单机/无 Kafka)。
- 事件身份/安全：网关清洗(HTML/XSS)后包 {uuid,type,session_id,source_key,body}; sanitize/log_ingestor._normalize_fields 负责字段归一化, 与 sync 完全一致。

## 6. 处理端「响应不阻塞消费推进」与速度解耦
- log_ingestor.ingest 内部 FastPath 响应编排用 `asyncio.create_task(_fast_response(...))`(非 await SSH 阻塞) 与 Audit-LLM `create_task(_audit_pipeline)` 均后台派发; handler 只 await store+调度,返回后消费者才统一 batch commit. → SSH/LLM 慢端不阻塞 batch 消费(& commit)推进, 减速解耦成立于消费循环与业务深度处理之间。
- Python queue 消费者默认 workers=8,poll=500ms,max_poll_records=50,分片 asyncio.gather 并发 → 队列消化并发化(env 可调 KAFKA_INGEST_WORKERS/KAFKA_INGEST_POLL_MS)。

## 7. 实测(2026-09-04, 同机同口径)
| 注入 | HTTP 同步路径(改造前 baseline) | HTTP 网关投递(改造后) | 加速 |
|---|---|---|---|
| 50 | 973.7 ms | 7.3 ms | ~133× |
| 200 | 3464.8 ms | 249.2 ms | ~14× |
- queue consumer `python_ingest_consumed=255`(5+50+200) errors=0; 事件落库走原 log_ingestor 全链(幂等)。
- 相关回归(pytest ing): `tests/test_arch_unification etc 5 files` → 38 passed(kafka_enabled=false 原同步路径不变)。
- 说明:批 wall 不含审计 LLM 时长(异步处理), 反映"入队即返"的上游吞吐上界; 审计处理耗时的消化速率见消费者 lag/workers 指标。

## 8. 故障解耦边界与权衡(定稿)
- 已达成: HTTP ingest 不再触碰 DB/LLM → DB/LLM 故障/超时不阻塞入队(Kafka 积压缓冲); 事件队列入 Kafka, backend 崩溃不丢失(consumer offset 手动+未 commit 在 Kafka 侧重放,event_store 幂等去重)。
- 进程崩溃时"内存中已派发的单条 LLM 审计协程"仍可能中断丢失(与旧 HTTP 同源同界, 非本次引入); audit_pq(Redis, P0/P1 shed 持久化)已在 log_ingestor._audit_pipeline inline,专注 inflight 满降级场景; 其余依托 `stuck_auto_reset`(scheduler)作为最终 backstop 回收 analyzed=false 事件。
- 为杜绝 Python 权威路径与 Flink 旧 enriched/audit 调度对同一物理事件双审计/双 LLM,决策 §5 采用 single-owner 分区(HTTP→events-ingest,外部→raw) — 物理事件不重复跨喂(见 §5 修订),故 kafka_flink_secondary_llm 开关保留为未来需要 Flink 补审计时的逃生口(默认 false)。

### 8.1 无丢失实证(crash-resume, 2026-09-04)
- 消费循环改为**仅整批全成功才 commit**;任一条失败→不推进 offset→瞬断/DB 故障重放, 不丢(commit-gating)。
- 实证: 注入 600 条(网关即回 queued, produced=600/600)→消费推进至 16 即 `docker stop` 杀进程(截断于消费中)→ 重启 backend: `python_ingest_consumed=600, errors=0`(其余 584 由未 commit offset 从 Kafka 自动重放续处理)。
- 结论: HTTP 上游在 backend 处理被中断时全成功入队(请求不因下游状态失败)→满足时间解耦"DB/LLM故障不阻塞上游"; 恢复后 Kafka 积压自动消化不丢→故障解耦成立。



