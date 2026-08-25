# 07 · 数据模型与消息契约

> 这一章把"数据怎么存、消息怎么传、API 怎么接"梳理清楚。
> 查表式阅读：需要时直接跳到对应小节。

---

## 一、PostgreSQL 表（核心 20+ 张）

> 完整 DDL 见 `init.sql`（23.6 KB，~40 张表）
> 关键索引都用 HNSW（pgvector）做向量检索

### 主表清单

| 表 | 用途 | 关键字段 | 关键索引 |
|----|------|---------|----------|
| `security_events` | 事件主表 | id / event_type / severity / src_ip / dst_ip / analyzed / status / case_id / anomaly_score | severity / analyzed / status / anomaly_score / case_id |
| `memories` | Agent 记忆 | id / agent_id / content / embedding(vector) | hnsw(embedding) / agent_id / created_at |
| `conversations` | 对话历史 | id / session_id / agent_id / role / content | (session_id, created_at) |
| `memory_tree_nodes` | 层次化记忆 | id / parent_id / depth / content / summary / importance | session_id / parent_id / node_type |
| `knowledge_docs` | 知识库文档 | id / title / content / source / threat_types / tags | — |
| `knowledge_chunks` | 知识库分块 | id / doc_id / content / embedding(vector) | hnsw / threat_types(gin) / severity / source |
| `response_logs` | 响应执行日志 | id / session_id / event_id / threat_* / action_* / rollback_token | event_id / threat_type / src_ip / action_name |
| `network_flows` | NDR 流量 | src_ip / dst_ip / bytes_in/out / packets / app_protocol / country_src/dst | src_ip / dst_ip / dst_port / app_protocol / sensor_id |
| `tls_sessions` | TLS 会话 | sni / ja3 / ja3s / ja4 / cert_subject / cert_is_self_signed / risk_score | sni / ja3 / is_expired |
| `pcap_files` | PCAP 元数据 | file_path / file_size / sensor_id / packet_count | sensor_id / status |
| `edr_events` | EDR 融合事件 | source_type / computer / user / process / image_hash / mitre_technique | source_type / computer / process / hash / mitre |
| `threat_iocs` | 威胁情报 IOC | ioc_type / ioc_value / threat_type / confidence / source / stix_id / mitre_attack_id | type / value / threat / stix / active |
| `threat_intel_feeds` | 威胁情报源 | name / feed_type / url / poll_interval_min / last_poll_status | enabled |
| `sandbox_tasks` | 沙箱任务 | task_id / sample_hash / sandbox_type / status / verdict / score / mitre_techniques | task_id / hash / status / verdict / submitted |
| `assets` | 资产 | asset_key / asset_type / ip / hostname / criticality / business_owner | ip / criticality / owner / active / bu |
| `asset_changes` | 资产变更 | asset_id / change_type / diff / changed_by | asset_id / created_at |
| `asset_discovery_tasks` | 资产发现任务 | task_id / scope / scanner / status / result | status / created_at |
| `data_sources` | 数据源 | api_key_hash / name / source_type / enabled | api_key_hash / enabled |
| `work_orders` | 工单 | （SQLAlchemy 创建）| — |
| `security_cases` | 案例 | （SQLAlchemy 创建）| — |
| `cases` | 案例关系 | event_id ↔ case_id | — |
| `cad_reports` | CAD 报告 | event_id / hallucination_risk / evidence_completeness | — |
| `audit_trail` | 审计轨迹 | actor / action / target / decision / reason | — |
| `memories_qdrant_meta` | Qdrant 同步元数据 | memory_id / qdrant_point_id / last_synced | — |
| `production_orders` | 工单流转 | status / priority / assignee / due_at | — |
| `approval_tickets` | 审批工单 | tool / args / status / decided_by | — |
| `phishing_verdicts` | 反钓鱼判定 | request_type / score / verdict / reasons | — |
| `detection_results` | Sigma 命中 | rule_id / event_id / matched_at | — |
| `grounding_reports` | Grounding 报告 | claim / grounded / confidence | — |
| `i18n_translations` | 国际化 | key / locale / value | — |
| `user_preferences` | 用户偏好 | user_id / preference_key / value | — |
| `user_sessions` | 会话 | user_id / token / expires_at | — |
| `users` | 用户 | username / password_hash / role / last_login | — |
| `federated_learn_runs` | 联邦学习 | model_id / round / metrics | — |
| `chat_sessions` | 对话 | session_id / user_id / created_at | — |
| `analyst_metrics` | 分析师指标 | analyst_id / case_id / mttr | — |
| `tool_call_logs` | 工具调用日志 | tool_name / args / decision | — |
| `lifecycle_events` | 事件生命周期 | event_id / from_status / to_status | — |
| `response_feedback` | 响应反馈 | response_id / helpful / comment | — |
| `feedback_signals` | 反馈信号 | source / signal / weight | — |
| `case_relationships` | 案例关联 | case_a / case_b / relation | — |

> 部分表由 SQLAlchemy `models.py` 在启动时 `create_all` 创建，故 `init.sql` 未必全列。
> 表多但每张表都不复杂，遵循"窄字段 + JSONB 兜底"风格。

### 字段约定
- 所有 `id` 用 SERIAL（自动递增整数）
- 所有时间用 `TIMESTAMP WITH TIME ZONE DEFAULT NOW()`
- 文本字段有 DEFAULT `''` 或 `0`（避免空值判断）
- JSONB 字段有 DEFAULT `'{}'` 或 `'[]'`
- 向量字段用 `vector` (pgvector)

---

## 二、向量库

### Qdrant（默认启用）
- RAG 知识库 collection：`mitre_techniques` / `capec_attack_patterns` / `case_chunks`
- Agent 记忆 collection：`agent_memories`（独立于 RAG）
- 字段：`agent_id` 用于按 Agent 隔离（payload 过滤）

### pgvector（兜底）
- 表：`memories.embedding`、`knowledge_chunks.embedding`
- 索引：HNSW (`m=16, ef_construction=64`)
- 相似度：cosine

### 双写策略
- 写：先 pg，再 Qdrant
- 读：Qdrant 优先，失败/不可用降级 pgvector
- 同步：迁移脚本 `migrate_pgvector_to_qdrant.py` 提供 `--scope chunks|memories|all`

---

## 三、Redis 用法

| 用途 | Key 模式 | 生命周期 |
|------|---------|----------|
| 限流 | `rl:{ip}:{minute}` | 60s TTL |
| JWT 黑名单 | `jwt:blacklist:{jti}` | 等同 token 剩余时间 |
| TTL 回收 | `ttl:fw_rule:{rule_id}` | 自定义 |
| 缓存 | `cache:{key}` | 自定义 |
| Session | `session:{token}` | JWT 过期 |

---

## 四、Kafka 消息契约

### 通用字段
所有事件类消息都有：
```json
{
  "eventId": "uuid",
  "traceId": "uuid",
  "timestamp": 1724567890123,
  "rawData": {
    "_traceparent": "00-abc-...-01"
  }
}
```

### 消息头
- `traceparent`：W3C trace context
- `soc.source_id`：数据源 ID
- `soc.api_key_hash`：数据源 API Key 哈希（不存明文）

### 各 topic 特有字段

**`security-logs-raw`** — 原始日志：
```json
{
  "eventId": "...",
  "eventType": "BRUTE_FORCE",
  "severity": "high",
  "srcIp": "1.2.3.4",
  "dstIp": "5.6.7.8",
  "protocol": "SSH",
  "message": "...",
  "confidence": 80,
  "apiKey": "soc-...",
  "sourceId": "edge-firewall-1"
}
```

**`security-logs-rejected`** — 被拒：
```json
{
  "rawMessage": "...",
  "rejectionType": "AUTHENTICATION_FAILED",
  "rejectionReason": "...",
  "rejectedAt": 1724567890456,
  "jobName": "LogValidationJob",
  "stage": "AUTH"
}
```

**`security-logs-validated`** — 已校验：等同 raw，但通过 schema + 认证 + 去重 + 标准化

**`security-events-enriched`** — 富化：
```json
{
  "...": "已校验字段",
  "anomalyScore": 0.85,
  "reasons": ["frequency_high", "high_severity", "off_hours"]
}
```

**`security-alerts`** — 告警：
```json
{
  "...": "已校验字段",
  "anomalyScore": 0.85,
  "alertType": "ANOMALY" | "CEP_CHAIN",
  "cepPatternId": "port_scan_to_c2"  // 仅 CEP 命中时有
}
```

**`security-audit-queue`** — 待审：等同 enriched（多走 audit-queue 通路）

**`security-audit-results`** — 审计完成：
```json
{
  "eventId": "...",
  "traceId": "...",
  "audit_llm_data": {
    "decomposer": {...},
    "tool_builder": {...},
    "executor": {...},
    "reviewer": {...},
    "evidence_trail": [...],
    "final_verdict": "malicious" | "benign" | "suspicious",
    "confidence": 0.85,
    "actions": [...]
  },
  "cad_report": {
    "hallucination_risk": 0.05,
    "evidence_completeness": 0.92
  }
}
```

---

## 五、FastAPI 路由端点清单

> 完整端点列表：`curl http://localhost:8001/openapi.json`（约 179 个端点）
> 路由常量定义在各 `routers/*.py` 顶部 `prefix=` 字段，下面给的是主要端点。

### 认证 (`/api`)
- `POST /api/auth/login` — 登录（限流、3 次失败锁定）
- `GET  /api/health` — 整体健康
- `GET  /api/metrics` — Prometheus

### 事件 / 日志 (`/api/logs`)
- `POST   /api/logs/ingest` — HTTP 单条
- `POST   /api/logs/ingest/batch` — HTTP 批量
- `POST   /api/logs/analyze` — 触发分析
- `GET    /api/logs/status` — 状态
- `GET    /api/logs/review` — 待审
- `GET    /api/logs/stuck` — 卡住的事件

### Chat 与 SSE (`/api/chat`)
- `GET    /api/chat` — 聊天
- `POST   /api/chat/stream` — 流式聊天
- `GET    /api/events/stream` — 事件 SSE
- `GET    /api/events/recent` — 最近事件
- `GET    /api/tree/*` — 记忆树相关

### 审计 / LLM / CAD (`/api`)
- `GET    /api/audit-llm/run` — 触发审计
- `GET    /api/audit-llm/pipeline/{event_id}` — 流水线详情
- `GET    /api/audit-llm/evidence/{event_id}` — 证据链
- `GET    /api/audit-llm/stats` — 审计统计
- `GET    /api/llm/cost` — LLM 成本
- `GET    /api/sigma/stats` — Sigma 统计
- `POST   /api/sigma/detect` — Sigma 检测
- `GET    /api/guard/status` — Guard 状态
- `POST   /api/guard/call` — 测试 Guard 调用
- `GET    /api/cad/status` — CAD 状态
- `GET    /api/cad/circuit-breaker` — 熔断器状态
- `POST   /api/cad/circuit-breaker/reset` — 重置（需 admin）
- `POST   /api/cad/override/{event_id}` — 人工覆盖
- `GET    /api/cad/accuracy` — CAD 准确率
- `GET    /api/cad/verification/{event_id}` — 验证详情
- `POST   /api/cad/audit-context` — 上下文审计

### 响应 (`/api/response`)
- `GET    /api/response/queue` — 待审批
- `POST   /api/response/approve` — 批准
- `POST   /api/response/deny` — 拒绝
- `POST   /api/response/execute` — 手动触发
- `POST   /api/response/rollback/{token}` — 回滚
- `GET    /api/response/logs` — 执行日志

### 运营 (`/api/ops` — 最大 router 38K)
- `GET/POST   /api/ops/cases` — 案例
- `GET/POST   /api/ops/workorders` — 工单
- `GET/POST   /api/ops/postmortems` — 复盘
- `GET/POST   /api/ops/rules` — 规则 CRUD
- 等等

### 资产 (`/api/assets`)
- `GET/POST/DELETE /api/assets` — 资产管理
- `GET  /api/assets/{id}/history` — 变更历史
- `POST /api/assets/discovery` — 资产发现
- `GET  /api/assets/discovery/tasks` — 发现任务

### 数据源 (`/api/sources`)
- 数据源注册 / 吊销 / 拒绝

### RAG (`/api/rag`)
- `GET    /api/rag/knowledge` — 知识库列表
- `POST   /api/rag/search` — 检索
- `POST   /api/rag/import` — 导入 MITRE/CAPEC
- `GET    /api/rag/import/status`

### Kafka 与 CEP (`/api/kafka`)
- `GET    /api/kafka/status` — 状态
- `GET    /api/kafka/rejections` — 拒绝日志（不是 /rejected）
- `GET    /api/cep/patterns` — CEP 模式
- `POST   /api/cep/patterns/{id}/toggle` — 启停
- `POST   /api/cep/patterns/{id}/shadow` — 灰度
- `POST   /api/cep/replay` — 重放
- `GET    /api/pipeline/status` — 整体流水线状态

### 反钓鱼 (`/api/phishing`)
- `POST /api/phishing/detect/email` — 邮件
- `POST /api/phishing/detect/web` — 网页
- `POST /api/phishing/detect/domain` — 域名
- `POST /api/phishing/detect/attachment` — 附件
- `POST /api/phishing/detect/sms` — 短信
- `POST /api/phishing/detect/qrcode` — 二维码
- `POST /api/phishing/detect/bec` — 商业邮件诈骗
- `GET  /api/phishing/stats`
- `GET  /api/llm-enhancer/status`

### NDR (`/api/ndr`)
- `GET  /api/ndr/flows` — 流量
- `GET  /api/ndr/tls` — TLS 会话
- `GET  /api/ndr/pcap` — PCAP 文件
- `GET  /api/ndr/capture/stats` — 抓包统计

### EDR / 威胁情报 / 沙箱 (`/api/edr-intel`)
- `GET/POST /api/edr/events` — EDR 事件
- `GET/POST /api/edr/ingest` — EDR 推送
- `GET  /api/edr/stats`
- `GET  /api/intel/iocs` — IOC 列表
- `GET  /api/intel/feeds` — 情报源
- `POST /api/intel/match` — IOC 匹配
- `GET  /api/sandbox/tasks` — 沙箱任务
- `POST /api/sandbox/submit` — 提交样本
- `GET  /api/sandbox/status`

### 能力总览 (`/api/capabilities`)
- `GET /api/capabilities/status`

---

## 六、SSE 事件类型

`/api/events/stream` 推送的事件：

| type | 数据 | 用途 |
|------|------|------|
| `security_event` | SecurityEvent 简化 | 实时事件流 |
| `alert` | AlertEvent | 实时告警 |
| `audit_result` | 审计完成 | 审计详情 |
| `cad_report` | CAD 报告 | 自审计 |
| `response_log` | 响应执行 | 响应流 |
| `circuit_breaker` | 熔断器状态变化 | 监控 |
| `watchdog` | 健康告警 | 监控 |
| `system` | 系统通知 | 杂项 |

前端 `useEventStream(type, handler)` 按类型订阅。

---

## 七、配置项（`config.py` 关键项）

### 服务
- `service_name` / `service_version` / `environment`
- `api_host` / `api_port` / `cors_origins`

### 数据
- `postgres_*` / `redis_*` / `qdrant_*`
- `embedding_api_url` / `embedding_api_key` / `embedding_model` / `embedding_dim`

### LLM
- `llm_api_url` / `llm_api_key` / `llm_model` / `llm_timeout`
- `audit_llm_*_enabled`（各增强开关）
- `audit_llm_max_tokens` / `audit_llm_temperature`

### 响应
- `response_default_mode` (auto/soft/dry-run)
- `response_approval_required_severity`
- `response_ttl_default` (秒)

### 观测
- `tracing_enabled` / `tracing_sample_rate`
- `metrics_enabled`

### 自审计
- `circuit_breaker_threshold` (默认 0.3)
- `circuit_breaker_cooldown` (默认 300s)
- `mcp_guard_enabled` / `security_guard_enabled`
- `grounding_enabled`

> 完整列表见 `config.py`，全部可由 `.env` 覆盖。

---

## 上一章

> [06 前端架构与页面](./06-frontend.md)

---

## 下一章

- 想看怎么部署：→ [08 部署、运维与调优]
- 想看推荐学习路径：→ [09 推荐学习路径]
- 卡住了：→ [10 常见问题与陷阱]


---

## 动手点

1. **查一张表的真实数据**：
   ```bash
   # 查事件
   PGPASSWORD=$POSTGRES_PASSWORD psql -h 127.0.0.1 -p 5433 -U postgres -d soc \
     -c "SELECT id, event_type, severity, src_ip, analyzed FROM security_events ORDER BY id DESC LIMIT 10;"
   ```

2. **看 Kafka 实际消息**：
   ```bash
   docker exec soc-kafka /opt/kafka/bin/kafka-console-consumer.sh \
     --bootstrap-server localhost:9092 \
     --topic security-events-enriched \
     --from-beginning --max-messages 1
   ```

3. **看 SSE 实时流**：
   ```bash
   curl -N http://localhost:8001/api/events/stream
   ```
