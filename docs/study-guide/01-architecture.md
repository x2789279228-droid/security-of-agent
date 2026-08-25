# 01 · 架构总览

> 平台不是"一个服务"，而是**一组有清晰边界的服务**，通过 Kafka 和 REST / SSE 通信。
> 这一章让你对每个进程的职责、谁调谁、数据怎么走，建立一张可复用的"地图"。

---

## 进程全景

```
┌──────────────────────────────────────────────────────────────────────┐
│                       外部日志源 (syslog / agent / WAF)                 │
└────────────────────────────┬─────────────────────────────────────────┘
                             │  ① 携带 API Key，HTTPS / Kafka 推送
                             ▼
   ╔══════════════════════════════════════════════════════════════════╗
   ║  数据接入层 (Kafka)         security-logs-raw                     ║
   ╚════════════════════════╤═════════════════════════════════════════╝
                            ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  Flink 集群 (Java)                                                │
   │  ┌────────────────────────┐   ┌────────────────────────────────┐  │
   │  │ Job1: LogValidation    │──▶│ Job2: AnomalyDetection + CEP  │  │
   │  │  · JSON 解析           │   │  · 频率 / 严重度 / 时段评分     │  │
   │  │  · Schema 校验         │   │  · CEP 攻击链 (3+ 模式)        │  │
   │  │  · API Key 认证        │   │  · 智能路由                     │  │
   │  │  · 字段标准化          │   │    alerts / audit / enriched   │  │
   │  │  · 60s 去重            │   └────────────────────────────────┘  │
   │  └────────────────────────┘   ┌────────────────────────────────┐  │
   │                                │ Job3: SigmaThresholdAggreg.   │  │
   │                                │  · Sigma 命中阈值去抖聚合      │  │
   │                                └────────────────────────────────┘  │
   │  (NDR 作业: FlowAggregation / TlsFingerprint                      │
   │    需 SUBMIT_NDR_JOBS=1 才提交)                                   │
   └──┬────────────────────┬─────────────────┬─────────────────────┬──┘
      ▼                    ▼                 ▼                     ▼
   security-logs-    security-         security-            security-
   rejected          logs-validated    events-enriched      alerts
   (失败归档)         (待评分)          (富化全量)          (高优告警)
                                          │
                                          ▼
   ╔══════════════════════════════════════════════════════════════════╗
   ║                       Backend (FastAPI)                          ║
   ║  ┌──────────────────────────────────────────────────────────┐   ║
   ║  │ Kafka Consumer  ←  3 个 topic (enriched / audit / alerts)│   ║
   ║  └──────┬───────────────┬───────────────────────────┬────────┘   ║
   ║         ▼               ▼                           ▼             ║
   ║   EventStore        Audit-LLM              ResponseEngine         ║
   ║   (PostgreSQL)      (Decomposer →         (策略 / 审批 / SSH)     ║
   ║         │           ToolBuilder →                                 ║
   ║         │           Executor →                                    ║
   ║         │           Reviewer)                                     ║
   ║         │              │                                          ║
   ║         │              ▼                                          ║
   ║         │           CAD 独立监督                                  ║
   ║         │           (穿透验证 + 熔断)                              ║
   ║         ▼              ▼                                          ║
   ║   ┌──────────────────────────────────────────────────────────┐   ║
   ║   │  辅助模块                                                    │   ║
   ║   │  RAG / Sigma / Stabilizer / SecurityGuard / MCP Guard      │   ║
   ║   │  NDR / EDR / ThreatIntel / Phishing / Sandbox              │   ║
   ║   │  (默认关，开关启用)                                          │   ║
   ║   └──────────────────────────────────────────────────────────┘   ║
   ╚════════════╤══════════════════════════════╤═══════════════════════╝
                ▼                              ▼
        PostgreSQL + Qdrant +          Frontend (React)
        pgvector + Redis               (SSE 实时推送)
```

---

## 五层职责划分

| 层 | 进程 | 关键职责 | 失败容忍 |
| :--- | :--- | :--- | :--- |
| **接入层** | syslog-adapter / log_simulator | 把多源日志转 Kafka，附 API Key | 单条失败可丢，但要有拒绝审计 |
| **流处理层** | Flink 2 作业 | 校验、认证、去重、打分、CEP 攻击链 | 重启不丢不重（EXACTLY_ONCE） |
| **业务层** | FastAPI backend | 入库、LLM 审计、响应编排、监督 | 异步任务有 watchdog 自动拉起 |
| **存储层** | PostgreSQL / Qdrant / Redis | 事件、记忆、知识、审计 | PostgreSQL 主库用 pgvector + Qdrant 双写 |
| **表现层** | React 前端 | 监控、审计、运营、复盘 | SSE 长连接，需重连退避 |

---

## 通信方式

| 路径 | 协议 | 用途 |
| :--- | :--- | :--- |
| 数据源 → Kafka | Kafka SASL_SSL (9093) / PLAINTEXT_HOST (9094) | 日志接入 |
| Flink ↔ Kafka | Kafka（无 SASL，容器内网） | 验证、富化、CEP |
| Backend ↔ Kafka | Kafka | 消费 enriched / audit / alerts |
| Backend ↔ PostgreSQL | SQLAlchemy 异步（asyncpg） | 事件、记忆、案例 |
| Backend ↔ Qdrant | HTTP（REST） | 向量检索 |
| Backend ↔ Redis | aioredis | 限流、缓存、TTL |
| Backend → 资产 | paramiko SSH / Windows netsh | 响应执行 |
| Backend → Frontend | REST + SSE（text/event-stream） | 控制面 + 实时推送 |
| Frontend → Backend | HTTPS + JWT | 鉴权后所有请求 |

---

## 服务清单（docker compose 视角）

```yaml
# docker-compose.yml 摘要（去掉了端口细节）
services:
  # 数据与消息
  postgres:        # 事件 / 记忆 / 案例 / 响应日志 / 资产
  redis:           # 限流 / 缓存 / TTL
  kafka:           # 7 个 topic 的消息总线
  schema-registry: # Avro schema（备用）
  zookeeper:       # （KRaft 后基本不再需要）

  # 流处理
  flink-jobmanager:    # Flink 主控
  flink-taskmanager:   # Flink 计算

  # 应用
  backend:         # FastAPI 8001
  frontend:        # React 通过 nginx，3001
  kafka-ui:        # 18082，需登录

  # 反代
  nginx:           # /3002 → Flink Dashboard Basic Auth

  # 观测
  prometheus:      # 指标
  grafana:         # 看板
  tempo:           # 链路追踪后端
  otel-collector:  # 收集并转 tempo
  jaeger:          # （备用 UI）
```

> 完整服务定义见 `docker-compose.yml` 与 `config/*/provisioning/` 下的配置文件。

---

## 关键设计模式

> 读源码时遇到这些模式不要奇怪，它们是平台反复用到的。

### 模式 1 · 多 Topic 分级路由

不是为了用 Kafka 而用 Kafka，而是**让不同重要性的事件走不同消费者**：

```
高分 / 严重  →  security-alerts        →  立即触发响应
中分 / 可疑  →  security-audit-queue   →  LLM 深度审计
全量          →  security-events-enriched → 入库 / 检索
被拒          →  security-logs-rejected → 审计归档
```

### 模式 2 · 三段式异步任务

- **Watchdog**：监控关键进程，挂掉自动拉起（`backend/observability/watchdog.py`）
- **PipelineTracer**：每个事件生成 `trace_id`，贯穿全链路（`observability/pipeline_tracer.py`）
- **HealthMonitor**：HTTP 端点 `/health` 暴露各组件健康（`observability/health_monitor.py`）

### 模式 3 · LLM 4 层流水线

```
原始事件 → Decomposer(拆解威胁) → ToolBuilder(拼工具) →
         Executor(执行工具)     → Reviewer(复核结论) → 响应建议
每一层都有产物，每一层都可被 CAD 独立审计。
```

### 模式 4 · 工具调用安全四闸

任何 LLM 想调用工具必须经过：

```
Registry 白名单 → Permission RBAC → ParamValidator (Pydantic) →
PolicyEngine (规则) → 放行 / 拦截 / 转人工
```

源代码在 `backend/mcp_guard/`，详见 [05 自审计体系](./05-self-audit.md)。

### 模式 5 · 配置即代码

所有路由、Topic、规则、资产白名单都在代码里，通过 `config.py` + `.env` 切换：

- `config.py`：默认配置 + 环境变量读取
- `.env`：敏感信息（密码、API Key）
- `init.sql`：数据库 Schema
- 内存状态 vs 数据库状态：区分缓存（Redis）与权威库（PG）

---

## 部署视角的"两套组合"

```bash
# 开发：源码构建 + 调试端口打开
docker compose up -d --build

# 生产：拉预构建镜像 + 关闭调试端口
IMAGE_TAG=v1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
IMAGE_TAG=v1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

- 镜像发布在 `ghcr.io/<owner>/soc-{backend,frontend,flink}`
- `main` 分支 → `:main` + `:sha-<7>`
- `v*` 标签 → `:<semver>` + `:latest`

> 详细见 [08 部署、运维与调优](./08-deployment.md)。

---

## 下一章

- 想追一条事件  →  [02 数据流与事件生命周期](./02-data-flow.md)
- 想看后端模块地图  →  [03 后端核心模块](./03-backend-modules.md)
- 想看 Flink 怎么写  →  [04 Flink 流处理作业](./04-flink-jobs.md)

---

## 动手点

1. **看 Kafka topic 列表**

   ```bash
   docker exec soc-kafka /opt/kafka/bin/kafka-topics.sh \
     --bootstrap-server localhost:9092 --list
   ```

   应该看到 7 个 `security-*` topic。

2. **看 Flink 作业状态**

   ```bash
   curl -u admin:password http://localhost:3002/api/v1/jobs/overview
   ```

   应该看到 2 个 RUNNING。

3. **看 backend 注册的路由数**

   ```bash
   curl -s http://localhost:8001/openapi.json | jq '.paths | keys | length'
   ```

   应该看到 100+ 端点。

---

> 上一章：[00 项目地图](./00-overview.md) · 下一章：[02 数据流与事件生命周期](./02-data-flow.md)
