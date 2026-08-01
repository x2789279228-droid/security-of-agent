# 共享记忆安全审计 Agent 平台

全自动安全审计 Agent 平台，基于 **Kafka + Flink** 流处理架构，集成数据源认证、实时异常检测、攻击链 CEP、LLM 智能审计与自动响应执行。

## 架构 (Kafka + Flink)

```
日志源 (syslog/API/模拟器)
    │  携带 API Key 认证
    ▼
┌─────────────────────────────────────────────────────────┐
│  Kafka: security-logs-raw                               │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Flink Job 1: LogValidationJob                          │
│  ① Schema 校验 (必填字段/类型)                           │
│  ② 数据源认证 (API Key 白名单)                           │
│  ③ 字段归一化 (severity 映射/截断)                       │
│  ④ 60s 去重 (srcIp+eventType+messageHash)               │
└──────┬──────────────────────────────┬───────────────────┘
       ▼                              ▼
  security-logs-rejected       security-logs-validated
  (拒绝记录+原因)                     │
                                      ▼
┌─────────────────────────────────────────────────────────┐
│  Flink Job 2: AnomalyDetectionJob                       │
│  ① 多维异常评分 (频率/严重度/时段)                       │
│  ② Flink CEP 攻击链检测 (3种模式)                       │
│  ③ 智能分级路由                                         │
└──┬──────────────┬──────────────────┬────────────────────┘
   ▼              ▼                  ▼
security-     security-          security-
alerts        audit-queue        events-enriched
(即时告警)    (LLM审计)          (全量存储)
   │              │                  │
   ▼              ▼                  ▼
响应引擎     Audit-LLM 流水线    EventStore + 记忆树
(策略匹配)   (Decomposer→       (PostgreSQL)
(SSH执行)     ToolBuilder→
              Executor→
              Reviewer)
                 │
                 ▼
            CAD 独立监督
            (熔断器+穿透验证)
```

## 核心模块

| 模块 | 说明 |
|------|------|
| **Kafka 消息总线** | 7 个 Topic 分级路由，解耦数据源与处理引擎，支持重放 |
| **Flink 验证** | Schema 校验 + API Key 认证 + 去重，拒绝非法数据源 |
| **Flink CEP** | 3 种攻击链模式实时检测 (端口扫描→C2 / 横向移动 / 数据外泄) |
| **Flink 异常检测** | 频率异常 + 严重度加权 + 时段异常，多维评分 |
| **Sigma 检测引擎** | 11 条规则覆盖 8 类攻击，规则化精确匹配，< 1ms 延迟 |
| **Audit-LLM** | 四层流水线: Decomposer→ToolBuilder→Executor→Reviewer，迭代审核 + 反幻觉 |
| **Grounding 验证** | 三层校验: 程序化字段溯源 + 知识库交叉验证 + LLM 复核 |
| **CAD** | 独立监督角色: 穿透验证 + 上下文审计 + 熔断器 |
| **MCP Guard** | 4 层工具调用控制: 白名单→RBAC→参数校验→规则引擎 |
| **SecurityGuard** | 调用安全守卫: 意图审查 + 序列管控 + 频率限制 + 上下文感知 |
| **Stabilizer** | LLM 输出稳定化: JSON 修复→工具名归一→参数强转→Schema 校验 |
| **响应引擎** | 8 条策略、5 种动作，SSH 真实执行 + iptables 防火墙 + 按 rule_id 回滚 |
| **RAG 知识库** | MITRE ATT&CK / CAPEC 导入，向量检索 + LLM 重排，断言验证 |
| **数据源管理** | API Key 注册/吊销/拒绝日志，解决无差别接收问题 |

## 技术栈

- **消息总线**: Apache Kafka 3.7 (KRaft 模式)
- **流处理**: Apache Flink 1.18 (Java, CEP + DataStream API)
- **后端**: FastAPI + SQLAlchemy + pgvector + Redis + aiokafka
- **安全工具**: paramiko SSH + iptables + nmap (真实防火墙操作)
- **工具调用控制**: MCP Guard 4 层检查 + SecurityGuard 安全守卫
- **前端**: React 19 + TypeScript + Tailwind CSS 4 + Framer Motion
- **LLM**: OpenAI 兼容 API (mimo-v2.5)
- **部署**: Docker Compose (PostgreSQL 16 + Redis 7 + Kafka + Flink)
- **可视化**: Kafka UI (Topic 监控 / 消息浏览)

## 快速启动

### 1. 配置环境变量

编辑 `.env`，填入真实的 API Key:

```env
SHARED_MEMORY_LLM_API_KEY=your-key
SHARED_MEMORY_EMBEDDING_API_KEY=your-key
SHARED_MEMORY_JWT_SECRET=random-secret
SHARED_MEMORY_ADMIN_PASSWORD=your-password
SHARED_MEMORY_KAFKA_ENABLED=true
```

### 2. 启动全部服务

```bash
docker-compose up -d --build
```

服务地址:
- 前端: http://localhost:3001
- 后端 API: http://localhost:8001
- API 文档: http://localhost:8001/docs
- **Kafka UI**: http://localhost:8080 (Topic 监控 / 消息浏览)
- **Flink Dashboard**: http://localhost:8081 (作业状态 / 吞吐量)

### 3. 提交 Flink 作业

```bash
# 进入 Flink JobManager 容器提交作业
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
```

### 4. 注入测试数据 (Kafka 模式)

```bash
# 攻击链 → Kafka → Flink CEP 检测
python log_simulator.py --kafka localhost:9092 --mode chain

# 持续日志流 → Kafka
python log_simulator.py --kafka localhost:9092 --mode continuous --interval 2

# 突发注入
python log_simulator.py --kafka localhost:9092 --mode burst --count 50
```

### 5. 兼容旧版 HTTP 直连

```bash
# 不启用 Kafka 时仍可使用 HTTP 直连
python log_simulator.py --mode chain --api http://localhost:8001
```

## Kafka Topic 说明

| Topic | 说明 | 生产者 | 消费者 |
|-------|------|--------|--------|
| `security-logs-raw` | 原始日志入口 | syslog-adapter / log_simulator | Flink Job 1 |
| `security-logs-validated` | 已验证日志 | Flink Job 1 | Flink Job 2 |
| `security-logs-rejected` | 被拒绝日志 (含原因) | Flink Job 1 | 审计归档 |
| `security-events-enriched` | 富化事件 (含异常分) | Flink Job 2 | Backend (存储) |
| `security-alerts` | 高优先级告警 | Flink Job 2 | Backend (响应引擎) |
| `security-audit-queue` | LLM 审计队列 | Flink Job 2 | Backend (Audit-LLM) |
| `security-audit-results` | 审计结果 | Backend | 前端 SSE / 归档 |

## 项目结构

```
├── flink-jobs/                    # ★ Flink 流处理作业 (Java)
│   ├── pom.xml                    # Maven 项目 (Flink 1.18 + CEP + Kafka)
│   ├── Dockerfile                 # 多阶段构建: Maven → Flink 运行时
│   ├── submit-jobs.sh             # 作业提交脚本
│   └── src/main/java/com/soc/
│       ├── job/
│       │   ├── LogValidationJob.java      # 验证+认证+去重
│       │   └── AnomalyDetectionJob.java   # 异常评分+CEP攻击链
│       ├── model/
│       │   ├── SecurityEvent.java         # 安全事件模型
│       │   └── AlertEvent.java            # 告警事件模型
│       └── util/
│           └── KafkaConfig.java           # Kafka Topic 配置
├── backend/
│   ├── app.py                 # FastAPI 主应用 (50+ 端点)
│   ├── kafka_consumer.py      # ★ Kafka 消费者 (enriched/audit/alerts)
│   ├── kafka_producer.py      # ★ Kafka 生产者 (审计结果回写)
│   ├── source_registry.py     # ★ 数据源注册与认证
│   ├── agents/                # Audit-LLM 四层 + CAD
│   ├── response_engine/       # 响应引擎 (策略/执行/审批/SSH)
│   ├── rag/                   # RAG 知识库 (检索/验证/导入)
│   ├── log_ingestion.py       # 日志接入 + 自动审计 + 自动响应
│   ├── anomaly_detector.py    # 异常检测 (Python 侧，兼容 HTTP 模式)
│   ├── correlation_engine.py  # 攻击链关联 (Python 侧)
│   ├── event_bus.py           # 实时事件总线 (SSE)
│   └── scheduler.py           # 定时任务
├── tools/
│   └── syslog-adapter.py      # ★ Syslog → Kafka 适配器
├── frontend/                  # React 前端
├── docker-compose.yml         # ★ 含 Kafka + Flink + Kafka UI
├── log_simulator.py           # ★ 日志模拟器 (支持 Kafka/HTTP 双模式)
├── init.sql                   # 数据库 Schema
└── demo_e2e.py                # 端到端演示验证
```
