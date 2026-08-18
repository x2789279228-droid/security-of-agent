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
| **Flink CEP** | 3 种攻击链模式实时检测 + 部分匹配预警 (端口扫描→C2 / 横向移动 / 数据外泄) |
| **Flink 异常检测** | 频率异常 + 严重度加权 + 时段异常，多维评分 |
| **Sigma 检测引擎** | 11 条规则覆盖 8 类攻击，规则化精确匹配，< 1ms 延迟 |
| **Audit-LLM** | 四层流水线: Decomposer→ToolBuilder→Executor→Reviewer，迭代审核 + 反幻觉 |
| **Grounding 验证** | 三层校验: 程序化字段溯源 + 知识库交叉验证 + LLM 复核 |
| **CAD** | 独立监督角色: 穿透验证 + 上下文审计 + 熔断器 |
| **MCP Guard** | 4 层工具调用控制: 白名单→RBAC→参数校验→规则引擎 |
| **SecurityGuard** | 调用安全守卫: 意图审查 + 序列管控 + 频率限制 + 上下文感知 |
| **Stabilizer** | LLM 输出稳定化: JSON 修复→工具名归一→参数强转→Schema 校验 |
| **响应引擎** | 8 条策略、5 种动作，SSH 真实执行 + iptables 防火墙 + 按 rule_id 回滚 |
| **响应执行安全** | 命令/资产双白名单、执行模式分级、安全执行器、执行后校验、TTL 失效回收 |
| **RAG 知识库** | MITRE ATT&CK / CAPEC 导入，向量检索 + LLM 重排，断言验证 |
| **数据源管理** | API Key 注册/吊销/拒绝日志，解决无差别接收问题 |
| **规则管理** | 动态规则下发/启停，响应策略热更新，无需重启服务 |
| **运营工单** | 告警→工单流转，处置时限、优先级、责任人分配 |
| **案例管理** | 已处置告警沉淀为案例，经验复用，同类告警自动关联 |
| **反馈闭环** | 处置结果回灌检测引擎，误报抑制、漏报补偿 |
| **复盘分析** | 事件后置 Post-Mortem：时间线重建、根因分析、改进项跟踪 |
| **字段加密** | 敏感日志字段 (IP/账号) 落库前脱敏，查询权限控制 |
| **可观测性** | 流水线追踪 (trace_id 贯穿)、健康监控、看门狗自动恢复 |

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

复制 `.env.example` 为 `.env`，填入真实的 API Key 与**安全必填项**:

```env
SHARED_MEMORY_LLM_API_KEY=your-key
SHARED_MEMORY_EMBEDDING_API_KEY=your-key
SHARED_MEMORY_JWT_SECRET=random-secret
SHARED_MEMORY_ADMIN_PASSWORD=your-password
POSTGRES_PASSWORD=your-strong-password
REDIS_PASSWORD=your-redis-password
KAFKA_UI_PASSWORD=your-kafka-ui-password
KAFKA_PUBLIC_HOST=your-host-ip-or-domain   # 外部日志源经 SASL_SSL 连接的地址
```

首次部署还需生成 Flink Dashboard 的 Basic Auth 凭证:

```bash
bash tools/gen-htpasswd.sh admin your-flink-ui-password
```

### 2. 启动全部服务

```bash
docker-compose up -d --build
```

服务地址:
- 前端: http://localhost:3001
- 后端 API: http://localhost:8001 (JWT 保护)
- API 文档: http://localhost:8001/docs
- **Kafka UI**: http://localhost:18082 (登录认证, 账号见 `.env` 的 `KAFKA_UI_USER/PASSWORD`)
- **Flink Dashboard**: http://localhost:3002 (Basic Auth, 凭证由 `tools/gen-htpasswd.sh` 生成)
- Redis / PostgreSQL / Schema Registry 仅绑定 `127.0.0.1`, 不对外网暴露

### 3. 提交 Flink 作业

```bash
# 进入 Flink JobManager 容器提交作业 (REST 8081 不再映射宿主)
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
```

### 4. 注入测试数据 (Kafka 模式)

```bash
# 本机经 PLAINTEXT_HOST(9094, 仅 127.0.0.1) 推送
# 攻击链 → Kafka → Flink CEP 检测
python log_simulator.py --kafka localhost:9094 --mode chain

# 持续日志流 → Kafka
python log_simulator.py --kafka localhost:9094 --mode continuous --interval 2

# 突发注入
python log_simulator.py --kafka localhost:9094 --mode burst --count 50
```

### 5. 兼容旧版 HTTP 直连

```bash
# 不启用 Kafka 时仍可使用 HTTP 直连
python log_simulator.py --mode chain --api http://localhost:8001
```

## CI/CD 与部署

- **CI (合并门禁)**: 每次 PR / push main 自动执行 后端 pytest(覆盖率门禁) → 前端 lint+build → Flink 编译 → Docker 构建校验 (`publish.yml` 推送 GHCR 镜像 `ghcr.io/<owner>/soc-{backend,frontend,flink}`)。
- **镜像版本**: main → `:main` + `:sha-<7>`; 打 `v*` 标签 → `:<semver>` + `:latest`; 生产必须显式指定 `IMAGE_TAG`。
- **环境分离**: dev = `docker-compose.yml`(源码构建); prod = 叠加 `docker-compose.prod.yml`(拉取预构建镜像 + 关闭调试端口)。
- **部署**: `deploy.yml` 手动触发, staging/production 双环境 (production 人工审批), 暂无远程服务器前默认禁用。
- 详细手册见 [`docs/deployment.md`](docs/deployment.md)。

```bash
# 开发
docker compose up -d --build
# 生产
IMAGE_TAG=1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
IMAGE_TAG=1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
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

## 安全加固

针对平台自身的渗透审计结论(Redis 未授权、Flink REST 无认证、配置泄露、
安全响应头缺失、端口过度暴露)已完成加固, 要点如下:

### 端口暴露矩阵

| 服务 | 端口 | 绑定 | 防护 |
|------|------|------|------|
| 前端 Web | 3001 | 对外 | Nginx 隐藏版本 + 完整安全响应头 |
| Flink Dashboard 反代 | 3002 | 对外 | HTTP Basic Auth |
| 后端 API | 8001 | 对外 | JWT + 限流 |
| Kafka UI | 18082 | 对外 | 登录认证 (LOGIN_FORM) |
| Kafka SASL_SSL | 9093 | 对外 | TLS + SCRAM-SHA-512 账号 (见下) |
| Kafka 本机 | 9094 | 127.0.0.1 | 仅本机工具 |
| PostgreSQL | 5433 | 127.0.0.1 | 密码 |
| Redis | 6380 | 127.0.0.1 | requirepass + protected-mode |
| Schema Registry | 8085 | 127.0.0.1 | — |
| Flink REST | 8081 | **不映射** | 经 3002 反代访问 |

### 外部日志源接入 (Kafka SASL_SSL)

1. 生成证书 (首次, `.env` 中设置 `KAFKA_PUBLIC_HOST` 后再执行, SAN 会包含该地址):
   `bash tools/gen-kafka-certs.sh`
2. 启动 Broker 后创建日志源账号:
   `bash tools/create-kafka-users.sh soc-log-source <强密码>`
3. 将 `certs/kafka/ca-cert.pem` 与账号分发给日志源机器, 经 9093 推送:
   ```bash
   python log_simulator.py --kafka <主机IP>:9093 --mode chain \
       --sasl-user soc-log-source --sasl-password <密码> \
       --ca-cert certs/kafka/ca-cert.pem
   ```

### 防火墙白名单 (双保险)

Kafka 9093 虽有认证, 仍建议在网络层限制来源 IP:

```powershell
# Windows: 仅允许日志源网段访问 Kafka
netsh advfirewall firewall add rule name="Kafka-SASL-Allow" dir=in action=allow protocol=TCP localport=9093 remoteip=10.0.20.0/24
```

```bash
# Linux (ufw)
ufw allow from 10.0.20.0/24 to any port 9093 proto tcp
ufw deny 9093
```

### 部署检查清单

- [ ] `.env` 已设置全部 `:?` 必填项 (POSTGRES/REDIS/KAFKA_UI/JWT/ADMIN/KAFKA_PUBLIC_HOST/KAFKA_SSL_PASSWORD)
- [ ] `bash tools/gen-htpasswd.sh <用户> <密码>` 已生成 `config/nginx/flink.htpasswd`
- [ ] 外部验证: `redis-cli -h <主机IP> -p 6380 ping` 与 `curl http://<主机IP>:8081` 均不可达
- [ ] `curl -sI http://localhost:3001/` 无 Nginx 版本号, 且含 X-Frame-Options / CSP 头
- [ ] http://localhost:3002 未登录返回 401

## 项目结构

```
├── flink-jobs/                    # ★ Flink 流处理作业 (Java)
│   ├── pom.xml                    # Maven 项目 (Flink 1.18 + CEP + Kafka)
│   ├── Dockerfile                 # 多阶段构建: Maven → Flink 运行时
│   ├── submit-jobs.sh             # 作业提交脚本
│   └── src/main/java/com/soc/
│       ├── job/
│       │   ├── LogValidationJob.java      # 验证+认证+去重
│       │   ├── AnomalyDetectionJob.java   # 异常评分+CEP攻击链
│       │   ├── CepPatternConfig.java      # CEP 攻击链模式配置
│       │   ├── CepPartialMatchFunction.java # CEP 部分匹配（半截攻击链提示）
│       │   └── SourceReputationFunction.java # 数据源信誉评分
│       ├── model/
│       │   ├── SecurityEvent.java         # 安全事件模型
│       │   └── AlertEvent.java            # 告警事件模型
│       ├── schemas/                       # AVRO 消息 Schema
│       └── util/
│           └── KafkaConfig.java           # Kafka Topic 配置
├── backend/
│   ├── app.py                 # FastAPI 主应用 (50+ 端点)
│   ├── kafka_consumer.py      # ★ Kafka 消费者 (enriched/audit/alerts)
│   ├── kafka_producer.py      # ★ Kafka 生产者 (审计结果回写)
│   ├── source_registry.py     # ★ 数据源注册与认证
│   ├── case_manager.py        # 案例管理与经验复用
│   ├── feedback_loop.py       # 反馈闭环 (误报抑制/漏报补偿)
│   ├── rule_manager.py        # 动态规则管理
│   ├── work_order_service.py  # 运营工单流转
│   ├── post_mortem_service.py # 事件复盘分析
│   ├── field_cipher.py        # 敏感字段脱敏
│   ├── agents/                # Audit-LLM 四层 + CAD
│   ├── response_engine/       # 响应引擎 (策略/执行/审批/SSH/白名单/安全执行器)
│   ├── rag/                   # RAG 知识库 (检索/验证/导入)
│   ├── observability/         # 流水线追踪 / 健康监控 / 看门狗
│   ├── log_ingestion.py       # 日志接入 + 自动审计 + 自动响应
│   ├── anomaly_detector.py    # 异常检测 (Python 侧，兼容 HTTP 模式)
│   ├── correlation_engine.py  # 攻击链关联 (Python 侧)
│   ├── event_bus.py           # 实时事件总线 (SSE)
│   └── scheduler.py           # 定时任务
├── tools/
│   ├── syslog-adapter.py      # ★ Syslog → Kafka 适配器
│   ├── gen-kafka-certs.sh     # Kafka TLS 证书生成 (SAN 含 KAFKA_PUBLIC_HOST)
│   ├── create-kafka-users.sh  # Kafka SCRAM 日志源账号创建 (SASL_SSL 接入)
│   ├── gen-htpasswd.sh        # Flink Dashboard Basic Auth 凭证生成
│   ├── init-kafka-topics.sh   # Topic 初始化
│   └── register-schemas.sh    # Schema 注册
├── frontend/                  # React 前端 (含运营 Operations 页面)
├── docker-compose.yml         # ★ 含 Kafka + Flink + Kafka UI
├── log_simulator.py           # ★ 日志模拟器 (支持 Kafka/HTTP 双模式)
├── init.sql                   # 数据库 Schema
└── demo_e2e.py                # 端到端演示验证
```

> 说明: 仓库会同步推送到 `security-of-agent` 与 `security-of-agent-max` 两个远端。
