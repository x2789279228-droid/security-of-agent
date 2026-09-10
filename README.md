# 共享记忆安全审计 Agent 平台

> 🚀 **第一次接触本项目？** 请先看 [`docs/study-guide/知识手册.md`](docs/study-guide/知识手册.md)（18 章连贯学习手册，71 KB）；速通者看 [`docs/study-guide/速查.md`](docs/study-guide/速查.md)；喜欢 PDF 排版看 [`docs/study-guide/总览-PDF风.md`](docs/study-guide/总览-PDF风.md)。
> 📚 完整文档导航见 [`docs/INDEX.md`](docs/INDEX.md)。

**全自动安全审计 Agent 平台**：从日志接入、实时异常检测、攻击链 CEP、LLM 智能审计，到响应执行、复盘沉淀，形成闭环。基于 **Kafka + Flink 1.19.3 + Java 11** 流处理主干，叠加 NDR / EDR / Threat Intel / 反钓鱼 / 红蓝自博弈 / UEBA-for-AI / 因果推断等 30+ 后端模块。

---

## 项目定位

| 维度 | 内容 |
|------|------|
| **业务问题** | 安全运营中心 (SOC) 的告警噪声、跨域关联、响应滞后、规则僵化、Agent 行为失控五大痛点 |
| **解决方式** | 流式数据底座 + 规则/Sigma 引擎兜底 + LLM 智能审计 + 自动响应 + 红蓝自博弈持续进化 + 工具调用四层控制 |
| **核心能力** | 30 个后端子模块、16 个 Router、219 个 REST 端点、16 个前端页面、9 个 Flink 作业、7 类 Kafka Topic、98 项后端测试 |
| **目标用户** | 企业 SOC 运营方 / MSSP 安全托管 / 高校与竞赛团队 / 平台自审计研究 |
| **场景** | 揭榜挂帅（共享记忆）智能体竞赛 · 校级 SOC 试点 · 攻防演练与红蓝自博弈训练 |

---

## 架构 (Kafka + Flink 1.19.3)

```
日志源 (syslog/API/EDR/NDR/反钓鱼)
    │  经 API Key 或 SASL_SSL 认证
    ▼
┌─────────────────────────────────────────────────────────┐
│  Kafka: security-logs-raw (7 类 Topic 分级路由)         │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Flink 作业群 (3 核心 + 4 扩展)                          │
│  ── 核心 ──                                              │
│  LogValidationJob              ① 校验 ② 认证 ③ 去重     │
│  AnomalyDetectionJob           ④ 异常评分 ⑤ CEP 攻击链   │
│  SigmaThresholdAggregationJob  ⑥ Sigma 阈值聚合          │
│  ── 扩展 (NDR / EDR, 默认关闭, 见 §3) ──                │
│  FlowAggregationJob            ⑦ 网络流聚合              │
│  TlsFingerprintJob             ⑧ TLS/JA3 指纹           │
│  BehaviorAnomalyJob            ⑨ 行为异常                │
└──────┬──────────────────────────────┬───────────────────┘
       ▼                              ▼
  security-logs-rejected       security-logs-validated
  (拒绝记录+原因)                     │
                                      ▼
                  ┌───────────────────┴─────────────┐
                  ▼                                 ▼
        security-alerts (高危)         security-audit-queue (LLM)
                  │                                 │
                  ▼                                 ▼
          响应引擎 (策略/审批/         Audit-LLM 四层流水线
          白名单/SSH/执行)            Decomposer→ToolBuilder
                  │                  →Executor→Reviewer
                  ▼                       │
          8 类动作 + 5 种执行模式         ▼
                  │                 CAD 独立监督
                  ▼                 (熔断器+穿透验证)
          安全执行器 + 回滚                │
                  │                       ▼
                  └────────► security-audit-results ◄──┘
                                    │
                                    ▼
                            EventStore + 记忆树
                            (PostgreSQL + Qdrant)
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
     红蓝自博弈闭环          学习闭环 (learn_loop)    运营工单/案例/复盘
     (self_play)            (规则挖掘+改进)         (work_order/case/post_mortem)
```

辅助通路（横向能力）：`causal_chain` 因果推断（PC / GES / do-calculus）→ `phishing_guard` 反钓鱼 6 通道 → `mcp_guard` 4 层工具调用控制 → `security_guard` 调用安全守卫 → `tool_behavior_signature` UEBA-for-AI → `sigma_engine` 25+ 规则动态管理。

---

## 核心模块（按后端 30 个子目录分组）

### 数据接入与流处理

| 模块 | 说明 |
|------|------|
| **Kafka 消息总线** | 7 个 Topic 分级路由（raw / validated / rejected / events-enriched / alerts / audit-queue / audit-results），支持重放与解耦 |
| **Flink 验证 (LogValidationJob)** | Schema 校验 + API Key 白名单 + 60 s 去重 (srcIp+eventType+messageHash) |
| **Flink 异常检测 (AnomalyDetectionJob)** | 多维异常评分 (频率/严重度/时段) + Flink CEP 攻击链 (3 模式) + 部分匹配预警 |
| **Flink Sigma 聚合 (SigmaThresholdAggregationJob)** | Sigma 规则阈值滚动聚合，写回 alerts/audit-queue |
| **Flink 网络流 (FlowAggregationJob)** | 5 元组聚合 + 异常会话标记 |
| **Flink TLS 指纹 (TlsFingerprintJob)** | JA3 / SNI / 证书元数据流式提取 |
| **Flink 行为异常 (BehaviorAnomalyJob)** | 跨域行为序列实时打分 |
| **数据源管理 (source_registry)** | API Key 注册 / 吊销 / 拒绝日志，解决无差别接收 |
| **日志接入 (log_ingestion)** | HTTP 模式兼容入口 + 自动审计 + 自动响应触发 |
| **Kafka 生产者/消费者 (kafka_producer / kafka_consumer)** | 审计结果回写 + 富化事件消费 + 告警消费 |
| **Syslog 适配器 (tools/syslog-adapter.py)** | syslog → Kafka 桥接 |

### LLM 智能审计与监督

| 模块 | 说明 |
|------|------|
| **Audit-LLM 四层流水线** | Decomposer → ToolBuilder → Executor → Reviewer，迭代审核 + 反幻觉 |
| **6 类 Agent (agents/)** | `agent_a` 数据 / `agent_b` 富化 / `agent_c` 决策 / `agent_d` 复核 / `agent_cad` 监督 + 流水线基类 |
| **CAD 独立监督** | 穿透验证 + 上下文审计 + 熔断器（运行于 `agents/agent_cad.py`） |
| **Sub-Auditor (sub_auditor)** | 复杂事件拆解给多个 Sub-Agent 并行审议 |
| **Grounding 验证 (grounding_verifier)** | 三层校验：程序化字段溯源 + 知识库交叉 + LLM 复核 |
| **Faithfulness Gate (faithfulness_gate)** | 阻断 LLM 自相矛盾或越权断言 |
| **Veto Gates (veto_gates)** | 多级一票否决（数据/工具/响应层） |
| **Stabilizer** | LLM 输出稳定化：JSON 修复 → 工具名归一 → 参数强转 → Schema 校验 |
| **LLM Fallback (agents/llm_fallback)** | 主备模型切换 + 降级策略 + 限流 (llm_limiter) |
| **Prompt 管理 (prompts/)** | Loader + 版本化模板 |

### 工具调用与 Agent 行为安全

| 模块 | 说明 |
|------|------|
| **MCP Guard (mcp_guard/)** | 4 层工具调用控制：白名单 → RBAC → 参数校验 → 规则引擎，含行为签名 (behavior_signature) 与行为检测 (behavior_detector) |
| **Security Guard (security_guard/)** | 调用安全守卫：意图审查 (intent_checker) + 序列管控 (sequence_guard) + 频率限制 (rate_limiter) + 上下文感知 (context_manager) |
| **Tool Behavior Signature** | UEBA-for-AI：工具调用行为画像、偏离基线告警 |
| **Tool Registry (tool_registry)** | 工具注册中心 + 签名 + 调用统计 |
| **Approval Queue (mcp_guard/approval_queue)** | 高危工具人工审批队列 |
| **Permission Manager** | 动态 RBAC + 角色继承 |

### 响应引擎与执行安全

| 模块 | 说明 |
|------|------|
| **响应策略 (response_policies)** | 多维匹配：threat_type / min_confidence / min_severity / 源 IP 信誉度 |
| **响应编排 (response_orchestrator)** | 决策 → 预览 → 审批 → 执行 → 验证 → 回滚 全链路 |
| **安全执行器 (safe_executor)** | 命令/资产双白名单 + 执行模式分级 (execution_modes) + 执行后校验 (post_validator) + TTL 失效回收 (ttl_manager) |
| **SSH 防火墙 (ssh_firewall)** | paramiko 真实 SSH + iptables 真实防火墙操作 + 主机响应适配 (containment/host_adapter) |
| **Containment (containment/)** | 主机 / 邮箱 / 目录三类适配器，事件闭环隔离 |
| **Transport (transport)** | 多协议执行通道 (SSH / API / 邮件) |
| **资产白名单 (asset_whitelist)** | 动态资产管理 + 操作约束 |
| **人工审批 (human_approval)** | 分级审批 (高/中/低风险) + 审批理由审计 |
| **威胁分类法 (threat_taxonomy)** | 5 级威胁类型分类树 |
| **响应日志 (response_log)** | 全链路不可篡改审计日志 |
| **策略存储 (policy_store)** | 热更新策略中心 |

### 检测引擎与攻击建模

| 模块 | 说明 |
|------|------|
| **Sigma 检测引擎 (sigma_engine / sigma_detector)** | 25+ 规则 (4 类目录：默认 / 社区活跃 / 社区候选 / 自博弈影子)，动态启停 + 规则导入 (dry_run_import) + 引擎 (engine) + 映射 (mapping) |
| **CEP 攻击链 (CepPatternConfig / CepPartialMatchFunction)** | 端口扫描→C2 / 横向移动 / 数据外泄 3 模式 + 部分匹配 |
| **源信誉评分 (SourceReputationFunction)** | 数据源动态信誉 + 信誉衰减 |
| **异常检测 (anomaly_detector)** | Python 侧兼容 HTTP 模式 + 频率/严重度/时段多维评分 |
| **攻击链关联 (correlation_engine)** | 跨事件时间窗关联 + 攻击重建 |
| **行为异常分析 (zeroday_detect/behavior_analyzer)** | 0day 检测：变体聚类 (variant_cluster) + LLM 行为 (llm_behavior) + 沙箱对接 (sandbox_connector) |

### NDR / EDR / Threat Intel / 反钓鱼

| 模块 | 说明 |
|------|------|
| **加密流量 (encrypted_traffic/)** | TLS 元数据 (tls_metadata) + 会话采集 (session_collector) + MITM 代理 (mitm_proxy) + JA3 指纹 (ja3_fingerprint) + 证书分析 (cert_analyzer) + LLM TLS 分析 |
| **流量采集 (traffic_capture/)** | 抓包引擎 (capture_engine) + PCAP 存储 (pcap_store) + 流聚合 (flow_aggregator) |
| **协议解析 (protocol_parser/)** | TLS / SMB / HTTP / DNS / 通用 dissector |
| **流量基线 (traffic_baseline/)** | 时序季节性 (seasonal) + 同侪组 (peer_group) + LLM 异常 (llm_anomaly) |
| **EDR 融合 (edr_fusion/)** | 适配器 (edr_adapter) + Sysmon/WinEvent 解析 (sysmon_parser / winevent_parser) + LLM 关联 (llm_correlation) + 跨源关联 (cross_correlator) |
| **IDS 对接 (ids_connector/suricata_connector)** | Suricata EVE JSON 接入 |
| **威胁情报 (threat_intel/)** | STIX/TAXII 拉取 + IOC 匹配 (ioc_matcher) + 信誉 (reputation) + 富化 (intel_enricher) + LLM 上下文 |
| **反钓鱼 (phishing_guard/)** | 6 通道：邮件 (email_detector) / BEC (bec_detector) / 网站 (web_detector) / SMS / 二维码 (qrcode_detector) / 附件 (attachment_detector) + LLM 维度 (llm_dimension) + 评分 (scoring) + 演练 (drill_manager) |

### 知识库与 RAG

| 模块 | 说明 |
|------|------|
| **RAG (rag/)** | 检索 (retriever) + 重排 (reranker) + 查询转换 (query_transform) + 词法 (lexical) + 上下文构建 (context_builder) + 分块 (chunker) |
| **MITRE / CAPEC 导入** | mitre_importer / capec_importer + seeder + 导入状态 (import_status) |
| **证据验证 (evidence_verifier)** | 断言级证据验证 |
| **向量存储 (vector_store / qdrant_store)** | PostgreSQL pgvector + Qdrant 双引擎，迁移工具齐备 |
| **知识库 (knowledge_base)** | 文档生命周期管理 |

### 运营闭环

| 模块 | 说明 |
|------|------|
| **运营工单 (work_order_service)** | 告警→工单流转 + 处置时限 + 优先级 + 责任人 |
| **案例管理 (case_manager)** | 已处置告警沉淀 + 经验复用 + 同类告警自动关联 |
| **反馈闭环 (feedback_loop)** | 处置结果回灌检测引擎 + 误报抑制 + 漏报补偿 |
| **复盘分析 (post_mortem_service)** | 事件后置 Post-Mortem：时间线重建 + 根因 + 改进项跟踪 |
| **学习闭环 (learn_loop/)** | 规则挖掘 (propose) + 编排 (orchestrator) + 收割 (harvest) + 应用 (apply) + 序列/聚类/统计模型 |
| **红蓝自博弈 (self_play/)** | 红队 (red_agent) + 蓝队 (blue_learner / blue_observer) + 编排 (orchestrator) + 仿真环境 (sim_env) + 课程 (curriculum) + 新颖度 (novelty) + Sigma 导出 + 规则生命周期 + 评审 (reviewer) |
| **KPI 计算 (ops_metrics/)** | SLA 跟踪 (sla_tracker) + KPI 聚合 (kpi_calculator) |

### 因果推断与因果链

| 模块 | 说明 |
|------|------|
| **因果链 (causal_chain/)** | PC 算法 (pc) / GES 算法 (ges) / do-calculus (do_calculus) / 变量定义 (variables) / 存储 (store) / 学习 (learn) / 对比 (compare) |
| **会话重建 (session_reconstruct)** | 跨事件会话串联 |
| **事件归档 (event_archive)** | 长期归档与回溯 |

### 时序工作流

| 模块 | 说明 |
|------|------|
| **Temporal (temporal/)** | Temporal 工作流：长跑任务 (审计重做 / 复盘) 跨服务编排与补偿 |

### 可观测性与安全

| 模块 | 说明 |
|------|------|
| **可观测性 (observability/)** | 流水线追踪 (pipeline_tracer) + 健康监控 (health_monitor) + 看门狗 (watchdog) + 阶段事件 (stage_events) + 思维事件 (thought_events) |
| **OTEL 接入 (otel_setup)** | OpenTelemetry 链路追踪 + 采样 (docs/otel_sampling.md) |
| **事件总线 (event_bus)** | SSE 实时事件总线 |
| **字段加密 (field_cipher + security_crypto)** | 敏感日志字段 (IP / 账号) 落库前脱敏 + 国密算法 (TEE-GM, 见 docs/upgrade-proposals/2026-q3-tee-gm-crypto.md) |
| **Schema Registry (schema_registry)** | AVRO Schema 注册与兼容检查 |
| **数据安全 (data_security/llm_classifier)** | 流出内容合规分类 |

---

## 技术栈

- **消息总线**: Apache Kafka 3.7 (KRaft 模式)
- **流处理**: Apache Flink **1.19.3** (Java 11, CEP + DataStream API, Kafka Connector 3.2.0-1.19)
- **后端**: FastAPI + SQLAlchemy (async) + pgvector + Qdrant + Redis + aiokafka + Temporal
- **AI**: OpenAI 兼容 LLM + Embedding (mimo-v2.5) + UEBA-for-AI (tool_behavior_signature)
- **安全工具**: paramiko SSH + iptables + Suricata + nmap (真实防火墙操作)
- **工具调用控制**: MCP Guard 4 层检查 + Security Guard 安全守卫 + Veto Gates
- **前端**: React 19 + TypeScript + Tailwind CSS 4 + Framer Motion + 自研组件库 (`components/{brand,home,monitor,operations,rag,phishing,ui,hero,common,chat,login,memories}`)
- **可视化**: Kafka UI (Topic 监控 / 消息浏览) + Prometheus + Grafana (经 OTEL)
- **部署**: Docker Compose (PostgreSQL 16 + Redis 7 + Kafka + Flink + Qdrant + Temporal)
- **测试**: pytest (98 项后端测试) + 前端 lint/build + Flink 编译 + Docker 构建校验

---

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

> **说明**: `--build` 是必须的，因为 `soc-backend` / `soc-frontend` / `soc-flink` 三个自研镜像托管在**私有 GHCR**，源码提交包**不依赖远程镜像**。`docker-compose.yml` 已移除 `image:` 行，每个 service 都走本地 Dockerfile build。首次启动会本地构建这三个镜像，约 **5-15 分钟**（取决于机器 CPU 与网络）；之后 `docker compose up -d` 会复用本地缓存，不再重新 build。

服务地址:

| 服务 | 地址 | 认证 |
|------|------|------|
| 前端 Web | http://localhost:3001 | JWT (登录页) |
| 后端 API | http://localhost:8001 | JWT |
| API 文档 | http://localhost:8001/docs | — |
| Kafka UI | http://localhost:18082 | LOGIN_FORM (`KAFKA_UI_USER/PASSWORD`) |
| Flink Dashboard | http://localhost:3002 | HTTP Basic (`tools/gen-htpasswd.sh` 生成) |
| Redis / PostgreSQL / Schema Registry | 127.0.0.1 | 仅本机工具 |
| Qdrant | 127.0.0.1:6333 | 仅本机工具 |
| Temporal | 127.0.0.1:7233 | 仅本机工具 |

### 3. Flink 作业提交

作业启动已自动化:compose 内置 `flink-job-submitter` 守护服务,`docker compose up -d`
后无需任何手动命令,待 JobManager 与 3×TaskManager(集群 15 并发槽)就绪即自动提交
LogValidationJob / AnomalyDetectionJob / SigmaThresholdAggregationJob 三个核心作业;
JobManager 重启或作业失败后亦会自动补交(幂等,不产生双实例)。

```bash
# 查看提交日志
docker compose logs -f flink-job-submitter

# 手动(兜底)重提 — 仅重提默认 3 个核心作业, 守护本就幂等, 手动仅排查用
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager

# 可选: 额外启用 NDR/EDR 扩展作业 (Flow/TLS/Behavior, 需先自行核实输出 topic 端到端消费)
#   槽位告警: 默认 3 作业并行度 5 已用满集群 15 槽; 再加 NDR (共 6 作业×上行并行)
#   可能槽位不足 → 先调低 FLINK_PARALLELISM 或扩充 TaskManager 再执行。
docker exec -e SUBMIT_NDR_JOBS=1 -e FLINK_PARALLELISM=2 \
  soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
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

### 6. 端到端验证

```bash
python demo_e2e.py          # 一键全链路验证
python demo_start.bat       # Windows 批处理版
```

---

## CI/CD 与部署

- **CI (合并门禁)**: 每次 PR / push main 自动执行 后端 pytest(覆盖率门禁, 98 项) → 前端 lint+build → Flink 编译 → Docker 构建校验 (`publish.yml` 推送 GHCR 镜像 `ghcr.io/<owner>/soc-{backend,frontend,flink}`)。
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

---

## Kafka Topic 说明

| Topic | 说明 | 生产者 | 消费者 |
|-------|------|--------|--------|
| `security-logs-raw` | 原始日志入口 | syslog-adapter / log_simulator / EDR / NDR | Flink Job 1 |
| `security-logs-validated` | 已验证日志 | Flink Job 1 | Flink Job 2 |
| `security-logs-rejected` | 被拒绝日志 (含原因) | Flink Job 1 | 审计归档 |
| `security-events-enriched` | 富化事件 (含异常分) | Flink Job 2 | Backend (存储) |
| `security-alerts` | 高优先级告警 | Flink Job 2 | Backend (响应引擎) |
| `security-audit-queue` | LLM 审计队列 | Flink Job 2 | Backend (Audit-LLM) |
| `security-audit-results` | 审计结果 | Backend | 前端 SSE / 归档 |

NDR/EDR 扩展作业输出 topic 见 `flink-jobs/src/main/java/com/soc/util/KafkaConfig.java`。

---

## 安全加固

针对平台自身的渗透审计结论(Redis 未授权、Flink REST 无认证、配置泄露、
安全响应头缺失、端口过度暴露)已完成加固, 要点如下:

### 端口暴露矩阵

| 服务 | 端口 | 绑定 | 防护 |
|------|------|------|------|
| 前端 Web | 3001 | 对外 | Nginx 隐藏版本 + 完整安全响应头 |
| Flink Dashboard 反代 | 3002 | 对外 | HTTP Basic Auth |
| 后端 API | 8001 | 对外 | JWT + 限流 (域级豁免 + 高危端点点名限流, 见下) |
| Kafka UI | 18082 | 对外 | 登录认证 (LOGIN_FORM) |
| Kafka SASL_SSL | 9093 | 对外 | TLS + SCRAM-SHA-512 账号 (见下) |
| Kafka 本机 | 9094 | 127.0.0.1 | 仅本机工具 |
| PostgreSQL | 5433 | 127.0.0.1 | 密码 |
| Redis | 6380 | 127.0.0.1 | requirepass + protected-mode |
| Schema Registry | 8085 | 127.0.0.1 | — |
| Qdrant | 6333 | 127.0.0.1 | — |
| Temporal | 7233 | 127.0.0.1 | — |
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

### HTTP 限流策略 (2026-09-10 重定)

全局限流是 `backend/app.py::rate_limit_middleware` 的 60s 滑窗 (每桶 `SHARED_MEMORY_RATE_LIMIT_PER_MINUTE` 次, 默认 120), 桶 key 按 `X-API-Key > Bearer > X-Forwarded-For > client_ip` 区分。判定表在 `backend/http_guards.py`:

| 类别 | 规则 | 示例 |
|------|------|------|
| 豁免 (`RATE_LIMIT_WHITELIST`, 51 条前缀/端点) | 全部业务域 / 运营只读端点 / 探针 / 文档不计入滑窗 | `/api/cases`、`/api/agent-traces/*`、`/api/observability/*`、`/api/tree/*`、`/api/cad/*`、`/api/audit-llm/*`、`/metrics` |
| 点名限流 (`RATE_LIMIT_FORCED`, 31 条) | 已豁免前缀中的**不可逆高危动作 + LLM 重端点**仍限流, 并使用独立 `crit:` 桶 (不被普通流量占额度) | `POST /api/response/execute`、`POST /api/response/rollback`、`POST /api/firewall/connect`、`POST /api/guard/call`、`POST /api/logs/ingest`、`POST /api/rules`、`POST /api/phishing/detect/*` |
| 未归类 | 走全局 `std:` 桶 (默认限流) | 新增业务域未归类时 |

- 方法敏感: 如 `/api/response/approvals` 的 `GET` 豁免、`POST` (审批/预览) 限流; `/api/rules` 读豁免、写限流。
- 现场热调: `SHARED_MEMORY_RATE_LIMIT_WHITELIST` 追加豁免前缀 (逗号分隔, 只增不减), 无需改代码。
- 防复发守卫: `backend/tests/test_route_classification.py` 遍历全部路由, 任何未归类的新端点会直接让测试失败, 而不是上线后 429。
- 另有两层独立限流不受此白名单影响: 登录防爆破 429 (`routers/auth.py`)、响应动作级 30/min (`security_guard/rate_limiter.py`)。

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

---

## 能力索引（16 个后端 Router · 16 个前端页面 · 9 个 Flink 作业）

### 后端 REST 端点（按 router 聚合, 总计 219）

| Router | 端点数 | 端点前缀 |
|--------|------:|---------|
| `ops.py` | 63 | 运营总览 / 工单 / 案例 / 反馈 / 复盘 / 规则 / 资产 / KPI / 学习 / 跟踪 |
| `audit.py` | 22 | 审计流水线 / CAD / 思维链 / 监督 |
| `response.py` | 21 | 响应编排 / 执行 / 回滚 / 审批 / 预览 |
| `phishing.py` | 20 | 邮件 / BEC / 网站 / SMS / 二维码 / 附件 + 演练 |
| `rag.py` | 19 | 检索 / 重排 / 导入 / 评估 |
| `chat.py` | 13 | 对话 / 解释 / 摘要 |
| `logs.py` | 10 | 日志接入 / 查询 / 富化 |
| `edr_intel.py` | 9 | EDR 接入 / 威胁情报 |
| `self_play.py` | 9 | 自博弈 / 红蓝 / 课程 / 评估 |
| `kafka.py` | 8 | Kafka 拓扑 / 主题 / 偏移 |
| `assets.py` | 6 | 资产 CRUD / 关联 |
| `auth.py` | 5 | 登录 / 注册 / 刷新 |
| `causal.py` | 4 | 因果链 / PC / GES / do-calculus |
| `ndr.py` | 4 | NDR 流 / TLS / 会话 |
| `sources.py` | 4 | 数据源 CRUD / 认证 |
| `capabilities.py` | 1 | B 类能力开关 + Prometheus 聚合 |

### 前端页面（16 个）

| 页面 | 路径 |
|------|------|
| **Home** | `pages/Home.tsx` — 守望品牌首页（Hero / Blueprint / Manifesto / ShiftConsole） |
| **Monitor** | `pages/Monitor.tsx` — 实时监控（事件流 / 思维链 / 工具签名 / 管道） |
| **Operations** | `pages/Operations.tsx` — 运营中心（14 个 Tab：概览 / KPI / 工单 / 案例 / 反馈 / 复盘 / 规则 / 审计 / 跟踪 / 学习 / 资产 / 成本 / 生命周期 / 徽记） |
| **Logs** | `pages/Logs.tsx` — 日志检索 / 富化 |
| **Response** | `pages/Response.tsx` — 响应编排 / 审批 / 执行 |
| **RAG** | `pages/RAG.tsx` — 知识库检索 / 重排 / 质量 |
| **Phishing** | `pages/PhishingDetect.tsx` — 反钓鱼演练 / 检测（独立组件，因含 6 通道） |
| **Intel** | `pages/Intel.tsx` — 威胁情报 / IOC |
| **EDR** | `pages/EDR.tsx` — EDR 融合视图 |
| **Traffic** | `pages/Traffic.tsx` — 流量基线 / 异常 |
| **Encrypted** | `pages/Encrypted.tsx` — 加密流量 / TLS 指纹 |
| **Sandbox** | `pages/Sandbox.tsx` — 0day 沙箱 |
| **SelfPlay** | `pages/SelfPlay.tsx` — 红蓝自博弈 |
| **SecurityAudit** | `pages/SecurityAudit.tsx` — 平台自审计 |
| **CapabilitiesDashboard** | `pages/CapabilitiesDashboard.tsx` — 能力开关总览 |
| **Login / Register** | `pages/{Login,Register}.tsx` |

### Flink 作业（9 个 Java 作业）

| 作业 | 角色 | 默认启用 |
|------|------|---------|
| **LogValidationJob** | 校验 + 认证 + 去重 | ✅ |
| **AnomalyDetectionJob** | 多维异常 + CEP 攻击链 | ✅ |
| **SigmaThresholdAggregationJob** | Sigma 规则阈值聚合 | ✅ |
| **FlowAggregationJob** | NDR 5 元组聚合 | 可选 (`SUBMIT_NDR_JOBS=1`) |
| **TlsFingerprintJob** | TLS/JA3 指纹 | 可选 |
| **BehaviorAnomalyJob** | 跨域行为异常 | 可选 |
| `CepPatternConfig` | CEP 模式定义 (内嵌) | ✅ |
| `CepPartialMatchFunction` | CEP 部分匹配 (内嵌) | ✅ |
| `SourceReputationFunction` | 数据源信誉 (内嵌) | ✅ |

---

## 测试矩阵

| 层级 | 命令 | 覆盖 |
|------|------|------|
| 后端单元/集成 | `pytest backend/tests -q` | 98 项测试, 覆盖审计流水线 / 限流分类 / 路由白名单 / 沙箱 / 反馈闭环 / 自博弈 / Sigma / 工具行为签名 / 因果链 / 撤销门 |
| 后端导入检查 | `python -c "import app"` | 主应用可启动 |
| 前端 | `cd frontend && npm run lint && npm run build` | 16 页 + 100+ 组件 |
| Flink | `cd flink-jobs && mvn -DskipTests package` | 9 个 Java 作业编译 |
| Docker | `docker compose config` | compose 文件可解析 |
| 端到端 | `python demo_e2e.py` | 全链路验证 |

---

## 项目结构

```
├── flink-jobs/                              # ★ Flink 流处理作业 (Java 11)
│   ├── pom.xml                              # Maven (Flink 1.19.3 + Java 11 + CEP + Kafka Connector 3.2.0-1.19)
│   ├── Dockerfile                           # 多阶段构建: Maven → Flink 运行时
│   ├── submit-jobs.sh / auto-submit.sh      # 守护式作业提交
│   ├── schemas/                             # AVRO Schema
│   │   ├── security-event.avsc
│   │   └── alert-event.avsc
│   └── src/main/java/com/soc/
│       ├── job/                             # 9 个 Flink 作业
│       │   ├── LogValidationJob.java        # 校验+认证+去重
│       │   ├── AnomalyDetectionJob.java     # 异常评分+CEP攻击链
│       │   ├── SigmaThresholdAggregationJob.java
│       │   ├── FlowAggregationJob.java      # NDR 扩展
│       │   ├── TlsFingerprintJob.java       # NDR 扩展
│       │   ├── BehaviorAnomalyJob.java      # EDR 扩展
│       │   ├── CepPatternConfig.java        # CEP 模式定义
│       │   ├── CepPartialMatchFunction.java # CEP 部分匹配
│       │   └── SourceReputationFunction.java
│       ├── model/                           # 事件模型
│       └── util/                            # KafkaConfig / TraceUtil / TraceIdHeaderProvider
├── backend/                                 # ★ Python 后端 (FastAPI + 30 子模块)
│   ├── app.py                               # 主应用入口（中间件 / 路由挂载 / 限流）
│   ├── http_guards.py                       # 限流白名单 / 点名分类
│   ├── config.py / settings                 # 配置中心
│   ├── models.py / schema_registry.py       # SQLAlchemy + AVRO
│   ├── auth.py / user_store.py              # JWT 认证
│   ├── kafka_consumer.py / kafka_producer.py  # Kafka 客户端
│   ├── log_ingestion.py / ingest_pipeline.py # 日志入口
│   ├── source_registry.py / rule_manager.py  # 数据源 / 规则管理
│   ├── case_manager.py / work_order_service.py / post_mortem_service.py / feedback_loop.py
│   ├── event_store.py / memory_tree.py / stats_counter.py / sliding_window.py
│   ├── field_cipher.py / security_crypto.py  # 字段加密 / 国密
│   ├── event_bus.py / context_stream.py     # 实时事件
│   ├── otel_setup.py / trace_hook.py / trace_context.py
│   ├── memory_guard.py / llm_limiter.py / llm_enhancer.py / hierarchical_attention.py
│   ├── vector_store.py / qdrant_store.py    # 向量存储
│   ├── grounding_verifier.py / faithfulness_gate.py / veto_gates.py
│   ├── cad.py / audit_worker.py / audit_single.py / audit_types.py / audit_triage.py / audit_pq.py / audit_cache.py / audit_trail.py / audit_schemas.py
│   ├── anomaly_detector.py / correlation_engine.py
│   ├── sigma_detector.py / sigma_engine/    # Sigma 引擎
│   ├── red_agent.py / blue_* / self_play/   # 红蓝自博弈
│   ├── chat.py / demo_traffic.py / demo_seed_b.py
│   ├── eval_service.py / eval_repository.py / eval_metrics.py
│   ├── prompts/                             # Prompt 模板
│   ├── agents/                              # ★ Audit-LLM 四层 + 6 类 Agent + CAD
│   │   ├── agent_a.py / agent_b.py / agent_c.py / agent_d.py / agent_cad.py
│   │   ├── agent_decomposer.py / agent_tool_builder.py / agent_executor.py / agent_reviewer.py
│   │   ├── audit_single.py / sub_auditor.py / chunker.py / llm_fallback.py / base.py
│   ├── routers/                             # ★ 16 个 FastAPI Router（218 端点）
│   ├── response_engine/                     # 响应引擎（18 模块 + containment/）
│   ├── security_guard/                      # 调用安全守卫（7 模块）
│   ├── mcp_guard/                           # MCP 工具调用控制（10 模块）
│   ├── rag/                                 # RAG 知识库（11 模块）
│   ├── phishing_guard/                      # 反钓鱼 6 通道（12 模块）
│   ├── threat_intel/                        # 威胁情报（6 模块）
│   ├── encrypted_traffic/                   # 加密流量分析（7 模块）
│   ├── traffic_capture/                     # 流量采集（3 模块）
│   ├── protocol_parser/                     # 协议解析（5 模块）
│   ├── traffic_baseline/                    # 流量基线（4 模块）
│   ├── edr_fusion/                          # EDR 融合（5 模块）
│   ├── zeroday_detect/                      # 0day 检测（5 模块）
│   ├── ids_connector/                       # Suricata 对接
│   ├── data_security/                       # 数据安全 (LLM 分类器)
│   ├── causal_chain/                        # 因果推断（7 模块：PC/GES/do-calculus）
│   ├── learn_loop/                          # 学习闭环（10 模块）
│   ├── ops_loop.py / ops_metrics/           # KPI 跟踪
│   ├── observability/                       # 可观测性（5 模块）
│   ├── prompts/                             # Prompt Loader
│   ├── temporal/                            # Temporal 工作流
│   ├── session_reconstruct/                 # 会话重建
│   ├── event_archive/                       # 长期归档
│   ├── schemas/                             # AVRO Schema (Python 端)
│   ├── tests/                               # ★ 98 项 pytest
│   └── tools/                               # 维护脚本
├── frontend/                                # ★ React 19 前端
│   ├── src/
│   │   ├── App.tsx / main.tsx / index.css
│   │   ├── pages/                           # 16 个页面
│   │   ├── components/                      # 13 个组件分类
│   │   │   ├── brand/ (BrandCrest/BrandMark/BrandSeal)
│   │   │   ├── home/ (Blueprint/EventTicker/ShiftConsole/ShiftOrbit)
│   │   │   ├── monitor/ (12 个监控组件)
│   │   │   ├── operations/ (14 个运营 Tab)
│   │   │   ├── phishing/ (Detect/Drill)
│   │   │   ├── rag/ (QualityPanel/TracePanel)
│   │   │   ├── ui/ (20+ UI 基础组件)
│   │   │   ├── hero/ charts/ common/ login/ memories/ chat/
│   │   ├── hooks/ (useTilt)
│   │   ├── layouts/ (RootLayout/Sidebar/TopNav/nav)
│   │   ├── lib/ (api/eventStream/agentPipeline/thoughtChain/...)
│   │   ├── stores/ (authStore/serviceStore)
│   │   └── types/ (index/operations)
│   ├── scripts/ public/
│   ├── package.json / vite.config.ts / tsconfig.json
│   └── README.md
├── tools/                                   # 运维 / 注入 / 证书 / 部署脚本
│   ├── syslog-adapter.py                    # syslog → Kafka
│   ├── monitor-2026-09-10.py                # 性能监控
│   ├── attack-simulator.sh / attack-large-scale-2026-09-10.py
│   ├── generate_test_feed.py / kali_sim_perf.py
│   ├── gen-kafka-certs.sh / create-kafka-users.sh  # Kafka TLS + SCRAM
│   ├── gen-htpasswd.sh                      # Flink Basic Auth
│   ├── init-kafka-topics.sh / register-schemas.sh
│   ├── install-service.ps1 / windows-log-collector.ps1
│   ├── security-tray.ps1 / enable-rerank.ps1
├── docker-compose.yml                       # ★ 主编排（含 Kafka + Flink + Kafka UI）
├── docker-compose.dev.yml / docker-compose.prod.yml  # 环境分离
├── init.sql                                 # PostgreSQL Schema (30 KB)
├── log_simulator.py                         # ★ 日志模拟器（Kafka/HTTP 双模式）
├── demo_e2e.py / demo_start.bat             # 端到端演示
├── .env.example                             # 环境变量模板 (12 KB)
└── docs/                                    # ★ 60+ 文档
    ├── INDEX.md                             # 文档导航
    ├── deployment.md / dependency_versions.md
    ├── advanced_capabilities.md
    ├── otel_sampling.md
    ├── study-guide/                         # 11 篇学习手册 + 速查 + PDF 总览
    ├── architecture/                        # 架构深读
    ├── performance/                         # 性能 / Kafka 解耦
    ├── security-audit/                      # 渗透审计 + 压测报告
    ├── upgrade-proposals/                   # 滚动 8 版技术栈升级
    └── competition-materials/               # 总结报告 / 合规声明 / 原创声明
```

---

## 文档导航

| 我想… | 去看 |
|-------|------|
| 5 分钟看懂项目 | [`docs/study-guide/速查.md`](docs/study-guide/速查.md) |
| 从头到尾系统学 | [`docs/study-guide/知识手册.md`](docs/study-guide/知识手册.md) (18 章) |
| 看 PDF 风总览 | [`docs/study-guide/总览-PDF风.md`](docs/study-guide/总览-PDF风.md) |
| 了解部署细节 | [`docs/deployment.md`](docs/deployment.md) |
| 看 NDR/EDR/反钓鱼/0day | [`docs/advanced_capabilities.md`](docs/advanced_capabilities.md) |
| 看技术栈演进 | [`docs/upgrade-proposals/`](docs/upgrade-proposals/) (v1→v8 + 创新矩阵) |
| 看安全审计报告 | [`docs/security-audit/AUDIT_REPORT.md`](docs/security-audit/AUDIT_REPORT.md) |
| 看大规模压测 | [`docs/security-audit/attack-perf-large-scale-2026-09-10.md`](docs/security-audit/attack-perf-large-scale-2026-09-10.md) |
| 看 RAG 评估 | [`docs/rag-eval-2026-09-05.md`](docs/rag-eval-2026-09-05.md) |
| 看 Kafka 解耦 | [`docs/performance/kafka-decoupling-baseline.md`](docs/performance/kafka-decoupling-baseline.md) |

完整索引：[`docs/INDEX.md`](docs/INDEX.md)

---

> 说明: 仓库会同步推送到 `security-of-agent` 与 `security-of-agent-max` 两个远端。
> 最后一次大审计：2026-09-10（HTTP 限流分类 / 端口矩阵 / 模块清单同步代码现状）。
