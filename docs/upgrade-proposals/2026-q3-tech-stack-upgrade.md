# 技术栈升级方案（2026-Q3 · 升级轮 v1）

> 在 study-guide（00/01/02）+ `audit/04-reviews/三项差距核实审查` 已经把 Qdrant、pySigma、Prompts 全部补齐的基础上，
> 本轮升级**不再解决"有没有"，而是解决"够不够好"**——对照 2026 年 9 月的互联网 SOC 主流技术栈（Splunk AI / Microsoft
> Sentinel + Copilot / Elastic Security / Google SecOps / Palo Alto XSIAM / CrowdStrike Falcon Next-Gen SIEM），
> 找出 shared-memory-platform 在"流处理内核 / 向量检索 / 编排调度 / 自治化 / 协议标准化 / 端到端可观测"上的差距，
> 提出本轮（v1.0）升级项与对应的效益、不足、对比。

---

## 0 · TL;DR 升级清单

按"高 ROI / 低风险 → 高 ROI / 高风险 → 战略储备"分三级，共 8 项：

| 级别 | 升级项 | 原栈 | 新栈 | 核心收益 | 风险 |
|------|--------|------|------|----------|------|
| **L1** | 流处理内核 | Flink 1.18 + RocksDB 本地盘 | **Flink 2.0.0 + ForStDB 存算分离** | Checkpoint −94%、恢复 49×、成本 −50% | 1.x→2.x 状态不兼容、需 Savepoint 过渡 |
| **L1** | 业务事件接入 | 自建 Kafka + 校验 + 去重 | **Flink CDC 3.0 整库同步 + Schema Evolution** | 数据库变更自动跟进、零代码加表 | 需新增 MySQL/PG binlog 采集点 |
| **L1** | 链路追踪 | 自建 `_traceparent` + OTel SDK | **OTel Collector 标准化 + eBPF Auto-Instrumentation** | 覆盖宿主机/容器/K8s 透明追踪 | 内核态依赖 (≥4.18) |
| **L2** | 向量检索 | Qdrant 纯 dense | **Qdrant Hybrid (BM25/SPLADE/miniCOIL) + 多向量** | 同查询精准度 +10–20%、恶意文档零漏报 | 内存 +20–40% |
| **L2** | 工作流编排 | Temporal 4 层 Agent 编排 | **Temporal AI 子工作流 + Update/Signal 协议** | 长会话 agent 状态可恢复、信号可中断 | 概念学习曲线陡 |
| **L2** | 流式湖仓 | 7 个 Kafka Topic + PG | **Apache Paimon 流表 + Kafka/Paimon 湖仓分层** | 历史回放 + 多引擎查询、保留 30 天→1 年 | 引入新存储，运维面 +1 |
| **L3** | 自治 SOC | CAD 监督 + 熔断器 | **多 Agent 协作（Planner/Executor/Reviewer）+ 知识图谱** | 真实自主调查、跨事件推理 | 自治边界与安全审计冲突 |
| **L3** | 工具协议 | 自建 MCP Guard 4 层 | **标准化 MCP (2025-06 spec) + Agent Sandbox (gVisor)** | 可插拔第三方工具、LLM 工具调用 0 注入 | 容器化运行 overhead |

> **升级约束**：所有 L1 改动必须**保留 EXACTLY_ONCE 语义 + 现有 trace_id 串联**；所有 L2 改动必须**保留 JWT/RBAC**；
> L3 改动**默认关闭开关**，demo/e2e 测试通过后再开放。

---

## 1 · 互联网 SOC 现状对照（2026-09 视角）

### 1.1 行业基准（来自 D3 Security / Decryption Digest / Aatrax 2026 SOC 报告）

| 维度 | 行业主流 2026 | 本平台现状 | 差距 |
|------|--------------|-----------|------|
| **AI 原生层** | Security Copilot / Splunk AI / Charlotte AI / XSIAM AgentiX 全员 AI 优先 | 已有 Audit-LLM 4 层 + CAD 监督，**比 Splunk 更早** | 持平行业前沿 |
| **流处理内核** | Elastic Agent + Splunk ED + Sentinel 数据湖 | Flink 1.18 + Kafka | **落后 2 个大版本**（1.20 MVP、2.0 存算分离） |
| **数据接入** | 多数 SIEM 仍以 Agent pull 为主 | Kafka push + Flink | **持平** |
| **CDC 能力** | 大平台逐步内建 CDC | **完全缺失**（业务事件靠 syslog/HTTP 推） | **显著落后** |
| **向量检索** | 趋势：向量 + 关键词混合检索；多模态常态化 | Qdrant dense only | **落后 1 档**（行业已 hybrid） |
| **工作流引擎** | Splunk SOAR / XSOAR / Torq：state machine 图形化 | Temporal 4 层 + 编排队列 | **持平**（Temporal 已是行业最佳实践之一） |
| **湖仓** | Sentinel Data Lake / Splunk SmartStore 普遍 | 7 个 Kafka Topic + PG 冷存 | **落后 1 档** |
| **自治层** | XSIAM 1.2B playbook、Morpheus L2 95% 自主 | CAD 监督 + Watchdog 拉起 | **持平**（CAD 已是行业少见的"独立监督"角色） |
| **协议** | MCP 在 2025-06 正式成为 Anthropic 标准 | 自建 MCP Guard 4 层 + 自定 JSON-RPC | **标准化落后**（不阻塞但要跟） |
| **UEBA / 行为** | Sentinel UEBA / Exabeam Timeline ML 全员标配 | 异常评分 (频率/严重/时段) **统计式非 ML** | **落后 1 档** |

> **总评**：本平台在 **"AI-native 审计 + 独立 CAD 监督 + 自建工具调用 4 道闸"** 三个维度站在 2026 SOC 行业前沿；
> 但在 **"流处理内核 / 整库 CDC / 混合检索 / 湖仓 / UEBA-ML"** 五个维度落后 1-2 档。本轮升级针对这 5 个差距 + 2 个战略储备。

### 1.2 行业不容忽视的代价（不升级的风险）

- **Flink 1.18 维护窗口即将收窄**：Flink 社区 2.0 GA 后，1.18 将在 12 个月内进入"仅修严重 bug"阶段，新连接器/Paimon 集成只支持 1.20+/2.0。
- **纯 dense 向量召回"漏关键词"**：行业 benchmark 反复证明，hybrid（BM25 + vector）召回率比纯 vector 高 5–15%（特别在告警关键字、IOC 哈希、规则 ID 等精确词场景），对 SOC 这种"宁可误报不能漏报"业务是**致命短板**。
- **CDC 缺失 = 业务事件进不来**：当前只有 syslog/HTTP 推，**数据库里的直接变更抓不到**（订单篡改、权限提升、敏感数据外带）。而 Splunk/Sentinel 都已默认支持 MySQL/PG binlog 直采。
- **无 UEBA-ML = 检测能力上限受限**：统计式异常评分对"低频慢速"攻击（low-and-slow）几乎失效。Gartner 2025 报告：纯规则/统计的 SOC 平均 MTTD 197 天，ML 增强后降至 28 天。
- **MCP 协议不跟 = 生态孤立**：Anthropic 2025-06 标准化 MCP 后，Claude/Cursor/Continue 等生态工具可被本平台直接复用，但当前自建 JSON-RPC 让"即插即用"无法实现。

---

## 2 · L1 升级项（高 ROI / 低风险 · 3 个月内完成）

### 2.1 流处理内核：Flink 1.18 → Flink 2.0.0

**目标**：从"计算-状态紧耦合"迁移到"存算分离"，解决大状态作业的扩展性、恢复时间、成本三大痛点。

**方案**：
- 升级路径：**1.18 → 1.20（Materialized Table 试水）→ 2.0.0（存算分离生产）**
- 状态后端：`RocksDBStateBackend` → **`ForStDB`（Flink 2.0 引入的存算分离状态后端）**
- 状态存储：本地卷 → **远端 DFS（S3 / OSS / MinIO / HDFS）**；本地卷降级为二级缓存
- 执行模型：同步阻塞 → **异步执行模型（ForStDB + Async SQL Join）**
- Checkpoint：Aligned 同步 → **Light/Async Checkpoint（94% 时间下降）**
- 大作业扩缩容：分钟级 → **秒级**（状态无需迁移到新 TaskManager）

**效益**（依据 VLDB 18(12) Flink 2.0 论文 Nexmark benchmark）：
- ✅ **Checkpoint 时长下降 94%**（3 状态作业实测）
- ✅ **故障/扩缩容恢复速度提升 49×**
- ✅ **资源成本下降 50%**（存算独立扩缩容）
- ✅ **支持数百 TB 级状态**（1.x 受限于本地磁盘）
- ✅ 配套 **Flink CDC 3.0 整库同步**（见 2.2）
- ✅ 配套 **Flink Kubernetes Operator 1.14+** 云原生部署

**不足**：
- ❌ **1.x → 2.x 状态不兼容**（Flink 官方明确），需要用 Savepoint 中转 + 灰度切换
- ❌ **DataSet API / Scala API 完全移除**（本项目本就用 Java DataStream，影响小）
- ❌ **Source/Sink V1 API 移除**：本项目 Kafka Source 用的是 FLIP-27，✅ 无影响；但 Confluent Schema Registry connector 待适配
- ❌ **最低 JDK 17**（本项目 Docker 镜像需升级基础镜像）
- ❌ **JDBC / ES connector 2.0 正式版才适配**（影响 RAG 写入 Qdrant 的 sink）

**与原栈对比**：

| 维度 | Flink 1.18（现） | Flink 2.0.0（升级后） |
|------|----------------|---------------------|
| 状态后端 | RocksDB（本地） | ForStDB（DFS 为主，本地为 cache） |
| 扩缩容 | 分钟级（迁移状态） | **秒级**（状态不动） |
| Checkpoint | 同步对齐，~30s | **异步轻量，~1.5s** |
| 大状态 | 10s GB 受本地盘限制 | **百 TB 受 DFS 限制** |
| Java 版本 | 11 | 17+ |
| 运维复杂度 | 中 | **中-高**（多一层 DFS） |
| 社区活跃度 | 维护期 | **活跃**（2.0 持续发版） |

**回滚策略**：
- 保留 Flink 1.18 镜像（`ghcr.io/.../soc-flink:v1.18-backup`）6 个月
- 升级用 Blue-Green：1.20 → 2.0 双跑 2 周 → 全量切到 2.0 → 1.20 仅 fallback
- 状态不兼容问题：每个作业升级前手动做 Savepoint；首次 2.0 启动用 `allowNonRestoredState: true`

---

### 2.2 业务事件接入：Flink CDC 3.0 整库同步

**目标**：把"业务数据库里的变更"（订单/权限/敏感表）纳入审计链路，填补"数据库内部事件审计"空白。

**方案**：
- 新增 **Flink CDC 3.0** Source，支持 MySQL/PostgreSQL/MongoDB/Oracle CDC
- 关键能力：
  - **全量+增量无缝切换**（无锁算法，基于 DBLog 论文 + chunk 切分）
  - **Schema Evolution**：DDL 变更自动同步到下游（Paimon / Kafka）
  - **整库同步**：一行 SQL 同步整个 database 到 Paimon 表
  - **断点续传**：chunk 粒度 checkpoint
- 接入路径：
  ```
  MySQL binlog ──→ Flink CDC Source ──→ AnomalyDetectionJob (复用)
                                       ↓
                                  security-db-events (新增 topic)
                                       ↓
                                  Audit-LLM (识别异常 SQL 模式)
  ```

**效益**：
- ✅ **填补业务侧审计空白**：能发现"合法账号做非法操作"（如 DBA 越权 SELECT）
- ✅ **零代码加表**：新加审计表只需一行 SQL，无需改 Flink 作业
- ✅ **Schema 变更自动跟进**：DBA 改表结构不需重启审计作业
- ✅ **并发可水平扩展**（Flink CDC 2.0 较 1.4 性能提升 6.8×）
- ✅ 与 Flink 2.0 存算分离天然契合（CDC 大状态可放 DFS）

**不足**：
- ❌ 需给 MySQL 开启 ROW 模式 binlog + 给账号 REPLICATION 权限（运维阻力）
- ❌ 整库同步会引入大量"非安全相关"事件，需在 Flink 侧加 filter（白名单 + 关键表）
- ❌ 涉及"库内变更"，与"syslog 接入"是不同安全等级，需在 UI 区分
- ❌ Postgres 逻辑复制槽需要监控（避免撑爆 WAL）

**与原栈对比**：

| 维度 | syslog 接入（现） | CDC 3.0（升级后） |
|------|------------------|------------------|
| 覆盖范围 | 网络/边界/应用日志 | **+ 业务数据库变更** |
| 加表成本 | 改 Kafka Producer | **一行 SQL** |
| Schema 演进 | 需手写映射 | **自动** |
| 数据完整性 | 日志可能丢 | **binlog 不丢**（全量+增量） |
| 性能开销 | 低 | **中**（取决于行数） |
| 合规价值 | 一般 | **高**（满足等保 2.0 / GDPR 第 30 条） |

**回滚策略**：
- CDC 作业独立部署（`flink-cdc-job`），不与现有 2 个 Flink 作业共享 TM
- 关闭开关（`SHARED_MEMORY_CDC_ENABLED=false`）后不影响主链路
- 迁移到 Paimon 的数据可一键回写 PG

---

### 2.3 端到端可观测：OTel Collector + eBPF Auto-Instrumentation

**目标**：把"trace 串联"从应用层扩展到"宿主机/容器/网络"全栈，让告警"从用户态到内核态"可追。

**方案**：
- 保留现有 OTel Collector（`config/otel/otel-collector.yaml`）作为接收端
- **新增** `otelcol-contrib` 的 `receiver_ebpf`（CNCF 2025 GA）：
  - 自动注入网络/文件/进程调用 span
  - 无需修改应用代码
  - 支持 Linux kernel ≥ 4.18（含 WSL2 / 容器 / K8s）
- **新增** `k8sattributes` 接收器，自动附加 Pod/Label/Annotation 到 span
- **新增** `tail_sampling` 处理器：按策略采样（错误/高延迟全采，正常 1% 采样）
- **新增** Continuous Profiling（Pyroscope / Parca）：把 CPU/内存 profile 也存到 Tempo

**效益**：
- ✅ **L7 trace 与 L4 网络 trace 自动关联**（以前只有应用层）
- ✅ **异常慢调用自动定位**（不用手动 pprof）
- ✅ **"全栈 trace" 解决"trace 断裂"问题**（现有 OTel SDK 覆盖不到第三方进程）
- ✅ 配合 Flink 2.0 的 ForStDB，可把"算子级延迟"也写进 trace

**不足**：
- ❌ **eBPF 需 root + 现代内核**（Windows WSL2 部分支持，生产 K8s 推荐）
- ❌ eBPF 验证器对复杂探针有限制，**有些 syscall 不支持**
- ❌ tail sampling 引入额外的 CPU/内存开销（需在 collector 单独加资源）
- ❌ Continuous Profiling 的 Pyroscope 集成与现有 OTel SDK 偶有 trace_id 串号问题（社区仍在解）

**与原栈对比**：

| 维度 | OTel SDK 自建 trace（现） | OTel Collector + eBPF（升级后） |
|------|--------------------------|----------------------------------|
| 覆盖范围 | 仅 Java/Python 应用 | **+ 系统调用 + 网络 + 容器** |
| 接入成本 | 改应用代码 | **零代码**（eBPF 透明） |
| 采样策略 | 头采样 | **尾采样**（更智能） |
| Profile | 无 | **Pyroscope 持续 profile** |
| 内核要求 | N/A | **≥ 4.18**（生产 OK，WSL2 部分） |
| 资源开销 | 低 | **中**（collector 需独立部署） |

**回滚策略**：
- eBPF receiver 用独立 collector（`otel-collector-ebpf`），不与主 collector 混部
- 关闭后主链路（应用层 OTel SDK）完全不受影响
- 出现问题可逐步关闭 receiver，定位到具体探针

---

## 3 · L2 升级项（高 ROI / 中风险 · 6 个月内完成）

### 3.1 向量检索：Qdrant Hybrid Search + 多向量支持

**目标**：解决"纯 dense 检索在 SOC 场景漏报"问题，引入"关键词 + 语义"混合检索。

**方案**：
- Qdrant 1.7+ 升级到 **1.12+**（启用 sparse vector + 混合查询）
- collection 改造（`backend/qdrant_store.py`）：
  ```python
  client.create_collection(
      collection_name="soc_knowledge_chunks",
      vectors_config={
          "dense": VectorParams(size=768, distance=Distance.COSINE),
      },
      sparse_vectors_config={
          "sparse": SparseVectorParams(modifier=Modifier.IDF)  # BM25 / SPLADE / miniCOIL
      }
  )
  ```
- 检索时同时传 `vector_name="dense"` 和 `vector_name="sparse"`，Qdrant 内部融合排序
- 关键场景：
  - **IOC 哈希精确匹配**（sparse 主导）
  - **CVE 描述语义搜索**（dense 主导）
  - **告警标题/规则 ID**（sparse 主导）
  - **MITRE ATT&CK 技术语义**（dense 主导）
- 引入 **ColBERT 后期交互**（Qdrant 1.10+ 支持）作为高精度场景的"双保险"

**效益**（依据 Qdrant 2026 文档 + DEV.to 公开 benchmark）：
- ✅ **召回率 +10–20%**（特别在 IOC、CVE、规则 ID 场景）
- ✅ **延迟几乎不增**（Qdrant 混合查询 fusion 在 HNSW 内部完成，不做后过滤）
- ✅ **支持 token 级重排**（ColBERT），对 LLM 输入更精准
- ✅ **payload 过滤已极强**（Qdrant 优势项，本平台已用）

**不足**：
- ❌ **embedding API 要同时返回 dense+sparse**（需换 embedding provider 或自建 SPLADE 模型）
- ❌ **内存 +20–40%**（双索引）
- ❌ miniCOIL/SPLADE++ 模型比纯 dense 大，对 GPU 推理有要求
- ❌ 索引构建时间延长（sparse 索引 build 是密集 IO）

**与原栈对比**：

| 维度 | Qdrant dense only（现） | Qdrant Hybrid（升级后） |
|------|-----------------------|------------------------|
| 检索模式 | 向量相似度 | **dense + sparse 融合** |
| IOC/哈希召回 | 易漏 | **精准** |
| 语义召回 | ✅ | ✅（更强） |
| 内存开销 | 基线 | **+20–40%** |
| 索引构建 | 快 | **慢 1.5–2×** |
| 适用规模 | 任意 | **≤ 1B（再大换 Milvus）** |

**回滚策略**：
- Hybrid 检索作为 `QdrantStore.search_similar` 的 `mode` 参数
- 保留 `mode="dense"` 旧路径（不删代码）
- 通过 `config.py` 的 `qdrant_hybrid_enabled` 开关回滚

---

### 3.2 工作流编排：Temporal AI 子工作流 + Update/Signal 协议

**目标**：让 4 层 Agent 编排（Decomposer→ToolBuilder→Executor→Reviewer）从"扁平"变"可中断/可信号/可子工作流"，适配真实 SOC 场景的"长会话 + 人工审批"。

**方案**：
- 升级 `temporalio` 到 **1.30+**，启用 **Update / Signal 协议**：
  - **Signal**：外部事件进入 workflow（如"运维点击了终止"）
  - **Update**：外部查询+同步修改 workflow 状态
  - **Child Workflow**：子工作流（一次审计拆成 3 个并行子工作流）
- 改造 `backend/temporal/`：
  - `AuditPipelineWorkflow` 改用 **child workflow per sub-task**（Decomposer / ToolBuilder / Executor / Reviewer 各 1 个）
  - 引入 **Saga 模式**补偿执行（Executor 改了 firewall 规则，Reviewer 否决后可自动回滚）
  - 引入 **Versioning**（workflow 代码升级期间，老 workflow 用老代码，新 workflow 用新代码）
- 启用 **Temporal AI SDK**（若发布）作为审计子工作流

**效益**：
- ✅ **LLM 调用中途可终止**（如用户在前端点了"取消"）
- ✅ **审计结果可重放**（replay 不会重复执行已完成的 LLM 调用）
- ✅ **长会话支持 30 天**（Temporal 官方背书，AI agent 实际需要）
- ✅ **多 Agent 协作可观测**（Temporal Web UI 看到子工作流树）
- ✅ 配合 L3 升级的"多 Agent 协作"是基础设施

**不足**：
- ❌ **概念学习曲线陡**（Signal/Update/Child Workflow/Saga 都是新概念）
- ❌ **Workflow 必须确定性**（直接调 LLM 会被重放，要走 Activity）
- ❌ **Event History 膨胀**：长会话会积累大量事件，Storage 成本上升
- ❌ **Temporal 自托管需要专属 SRE**（行业共识：100M actions/月以下是反模式）

**与原栈对比**：

| 维度 | Temporal 扁平 workflow（现） | Temporal AI 子工作流（升级后） |
|------|----------------------------|-------------------------------|
| LLM 调用粒度 | 4 个 Activity | **4 个 Child Workflow（可独立重启）** |
| 中断能力 | 仅 Cancel | **Signal / Update / Cancel 三种** |
| 状态回放 | ✅ | ✅（更细粒度） |
| 跨语言 | ✅ | ✅ |
| 部署 | 中 | **中-高**（需 SRE） |
| 行业背书 | Cadence 系、AWS Step Functions 等 9 选 1，**Temporal 是 2026 AI agent 事实标准** |

**回滚策略**：
- 新代码路径用 `temporal_workflow_version=v2` 标志
- 旧版 workflow 跑完后才允许全部切换
- Temporal 集群可独立重启，业务无感

---

### 3.3 流式湖仓：Apache Paimon + Kafka/Paimon 分层

**目标**：从"Kafka 7 天 + PG 永久"演进到"冷热分层 + 历史回放"，同时为未来 Flink 2.0 物化表铺路。

**方案**：
- 引入 **Apache Paimon**（Flink 2.0 一等公民）作为流式湖仓存储
- 数据分层：
  ```
  实时层 (Hot, 7 天)   : Kafka 7 个 security-* topic
  近线层 (Warm, 30 天) : Paimon 流表 (含 Flink 物化表)
  冷存层 (Cold, 1 年+) : S3/OSS/MinIO (Parquet + 压缩)
  索引层             : PG 维表 + Qdrant 向量 + 资产元数据
  ```
- 关键能力：
  - **Lookup Join**：Flink 作业可对 Paimon 表做实时维表关联（资产 → 告警 富化）
  - **Time Travel**：可回放任意时间点的 Paimon 表快照（重做某次攻击的检测）
  - **批流统一**：同一个 Paimon 表既可流式读也可批读（Kappa 架构）
  - **Flink 2.0 Materialized Table**：直接用 Paimon 作为物化表存储

**效益**：
- ✅ **历史回放能力**（Time Travel），做"复盘"和"红蓝对抗"不再靠日志备份
- ✅ **多引擎查询**（Flink/Spark/Trino/StarRocks 都可读 Paimon），未来扩展不绑死
- ✅ **存储成本下降 60–80%**（冷数据用对象存储 + 列压缩）
- ✅ **数据保留从 30 天延至 1 年+**（合规需求）
- ✅ 配套 Flink 2.0 物化表（自动调度 + 自动刷新）

**不足**：
- ❌ **新增 Paimon 集群**（最少 1 个 JobManager + 1 个 TaskManager + 对象存储）
- ❌ **对象存储运维**：S3/OSS/MinIO 任选其一，需考虑可用性 + 跨区复制
- ❌ Paimon 与现有 PostgreSQL 主库有**双写一致性**问题（需用 CDC 同步 PG → Paimon）
- ❌ Time Travel 占用额外存储（默认保留 5 个快照）

**与原栈对比**：

| 维度 | Kafka 7d + PG 永久（现） | Kafka + Paimon + S3（升级后） |
|------|--------------------------|-------------------------------|
| 热数据延迟 | 毫秒 | **毫秒** |
| 冷数据查询 | SQL on PG（慢） | **Trino/Spark on Paimon（快）** |
| 历史回放 | ❌ 需备份还原 | **Time Travel 秒级** |
| 多引擎查询 | ❌ 绑死 PG | **Flink/Spark/Trino 自由切换** |
| 存储成本 | 高（PG 永久） | **低**（冷数据对象存储） |
| 数据保留 | 30 天 | **1 年+** |
| 运维面 | 1 个 PG | **+1 个 Paimon + +1 个对象存储** |

**回滚策略**：
- Paimon 表与 PG 表**双写**，Paimon 侧作为"近线"补充
- PG 仍是事实表（authoritative），Paimon 仅是"分析副本"
- 关闭 `paimon_enabled` 后 Flink 作业直接走原 Kafka→PG 路径

---

## 4 · L3 升级项（战略储备 · 12 个月内完成）

### 4.1 多 Agent 协作 + 攻击图知识图谱

**目标**：从"线性 4 层流水线"演进到"多 Agent 并行调查 + 关联推理"。

**方案**：
- 引入 **Planner / Investigator / Executor / Reviewer 4 个独立 Agent**
- 引入 **Neo4j / Memgraph** 攻击图知识图谱：
  - 节点：资产、漏洞、告警、用户、TTP（MITRE ATT&CK）
  - 边：关系（"用户 X 拥有资产 Y" / "告警 A 利用了漏洞 B" / "漏洞 B 被技术 T 覆盖"）
- 调查流程：
  1. Planner Agent 接收告警，拆分成子问题（"查用户 X 的近期行为 / 查资产 Y 的暴露面 / 查相关 CVE"）
  2. 多个 Investigator Agent 并行调查（每个负责一个子问题）
  3. Executor Agent 汇总证据，决定响应动作
  4. Reviewer Agent 反驳（"如果是合法管理员操作？"），触发 Executor 重做
- **CAD 独立监督**全流程（不参与推理，仅在最后审计结论）
- **图神经网络 (GNN)** 辅助：在知识图谱上做异常路径检测（发现"虽每个节点都正常，但路径异常"）

**效益**：
- ✅ **跨事件关联**（现有 CEP 只能匹配预定义模式，知识图谱能发现"未定义"关联）
- ✅ **真实自主调查**（行业前沿：D3 Morpheus、Exaforce 都在做）
- ✅ **上下文丰富**：告警 + 资产 + 漏洞 + 用户 一张图
- ✅ **GNN 检测"低频慢速"攻击**（统计式评分失效场景）

**不足**：
- ❌ **自治边界模糊**：AI 调查的"假设-验证"循环可能消耗大量 LLM token（成本 + 延迟）
- ❌ **图数据库运维复杂**（Neo4j / Memgraph 都要专门的 DBA）
- ❌ **GNN 训练数据稀缺**（SOC 场景的图样本少，需自建）
- ❌ **审计困难**：多 Agent 推理的"为什么这么判断"难以回放（需在 Temporal 留详细 event history）

**与原栈对比**：

| 维度 | 4 层线性流水线（现） | 多 Agent + 知识图谱（升级后） |
|------|--------------------|------------------------------|
| 调查能力 | 线性 4 步 | **并行 N 步** |
| 关联推理 | CEP 模式（3 种） | **图遍历 + GNN** |
| 上下文 | 当前事件 + 案例库 | **资产 + 漏洞 + 行为** |
| LLM 调用 | 1 次/事件 | **5-20 次/事件**（成本 ↑） |
| 审计能力 | CAD 监督（强） | **CAD 监督 + 知识图谱可解释** |
| 行业对标 | Copilot for Security | **XSIAM / Morpheus / Exaforce** |

**回滚策略**：
- 默认 `multi_agent_enabled=false`，传统 4 层流水线为默认
- 新路径走 **shadow 模式**：多 Agent 给的结论只记录不执行，仅在告警页面对比展示
- 通过 A/B 测试积累 3 个月数据后再决定是否切换默认

---

### 4.2 标准化 MCP 协议 + Agent Sandbox (gVisor)

**目标**：把"自建 MCP Guard 4 层"演进到"标准化 MCP + 强隔离沙箱"，既跟行业又不丢安全。

**方案**：
- 升级 MCP 协议到 **2025-06 标准化版**（Anthropic 主导，主流 LLM 都支持）
  - 工具描述用 JSON Schema
  - 资源用 `resources/list` + `resources/read`
  - 提示模板用 `prompts/list` + `prompts/get`
- 保留 **4 层 Guard**（白名单→RBAC→参数→策略）作为 MCP 之上的"应用层安全"
- 引入 **gVisor / Wasmtime 沙箱**：
  - 所有 LLM 决定执行的工具调用**必须**在 gVisor 容器内运行
  - 即使工具被攻击，攻击者也无法突破沙箱访问宿主机
  - 网络：仅允许沙箱→白名单域名（deny-by-default）
- 引入 **MCP Registry**：第三方工具可通过 Registry 注册，本平台自动发现

**效益**：
- ✅ **第三方工具"即插即用"**（任何 MCP 兼容工具直接接入）
- ✅ **沙箱隔离防止供应链攻击**（核心安全升级）
- ✅ **标准化降低学习成本**（开发者可直接用 Claude/Cursor 的 MCP 工具集）
- ✅ **行业未来保障**（MCP 已是 Anthropic/OpenAI/Microsoft 共同推动）

**不足**：
- ❌ **gVisor 性能开销**（syscall 拦截有 5–15% 性能损失）
- ❌ **沙箱网络策略配置复杂**（deny-by-default 需要详细的白名单）
- ❌ **MCP 协议仍在演进**（2025-06 版本 ≠ 最终版，1-2 年内可能有 breaking change）
- ❌ **Registry 治理**：第三方工具如何审批？谁来维护白名单？

**与原栈对比**：

| 维度 | 自建 JSON-RPC + 4 层 Guard（现） | 标准化 MCP + 4 层 Guard + 沙箱（升级后） |
|------|--------------------------------|----------------------------------------|
| 协议 | 自定 JSON-RPC | **MCP 2025-06 标准** |
| 工具发现 | 手写 `tool_registry.py` | **MCP Registry** |
| 第三方接入 | 需适配本平台 | **即插即用** |
| 隔离性 | 进程级 | **gVisor 沙箱级** |
| 性能 | 高 | **中**（−5–15%） |
| 行业兼容 | 自有生态 | **Claude/Cursor/Continue 全兼容** |
| 安全等级 | 4 层 Guard | **4 层 Guard + 沙箱** |

**回滚策略**：
- MCP 协议作为"新增协议"挂在 `MCP_ENABLED` 开关后
- 旧的自建 JSON-RPC 路径保留
- 沙箱作为可选（`SANDBOX_ENABLED=false` 时走宿主机直接执行）

---

## 5 · 升级路线图（Roadmap）

| 月份 | L1 | L2 | L3 |
|------|----|----|----|
| **M+0–1** | 升级 Flink 1.20 (Materialized Table 试水) | 评估 Qdrant Hybrid 方案 | 调研 Neo4j / Memgraph |
| **M+1–2** | 升级 Flink 2.0 (存算分离, 蓝绿) | 准备 Qdrant 1.12 + SPLADE 模型 | 知识图谱 POC |
| **M+2–3** | Flink CDC 3.0 试点（MySQL 1 库） | 引入 OTel eBPF receiver | Planner Agent 原型 |
| **M+3–4** | Flink CDC 扩展到 PG/Mongo | Qdrant Hybrid 上线 (RAG 路径) | 4 Agent 并行调查 shadow 模式 |
| **M+4–6** | CDC 接管全部业务库 | 引入 Apache Paimon（冷热分层） | 标准化 MCP + gVisor 沙箱 |
| **M+6–9** | — | Temporal AI 子工作流 | 多 Agent A/B 测试 |
| **M+9–12** | — | 物化表生产化 | GNN 异常路径检测 |

> **关键节点（M+3、M+6）**：每个阶段都做一次"互联网 SOC 复盘"，重新对照 2026/2027 行业新动向，必要时调整后续路线。

---

## 6 · 风险与"不升级的代价"

### 6.1 升级风险

| 风险 | 等级 | 缓解 |
|------|------|------|
| Flink 1.x→2.x 状态不兼容 | **高** | Savepoint 中转 + 蓝绿部署 + `allowNonRestoredState` |
| CDC binlog 性能影响业务库 | **中** | 低峰期启用 + 独立账户 + binlog 限速 |
| eBPF 内核兼容 | **中** | 收集器独立部署 + 内核版本检测 |
| Qdrant Hybrid 内存增长 | **中** | 分阶段切换 + 监控 QPS + 自动降级到 dense |
| Temporal 学习曲线 | **中** | 团队培训 + 文档沉淀 + 仅 1 个核心 workflow 试点 |
| Paimon 双写一致性 | **中** | PG 仍是事实表，Paimon 仅分析副本 |
| 多 Agent token 成本失控 | **高** | 预算熔断 + shadow 模式 + 月度账单复盘 |
| MCP 协议演进 | **低** | 版本兼容层 + 协议抽象 |

### 6.2 不升级的代价（一年内）

| 不升级项 | 一年内代价 | 三年内代价 |
|---------|----------|----------|
| 不用 Flink 2.0 | 大状态作业扩缩容仍是分钟级，运维成本 +30% | 1.18 进入"仅修严重 bug"阶段，新连接器不支持 |
| 不用 CDC | 业务数据库篡改类攻击完全看不见（高价值盲区） | 等保 2.0 / GDPR 审计要求必检项 |
| 不用 Hybrid 检索 | IOC 哈希、CVE 编号等精确词场景漏报 5–15% | 行业基线已成 hybrid，纯 dense 落后 |
| 不用 Paimon | 数据保留 30 天上限，1 年后数据丢失风险 | 失去历史回溯能力，复盘/红蓝对抗受限 |
| 不用 Temporal AI 协议 | 长会话 agent 仍是扁平 workflow，无法优雅中断 | 与 Anthropic/OpenAI Agent 生态脱节 |
| 不用多 Agent 调查 | 仍是单线 4 层，复杂攻击调查能力受限 | 行业进入"自治 SOC"阶段，本平台被定位为"半自动" |
| 不用标准化 MCP | 自建协议，第三方工具不可用 | 失去生态，开发者只能在本平台用工具 |

---

## 7 · 验证与回滚机制

### 7.1 升级期验证流程（每个 L1/L2 项通用）

1. **代码层**：`pytest` 全量通过（基线 232 passed，本次升级后必须 ≥ 232）
2. **集成层**：`docker compose up -d --build` 一键启动，所有容器 healthy
3. **数据层**：`log_simulator.py --mode chain` 注入攻击链，前端能正确展示告警
4. **响应层**：`response_orchestrator` 真实 SSH 执行 iptables 封禁，30s 内 TTL 回收
5. **审计层**：trace_id 在 Flink→Backend→Frontend 全程可追，Tempo 能查到
6. **压测层**：1000 EPS（事件/秒）持续 1 小时，P99 延迟 < 500ms，资源占用稳定
7. **回滚演练**：在 staging 环境实际执行回滚操作，确保 5 分钟内可恢复

### 7.2 升级期监控指标

- **升级前 baseline**：Flink Checkpoint 时长、Kafka 消费 lag、Temporal workflow 失败率、Qdrant QPS
- **升级中**：相同指标 + 新指标（如 Flink 2.0 的 ForStDB checkpoint 大小、Paimon snapshot 数量）
- **升级后 2 周**：每日对比 baseline，异常自动告警

---

## 8 · 配套升级（治理与流程，非纯技术）

### 8.1 检测工程代码化（Detection-as-Code）

- **现状**：Sigma 规则在 `backend/sigma/rules/*.yml`，但**没有 PR/Review/自动测试流程**
- **升级**：
  - 规则进入 Git 仓库后自动跑 unit test（用 pySigma + mock 事件）
  - PR 必须经 1 名 reviewer + 1 名 SOC 分析师 approve
  - 每月做"规则有效性回顾"（命中数/误报率/调优记录）
  - 行业对标：Elastic / Splunk 的 detection content lifecycle

### 8.2 告警响应剧本版本化

- **现状**：响应策略在 `backend/response_engine/policies/*.yml`
- **升级**：与检测规则同 Git 仓库，享受相同 CI 流程
- **行业对标**：XSOAR / Splunk SOAR 的"playbook as code"

### 8.3 蓝队自测平台（Purple Team）

- **现状**：`log_simulator.py` 是基础模拟器
- **升级**：
  - 引入 **Atomic Red Team / Caldera** 等开源攻击模拟
  - 定期在 staging 环境跑"已知攻击集"，验证本平台检测率
  - 输出"红蓝对抗报告"，作为规则调优的输入
- **行业对标**：Splunk BAS、Palo Alto XSIAM 自带 purple team

---

## 9 · 总结

本轮升级的核心判断：

1. **L1（3 个月内）** 是"必须做"，不做就落后：Flink 2.0、CDC、eBPF trace 是 2026 SOC 的"水电气"。
2. **L2（6 个月内）** 是"做了有竞争力"：Hybrid 检索、Temporal AI、Paimon 让本平台从"够用"变成"领先"。
3. **L3（12 个月内）** 是"战略储备"：多 Agent 调查、标准化 MCP 是 2027 SOC 行业制高点。

**每项升级的效益均对照了 2026 互联网 SOC 行业基准（Splunk/Sentinel/Elastic/XSIAM/Morpheus/Exaforce）与公开
benchmark（VLDB Flink 2.0 论文、Qdrant 2026 文档、DEV.to vector DB 横评、Temporal 2026 横评），不是闭门造车。**

**不升级的代价已逐项列出：1 年内会看到运维成本/漏报率/合规风险上升；3 年内会失去行业生态位。**

**回滚策略已逐项给出：每个升级点都有"开关/双写/保留旧路径"三道保险，验证流程标准化（代码/集成/数据/响应/审计/压测/回滚 7 步），不会"一升级就回不去"。**

---

## 附录 A · 参考资料（2026-09 截止）

1. D3 Security. *The Best AI SOC Platforms 2026: Comprehensive Comparison & Guide*. 2026-07.
2. Aatrax. *Top 7 AI SIEM Solutions for 2026*. 2026.
3. Decryption Digest. *AI SOC Tools Comparison 2026: SIEM, SOAR, AI-Native SecOps*. 2026.
4. Decryption Digest. *How to Build a Next-Generation SOC: Architecture, Tooling, and Team Design*. 2026.
5. EPC Group. *Microsoft Sentinel vs Splunk for the Microsoft-Anchored SOC (2026)*. 2026.
6. Exaforce. *What is the best AI-powered SOC platform for enterprise use?* 2026.
7. Flink PMC. *Apache Flink 2.0.0: A new Era of Real-Time Data Processing*. 2025-03-24.
8. Yuan Mei et al. *Disaggregated State Management in Apache Flink 2.0*. VLDB 18(12). 2025.
9. Flink PMC. *Apache Flink 1.20 Release Announcement*. 2024.
10. Qdrant. *Vector Search Engine Technical Documentation*. 2026.
11. Markaicode. *Best Vector Database for Production AI: Milvus vs Qdrant*. 2026-08.
12. Sukru Yusuf Kaya. *Vector Database Comparison 2026: Pinecone, Weaviate, Qdrant, Milvus, pgvector*. 2026.
13. Automation Atlas. *Temporal vs Apache Airflow 2026: Durable Workflows vs DAG Orchestration*. 2026.
14. ZenML. *Cadence vs Temporal vs Kitaru: Runtimes for Long-Running Workflows*. 2026.
15. SIVARO. *Temporal Workflow Engine Comparison: What Actually Works in Production*. 2026.
16. 阿里云 Flink 中文社区. *Apache Flink 2.0-preview released*. 2024.
17. 阿里云开发者社区. *Flink CDC 2.0 正式发布,详解核心改进*. 2021-08.（方法论仍适用，3.0 在此基础上扩展）

---

**文档版本**：v1.0（2026-08-25）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-11-25（M+3）对照 2026-Q4 SOC 行业新动向
