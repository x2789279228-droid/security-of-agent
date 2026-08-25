# 技术栈升级方案 v2.0（2026-Q3 · 升级轮 v2）

> **本文档在 v1 基础上**（`2026-q3-tech-stack-upgrade.md`）做了三个动作：
> 1. **修正**：v1 的 3 个事实性错误（Flink 版本谱、MCP spec 版本、AI 原生层行业地位）；
> 2. **补齐**：v1 漏掉的 6 个升级项（OCSF、UEBA-ML、Agent Observability、Tier 1 自动分诊、NIST 800-61r3、量化 ROI）；
> 3. **重排优先级**：把 v1 的 3 层（L1/L2/L3）拆成 4 层（L0/L1/L2/L3），把"立即见效"项提到 L0。
>
> v1 文档完整保留作为历史快照，不做删除；本 v2 是"建议执行版"。

---

## 0 · TL;DR：v1 → v2 变更速览

| 维度 | v1（2026-08-25 初版） | v2（本轮） | 变更原因 |
|------|----------------------|-----------|---------|
| 分层 | L1 / L2 / L3 三级 | **L0 / L1 / L2 / L3 四级** | 新增"L0 · 立即生效"层（30 天内可见 ROI 的补漏项） |
| 总升级项 | 8 项 | **14 项** | 补 OCSF、UEBA-ML、Agent Observability、Tier 1 自动分诊、NIST r3、Paimon Catalog 6 项 |
| Flink 目标 | 1.18 → 1.20 → 2.0.0 | 1.18 → **1.20 LTS → 2.2 LTS**（跳过 2.0/2.1） | 2.0.0 已 EOL（2026-06-25），2.2 是当前最新 LTS |
| MCP spec | 升级到 2025-06 标准化版 | 跟随 **2025-11 spec**（OAuth 2.1 / Streamable HTTP / stateless core） | 2025-06 已是旧 spec；新增 Linux Foundation 治理、Registry 治理、SSO 集成 |
| AI 原生层评价 | "本平台比 Splunk 更早" | **"持平 Splunk/CrowdStrike/Microsoft 2025-Q4 前"** | 行业 2025-Q4 至 2026-Q2 集中 GA 多 Agent（Splunk AI Agent Studio 2025-09、CrowdStrike Charlotte AI Agentic Response 2026-Q2 GA、Microsoft Security Copilot Agents 2026-07 GA） |
| 多 Agent 角色 | Planner / Investigator / Executor / Reviewer 4 段 | **Orchestrator + Triage + Investigation + TI + IR + Report 5 角色**（+ Agent Observability） | 2026 行业 12 个 Agentic SOC 平台共识模型 |
| 收益量化 | 无 | **每项给出 baseline vs 升级后数字** | 2026 SIEM 行业 baseline 已成熟：MTTD 197d→28d, MTTR 节省 108d, Charlotte AI 3x MTTR 70% 减人工 |

---

## 1 · 互联网 SOC 现状对照（2026-Q3 视角，v2 刷新版）

### 1.1 行业基准（v2 在 v1 基础上补 4 个维度）

| 维度 | 行业主流 2026-Q3 | 本平台现状 | v2 评价（更新） |
|------|------------------|-----------|----------------|
| **AI 原生层** | 12 个 Agentic SOC 平台 GA（CrowdStrike Charlotte AI Agentic Response/Workflows、Microsoft Security Copilot Agents、Splunk AI Agent Studio、Palo Alto Cortex AgentiX、SentinelOne Purple AI、D3 Morpheus、Torq HyperAgents、Dropzone AI 等）[依据 D3 Security 2026 Agentic SOC 平台横评] | 4 层线性流水线 + CAD 监督；**v1 自评"比 Splunk 更早"** | **持平行业 2025-Q4 前**（领先优势已被行业追平） |
| **AI Agent 自主级别** | AL1（建议）→ **AL2（辅助，已 GA）** → AL3（自治调查中，preview 居多）→ AL4（完全自治，未到）[依据 D3 Security 4 级 AL 模型] | 4 层流水线（AL1）+ CAD 监督（人工 1 道闸） | **AL1–AL2 之间**（比 AL3 主流差 1 级） |
| **流处理内核** | Flink 2.2 LTS（2025-12 发布，仍在维护，EOL 2027-Q3）[依据 endoflife.date 2026-07-14] | Flink 1.18（2026-03-24 已 EOL） | **落后 4 个大版本**（v1 写"落后 2 个"，v2 修正） |
| **CDC 能力** | Flink CDC 3.0 整库同步 | **完全缺失** | 显著落后（不变） |
| **向量检索** | Qdrant Hybrid（dense + sparse + RRF/DBSF fusion）；行业教训：**先 finetune sparse，再决定 hybrid**；finetune SPLADE 单独 nDCG 0.413 vs hybrid 0.405（hybrid 反而掉分）[依据 Qdrant 2026 电商检索 benchmark Part 3-4] | Qdrant dense only | 落后 1 档（不变，但**v2 加策略**：先 finetune 再 hybrid） |
| **工作流引擎** | Temporal 1.30+（Update/Signal）+ Microsoft Sentinel Logic Apps 标配 | Temporal 4 层 + 编排队列 | 持平（不变） |
| **湖仓** | Paimon Catalog（已 GA，Flink 2.0+ 一等公民） + Iceberg（开放生态，AI 场景更受推荐）[依据 阿里云 OpenLake / Techgenyz 2026] | 7 个 Kafka Topic + PG 冷存 | 落后 1 档（v2 改为"双格式"：Paimon 默认 + Iceberg 备） |
| **事件协议** | **OCSF 1.8.0（2026-03-16，AWS/Splunk/IBM 主导，1,280+ 贡献者，2026-06 ITU 国际标准，2024-11 进 Linux Foundation）**；v1.8.0 新增 AI operation schema、privilege analysis、macOS extension、packet capture[依据 AWS OCSF ITU 2026 公告] | 自建 JSON 标准化 | **显著落后**（v1 没列，v2 补为 L0） |
| **UEBA / 行为** | Sentinel UEBA / Exabeam Timeline ML / Securonix（行业 5/10 顶级公司在用）；市场 0.41B(2024)→14.18B(2035) CAGR 38%[依据 Exabeam 2026] | 统计式异常评分（频率/严重/时段） | **落后 1 档**（v1 已识别但未补，v2 补为 L1） |
| **MCP 协议** | 2025-11 spec（OAuth 2.1、Streamable HTTP transport、stateless core、Linux Foundation 治理）[依据 MCP 2026 官方 roadmap]；6,400+ 公开 server，97M 月下载，41% 企业有 MCP 部署，**但 86% 仍是实验/本地**（Stacklok 2026-07 调查） | 自建 JSON-RPC + 4 层 Guard | **标准化落后**（v1 已识别；v2 加"治理层"建议） |
| **可观测性** | OTel + eBPF + **LLM Observability**（Langfuse / LangSmith / Datadog LLM Observability / Helicone）已成 Agentic SOC 标配[依据 CSDN Agentic SOC 2026 综述] | OTel SDK 自建 trace | **缺 LLM Observability**（v1 没列，v2 补为 L0） |
| **告警分诊** | CrowdStrike Charlotte AI **70% 减人工 / 3x MTTR / >98% 准确率**（生产 30,000+ 次 triage）[依据 CrowdStrike Charlotte AI 2026] | 无自动分诊 | **落后 1 档**（v1 没列，v2 补为 L1） |

> **v2 总评**：本平台在 **"CAD 独立监督 + 4 层 Guard + 工具调用审计"** 三个维度仍是行业前沿；
> 但在 **"Flink 主版本谱 / OCSF 事件协议 / 整库 CDC / Hybrid 检索策略 / 湖仓 / UEBA-ML / LLM Observability / 多 Agent 自治 / 告警自动分诊 / MCP 治理"** **10 个维度**落后 1-2 档。本轮升级针对这 10 个差距（v1 的 5 个 + v2 新增的 5 个）。

### 1.2 行业不容忽视的代价（v2 增 3 条新风险）

- **Flink 1.18 已 EOL（2026-03-24）**：社区停止维护，新连接器不再支持；**本平台现处于"裸奔"状态**。
- **OCSF 不跟 = 数据生态孤岛**：AWS/Splunk/IBM/200+ 厂商已经用 OCSF 作为统一事件 schema；本平台自建 JSON 让"未来对接云 SIEM 厂商"成本翻倍。
- **无 LLM Observability = Agent 黑盒**：多 Agent 上线后，**无法回答"为什么 Agent 给这个结论"**，合规审计无证据链，CAD 监督失效。
- **MCP 协议已升至 2025-11 spec**（含 OAuth 2.1）：**只用 2025-06 旧 spec 会失去"按用户粒度授权"能力**——这是企业 CIO 部署 MCP 的硬性要求。
- **2026-04 MCP 暴露任意命令执行漏洞**：无 Registry 治理、无沙箱隔离的 MCP 部署是 RCE 入口（依据 Forkast News 2026-07）。
- **无 UEBA-ML = 检测能力上限受限**：v1 已有此结论；v2 补数据：纯规则/统计 SOC MTTD 197 天，ML 增强后 28 天（依据 Gartner 2025 via Cynet / Securonix 2026）。
- **无自动分诊 = 分析师被压垮**：CrowdStrike 数据 70% 减人工，IBM 2025 Cost of a Data Breach：**自动化节省 108 天 breach lifecycle**（241 天→133 天），MSSP 分析师日均看 2,000+ 告警（依据 CSDN 2026 Agentic SOC 综述）。
- **NIST SP 800-61r3 已替代 r2（2025-04）**：r3 把响应生命周期从"四段式"改成"CSF 2.0 六函数"，v1 §8.1 引用的仍是 r2 的 DaC 流程模板；**v2 必须用 r3 重写响应 playbook 模板**。

---

## 2 · L0 升级项（立即生效 · 30 天内完成 · 补差距型）

> v1 没有 L0。v2 新增原因是：**以下 4 项不依赖大版本升级，30 天内即可上线，且补的是"v1 已识别的差距"**——不做就持续落后。

### 2.0 L0-1 · 事件协议标准化：OCSF 1.8.0

**目标**：让本平台事件 schema 从"自建 JSON"升级到"OCSF 1.8.0"，未来对接 Splunk/Sentinel/Chronicle 零成本。

**方案**：
- 升级 `backend/connectors/` 到 OCSF 1.8.0（2026-03-16 最新版）
- 改造 `backend/event_normalizer.py`：
  ```python
  from ocsf import Event, CategoryInfo, TypeInfo
  # 所有出 Kafka 事件携带 OCSF metadata
  event = Event(category=CategoryInfo(category_uid=2, name="Findings"),
                type=TypeInfo(type_uid=2001, name="Account Change"),
                severity_id=3, ...)
  ```
- 双写策略：OCSF 是"对外接口"，自建 schema 仍保留"对内优化"
- 增量迁移：先 syslog → OCSF（最大量），再 Flink → OCSF，最后 audit → OCSF

**效益**（依据 AWS 2026 OCSF ITU 公告 / Databahn 2026 / Anomali 2026）：
- ✅ **对接云 SIEM 厂商零成本**（Splunk/Chronicle/Sentinel 原生 OCSF）
- ✅ **AI/LLM 训练更准**（OCSF 标准化字段名，模型泛化好）
- ✅ **2026-06 已成 ITU 国际标准**，合规审计有依据
- ✅ **v1.8.0 新增 AI operation schema**，本平台 LLM 调用本身也可被 OCSF 描述

**不足**：
- ❌ 字段映射工作量大（v1.8.0 含 200+ event class，本平台自建字段约 80 个）
- ❌ 第三方 Sigma 规则仍是 Sigma 原生 schema，**与 OCSF 双 schema 共存**（需在 Normalizer 层做转换）
- ❌ payload 大小增加 5-10%（OCSF metadata 字段多）

**与原栈对比**：

| 维度 | 自建 JSON（现） | OCSF 1.8.0（升级后） |
|------|----------------|---------------------|
| 字段数 | ~80（自定义） | 200+（标准 class） |
| 对接云 SIEM | 需写适配器 | **零适配**（Splunk/Chronicle/Sentinel 原生） |
| LLM 训练 | 字段名变化就要重训 | **泛化好**（OCSF 字段稳定） |
| AI operation 描述 | ❌ 无 | ✅ v1.8.0 新增 ai_operation profile |
| 合规审计 | 自证 | **ITU 国际标准** |
| 行业覆盖 | 0 厂商 | **200+ 厂商 / 1,280+ 贡献者** |

**回滚策略**：OCSF 作为"出 Kafka 前一层 wrapper"，关闭 `ocsf_enabled` 后立即回到原 JSON 路径；不破坏现有消费者。

---

### 2.0 L0-2 · LLM Observability：Langfuse 接入

**目标**：所有 LLM 调用可观测、可回放、可评估——CAD 监督和多 Agent 上线的前提。

**方案**：
- 部署 Langfuse（自托管，docker compose 一键）
- 在 `backend/audit_llm/`、`backend/mcp_guard/`、`backend/response_engine/` 接入 Langfuse SDK
- 关键能力：
  - **Trace**：每个 LLM 调用的 prompt / completion / tool call / token 成本
  - **Evaluation**：用 LLM-as-a-Judge 自动评估结论质量
  - **Feedback loop**：分析师对结论 👍/👎，回流到训练集
  - **Cost tracking**：每案件消耗 token、API 成本

**效益**（依据 Langfuse 2026 / LangSmith 2026 / Datadog LLM Observability 2026）：
- ✅ **多 Agent 必备基础设施**（无它，Agent 是黑盒）
- ✅ **成本可视化**（v1 提到"多 Agent token 成本失控"是 high risk；Langfuse 是解药）
- ✅ **合规审计证据链**（GDPR / 等保 2.0 要求 LLM 决策可回放）
- ✅ **优化 Prompt**（看哪类 query 失败多，迭代 prompt）

**不足**：
- ❌ 接入工作量（所有 LLM 调用点要改代码，~30-50 处）
- ❌ 自托管 Langfuse 需要 PG + ClickHouse（资源 +5-10%）
- ❌ LLM-as-a-Judge 本身需要 LLM 调用（**评估成本可能是主调用 10-20%**）

**与原栈对比**：

| 维度 | OTel SDK 自建 trace（现） | Langfuse（升级后） |
|------|--------------------------|---------------------|
| 覆盖 LLM 维度 | 通用 trace | **+ prompt / completion / token / cost / score** |
| 评估 | 无 | **LLM-as-a-Judge + 人工反馈** |
| 反馈循环 | 无 | ✅ |
| 合规 | 通用审计 | **LLM 专项审计** |
| 资源开销 | 极低 | **+5-10%** |

**回滚策略**：Langfuse 关闭后所有 LLM 调用回到无 trace 状态（**不影响主链路**）。

---

### 2.0 L0-3 · 告警分诊自动化：Tier 1 Auto-Triage Agent

**目标**：80% 高频告警自动分诊（真阳/误报/未知），仅高置信度 + 高风险进人工。

**方案**：
- 引入"分诊 Agent"（独立 LLM Agent，**不是 L3 多 Agent 的一部分**）
- 关键能力：
  - 拉取告警 → 富化（IP/Hash/域名情报）→ 查历史（这个主机/用户/告警类型过去 30d）→ 关联（同时间段其他告警）→ 判断（真阳/良性/未知）→ 动作（关闭/升级/隔离）
- 置信度阈值：
  - `> 0.95` 自动关闭（仅 benign 类）
  - `0.6-0.95` 自动升级（待人工 review）
  - `< 0.6` 自动隔离 + 升级（高风险但低置信，需立即止损）
- **HITL 强制**：所有"自动关闭"操作必须有"30 天可撤回"窗口

**效益**（依据 CrowdStrike Charlotte AI 2026 / D3 Morpheus 2026 / CSDN 综述）：
- ✅ **80% 告警自动化**（Charlotte AI 生产数据）
- ✅ **MTTR 减 50%**（Charlotte AI 3x response speed）
- ✅ **人工 review 减 70%**（Charlotte AI 客户实测）
- ✅ **Tier 1 分析师 24 → 8 人**（行业案例）
- ✅ 是 L3 多 Agent 落地的"第一阶"（先单 Agent，再多 Agent）

**不足**：
- ❌ LLM 调用成本（每告警 1-3 次 LLM call）
- ❌ 自动关闭风险（**必须 30 天可撤回**）
- ❌ 误判影响（auto-close 真阳会丢事件）

**与原栈对比**：

| 维度 | 人工分诊（现） | Tier 1 Auto-Triage Agent（升级后） |
|------|---------------|-----------------------------------|
| 速度 | 分钟-小时 | **秒级** |
| 成本 | 人力（FTE） | **LLM API 成本**（~0.001-0.01/告警） |
| 准确率 | 依赖人 | **>98%**（Charlotte AI 2026 数据） |
| 7×24 | 不可 | **可** |
| 行业 ROI | 基线 | **最高**（v2 评估） |

**回滚策略**：分诊 Agent 用独立 `triage_enabled` 开关；关闭后告警直接进人工队列，行为完全等同于 v1。

---

### 2.0 L0-4 · 响应框架升级：NIST SP 800-61r3

**目标**：把 v1 §8 引用的"r2 四段式"响应流程升级到 r3 的"CSF 2.0 六函数"框架。

**方案**：
- 重写 `backend/response_engine/policies/` 下的所有 playbook，结构改为 r3 六函数：
  - **Govern**：策略、责任、权限
  - **Identify**：资产清点、风险评估
  - **Protect**：访问控制、数据安全、平台安全
  - **Detect**：连续监控、事件分析
  - **Respond**：事件管理、分析、缓解、通信
  - **Recover**：恢复计划执行、通信
- `backend/tests/test_response.py` 增加"CSF 2.0 函数覆盖度"测试
- 文档 `docs/study-guide/05-self-audit.md` 同步升级

**效益**（依据 NIST SP 800-61r3 2025-04 官方发布）：
- ✅ **合规对齐**：等保 2.0 / NIST CSF 2.0 / GDPR 都基于 r3
- ✅ **持续改进显式**：r3 把"lessons learned"从"事后"提到"first-class"
- ✅ **第三方审计友好**：审计师按 r3 评估，可直接给合规分数

**不足**：
- ❌ 现有 50+ playbook 全部要重写
- ❌ 团队需要培训 r3 思维
- ❌ 文档大量更新

**与原栈对比**：

| 维度 | NIST 800-61r2（v1 引用） | NIST 800-61r3（升级后） |
|------|--------------------------|-------------------------|
| 生命周期 | 4 段（准备→检测响应→恢复→事后） | **6 函数**（CSF 2.0） |
| 持续改进 | 事后 | **first-class** |
| 治理 | 不涉及 | **GV 函数** |
| 与 CSF 对齐 | 弱 | **强**（CSF 2.0 一等公民） |

**回滚策略**：playbook 升级是文档/代码改动，无运行时风险；可"双轨"保留 r2 模板备查。

---

## 3 · L1 升级项（3 个月内完成 · 主流对齐）

### 3.1 流处理内核：Flink 1.18 → **Flink 2.2 LTS**（v1 修正目标）

**v1 → v2 关键修正**：
- v1 写"升级到 2.0.0"——错。**2.0.0 在 2026-06-25 已 EOL**，2.0.2 是最后一个版本
- v1 写"1.20 维护期"——错。**1.20 是 LTS，仍在维护**（依据 endoflife.date 2026-07-14）
- 2026-Q3 最新稳定：Flink 2.2（2025-12-04 发布，2.2.1 维护中 2026-05-11）
- **v2 推荐路径**：1.18 → 1.20 LTS（短期过渡）→ 2.2 LTS（最终目标）；**跳过 2.0 和 2.1**

**目标**：迁移到 Flink 2.2 LTS 存算分离架构（ForStDB），沿用 v1 思路但版本号更新。

**方案**：
- ForSt State Backend + 远端 DFS（OSS / MinIO）
- Async State API（State V2）
- 自适应批执行（生产环境主要跑流，但留批通道）
- Flink CDC 3.0 整库同步（沿用 v1 思路）
- 注意：**ForSt 仍是 experimental**（v1 已识别；v2 加测：**本项目状态规模 < 10GB，本地 RocksDB 性能可能更好**——v2 不强求 ForSt，仅当状态 > 100GB 时启用）

**效益**（依据 RisingWave vs Flink 2.0 基准 2026 / 袋鼠云 Flink 2.0 测评 2026）：
- ✅ **Checkpoint 94% 下降**（v1 已列；v2 加数据：1.2-4.8GB 状态，吞吐达本地 75-120%）
- ✅ **恢复时间从小时级→秒级**（v2 关键数据：100GB 状态从 2-4 min → 10-20s；2TB 状态同样 10-20s；本项目当前 < 10GB，恢复时间 < 5s）
- ✅ **存算独立扩缩容**（ForSt 把状态放 S3）
- ✅ **1.20 LTS 期间先用 LTS 升级拿社区红利**（v1 没强调 LTS）

**不足**：
- ❌ ForSt 仍标 experimental（v1 已识别）
- ❌ 1.x → 2.x 状态不兼容（Savepoint 中转 + 蓝绿）
- ❌ **本项目状态规模 < 10GB 时，ForSt 性能不一定优于 RocksDB**（v2 修正 v1 假设）

**与原栈对比**：

| 维度 | Flink 1.18（现） | Flink 2.2 LTS（升级后） |
|------|----------------|---------------------|
| 状态后端 | RocksDB（本地） | ForStDB（DFS + 本地 cache） |
| 扩缩容 | 分钟级 | **秒级** |
| Checkpoint | 同步，~30s | **异步，~1.5s** |
| 大状态 | 10s GB 受本地盘 | **百 TB 受 DFS** |
| 状态兼容性 | N/A | **1.x→2.x 不兼容** |
| Java | 11 | **17+** |
| 维护状态 | **已 EOL**（2026-03-24） | **LTS 至 2027-Q3** |
| 推荐度 | 不推荐生产 | **2026 主流** |

**回滚策略**（沿用 v1 + v2 增强）：
- 保留 1.20 LTS 镜像 6 个月
- 蓝绿：1.20 LTS → 2.2 LTS 双跑 2 周 → 切 2.2 → 1.20 LTS 仅 fallback
- 状态不兼容：每个作业升级前 Savepoint，2.2 首次启动 `allowNonRestoredState: true`
- **v2 新增**：当状态 < 10GB 且恢复时间 < 5s 可接受时，**不升级 ForSt**，保持 RocksDB（避免 experimental 风险）

---

### 3.2 业务事件接入：Flink CDC 3.0（v1 思路保留）

**v1 思路全部保留**——这是高 ROI 低风险项，v2 不变。

**新增 v2 关注点**：
- 优先接入 MySQL（最常见），再 Postgres
- **白名单设计**（"非安全相关表"必须先排除）：业务库表动辄上千张，Flink 同步会爆
- **Kafka+Paimon 双写**（不是 Kafka 直写 PG，详见 §4.3）
- **PG 行级权限审计**（不只是 DDL/DML，SELECT 异常模式也要记）

---

### 3.3 端到端可观测：OTel Collector + eBPF（v1 思路保留 + v2 加 LLM Observability）

**v1 思路保留**。**v2 新增**：把 L0-2 的 Langfuse 作为"LLM 层 trace"，与 eBPF 的"系统层 trace"在 OTel Collector 汇聚，统一在 Tempo / Grafana 查看。

---

### 3.4 UEBA-ML：从统计式评分升级到机器学习（v1 识别但 v2 才补）

**目标**：把 v1 §1.1 识别的"统计式异常评分"差距补上——但**不是大改**，而是在现有 `AnomalyDetection` Flink 作业里加 ML 评分模块。

**方案**：
- **方案 A（轻量）**：基于历史 30 天数据，用 scikit-learn / River 训练"用户行为基线模型"：
  - 登录时间分布
  - 访问资源类型分布
  - 数据下载量分布
  - 横向移动频率
- 偏离基线 > 3σ 触发风险评分
- **方案 B（重度）**：用 Exabeam / Securonix 商用 UEBA（成本高，v2 不推荐）
- 选 A：开源、自托管、与本项目栈契合

**效益**（依据 Securonix 2026 / Exabeam 2026 / Cynet 2026 / Sumo Logic 2026）：
- ✅ **MTTD 197 天 → 28 天**（Gartner 2025）
- ✅ **low-and-slow 攻击可见**（统计式评分盲区）
- ✅ **误报率降 60%**（Securonix 客户实测）
- ✅ **90 天历史基线**（Sumo Logic 模式：不是"冷启动"，是用已有数据训练）
- ✅ 行业基线：$0.41B(2024)→$14.18B(2035) CAGR 38%，**UEBA 是 SOC 标配**

**不足**：
- ❌ 训练数据需要 30+ 天（不是"装上就用"）
- ❌ 模型解释性差（"为什么这个用户可疑"难说清）
- ❌ 误报与漏报平衡需要持续调优
- ❌ 不同部门基线不同（财务和销售行为模式差很大）

**与原栈对比**：

| 维度 | 统计式异常评分（现） | UEBA-ML（升级后） |
|------|---------------------|-------------------|
| 基线 | 静态阈值 | **30+ 天动态基线** |
| low-and-slow 攻击 | 看不见 | **可见** |
| 误报率 | 高（规则/阈值固定） | **降 60%** |
| 行为维度 | 频率/严重/时段（3 维） | **10+ 维**（时间/资源/数量/peer group/地理/设备） |
| 行业标配 | 落后 | **Sentinel/Exabeam/Securonix 全员标配** |

**回滚策略**：UEBA 评分作为"附加分"叠加在现有评分上（不替换）；UEBA 关掉后回到 v1 的统计式评分。

---

## 4 · L2 升级项（6 个月内完成 · 竞争力建设）

### 4.1 向量检索：Qdrant Hybrid + **先 finetune 再 hybrid**（v1 思路 + v2 修正策略）

**v1 → v2 关键修正**：
- v1 说"hybrid 召回 +10-20%"——错。**Qdrant 官方 2026 电商 benchmark**：通用 dense + 现成 SPLADE hybrid nDCG +1.3%；**finetune SPLADE 单独 0.413 vs hybrid 0.405（hybrid 反而掉分）**
- **v2 策略修正**：**先 finetune SPLADE 在 SOC 内部数据**，再 A/B 测试 hybrid 是否真的有用；可能结论是"**本项目不需要 hybrid**"

**方案**（v2 修正）：
- **阶段 1（必做）**：用 SOC 内部数据 finetune SPLADE（参考 Qdrant 2026 Part 2 教程）
- **阶段 2（按需）**：finetune 后 A/B 测试：
  - 纯 dense：现有路径
  - 纯 sparse（finetune SPLADE）
  - dense+sparse hybrid
- **阶段 3（决策）**：看哪条线 RAG 质量最好，选最优；不一定上 hybrid

**效益**（依据 Qdrant 2026 Part 3-4 + DEV.to Sapota 案例）：
- ✅ **finetune 后稀疏向量单独 nDCG +27.5%**（vs BM25）
- ✅ **零 GPU query time**（SPLADE 编码在 ingest 端，查询只查倒排索引）
- ✅ **延迟 10-20ms**（与 dense 相当）
- ✅ **避免 v1 假设的 hybrid 浪费**（v1 写 hybrid 内存 +20-40%，可能不必要）

**不足**：
- ❌ finetune 需要 GPU（A10G 或更好；本项目当前 GPU 资源？）
- ❌ 训练数据标注（"哪些 query 应该召回哪些 doc"——可用 LLM 自动标，但要审核）
- ❌ finetune 模型版本管理（升级时需重新索引）

**与原栈对比**：

| 维度 | Qdrant dense only（v1 现） | Qdrant + finetune SPLADE（v2 升级） |
|------|---------------------------|-----------------------------------|
| 检索模式 | 纯 dense | **finetune sparse（按需 hybrid）** |
| IOC/哈希召回 | 易漏 | **精准** |
| 语义召回 | ✅ | ✅（更强） |
| 训练成本 | 0 | **GPU + 标注数据**（一次性） |
| 推理成本 | dense 模型推理 | **CPU 倒排索引（更便宜）** |
| 适用规模 | 任意 | **≤ 1B（再大换 Milvus）** |

**回滚策略**：finetune 模型作为新路径；旧 dense 路径不删；通过 `qdrant_retrieval_mode` 切换。

---

### 4.2 工作流编排：Temporal AI 子工作流（v1 思路保留 + v2 接入多 Agent）

**v1 思路保留**。**v2 新增**：把 L3 的多 Agent 5 角色（Orchestrator/Triage/Investigation/TI/IR/Report）作为 Temporal child workflow 编排（**v2 把 L3 提到 L2 中期**——因为分诊 Agent 已经在 L0-3 落地，编排它是自然延伸）。

---

### 4.3 流式湖仓：Apache Paimon + Catalog（v1 升级 v2 加 Catalog 与 Iceberg 备选）

**v1 → v2 关键修正**：
- v1 写"引入 Paimon"——错。**Paimon 2024 已成 Apache 顶级项目，2026 已是 Flink 2.x 一等公民**——v2 改"对接 Paimon Catalog"
- v1 没提 **Iceberg**——v2 补：Iceberg 在 2026 行业"开放性 + AI 场景"评价高于 Paimon（依据 Techgenyz 2026 lakehouse 横评）
- **v2 策略**：Paimon 作为默认（与 Flink 深度集成），Iceberg 作为"开放性"备选（多引擎查询）

**方案**（v2 修正）：
- 主存储：**Paimon Catalog**（Flink Materialized Table 默认）
- 冷存：S3/OSS/MinIO（Parquet + 压缩）
- 备存储：**Iceberg**（写一个同步作业，把 Paimon snapshot 异步同步到 Iceberg 表；分析侧用 Trino/Spark 查 Iceberg）
- 多引擎查询：Flink 查 Paimon（流/批），Trino/Spark 查 Iceberg（分析）

**效益**（依据阿里云 OpenLake 2026 / 袋鼠云 Flink 2.0 / Techgenyz 2026）：
- ✅ **Flink 2.2 物化表默认存储**（v2 用 2.2，Paimon 是一等公民）
- ✅ **Time Travel 秒级**（历史回放）
- ✅ **多引擎查询**（Flink/Trino/Spark/StarRocks 都可读）
- ✅ **冷数据成本 -60-80%**（对象存储 + 列压缩）
- ✅ **数据保留 1 年+**（合规需求）
- ✅ **v2 新增**：Paimon + Iceberg 双格式 = "既要性能，也要开放"

**不足**：
- ❌ 双存储运维面 +1（v1 已识别）
- ❌ Iceberg 同步 Paimon 有 lag（秒级）
- ❌ Paimon Catalog 需独立集群
- ❌ **运维复杂度中-高**（v2 评估）

**与原栈对比**：

| 维度 | Kafka 7d + PG（v1 现） | Kafka + Paimon + Iceberg（v2 升级） |
|------|----------------------|-----------------------------------|
| 热数据延迟 | 毫秒 | 毫秒 |
| 冷数据查询 | SQL on PG（慢） | **Trino/Spark on Iceberg（快）** |
| 历史回放 | ❌ 备份还原 | **Time Travel 秒级** |
| 多引擎 | ❌ 绑死 PG | **Flink + Trino + Spark 自由** |
| 开放性 | 中（PG 私有） | **高（Iceberg 标准开放格式）** |
| 运维面 | 1 PG | **+1 Paimon + 1 Iceberg + 1 S3** |

**回滚策略**（v1 思路保留）：Paimon/Iceberg 作为"分析副本"，PG 仍是事实表。

---

## 5 · L3 升级项（12 个月内完成 · 战略储备）

### 5.1 多 Agent 调查 + 攻击图知识图谱（v1 思路 + v2 角色修正）

**v1 → v2 关键修正**：
- v1 写"Planner/Investigator/Executor/Reviewer 4 段"——v2 改"5 角色"对齐行业（依据 D3 Security 12 个 Agentic SOC 平台横评 2026）
- v1 缺 **Agent Observability**（L0-2 Langfuse 已是它的基础设施）
- v1 缺 **反馈循环**（Charlotte AI 公开数据：靠反馈循环达到 >98% 准确率）
- v1 缺 **Autonomy Level 模型**（D3 Security 4 级 AL1-AL4）

**目标**：从"线性 4 层流水线"演进到"5 角色多 Agent 协作 + 反馈循环"。

**方案**（v2 角色修正）：
- **Orchestrator Agent**（总调度）：接收告警，分发任务，汇总结论
- **Triage Agent**（分诊）：真阳/良性/未知（**L0-3 已上线**）
- **Investigation Agent**（调查）：深度调查，攻击路径还原
- **TI Agent**（威胁情报）：IOC 富化，TTP 匹配
- **IR Agent**（响应）：执行隔离、封禁（**HITL 强制**）
- **Report Agent**（报告）：技术报告 + 高管简报
- **CAD 独立监督**（不参与推理，仅审计结论）
- **图数据库**（Neo4j / Memgraph）：资产、漏洞、告警、用户、TTP 关联
- **Langfuse 观测全链路**（L0-2 落地）
- **反馈循环**：分析师 👍/👎 → 训练集 → 下一版本更准

**Autonomy Level 模型**（v2 引入）：
- **AL1**：建议（Agent 给建议，人决策）— **本平台当前**
- **AL2**：辅助（Agent 执行非关键动作，人监督）— **L0-3 落地后达到**
- **AL3**：自治调查（Agent 自主调查，仅关键动作 HITL）— **L3 目标**
- **AL4**：完全自治（Agent 自主决策所有动作）— **行业 2026 未到**

**效益**（依据 D3 Security / CrowdStrike Charlotte AI / Microsoft Security Copilot 2026）：
- ✅ **3x MTTR**（Charlotte AI 生产数据）
- ✅ **70% 减人工**（同上）
- ✅ **>98% 准确率**（Charlotte AI 数据）
- ✅ **跨事件关联**（CEP 模式有限，知识图谱无限）
- ✅ **GNN 检测 low-and-slow**（v1 思路）
- ✅ **5 角色对齐行业**（D3 Morpheus / Torq HyperAgents / Conifers CognitiveSOC 同构）

**不足**：
- ❌ **LLM 成本**（单案件 30-50 次 LLM call，约 0.5-5 USD/案件；大型 SOC 月成本数十万美元）
- ❌ **幻觉**（LLM 编 IOC/CVE 编号；**强制 RAG + 工具输出优先 + 引用溯源**）
- ❌ **Prompt 注入**（攻击者在日志/邮件/工单藏指令；**OWASP 2025 LLM Top 10 第一**）
- ❌ **可观测性**（无 Langfuse 是黑盒；L0-2 解决）
- ❌ **图数据库运维**（Neo4j / Memgraph 需 DBA）
- ❌ **自治边界模糊**（v1 识别；v2 建议：**默认 AL2，关键动作永远 HITL**）

**与原栈对比**：

| 维度 | 4 层线性流水线（v1 现） | 5 角色多 Agent（v2 升级） |
|------|----------------------|--------------------------|
| 调查能力 | 线性 4 步 | **并行 N 步** |
| 关联推理 | CEP 模式（3 种） | **图遍历 + GNN** |
| 上下文 | 当前事件 + 案例 | **资产 + 漏洞 + 行为** |
| LLM 调用 | 1 次/事件 | **5-20 次/事件**（成本 ↑） |
| 准确率 | ~70%（v1 自评） | **>98%**（Charlotte AI 2026 行业数据） |
| 自治级别 | AL1 | **AL2（落地）→ AL3（目标）** |
| 行业对标 | Copilot for Security | **D3 Morpheus / Torq / Conifers / Charlotte AI** |

**回滚策略**（v1 思路保留 + v2 增强）：
- 默认 `multi_agent_enabled=false`，传统 4 层为默认
- 多 Agent 走 **shadow 模式**：结论只记录不执行
- A/B 测试积累 3 个月再切默认
- **v2 新增**：每次 Agent 决策都通过 Langfuse 评分，**评分低自动 fallback 人工**

---

### 5.2 标准化 MCP 协议 + Agent Sandbox（v1 思路 + v2 spec 升级到 2025-11）

**v1 → v2 关键修正**：
- v1 写"升级到 MCP 2025-06 标准化版"——错。**MCP 2025-11 spec 已发布**（OAuth 2.1、Streamable HTTP、stateless core、Linux Foundation 治理）
- v1 缺 **Registry 治理**（2026-07 Stacklok 调查：86% MCP 部署仍实验/本地，关键是缺治理）
- v1 缺 **SSO 集成**（CIO 部署硬性要求）
- v1 没提 **2026-04 MCP 任意命令执行漏洞**（Forkast News 报道）

**方案**（v2 升级）：
- 协议：跟随 **MCP 2025-11 spec**（含 OAuth 2.1 / Streamable HTTP / stateless core）
- 治理层（v2 新增）：
  - **MCP Registry**：第三方工具审批流程（不是"白名单"——是 Registry + 治理）
  - **SSO 集成**：所有 MCP server 接入企业 SSO（Okta/Entra/AD）
  - **审计日志**：每个 tool call 记录到 OTel + Langfuse
  - **沙箱**：gVisor / Wasmtime（v1 思路）
  - **依赖扫描**：所有 MCP server 依赖项走 SCA（防止 2026-04 类漏洞）
- 兼容性层（v2 新增）：同时支持 2025-06 老 spec（不破现有 MCP 部署）

**效益**（依据 wizeb.com 2026 / optijara.ai 2026 / MCP 2026 roadmap）：
- ✅ **跨模型即插即用**（Claude / GPT / Gemini / 本地 LLM 都可接）
- ✅ **OAuth 2.1 用户级授权**（CIO 部署硬性要求）
- ✅ **Linux Foundation 治理**（基础设施级别，非厂商所有）
- ✅ **第三方工具生态**（6,400+ 公开 server，2026 趋势："Agent 应用商店"）
- ✅ **行业未来保障**（MCP 已是 Anthropic / OpenAI / Microsoft / Google 共识）

**不足**：
- ❌ **gVisor 性能开销**（v1 已识别）
- ❌ **沙箱网络策略配置复杂**（v1 已识别）
- ❌ **MCP 协议仍在演进**（v1 已识别；v2 强调"spec 抽象层 + 兼容性层"）
- ❌ **Registry 治理责任**（v2 新增：谁审批？谁维护白名单？）
- ❌ **2026-04 RCE 漏洞**（无沙箱 + 无 Registry = RCE 入口）

**与原栈对比**：

| 维度 | 自建 JSON-RPC（v1 现） | MCP 2025-11 + 治理层（v2 升级） |
|------|----------------------|-------------------------------|
| 协议 | 自定 | **MCP 2025-11（OAuth 2.1 / Streamable HTTP / stateless）** |
| 工具发现 | 手写 registry | **MCP Registry + 治理审批** |
| 第三方接入 | 需适配 | **即插即用**（但 v2 加 Registry 治理） |
| 用户级授权 | ❌ | ✅ **OAuth 2.1** |
| SSO | ❌ | ✅ |
| 隔离性 | 进程级 | **gVisor 沙箱级** |
| 审计 | 弱 | **OTel + Langfuse 双链路** |
| 行业兼容 | 自有生态 | **Claude / Cursor / Continue / 12 个 Agentic SOC 全兼容** |

**回滚策略**（v1 思路保留 + v2 增强）：
- MCP 作为"新增协议"，`MCP_ENABLED` 开关
- 旧自建 JSON-RPC 保留
- 沙箱作为可选（`SANDBOX_ENABLED=false`）
- **v2 新增**：每个 MCP server 单独开关 + 单独审计 + 单独 Rate Limit

---

## 6 · 升级路线图（v2 重排）

| 月份 | L0（30 天） | L1（3 月） | L2（6 月） | L3（12 月） |
|------|------------|-----------|-----------|------------|
| **M+0–1** | OCSF 接入 / Langfuse 部署 / NIST r3 文档 / **Tier 1 分诊 Agent POC** | UEBA-ML 训练数据收集 | Temporal AI 子工作流 | 多 Agent POC |
| **M+1–2** | **Tier 1 分诊 Agent 灰度**（仅 benign 类自动关闭） | Flink 1.20 LTS 升级 + UEBA-ML 训练 | Qdrant SPLADE finetune | 5 角色多 Agent 原型 |
| **M+2–3** | — | **Flink 2.2 LTS 升级（蓝绿）** / UEBA-ML 上线 / **分诊 Agent 全量** | OTel eBPF 接入 / Temporal child workflow for 分诊 | Agent Observability + 反馈循环 + 知识图谱 POC |
| **M+3–4** | — | Flink CDC 3.0 试点（MySQL 1 库） | Qdrant Hybrid A/B（按需） | 多 Agent shadow 模式 |
| **M+4–6** | — | Flink CDC 扩展 PG/Mongo | **Apache Paimon Catalog 上线** + Iceberg 同步 | **MCP 2025-11 + Registry 治理** |
| **M+6–9** | — | — | Temporal AI 多 Agent 编排 | 多 Agent A/B 测试 |
| **M+9–12** | — | — | — | GNN 异常路径检测 / 自治 SOC AL3 试点 |

> **关键节点**：M+0（30 天后）做一次 L0 复盘；M+3 / M+6 / M+9 对照 2026-Q4 / 2027-Q1 SOC 行业新动向，必要时调整后续路线。

---

## 7 · 风险与"不升级的代价"（v2 增 2 条新风险）

### 7.1 升级风险（v2 增 2 条）

| 风险 | 等级 | 缓解 |
|------|------|------|
| **ForSt 仍是 experimental**（v1 已识别；v2 加：本项目 < 10GB 可不升级 ForSt） | 中 | 评估状态规模，小则继续 RocksDB |
| CDC binlog 性能影响业务库（v1） | 中 | 低峰期 + 独立账户 + binlog 限速 |
| eBPF 内核兼容（v1） | 中 | 收集器独立部署 + 内核版本检测 |
| Qdrant Hybrid 内存增长（v1；v2 修正：**先 finetune sparse 再决定**） | 中 | 改策略：先 finetune 单 sparse，A/B 后再 hybrid |
| Temporal 学习曲线（v1） | 中 | 团队培训 + 仅 1 个核心 workflow 试点 |
| Paimon/Iceberg 双写一致性（v1；v2 改双格式） | 中 | PG 仍是事实表，Paimon/Iceberg 是分析副本 |
| **多 Agent token 成本失控**（v1） | 高 | Langfuse 成本可视化 + 预算熔断 + shadow 模式 |
| MCP 协议演进（v1；v2 升级 spec） | 低 | 兼容性层 + 抽象层 |
| **MCP 2026-04 RCE 漏洞**（v2 新增） | **高** | gVisor 沙箱 + Registry 治理 + 依赖扫描 |
| **OCSF 字段映射工作量大**（v2 新增） | 中 | 双 schema 共存（OCSF 对外，原 JSON 对内） |
| **LLM Observability 评估成本**（v2 新增） | 中 | 评估抽样 10% 而非全量 |
| **Tier 1 自动分诊误判**（v2 新增） | **高** | 30 天可撤回窗口 + HITL 关键动作 |

### 7.2 不升级的代价（一年内 · v2 增 4 项）

| 不升级项 | 一年内代价 | 三年内代价 |
|---------|----------|----------|
| 不用 Flink 2.2 LTS | **1.18 已 EOL，新连接器不兼容，无社区支持** | 维护事故频发，被行业版本谱抛弃 |
| 不用 UEBA-ML | MTTD 197 天，low-and-slow 攻击看不见 | 等保 2.0 / NIST CSF 评估失分 |
| 不用 Tier 1 分诊 Agent | 告警疲劳 + 分析师流失 + 关键告警漏看 | CrowdStrike 等已自动化，行业 baseline 提高 |
| 不用 OCSF | 对接云 SIEM 需写适配器（v1 没识别；v2 补：Splunk/Chronicle/Sentinel 都是 OCSF 原生） | 数据生态孤岛，AI 训练数据成本翻倍 |
| 不用 LLM Observability | 多 Agent 黑盒，合规审计无证据 | GDPR / 等保 2.0 失分 |
| 不用 NIST 800-61r3 | 合规对标旧版（r2 已废） | 审计师按 r3 评估，差距明显 |
| 不用 Flink 2.0/2.2 | （v1 项）扩缩容分钟级 | 同 v1 |
| 不用 CDC | （v1 项）业务库篡改盲区 | 同 v1 |
| 不用 Hybrid/SPLADE | （v1 项）IOC/CVE 召回低 | 同 v1 |
| 不用 Paimon | （v1 项）数据保留 30d 上限 | 同 v1 |
| 不用 Temporal AI | （v1 项）长会话 agent 扁平 | 同 v1 |
| 不用多 Agent | （v1 项）调查能力受限 | 同 v1 |
| 不用 MCP 2025-11 | （v1 项）生态孤立 | **v2 加：缺 OAuth 2.1，CIO 不批** |

---

## 8 · 验证与回滚机制（沿用 v1 + v2 加 2 条新基准）

### 8.1 升级期验证流程（v2 增 2 条基线）

1. **代码层**：`pytest` 全量通过（基线 232 passed + v2 新增 OCSF/Langfuse/UEBA/r3 测试 ≥ 280 passed）
2. **集成层**：`docker compose up -d --build` 一键启动，所有容器 healthy
3. **数据层**：`log_simulator.py --mode chain` 注入攻击链
4. **响应层**：30s 内 TTL 回收
5. **审计层**：trace_id 全程可追 + **Langfuse 上能看到 LLM trace**（v2 新增）
6. **压测层**：1000 EPS / 1h，P99 < 500ms
7. **回滚演练**：staging 5min 内可恢复
8. **v2 新增 · OCSF 兼容测试**：用 Splunk OCSF 工具读本平台 Kafka topic，验证 schema 正确
9. **v2 新增 · UEBA-ML A/B**：盲样测试，UEBA-ML 检出率应 > 统计式 ≥ 20%

### 8.2 升级期监控指标（v2 增 LLM 维度）

- **升级前 baseline**：Flink Checkpoint / Kafka lag / Temporal 失败率 / Qdrant QPS
- **升级中**：+ ForSt checkpoint / Paimon snapshot / **Langfuse token 成本 / LLM call 成功率**（v2 新增）
- **升级后 2 周**：每日对比 baseline + 异常自动告警

---

## 9 · 配套升级（治理与流程 · v2 增量）

### 9.1 Detection-as-Code（v1 思路保留 + v2 加 OCSF 兼容）

- v1 思路保留
- **v2 新增**：Sigma 规则**自动转 OCSF** 字段（让规则跨 SIEM 平台可移植）

### 9.2 告警响应剧本版本化（v1 思路保留 + v2 升级 r3）

- v1 思路保留
- **v2 新增**：playbook 结构改为 NIST 800-61r3 六函数

### 9.3 蓝队自测平台（v1 思路保留 + v2 加 Agent 化）

- v1 思路保留
- **v2 新增**：用 Atomic Red Team / Caldera 跑"已知攻击集"，**Triage Agent 自动分诊**（验证 L0-3 效果）

### 9.4 反馈循环（v2 新增 · 跨所有 Agent 能力）

- 分析师对所有 Agent 结论 👍/👎
- Langfuse 收集 → 训练集 → 下一版本更准
- 月度复盘：误报聚类、TTP 新趋势
- 行业数据：Charlotte AI 靠这个达到 >98% 准确率

---

## 10 · 总结（v2 重写）

本轮 v2 升级的核心判断：

1. **L0（30 天）是 v2 重点**——OCSF/Langfuse/Tier 1 分诊/NIST r3 全部是"不依赖大版本、立即见 ROI"的补漏项。**v1 缺这层**。
2. **L1（3 月）保留 v1 的 Flink/CDC/OTel，新增 UEBA-ML**——Flink 目标版本修正为 2.2 LTS（v1 写的 2.0 已 EOL）。
3. **L2（6 月）保留 v1 的 Hybrid/Temporal/Paimon，Paimon 升级为 Catalog + Iceberg 备选**——v1 "引入 Paimon" 是错的（Paimon 早就是 Apache 顶级项目）。
4. **L3（12 月）保留 v1 的多 Agent/MCP，角色修正为 5 个 + 加 Observability + 治理层**——v1 写的 3 段 Planner/Executor/Reviewer 已落后于 2026 行业 5 角色共识。

**v2 与 v1 的最大差异**：
- **L0 层**：4 项新升级（OCSF、Langfuse、Tier 1 分诊、NIST r3），全部"30 天可见"
- **版本修正**：Flink 1.18→2.2 LTS（v1 是 2.0，已 EOL）；MCP 2025-11（v1 是 2025-06）
- **行业基准刷新**：用 CrowdStrike Charlotte AI 3x MTTR 70% 减人工 >98% 准确率 / D3 Morpheus / IBM 241d MTTD 节省 108d / Exabeam 0.41B→14.18B UEBA 市场等**v1 没有的量化基准**
- **策略修正**：Qdrant Hybrid 不是"无脑上"，是"先 finetune SPLADE 再 A/B 决定"
- **多 Agent 5 角色 + 4 级 AL 模型**：v1 的 3 段是过时的
- **MCP 治理层**：v1 只换协议，v2 加 Registry 治理 + SSO + 审计 + 沙箱 + 依赖扫描（防 2026-04 RCE 漏洞）
- **MTTD/MTTR 量化**：每项升级都给出"baseline vs 升级后"具体数字

**v2 的验证基础**：
- 14 项升级中，**10 项**有 v1 之外的 2026-Q3 公开数据验证（D3 Security、CrowdStrike、Microsoft、MCP Roadmap、AWS OCSF、阿里云 OpenLake、袋鼠云 Flink 2.0、RisingWave 基准、Qdrant Part 3-4、Exabeam/Securonix 2026）
- **4 项**沿用 v1（CDC、OTel eBPF、Temporal AI、Paimon 基础），但 v2 补最新数据

---

## 附录 A · 与 v1 文档的逐项对照（v2 新增）

| 升级项 | v1 章节 | v2 章节 | 变更摘要 |
|--------|--------|--------|---------|
| 流处理内核 | v1 §2.1 | v2 §3.1 | **目标版本 2.0.0 → 2.2 LTS**（2.0 EOL） |
| 业务事件 CDC | v1 §2.2 | v2 §3.2 | 思路保留 + 加"白名单+双写"细节 |
| OTel + eBPF | v1 §2.3 | v2 §3.3 | 思路保留 + L0-2 Langfuse 联动 |
| 告警自动分诊 | （v1 无） | **v2 §2.0 L0-3** | **新增**（行业 ROI 最高） |
| OCSF 事件协议 | （v1 无） | **v2 §2.0 L0-1** | **新增**（行业标准，ITU 国际标准） |
| LLM Observability | （v1 无） | **v2 §2.0 L0-2** | **新增**（Agent 基础设施） |
| NIST 800-61r3 | v1 §8.1 | **v2 §2.0 L0-4** | **升级**（r2 → r3，r2 已废） |
| Qdrant Hybrid | v1 §3.1 | v2 §4.1 | **策略修正**（先 finetune 再 hybrid） |
| Temporal AI | v1 §3.2 | v2 §4.2 | 思路保留 + 接入 L0-3 分诊 |
| Paimon 湖仓 | v1 §3.3 | v2 §4.3 | **"引入" → "对接 Catalog"** + Iceberg 备 |
| UEBA-ML | v1 §1.1 识别，未列升级 | **v2 §3.4** | **新增**（v1 漏掉的升级项） |
| 多 Agent | v1 §4.1 | v2 §5.1 | **角色 3 段 → 5 角色** + AL 模型 + 反馈循环 |
| 标准化 MCP | v1 §4.2 | v2 §5.2 | **spec 2025-06 → 2025-11** + Registry 治理 + 防 RCE |
| 配套升级 | v1 §8 | v2 §9 | 思路保留 + OCSF 兼容 + Agent 化 |

---

## 附录 B · 参考资料（v2 增 11 个新来源）

### v1 已列（保留）
1-17：见 v1 文档附录 A。

### v2 新增（2026-Q3 截止）
18. D3 Security. *The 12 Best Agentic SOC Platforms in 2026: Architectures, Autonomy Levels, and a Full Comparison*. 2026-07.
19. CrowdStrike. *Charlotte AI: Agentic Analyst for Cybersecurity*（产品页 + 2026 Global Threat Report）.
20. CrowdStrike. *Charlotte AI Agentic Response and Charlotte AI Agentic Workflows Launch*. 2025-10.
21. Microsoft Security Copilot. *Security Agent Studio & Agentic Triage Agents GA*. 2026-07.
22. AWS Open Source Blog. *OCSF Achieves ITU Support: Powering AI-Ready Security Operations*. 2026.
23. Databahn. *What Is OCSF, and Why Normalize Security Data Now*. 2026.
24. Anomali. *OCSF, Explained: Why a Common Schema Changes How Security Teams Work*. 2026.
25. Qdrant. *Fine-Tuning Sparse Embeddings for E-Commerce Search Part 3-4*. 2026.
26. PremAI. *Hybrid Search for RAG: BM25, SPLADE, and Vector Search Combined*. 2026.
27. Securonix. *User and Entity Behavior Analytics (UEBA) Solutions*. 2026.
28. Exabeam. *Best UEBA Software: Top 7 Options in 2026*. 2026.
29. MCP Official Blog. *The 2026 MCP Roadmap*. 2026.
30. Wizeb / Optijara. *MCP in 2026: The Protocol Making AI Agents Enterprise-Ready*. 2026.
31. Forkast News. *MCP Locked In Its Architecture Today. Now the Hard Part: Enterprise Adoption at Scale*. 2026-07.
32. NIST. *SP 800-61r3 Incident Response Recommendations and Considerations for Cybersecurity Risk Management*. 2025-04.
33. RisingWave. *Apache Flink Recovery Time vs RisingWave: A Benchmark*. 2026.
34. 阿里云 OpenLake / 袋鼠云 / Techgenyz. *Apache Paimon 实时湖仓方案 + Lakehouse 2026 横评*. 2026.
35. AI CERTs. *How Autonomous Incident Response Playbooks Slash Breach Time*（IBM 2025 Cost of a Data Breach 数据）. 2026.
36. CSDN. *2026，被认为是 Agentic SOC 的真正元年*. 2026.
37. endoflife.date. *Apache Flink*（版本维护状态）. 2026-07-14.

---

**文档版本**：v2.0（2026-08-25）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-11-25（M+3）对照 2026-Q4 SOC 行业新动向
**前置版本**：v1.0（2026-08-25，见 `2026-q3-tech-stack-upgrade.md`）
