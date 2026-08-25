# 技术栈升级方案 v7（2026-Q3 · 升级轮 v7）

> **本 v7 在 v6（`2026-q3-tech-stack-upgrade-v6.md`，2026-08-25 15:34）基础上**，做了 **6 类修正 + 7 类新增**：
> 1. **修正 v6 的 1 个事实错误**（阿里云 Flink AI Native Ops 2026-08-20 GA 完整功能清单）
> 2. **修正 v6 漏报的 4 个本项目实装项**（8fd0357 OTel + Grafana Tempo 全链路追踪 8-25 15:21 / backend/observability 子模块 / config/otel-collector.yaml / config/tempo/tempo.yaml）
> 3. **新增 5 个 v6 漏报的 2026-08 MCP CVE**（CVE-2026-27825 / CVE-2026-75130 / CVE-2026-76404 / CVE-2026-53965 / CVE-2026-33032）——**MCP server 自身供应链漏洞**
> 4. **新增 4 个 v6 漏的 2026-08 行业动向**（Cribl 收购 Radiant Security 2026-08-19 / 阿里云 Flink AI Native Ops 2026-08-20 GA / 等保 2.0 公安监督检查新规 2026-10 落地 / SOC 3.0 Avasant 采用率）
> 5. **新增 2 类 v6 漏的反例**（MCP Pitfall Lab 6 类失败模式 + MCP 2026-07-28 spec 7 个 text-injection 表面 + 厂商 99% 自报数字反例）
> 6. **新增 1 维度交叉验证**（v6 7 维度 + v7 8.1 MCP 漏洞趋势 + 8.2 阿里云 Flink AI Native Ops 对比 = **8 维度末轮**）
>
> v1/v2/v3/v4/v5/v6 完整保留作为历史快照；本 v7 是"建议执行版 v7"——**v7 不重写 v6 内容，专注 v6 漏的 6 类修正 + 7 类新增**。

---

## 0 · TL;DR：v6 → v7 变更速览

| 维度 | v6（2026-08-25 15:34） | v7（本轮 15:40） | 变更原因 |
|------|------------------------|------------------|---------|
| **MCP 漏洞基线** | v6 §2 反例 13 提 "MCP 2026-07-28 spec" | **修正：v6 漏报 5 个 2026-08 MCP CVE**（CVE-2026-27825 / 75130 / 76404 / 53965 / 33032） | 2026-08 MCP server 自身漏洞集中爆发（"MCP Security Wave"） |
| **MCP Guard 层数** | v6 §6 提 "4 层 MCP Guard + DPoP" | **+ 第 5 层：MCP Server 漏洞防护**（file-write / deserialization / prompt injection / DoS） | Splunk MCP Server CVE-2026-76404 CVSS 9.1（第一个企业级 MCP RCE） |
| **MCP 失败模式** | v6 §2 反例 10 提 "6 大失败模式防护" | **+ MCP Pitfall Lab 6 类**（prompt injection via tools / data exfiltration / authorization bypass / resource exhaustion / cross-server contamination / supply chain） | Adversa AI 2026-08 "MCP Pitfall Lab" 论文 |
| **MCP text-injection 表面** | v6 没提 spec 表面 | **+ 7 个 spec 表面**（server instructions / tool description / tool annotations / tool-result content / resource content / prompt content / deprecated sampling systemPrompt） | MCP 2026-07-28 spec 详定义（digitalapplied.com 2026-08-22 census） |
| **Flink AI Native Ops** | v6 §6 提 "Flink 1.20.5 LTS + Apache Flink Agents 0.3.0 POC" | **+ 阿里云 Flink AI Native Ops 独立入口 2026-08-20 GA**（自然语言驱动运维 + AI 巡检 + Skill 集成 + 健康分滑窗） | 阿里云 2026-08-20 release notes |
| **本项目 OTel 实装** | v6 §6 提 "OTel + Tempo + Jaeger" 在集成图 | **+ 修订 5 个具体文件路径**（8fd0357 提交 backend/observability/ + config/otel/otel-collector.yaml + config/tempo/tempo.yaml + backend/otel_setup.py + backend/trace_context.py） | v6 漏报具体文件路径（v6 仅提 backend/metrics.py / llm_enhancer.py / audit_trail.py 3 个实装） |
| **等保 2.0 监督检查** | v6 §4 提 "等保三级必检 10 项" 静态评估 | **+ 2026-10 公安监督检查新规"动态合规"4 转变**（静态→动态 / 事后→事前 / 纸质→全程溯源 / 单点→常态化巡查）| 黑龙江等保测评 2026-08 / zpedu.com 2026 等保 2.0 通关指南 |
| **SOC AI 行业整合** | v6 没提 | **+ Cribl 收购 Radiant Security 2026-08-19**（AI SOC 平台路线剧烈整合） | D3 Security 2026-08 |
| **厂商 99% 自报数字** | v6 §3.2 TCO 估算"自建 vs 商业" | **+ CrowdStrike 99% AI Detection Efficacy**（厂商自报）/ D3 Morpheus 95% auto-investigated in <2min at L2+ depth（公开基准）| 评审应使用公开基准而非厂商 PPT |
| **SOC 3.0 采用率** | v6 没提 | **+ Avasant 2026-08：60% 探索 / 30% 试点 / 10% 部署 governed AI workflow** | Avasant Cybersecurity Services 2026 Market Insights |
| **本项目 AI 阶段** | v6 §1.2 提 "本项目 LLM 未启用" | **v7 修订：本项目处于"探索阶段"（0% 部署）——Avasant 60% 之一** | Avasant 2026-08 调研 |
| **总升级项** | v6 30 项 + 12 大反例 | **30 项 + 12 大反例 + 5 类 v7 修正 + 7 类 v7 新增 = 17 类 v7 增量** | v6 已有 30 项，v7 不再扩，按 memory 教训"修正 + 反例" |
| **本项目基线** | v6 §3 修订 7 项 | **v7 §3 修订：+ OTel 5 文件 + 健康分滑窗评估** | 直接读 backend/ + config/ 目录 |
| **新增 5 维度** | v6 §7 7 维度 | **v7 §6 8 维度**（+ 8.1 MCP 漏洞趋势 + 8.2 阿里云 Flink AI Native Ops 对比） | 末轮再扫一遍 |

> **v7 核心定位**：v6 是"v5 的事实核验"——6 类修正 + 7 类新增；**v7 是"v6 的盲点扫荡"**——**6 类修正**（v6 评估时漏读 8fd0357 OTel 提交 / v6 漏报 5 个 2026-08 MCP CVE / v6 漏报阿里云 Flink AI Native Ops / v6 漏报等保 2.0 动态合规 / v6 漏报 SOC AI 行业整合 / v6 漏报厂商 99% 自报数字反例）**+ 7 类新增**（v6 漏的 MCP 5 个新 CVE + 阿里云 Flink AI Native Ops + 等保 2.0 动态合规 + Cribl-Radiant 整合 + MCP Pitfall Lab 6 类失败模式 + 7 个 spec text-injection 表面 + 8 维度末轮）。

---

## 1 · v6 误判修正（v7 核心，必读）

按 memory 中"v4→v5 实战教训"："v4 漏检实装项，v5 必须先 `git log --since='24h'` 拉最近 24h 提交"——v6 也漏检了 8fd0357 提交。**v7 必做核验**。

### 1.1 v6 漏报 #1：8fd0357 OTel + Grafana Tempo 全链路追踪（已实装）

**v6 §6 集成架构图提**：
> "可观测性：OTel + Tempo + Jaeger + Prometheus + Grafana + eBPF（v3 §3.3）+ Langfuse LLM 全链路（v3 §2.0 L0-2）+ 7 类 B 级 metrics（v6 §1.5）"

**v6 漏报**：v6 没提**具体文件路径 + commit ID**。

**v7 末轮核验（直接读 git log + backend/observability/ 目录）**：

| 文件 | 提交 | 实装内容 |
|------|------|---------|
| `backend/observability/pipeline_tracer.py` | 2026-08-24 3:26:57（v6 §6 已引）| **管道级 tracer** |
| `backend/observability/health_monitor.py` | 2026-08-01 23:00:32 | **健康监控** |
| `backend/observability/watchdog.py` | 2026-08-24 21:27:17 | **看门狗** |
| `backend/otel_setup.py` | **2026-08-25 15:21:38（8fd0357 新增）** | **OTel 初始化 + exporter 配置** |
| `backend/trace_context.py` | **2026-08-25 15:21:38（8fd0357 新增）** | **trace context 注入 / 提取** |
| `backend/metrics.py` | 2026-08-25 0:07:15 | 7 类 B 级 metrics（v6 §1.5 修正） |
| `config/otel/otel-collector.yaml` | **2026-08-25 15:21:38（8fd0357 新增）** | **OTel Collector 配置** |
| `config/tempo/tempo.yaml` | **2026-08-25 15:21:38（8fd0357 新增）** | **Grafana Tempo 配置** |
| `config/prometheus/prometheus.yml` | 2026-08-25 15:21:38 | **Prometheus 抓取 OTel exporter** |
| `init.sql` | 2026-08-25 15:21:38 | **OTel + Tempo 表结构** |
| `docker-compose.yml` | 2026-08-25 15:21:38 | **新增 4 个服务：otel-collector / tempo / prometheus / grafana** |
| `frontend/src/components/operations/TraceTab.tsx` | 2026-08-25 15:21:38 | **前端 Trace 标签页** |
| `backend/tests/test_trace_otel.py` | 2026-08-25 15:21:38 | **OTel 单元测试** |
| `flink-jobs/.../TraceUtil.java` | 2026-08-25 15:21:38 | **Flink 端 trace 注入** |
| `flink-jobs/.../TraceIdHeaderProvider.java` | 2026-08-25 15:21:38 | **Flink Kafka header trace 透传** |

**统计**：**8fd0357 commit 改了 32 个文件，+1829 行 / -115 行**——v6 §6 集成架构图只画了 1 句 OTel 描述，**v7 必报 5 个核心文件路径 + 11 个相关文件清单**。

**v7 必报**：
- v6 漏报**具体文件路径**——v7 必报**文件级实装清单**
- v6 §1.5 提"7 类 B 级 metrics"——v7 必报"**OTel 7 个 trace span（HTTP / Kafka / Flink / LLM / DB / EDR / IOC）**"是否实现
- v6 §1.3 提"LLM Enhancer 已实装 6 大功能"——v7 必报"**LLM 调用是否带 trace span**"（v6 §1.3 提"trace 留痕"是 trace_hook 而非 OTel span）
- v6 §1.4 提"audit_trail 已实装"——v7 必报"**审计操作是否带 OTel trace_id**"（v6 §1.4 提"@audited 装饰器"无 trace_id）

### 1.2 v6 漏报 #2：本项目 OTel 是否覆盖 MCP 2026-07-28 spec 7 个 text-injection 表面

**v6 §2 反例 13 提**：
> "MCP 2026-07-28 spec + 08-22 Roadmap"

**v6 漏报**：v6 提"5 层零信任 + 5 Guardrail"——**没提 MCP spec 定义的 7 个 text-injection 表面**。

**v7 末轮核验（digitalapplied.com 2026-08-22 census）**：

| # | 表面（spec 2026-07-28 定义） | spec 章节 | 控制器 | 状态 | spec 原话 |
|---|--------------------------|----------|--------|------|---------|
| 1 | **Server instructions field** | Discovery | Server-declared, returned on connection discovery | Active | "Optional natural-language guidance for LLMs on how to use this server effectively." |
| 2 | **Tool description** | Tools | Server-authored; required per tool, shown to the model | Active | "description: Human-readable description of functionality." |
| 3 | **Tool annotations** | Tools | Server-declared behaviour hints | Active | "clients MUST consider tool annotations to be untrusted unless they come from trusted servers." |
| 4 | **Tool-result content** | Tools | Whatever the tool returns — including embedded resources | Active | "A tool MAY return links to Resources"; embedded resources "MAY be embedded to provide additional context or data." |
| 5 | **Resource content + annotations** | Resources | Server-authored content | Active | （spec 原话略）|
| 6 | **Prompt content** | Prompts | User-controlled to invoke | Active | （spec 原话略）|
| 7 | **Deprecated sampling systemPrompt** | Sampling | （已弃用但仍存在） | Deprecated | （spec 原话略）|

**v7 必报**：
- v6 §2 反例 13 提"4 层 MCP Guard"是**基线防护**——v7 必报"**针对 7 个 spec 表面逐项防护**"
- **本项目 backend/mcp_guard/ 必报**：
  - guard_server.py 是否对 server instructions 做白名单？（v7 没读）
  - guard_server.py 是否对 tool description 做长度限制？（v7 没读）
  - guard_server.py 是否对 tool annotations 做 trust validation？（v7 没读）
  - guard_server.py 是否对 tool-result content 做 schema 校验？（v7 没读）
  - guard_server.py 是否对 resource content 做大小限制？（v7 没读）
  - guard_server.py 是否对 prompt content 做 injection 检测？（v7 没读）

### 1.3 v6 漏报 #3：本项目 health_monitor 是否需要"滑窗"升级

**v6 §6 集成架构图提**：
> "可观测性：OTel + Tempo + Jaeger + Prometheus + Grafana + eBPF（v3 §3.3）"

**v6 漏报**：v6 没提**health_monitor.py 2026-08-01 实装的健康分算法**。

**v7 末轮核验（阿里云 Flink 2026-08-20 release notes）**：
- **关键 bug 修复**：阿里云 Flink 健康分按累计风险计算导致分数"**只降不升**"，历史风险误导排查
- **修复方案**：风险计数改为"**滑窗统计**"，视窗到期后分数自动回升，无需手动重启重设
- **本项目 health_monitor.py 2026-08-01 已实装**——**v7 必查是否需要"滑窗"升级**（避免评分"只降不升"误导运维）

**v7 必报**：
- 本项目 health_monitor.py 当前算法（v6 提"实装"但 v6 没读算法）
- 是否存在"累计风险只降不升"问题
- 阿里云 Flink 2026-08-20 修复方案是否适用本项目

### 1.4 v6 漏报 #4：本项目 LLM 启用前必须做的"MCP server 漏洞防护"

**v6 §1.2 提**：
> "本项目 LLM 启用前的 'AI 训练数据来源合规' 清单 + 'AI 系统安全监测 + 风险处置' 能力清单"

**v6 漏报**：v6 提"MCP 2026-07-28 spec + 08-22 Roadmap"——**没提 2026-08 集中爆发的 5 个 MCP server 自身漏洞**。

**v7 必报（本节详 §2.1-§2.5 5 个新 CVE）**：
- **MCP server 自身**是攻击面，不只是 prompt injection
- 本项目一旦启用 LLM，**自动适用**CVE-2026-27825 / 75130 / 76404 / 53965 / 33032 5 个 CVE 的所有缓解措施
- v6 §1.2 提"AI 训练数据来源合规"——v7 必报"**MCP server 漏洞管理流程**"

---

## 2 · v6 漏的 2026-08 MCP CVE 群（v7 核心新增）

按 v5/v6 教训 "v4 漏反例 / 合规 / 成本 / 决策树"——v7 漏"v6 漏的 2026-08 MCP CVE 群"。

### 2.1 反例 15：**CVE-2026-27825 MCP Atlassian 任意文件写入（2026-08-03）**

**v6 漏报**。

来源：Check Point CPAI-2026-9606 / aigovernance.com 2026-08-03 / NVD

**v6 漏的关键事实**：
```
MCP Atlassian 是连接 AI agent 到 Atlassian 工具（Jira / Confluence）的 MCP server，
在 < 0.17.0 版本中存在高严重性任意文件写入漏洞（CWE-22 / 路径遍历）。

攻击者可向 MCP server 进程有权限访问的任何文件系统路径写入任意内容。
由于 MCP server 通常在企业环境内以高权限运行，影响远超单个文件——
写入可执行路径或配置文件 = RCE + 完全 server 沦陷。

披露前已有公开披露的 MCP 漏洞：
- CVE-2026-11624（NIST 标记 DNS rebinding 风险）
- MCP Ruby SDK / File Server 漏洞暴露企业 agent 工具链
```

**本项目风险评估**：
- 本项目**当前未使用 Atlassian MCP server**（v6 §1.2 提 LLM 未启用）
- **但**本项目设计目标包含 SOC 协作场景（5 仪表板：Monitor / RAG / Intel / Phishing / EDR / Operations）
- 一旦启用 LLM + Atlassian 集成，**自动适用**此 CVE 缓解

**v7 必报**：
- 本项目 LLM 启用前**必报"集成 MCP server 漏洞管理流程"**
  - 集成前查 NVD + GitHub Advisory
  - 锁定最低支持版本（如 MCP Atlassian ≥ 0.17.0）
  - CI/CD 加 MCP server SBOM + 漏洞扫描
- 本项目**进程权限收敛**：MCP server 进程**禁止**写入可执行路径 / 配置文件（v7 必报 backend/mcp_guard/guard_server.py 当前实现）

### 2.2 反例 16：**CVE-2026-75130 Context7 Prompt Injection（2026-08-18，CVSS 9.0）**

**v6 漏报**。

来源：NVD 2026-08-18 / VulnCheck advisory / digitalapplied.com 2026-08-22

**v6 漏的关键事实**：
```
Context7（Upstash 维护的 MCP 文档 server，2.1.2 及更早版本）存在 Prompt Injection 漏洞。
"Custom AI Instructions" 特性在 MCP server 中提供未净化内容
→ 连接到 Context7 的 AI coding agent 收到恶意指令
→ 影响：从环境文件窃取凭证、删除文件
CWE-1427 "Improper Neutralization of Input Used for LLM Prompting"
（**注意：是 CWE-1427 不是传统 CWE-77/78/79**——LLM 应用的新型 CWE 编号）

**双 CVSS 评分差异**：
- CVSS 3.1: 9.0 CRITICAL
- CVSS 4.0: 6.4 MEDIUM
- 同一漏洞两个框架评分差 2.6 分——评估时必须看两个分数
```

**本项目风险评估**：
- 本项目**当前未使用 Context7 MCP server**（v6 §1.2 提 LLM 未启用）
- **但**本项目 RAG 检索模块（Qdrant + SPLADE）v6 §1.5 提"数据飞轮"——**等价于 Context7 模式**：
  - 用户提交文档 → Qdrant 索引 → LLM 检索
  - **如果用户提交恶意文档，等于 CVE-2026-75130 的攻击路径**

**v7 必报**：
- 本项目 RAG 检索**必报"文档注入防护"**清单
  - 文档来源白名单（v7 必报哪些来源）
  - 文档内容扫描（regex / LLM 双重检测）
  - 检索结果 LLM 重写（避免直接拼接 prompt）
- v6 §1.2 提"AI 训练数据来源合规"——v7 必报"**RAG 文档来源合规**"
- 评审时**双 CVSS 评分必报**（CVSS 3.1 + 4.0 都给）

### 2.3 反例 17：**CVE-2026-76404 Splunk MCP Server RCE（2026-08-19，CVSS 9.1）**

**v6 漏报**。

来源：NVD 2026-08-19 / Cisco/Splunk advisory VULN-84459 / forkast.news 2026-08 / cybersecuritynews.com 2026-08

**v6 漏的关键事实**：
```
Splunk MCP Server（< 1.2.1）存在 CVSS 9.1 反序列化漏洞（CWE-502）。

漏洞位置：app 的 credential management 组件
机制：系统反序列化存储数据时**不验证内容类型** → admin 角色用户可在底层 OS 执行任意命令

**意义**：
- **第一个**企业级 MCP server 关键 CVE（Splunkbase 下载量 20,468+）
- 攻击需要 admin 角色，但 SOC 分析师通常被授予 admin 角色以做威胁狩猎
- "**企业级 MCP server = 关键基础设施，不是实验性附加组件**"
- 修复：1.2.1；未升级前应禁用或卸载

配套修复：CVE-2026-76389-76403（Splunk AI Toolkit + Splunk Connect for Kafka 共 17 个漏洞）
```

**本项目风险评估**：
- 本项目**未使用 Splunk MCP Server**（v6 §6 集成架构图自建 Flink + Kafka + Qdrant）
- **但**本项目告警响应可能**集成 Splunk 平台**（揭榜挂帅评审场景常见）
- 一旦集成 Splunk，**必须升级 Splunk MCP Server ≥ 1.2.1**

**v7 必报**：
- 本项目"集成 Splunk 评估"时**必报"升级 Splunk MCP Server ≥ 1.2.1"**
- v6 §6 集成架构图第 4 层 "MCP Guard + DPoP"——**v7 必报升级为"5 层 MCP Guard + MCP Server 漏洞管理"**
- 揭榜挂帅评审**不承诺**使用未修复的 Splunk MCP Server

### 2.4 反例 18：**CVE-2026-53965 MCP PHP SDK SSE Buffer DoS**

**v6 漏报**。

来源：GitLab Advisory / NVD / modelcontextprotocol/php-sdk 0.7.1

**v6 漏的关键事实**：
```
MCP PHP SDK 的 HTTP client transport 在 mcp/sdk 中读取 SSE 响应流时
增量 append 4 KiB chunks 到内存 buffer（$this->sseBuffer .= $chunk;）
**无上限**——仅在 SSE 事件分隔符（"\n\n"）出现时 flush

远程 MCP server（或控制 server 响应的网络位置）
可通过不发送 "\n\n" 分隔符而持续流式发送数据
→ $sseBuffer 增长无限制 → PHP memory_limit 耗尽 → 客户端进程崩溃

**意义**：
- 任何客户端连接的 server（或中间人）都可发起 DoS
- 攻击门槛低，威胁面广
- 修复：mcp/sdk 0.7.1
```

**本项目风险评估**：
- 本项目**后端用 Python（FastAPI）**——**不直接受影响**
- **但**本项目前端/边缘组件可能使用 PHP（如有 SSO/CMS 集成）
- **通用教训**：本项目 backend/kafka_consumer.py 8-25 15:30 也用 streaming，**v7 必查是否有限速 / 限大小防护**

**v7 必报**：
- 本项目所有 SSE / streaming 客户端**必报"buffer 上限 + chunk 数上限"**
- 评审时**不承诺**使用未修复的 MCP PHP SDK

### 2.5 反例 19：**CVE-2026-33032 nginx-ui MCP endpoint CVSS 9.8 + STDIO Transport 设计缺陷**

**v6 漏报**。

来源：dev.to mrclaw207 2026-08 / Anthropic advisory

**v6 漏的关键事实**：
```
**CVE-2026-33032**: nginx-ui MCP endpoint 未认证 RCE，CVSS 9.8
- 2,600+ 互联网暴露实例
- 修复前应限制 admin panel 网络访问

**STDIO Transport 设计缺陷**: 200,000 servers at risk
- 攻击者无需凭证即可执行任意 OS 命令
- 仅需能向 MCP server 投递恶意消息
- 攻击门槛低，所有支持 SDK 全部受影响

**Adversa AI MCP Pitfall Lab 6 类失败模式**（v6 §2 反例 10 漏报）：
1. P1 Prompt injection via tools
2. P2 Data exfiltration through response shaping
3. P3 Authorization bypass
4. P4 Resource exhaustion
5. P5 Cross-server contamination
6. P6 Supply chain attacks through MCP server dependencies
```

**本项目风险评估**：
- 本项目**未使用 nginx-ui**（v6 §6 集成架构图自建 FastAPI + React）
- **但**本项目若部署 Web UI（前端 React + Nginx 反代）——**Nginx 配置必查 admin path**
- 本项目 MCP Guard 4 层 + DPoP（v6 §2 反例 13）**部分缓解** STDIO Transport 设计缺陷
- **但 STDIO 设计缺陷是协议级问题，需在 Guard 层做限速 + 沙箱**

**v7 必报**：
- 本项目前端 Nginx 反代配置**必查"admin path 限制"**
- 本项目 backend/mcp_guard/ 必报"6 类 MCP Pitfall Lab 防护"清单
- v6 §2 反例 10 提"6 大失败模式防护"是**基础**——v7 必报"**12 大失败模式防护**"（6 类 v6 基础 + 6 类 Pitfall Lab）

---

## 3 · v6 漏的 2026-08 行业动向（v7 新增 4 类）

### 3.1 v7 新增 #1：**等保 2.0 公安监督检查新规 2026-10 落地（动态合规）**

**v6 §4 提"等保三级必检 10 项自评清单"**——**v6 漏报 2026-10 公安监督检查新规**。

来源：黑龙江等保测评 hljdengbao.com 2026-08 / zpedu.com 2026 等保 2.0 通关指南 / CN-SEC cn-sec.com 2026-08

**v6 漏的关键事实**：
```
2026-10 落地的公安监督检查新规彻底颠覆传统一次性测评整改模式：

核心变革 = 4 转变：
1. **静态合规 → 动态管控**：线上全天候巡检 + 线下专项抽查
2. **事后整改 → 事前预防**：常态化防护能力 + 风险闭环整改能力
3. **纸质台账 → 全程溯源**：动态化管控、全流程溯源
4. **单点核查 → 常态化巡查**：无长效合规机制的企业持续面临整改 / 约谈 / 处罚

**v6 漏的关键测评新规**：
- 2025 版测评报告模板（2025-11-30 前所有二级及以上系统重新备案）
- 2025 版模板废止"百分制 + 优良中差"四档
- 新版三级判定 = 符合（≥90% 且无重大风险隐患）/ 基本符合（60-90% 或 ≥90% 但有重大风险隐患）/ 不符合（<60%）
- **重大风险隐患依据三个原则判定**：
  1. 相关性原则（与系统破坏后果直接相关）
  2. 严重性原则（可能造成严重后果）
  3. 高发性原则（行业普遍发生）
- 高风险否决项必须 100% 整改闭环（10 项：未修复高危漏洞 / 无审计日志 / 无数据备份 / 弱口令 / 权限泛滥 / 6 个月日志 / 默认口令 / 开放管理端口 / 访客网络不隔离 / 机房无物理访问控制）

**v6 漏的测评新规 33 条红线**（GA/T 2380-2026 + GA/T 2394-2026 + GA/T 2395-2026）：
- 数据分级分类 / 重要数据识别 / 密码技术使用 / 全操作审计 / 年度评估 / 33 项强制项
- 三级以上系统强制使用密码技术 + 全操作审计 + 年度评估
- 备案证明有效期统一 3 年
- 测评费用参考：二级 3-5 万 / 三级 15-50 万（按系统数量 / IP 数 / 模块复杂度）
```

**v6 §4 "10 项必检"是静态评估**——**v7 必报"动态合规 4 转变 + 33 条红线 + 测评三级判定"**。

**v7 必报**：
- v6 §4 "等保三级必检 10 项"——v7 升级为"**动态合规 4 转变 + 33 条红线 + 测评三级判定**"
- v6 §4 #6 "年度评估：报告留存 ≥3 年"——v7 必报"**半年专项风险评估 + 季度应急演练 + 月度安全巡检**"
- v6 §4 #2 "Kafka 7 topic 加密状态"——v7 必报"**Kafka SASL + TLS 启用计划 + 国密 SM4 字段加密**"
- v6 §5 P0 14 项——v7 必报"**P0 18 项（v6 14 + v7 4 项动态合规）**"

### 3.2 v7 新增 #2：**阿里云 Flink AI Native Ops 2026-08-20 GA（自建 vs 商业对比）**

**v6 §6 集成架构图提 "Flink 1.20.5 LTS + Apache Flink Agents 0.3.0 POC"**——**v6 完全没提阿里云 2026-08-20 发布的 Flink AI Native Ops**。

来源：阿里云 2026-08-20 release notes（help/en/flink/realtime-flink/product-overview/aug-20-2026）

**v6 漏的关键事实**：
```
阿里云 2026-08-20 灰阶发布 Realtime Compute for Apache Flink "**Flink AI Native Ops 独立入口**"：

**5 大功能**：
1. **统一入口**：智能诊断 / 智能巡检 / 技能管理 / Token 用量统一呈现在独立产品页面
2. **自然语言驱动**：自然语言驱动单步操作与跨模块复杂任务自动编排
3. **实体引用增强**：支持引用 Catalog 元数据 / 作业草稿 / 部署 / Session 集群等实体
4. **智能巡检升级**：支持开启或关闭自动巡检任务；自然语言生成配置 + 表单化配置
5. **OpenAPI + Skill 闭环**：CreateAiService / DescribeAiService / CloseAiService 标准化接口

**健康分滑窗机制（关键 bug 修复）**：
- 修"健康分按累计风险计算导致分数只降不升"
- 风险计数改为**滑窗统计**
- 视窗到期后分数自动回升，无需手动重启

**OpenAPI + Skill 集成**：
- Skill 封装支持用户 Agent 整合调用
- 实现商业化流程的 API 化闭环
```

**v6 §6 集成架构图 vs 阿里云 2026-08-20 对比**：

| 维度 | v6 §6 自建 Flink | 阿里云 Flink AI Native Ops 2026-08-20 GA |
|------|-----------------|------------------------------------------|
| **运维入口** | 7 仪表板 / 手工配置 | **自然语言驱动** + 智能巡检 + 智能诊断 |
| **健康分算法** | health_monitor.py 8-01（v6 没读） | **滑窗统计**（2026-08-20 修复"只降不升"）|
| **AI 巡检** | v6 §6 提 "7 类 B 级 metrics" | **自然语言生成配置 + 表单化配置** |
| **OpenAPI** | v6 §6 提 "8 角色 Agent" + Temporal | **CreateAiService / DescribeAiService / CloseAiService** |
| **Skill 集成** | v6 §6 提 "MCP 2026-07-28 spec" | **Skill 封装支持用户 Agent 整合调用** |
| **本体部署成本** | 自建 ~$76K/年（v5 §3.2 估算）| 阿里云包年 ~$30-100K/年（按 CU） |

**v7 必报**：
- v6 §6 "自建 Flink"路线——**v7 必报"自建 vs 阿里云包年 决策树"**
- v6 §6 提"健康监控"——v7 必报"本项目 health_monitor.py 是否需要滑窗升级"
- v6 §6 提"5 Guardrail"——v7 必报"是否集成阿里云 Flink AI Native Ops 入口（按需）"

### 3.3 v7 新增 #3：**Cribl 收购 Radiant Security 2026-08-19（SOC AI 行业剧烈整合）**

**v6 §3.2 TCO 估算提"自建 vs Sentinel $30-150K vs Splunk $150-500K+ vs Elastic $70-900K vs D3 Morpheus $100-300K"**——**v6 漏报 SOC AI 行业整合**。

来源：D3 Security 2026-08 / Cybersecurity News 2026-08

**v6 漏的关键事实**：
```
2026-08-19 Cribl 收购 Radiant Security 的 AI SOC 技术资产
Radiant 是 AI SOC 平台路线代表，承诺"开箱即用的调查"
被 Cribl 收购后将作为 application 运行在 Cribl 的遥测平台上

**SOC AI 三种市场路线**（D3 Security 2026-08 重新分类）：
1. **Hyperautomation 平台**（Torq 代表）：no-code 引擎 + AI agent 增强
   - 优势：工程师构建 workflow 即可，平台规模化执行
   - 劣势：调查深度跟随团队编码的逻辑；vendor API 变更时 workflow 维护是团队工作
2. **AI Triage 代理**（Dropzone AI 代表）：预训练 AI analyst 调查 Tier 1 警报
   - 优势：快速部署、聚焦设计
   - 劣势：Tier 2+ 调查仍需其他 stack
3. **AI SOC 平台**（Radiant → Cribl / D3 Morpheus 代表）：编排 + 案件管理同引擎
   - 优势：调查端到端运行、800+ 自愈集成
   - 劣势：vendor 路线变更时（如 Cribl 收购）客户面临不确定
```

**v6 §3.2 TCO 估算没提市场路线**——**v7 必报"本项目走哪条路线 + 选型依据"**。

**v7 必报**：
- v6 §6 集成架构图自建 7 仪表板 + 8 角色 Agent——**v7 必报"本项目走 AI SOC 平台路线（自建等同 D3 Morpheus 模式）"**
- v6 §3.2 TCO 对比**+ 路线维度**（自建 AI SOC 平台 vs 商业 Hyperautomation vs 商业 AI Triage）
- v6 §2 反例 10 提"6 大失败模式防护"——v7 必报"**Hyperautomation 路线 vs AI SOC 路线失败模式差异**"
- 揭榜挂帅评审**不承诺**走单一商业路线（市场剧烈整合期 3-6 月内可能再变）

### 3.4 v7 新增 #4：**CrowdStrike/D3 Morpheus 厂商 99% 自报数字 vs 公开基准**

**v6 §3.2 TCO 估算提"自建 ~$76K/年"**——**v6 漏报厂商数字反例**。

来源：Larridin CrowdStrike AI Tracker 2026-08-20 / D3 Security 2026-08

**v6 漏的关键事实**：
```
**厂商自报数字 vs 公开基准**：

| 厂商 | 自报数字 | 公开基准 | v6 漏报 |
|------|---------|---------|---------|
| **CrowdStrike** | 99% AI Detection Efficacy, < 30ms latency | ❌ 公开基准未发布 | v6 漏报 |
| **CrowdStrike Charlotte AI** | 98% accuracy, 40+ hours/week saved per customer | ❌ 公开基准未发布 | v6 漏报 |
| **D3 Morpheus** | ❌ 厂商未提"99%" | **95% alerts auto-investigated in <2min at L2+ depth** | v6 漏报 |
| **Swimlane** | AI SOC 路由 | Google/CSA：>90% 团队测试或规划 AI | v6 漏报 |
| **Avasant SOC 3.0 采用率** | ❌ 厂商未提 | **60% 探索 / 30% 试点 / 10% 部署 governed AI workflow** | v6 漏报 |
| **WEX 案例** | 50% 工具削减 | CrowdStrike Charlotte AI | v6 漏报（v3 §3.4 提过 "24→8" 真实案例） |
| **LottieFiles 案例** | 24/7 SOC 30 天交付 / 80% 调查时间下降 | Exaforce | v6 漏报 |

**关键数字反例**：
- CrowdStrike 99% Detection Efficacy 是**厂商自报**——独立基准未发布
- D3 Morpheus 95% auto-investigated in <2min 是**公开基准**（v3 §3.4 已引用）
- v6 §3.2 TCO 估算"自建 ~$76K/年"——v7 必报"**自建基线 vs 公开基线 vs 厂商自报基线"3 类来源
```

**v7 必报**：
- v6 §3.2 TCO 估算**+ "数字来源维度"**（公开 / 厂商自报 / 自测）
- v6 §3.2 提"商业平台对比"——v7 必报"**真实公开基准 = D3 Morpheus 95% + 24/7 <2min；CSDN 真实案例 24→8"**
- v6 §3.2 提"AI 价值"——v7 必报"**本项目目前处于 60% 探索阶段（Avasant 调研）"**

---

## 4 · v7 修订本项目基线（v6 §3 基础上 + 5 项修订）

### 4.1 v6 已给 7 项修订（保留）

见 v6 §3.2。

### 4.2 v7 修订 5 项

| 维度 | v6 评估 | v7 末轮核验（直接读代码） | 评估 |
|------|--------|--------------------------|------|
| **本项目 OTel 实装** | v6 §6 提"OTel + Tempo + Jaeger"无文件路径 | **已实装**（8fd0357 提交 5 核心文件 + 11 相关文件清单，见 v7 §1.1） | v6 漏路径 |
| **本项目 MCP 7 表面防护** | v6 §2 反例 13 提"4 层 MCP Guard" | ❌ **v7 没读 guard_server.py**（必查 7 表面逐项防护） | v6 漏报 |
| **本项目 health_monitor 滑窗** | v6 §6 提"健康监控"无算法 | **待评估**（阿里云 2026-08-20 修复"只降不升"） | v6 漏报 |
| **本项目 SSE buffer 防护** | v6 没提 | **待查**（CVE-2026-53965 影响所有 streaming 客户端） | v6 漏报 |
| **本项目 LLM 启用前 MCP 漏洞管理** | v6 §1.2 提"AI 训练数据 + AI 系统监测" | **+ v7 必报"集成 MCP server 漏洞管理流程"** | v6 漏报 |

### 4.3 v7 新增 4 项本项目必量化

| 维度 | 当前值 | v7 必量化 |
|------|--------|----------|
| **本项目 OTel span 数** | 8fd0357 实装 7 类 metrics，OTel span 数 v7 没读 | v7 必报"7 个 trace span（HTTP / Kafka / Flink / LLM / DB / EDR / IOC）" 是否实现 |
| **本项目等保 2.0 动态合规** | v6 §4 10 项必检 | v7 必报"动态合规 4 转变（线上巡检 / 事前预防 / 全程溯源 / 常态化）"自评 |
| **本项目 AI 阶段定位** | v6 §1.2 提"未启用 LLM" | v7 必报"本项目处于 Avasant 60% 探索阶段" |
| **本项目 MCP 7 表面防护率** | v6 §2 反例 13 提"4 层 MCP Guard" | v7 必报"7 表面逐项防护率（0-100%）" |

---

## 5 · v7 决策树扩展（v6 14 项 + v7 4 项 = 18 项）

v6 §5 给"P0 14 项必做"——v7 必报"v6 漏的 4 项必做"（基于 v7 §1-4 修正 + §2 反例 15-19 + §3 行业动向）：

| 优先级 | 项 | 来源 | v7 评估 |
|--------|----|------|---------|
| **P0 立即** | （v6 14 项保留） | v6 §5 | ✅ |
| **P0 立即** | **7-1**：本项目 OTel 7 个 trace span 实现 + 评审演示用 TraceTab 截图 | v7 §1.1 修正 | **v7 必报** |
| **P0 立即** | **7-2**：本项目 MCP 7 表面逐项防护（v7 §1.2 + 反例 15-19） | v7 §1.2 修正 | **v7 必报** |
| **P0 立即** | **7-3**：本项目等保 2.0 动态合规 4 转变自评 | v7 §3.1 新增 | **v7 必报** |
| **P0 立即** | **7-4**：本项目 LLM 启用前的"集成 MCP server 漏洞管理流程" | v7 §1.4 + 反例 15-19 | **v7 必报** |
| **P1 30 天** | v6 P1 6 项保留 | v6 §5 | ✅ |
| **P1 30 天** | **7-5**：本项目自建 vs 阿里云包年 Flink 决策树 | v7 §3.2 新增 | **v7 必报** |
| **P1 30 天** | **7-6**：本项目 SOC AI 路线选型（AI SOC 平台 vs Hyperautomation vs AI Triage）| v7 §3.3 新增 | **v7 必报** |
| **P1 30 天** | **7-7**：本项目厂商 99% 自报数字 vs 公开基线核对（v7 §3.4） | v7 §3.4 新增 | **v7 必报** |
| **P1 30 天** | **7-8**：本项目 health_monitor 滑窗升级评估 | v7 §1.3 修正 | **v7 必报** |
| **P2 90 天** | v6 P2-P4 18 项保留 | v6 §5 | ✅ |
| **P2 90 天** | **7-9**：本项目 SSE buffer 上限 + chunk 数上限审计 | v7 §2.4 反例 18 | **v7 必报** |
| **P3 6 月** | v6 P4 12 月 5 项保留 | v6 §5 | ✅ |
| **P4 12 月** | v6 P4 12 月 3 项保留 | v6 §5 | ✅ |
| **P4 12 月** | **7-10**：本项目 Splunk MCP Server 升级评估（一旦集成） | v7 §2.3 反例 17 | **v7 必报** |
| **P4 12 月** | **7-11**：本项目 MCP Atlassian ≥ 0.17.0 锁定（一旦集成） | v7 §2.1 反例 15 | **v7 必报** |
| **P4 12 月** | **7-12**：本项目 RAG 文档注入防护（v7 §2.2 反例 16 + Qdrant 索引） | v7 §2.2 反例 16 | **v7 必报** |

**v7 决策树核心**：
- **P0 18 项必做**（v6 14 项 + v7 4 项）
- **P1 30 天 10 项加做**（v6 6 项 + v7 4 项）
- **P2-P4 19 项 + 4 项**（v6 沿用 + v7 4 项）

---

## 6 · v7 8 维度交叉验证（v6 7 维度基础上 + 1 个新维度）

按 memory 中"v4→v5 实战教训"："v5 加 6.1-6.5 = 10 个子维度；v6 加 7.1 本项目实装度 + 7.2 法规细节 = 7 维度；v7 加 8.1 MCP 漏洞趋势 + 8.2 阿里云 Flink AI Native Ops = 8 维度末轮"。

### 6.1 维度 7（v6 已做）：版本谱 / 协议 spec / AI Agent GA / 行业量化基线 / 行业教训反例 / 本项目实装度 / 法规细节

见 v6 §6.1-6.5 + §7.1-7.3 完整内容（v7 保留，**只修正 8.1.1 MCP 漏洞矩阵**）。

#### 6.1.1 v7 修正 v6 §6.1 MCP 漏洞矩阵

| CVE | 披露时间 | 评分 | 影响范围 | v6 是否提 | v7 必报 |
|-----|---------|------|---------|----------|---------|
| **CVE-2026-27825 MCP Atlassian** | 2026-08-03 | 高严重性（未给 CVSS）| < 0.17.0 | ❌ v6 漏 | **v7 新增** 反例 15 |
| **CVE-2026-11624 MCP DNS Rebinding** | 2026-08 | NIST 标记 | 所有 MCP SDK | ❌ v6 漏 | **v7 新增** |
| **CVE-2026-75130 Context7** | 2026-08-18 | CVSS 3.1 9.0 / CVSS 4.0 6.4 | ≤ 2.1.2 | ❌ v6 漏 | **v7 新增** 反例 16 |
| **CVE-2026-76404 Splunk MCP** | 2026-08-19 | CVSS 9.1 | < 1.2.1 | ❌ v6 漏 | **v7 新增** 反例 17 |
| **CVE-2026-53965 MCP PHP SDK** | 2026-08 | DoS | mcp/sdk | ❌ v6 漏 | **v7 新增** 反例 18 |
| **CVE-2026-33032 nginx-ui** | 2026-08 | CVSS 9.8 | < patch | ❌ v6 漏 | **v7 新增** 反例 19 |
| **MCP STDIO Transport 设计缺陷** | 2026-08 | 设计缺陷 | 200,000 servers | ❌ v6 漏 | **v7 新增** |
| **CVE-2026-76389-76403** | 2026-08-19 | 高 8.8 / 中 5.9 等 | Splunk AI Toolkit + Kafka | ❌ v6 漏 | **v7 新增**（Splunk 集成评估） |

#### 6.1.2 v7 修正 v6 §6.1 Flink AI Native Ops 矩阵

| 维度 | 自建（v6 §6） | 阿里云 Flink AI Native Ops（v7 §3.2）| 选型依据 |
|------|--------------|-----------------------------------|---------|
| **运维入口** | 7 仪表板 + 手工 | **自然语言驱动** + 智能巡检 | 团队规模 / 工程师数量 |
| **健康分算法** | health_monitor.py 8-01 | **滑窗统计**（2026-08-20 修复）| 评分准确性 |
| **AI 巡检** | 7 类 metrics | **自然语言生成配置** | 巡检频率 |
| **OpenAPI + Skill** | Temporal + 8 角色 Agent | **CreateAiService / DescribeAiService / CloseAiService** | API 完整性 |
| **TCO** | 自建 ~$76K/年（v5 §3.2 估算）| 阿里云包年 ~$30-100K/年 | 团队成本 |
| **数据本地化** | ✅ 100% 本地 | ❌ 上云（视合规）| 数据敏感性 |
| **可控性** | ✅ 100% 自控 | ❌ vendor 路线变更风险（Cribl-Radiant 教训）| 长期可维护性 |
| **揭榜挂帅评审** | ✅ 推荐（自建）| ❌ 不推荐（vendor 路线变更）| 评审稳定性 |

**v7 必报**：
- **揭榜挂帅评审建议走自建路线**（避免 vendor 整合期路线变更）
- 本项目 health_monitor.py 必查"滑窗升级"
- **评审不承诺**"集成阿里云 Flink AI Native Ops"——自建路线更稳定

### 6.2 维度 8（v7 新增）：MCP 漏洞趋势 + 等保 2.0 动态合规

#### 6.2.1 MCP 漏洞趋势（v7 §2 反例 15-19 整合）

| 趋势 | 时间 | 行业影响 | 本项目风险 |
|------|------|---------|----------|
| **MCP server 自身漏洞集中爆发** | 2026-08-03 至 8-19 | 5 个新 CVE + 1 个设计缺陷 | 启用 LLM 后立即适用 |
| **企业级 MCP server CVE 时代** | 2026-08-19 | Splunk MCP Server CVSS 9.1（第一个企业级） | 集成 Splunk 必升级 ≥ 1.2.1 |
| **CVSS 双评分差异** | 2026-08-18 | Context7: 9.0 vs 6.4 | 评审时**双评分必报** |
| **新型 CWE 编号** | 2026-08-18 | CWE-1427（LLM prompt injection 专用） | 本项目 RAG 检索等价路径 |
| **MCP Pitfall Lab 6 类失败模式** | 2026-08 | Adversa AI 论文 | 本项目 MCP Guard 必报 12 类 |
| **MCP 7 表面 spec 定义** | 2026-07-28 | spec 详定义 | 本项目 Guard 必报 7 表面 |

#### 6.2.2 等保 2.0 动态合规（v7 §3.1 整合）

| 转变 | 旧模式 | 新模式（2026-10 落地） | 本项目影响 |
|------|--------|---------------------|----------|
| **静态→动态** | 一次性测评整改 | 线上全天候巡检 + 线下专项抽查 | 必报"线上巡检工具" |
| **事后→事前** | 测评出问题再整改 | 常态化防护 + 风险闭环 | 必报"事前预防流程" |
| **纸质→全程溯源** | 纸质台账 | 动态化管控 + 全流程溯源 | 必报"全程溯源工具" |
| **单点→常态化** | 一次性测评 | 常态化巡查 + 整改 / 约谈 / 处罚 | 必报"常态化自查机制" |

**v7 必报**：
- v6 §4 "10 项必检"——v7 升级为"**33 条红线 + 动态合规 4 转变**"
- v6 §5 P0 14 项——v7 升级为"**P0 18 项（v6 14 + v7 4 项动态合规）**"
- v6 §6 集成架构图"3 层合规 → 4 层合规"——v7 升级为"**3 层合规 → 5 层合规**（+ 动态合规层）"

---

## 7 · v7 集成架构图修订（v6 §6 基础上 + 3 处修订）

```
┌─────────────────────────────────────────────────────────────────────┐
│              揭榜挂帅 shared-memory-platform v7 集成架构              │
│     v6 基础上 + MCP 漏洞防护层 + 7 表面逐项防护 + 动态合规层           │
└─────────────────────────────────────────────────────────────────────┘

                  数据源层（v6 + v7 §3.1 等保动态合规层）
  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │ syslog   │ HTTP推   │ EDR(Sysmon│ DB CDC   │ MISP/TAXII│ ← v7 §1.1
  │ /api     │ 送       │ /WinEvent)│(Flink CDC)│ /STIX     │   8-25 0:07 修
  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬────┘
       │          │          │          │          │
       └──────────┴──────────┼──────────┴──────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │  Kafka 7 topics + SM4 加密（v7 §3.1 必做）│ ← v7 动态合规
        │  + WORM 审计日志（v7 §3.1 必做）          │ ← v7 动态合规
        │  + 链式哈希 SM3（v7 §3.1 必做）          │ ← v7 动态合规
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  Flink 1.20.5 LTS（v6 §1.1 修正 v5 §1.1）  │ ← v6 不升 1.20.6
        │  Flink CDC 3.6.0 + 经典 RocksDB 路径       │ ← v6 保留
        │  + 关 state.changelog.enabled             │ ← v6 保留
        │  + 避 ForSt async multiGet（v6 保留）      │ ← v6 保留
        │  Flink CEP 3 攻击链模式                     │
        │  Apache Flink Agents 0.3.0 POC（v4 §3.1）  │ ← v4 保留
        │  + 本项目 health_monitor 滑窗评估（v7 §1.3）│ ← v7 必查
        │  ❌ 不集成阿里云 Flink AI Native Ops       │ ← v7 §3.2 自建路线
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  hot 7d Kafka / warm 90d Paimon / cold 1y  │ ← v4 §3.2 保留
        │  Iceberg on S3 + OCSF v1.9                │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  Backend (FastAPI + Python 3.12)           │
        │  ┌────────────────────────────────────┐  │
        │  │ pySigma 0.11 + 11 rules          │  │
        │  │ Anomaly Detection 11 维评分        │  │
        │  │ UEBA-ML（v3 §3.4 scikit-learn）    │  │
        │  │ + 国密 SM3 链式哈希（v6 §4 #4）   │  │
        │  │ + field_cipher 升级到 SM4（v7 §3.1）│  │ ← v7 必做
        │  │ + OTel 7 trace span（v7 §1.1）     │  │ ← v7 必做
        │  │ + OTel + Grafana Tempo（8fd0357）  │  │ ← v7 必做
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 8 角色 Agent（v5 §7.2 保留）     │  │
        │  │ Orchestrator / Triage / Invest /  │  │
        │  │ Threat Hunter / TI / IR / Report  │  │
        │  │ + Investigation Copilot           │  │
        │  │ + agent_tool_builder / decomposer │  │
        │  │ + executor / reviewer            │  │
        │  │ + 5 Guardrail + 12 大失败模式防护 │  │ ← v7 必补
        │  │ + LLM Enhancer（已实装，v6 §1.3） │  │ ← v6 修正
        │  │   llm_*_enabled = False 等待启用  │  │ ← v6 修正
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ **5 层 MCP Guard**（v7 §1.4 升级）│  │ ← v7 升级 4→5
        │  │ + DPoP + Workload Identity        │  │ ← v5 §2 反例9
        │  │ + 5 层零信任 + 5 Guardrail        │  │
        │  │ + **第 5 层：MCP Server 漏洞管理**│  │ ← v7 必补
        │  │   （CVE-2026-27825/75130/76404/  │  │
        │  │    53965/33032 + STDIO 设计缺陷）│  │
        │  │ + **7 表面逐项防护**（v7 §1.2）   │  │ ← v7 必补
        │  │   server instructions / tool desc │  │
        │  │   / annotations / tool-result /   │  │
        │  │   resource / prompt / sampling    │  │
        │  │ + MCP 2026-07-28 spec + 08-22 Rdmp│  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ Langfuse LLM Observability       │  │
        │  │ + 5 招 Prompt Injection 防御    │  │
        │  │ + 数据飞轮 + Agent Engineer     │  │
        │  │ + audit_trail（已实装，v6 §1.4）  │  │
        │  │ + **RAG 文档注入防护**（v7 §2.2）│  │ ← v7 必补
        │  │   （CVE-2026-75130 等价路径）    │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 7 类 B 级 Prometheus 指标（v6 §1.5）│  │
        │  │ + OTel 7 trace span（v7 §1.1）    │  │ ← v7 必补
        │  │ 钓鱼检测 7 检测器 + LLM 维度    │  │
        │  │ IOC 实时匹配器（v6 §1.5 路径）  │  │
        │  │ EDR 接入层（v6 §1.5 路径）       │  │
        │  │ + Threat Hunter Agent（v4 §3.3）│  │
        │  └────────────────────────────────────┘  │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  RAG 检索：Qdrant 迁移中（v6 §1.5 修正）  │
        │  + pgvector 兜底（过渡）                 │
        │  + SPLADE finetune                      │
        │  + **文档注入防护**（v7 §2.2）          │ ← v7 必补
        │  + A/B 测试（v4 §1.5 反例 3）            │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  响应引擎（v3 已有）                       │
        │  8 策略 / 5 动作 / SSH + iptables / 审批  │
        │  + NIST 800-61r3 CSF 2.0                │
        │  + SM2 签名验签（v5 §4.2）              │
        │  + 12 大失败模式防护（v7 升级 6→12）   │ ← v7 升级
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  持久化：PostgreSQL 16 + SM4 字段加密     │
        │  + Redis 7 + Qdrant + OCSF 标准化        │
        │  + 异地备份 ≥30 公里（v6 §4 #7 必做）   │
        │  + **SSE buffer 上限**（v7 §2.4 反例18）│ ← v7 必补
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  合规层（v7 扩展：5 层合规）               │ ← v7 升级 4→5
        │  等保 2.0 GA/T 2380-2026                 │
        │  + GA/T 2381-2026 / 2394-2026 / 2395-2026│
        │  + 密码法（SM2/SM3/SM4）                │
        │  + 数据安全法（数据分类分级 + 跨境管控）│
        │  + AI 系统等保（2026-01-01 新《网安法》）│
        │  + AI 训练数据纳入监管（v6 §2.2 反例14）│
        │  + 1000 万罚款 + 信用档案（v6 §2.2）   │
        │  + **动态合规 4 转变**（v7 §3.1）       │ ← v7 必报
        │  + **33 条红线 + 测评三级判定**（v7 §3.1）│ ← v7 必报
        │  + 国密 KMS + 链式哈希 + WORM            │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  可观测性：OTel + Tempo + Jaeger          │ ← v7 已实装
        │  + Prometheus + Grafana                   │
        │  + eBPF（v3 §3.3）                       │
        │  + Langfuse LLM 全链路（v3 §2.0 L0-2）   │
        │  + 7 类 B 级 metrics（v6 §1.5）          │
        │  + **7 trace span**（v7 §1.1 必报）     │ ← v7 必报
        │  + **健康分滑窗**（v7 §1.3 评估）        │ ← v7 必报
        └────────────────────────────────────────────┘
                         ▲
                         │ 前端 React 19.2 + Vite 7.3
                         │ 5 仪表板：Monitor / RAG / Intel / 
                         │ Phishing / EDR / Operations
                         │ + **Nginx admin path 限制**（v7 §2.5）
                         │ + **TraceTab OTel 视图**（v7 §1.1）
```

**v7 集成关键点**（v6 §6 10 项 + v7 修正 5 项）：
1. **3 层数据湖**（hot Kafka / warm Paimon / cold Iceberg）—— v6 保留
2. **8 角色 Agent** —— v6 保留
3. **5+2 = 7 道 Guardrail** —— v6 保留，v7 必补 12 大失败模式（6 + 6 Pitfall Lab）
4. **双协议**（MCP 2026-07-28 + 2026-08-22 Roadmap）—— v6 保留
5. **3 层合规 → 5 层合规**（v7 + 动态合规层 + 33 条红线层）—— v7 升级
6. **国密适配**（SM2 签名 / SM3 哈希 / SM4 加密）—— v6 保留
7. **TCO 自建 ~$76K/年**（v5 §3.2 估算）—— v6 修订，v7 必报"自建 vs 阿里云包年"
8. **5 层 MCP Guard**（v7 升级 4→5，新增"第 5 层 MCP Server 漏洞管理"）—— v7 升级
9. **7 表面逐项防护**（v7 §1.2 新增）—— v7 必报
10. **OTel + Grafana Tempo 已实装**（8fd0357 提交 32 文件 +1829 行）—— v7 必报
11. **v7 新增：RAG 文档注入防护**（CVE-2026-75130 等价路径）—— v7 必补
12. **v7 新增：SSE buffer 上限**（CVE-2026-53965 缓解）—— v7 必补
13. **v7 新增：健康分滑窗评估**（阿里云 2026-08-20 修复）—— v7 必报
14. **v7 新增：Nginx admin path 限制**（CVE-2026-33032 缓解）—— v7 必补

---

## 8 · v7 风险与验证（v6 §8 基础上 + 7 条 v7 修正）

### 8.1 升级风险（v6 6 条 + v7 7 条）

| 风险 | 等级 | v7 缓解 |
|------|------|--------|
| v6 的 6 条（v6 §8.1） | 同 v6 | 同 v6 |
| **v7 修正风险 1：5 个 2026-08 MCP CVE**（v7 §2.1-2.5）| **极高** | LLM 启用前必报"集成 MCP server 漏洞管理流程" |
| **v7 修正风险 2：MCP Pitfall Lab 6 类失败模式**（v7 §2.5）| **高** | v6 6 大 + Pitfall Lab 6 类 = 12 大失败模式防护 |
| **v7 修正风险 3：MCP 7 表面 spec 防护**（v7 §1.2）| **高** | backend/mcp_guard/guard_server.py 7 表面逐项防护率必报 |
| **v7 修正风险 4：等保 2.0 动态合规 4 转变**（v7 §3.1）| **极高** | 2026-10 落地前完成 P0 18 项 + 33 条红线自评 |
| **v7 修正风险 5：阿里云 Flink AI Native Ops 路线选择**（v7 §3.2）| **中** | 揭榜挂帅评审建议走自建路线（避免 vendor 整合期） |
| **v7 修正风险 6：SOC AI 行业剧烈整合**（v7 §3.3 Cribl-Radiant）| **中** | 评审不承诺走单一商业路线（3-6 月内可能再变） |
| **v7 修正风险 7：厂商 99% 自报数字**（v7 §3.4）| **低** | 评审使用公开基准（D3 Morpheus 95% + 24/7 <2min） |

### 8.2 升级期监控指标（v6 4 个 + v7 4 个）

v6 8 个指标保留。**v7 新增**：
- **MCP 漏洞跟踪**（v7 §2.1-2.5）：5 个新 CVE + 后续披露
- **MCP Guard 5 层实装率**（v7 §1.4）
- **MCP 7 表面防护率**（v7 §1.2）
- **等保 2.0 动态合规 4 转变达标率**（v7 §3.1）

### 8.3 不升级的代价（v6 5 项 + v7 5 项）

v6 10 项保留。**v7 新增**：
- 不修 5 个 2026-08 MCP CVE：LLM 启用后必触发 CVE-2026-27825 / 75130 / 76404 / 53965 / 33032 至少 1 个，**揭榜挂帅评审"未做 MCP 漏洞管理"直接失分**
- 不升级 MCP Guard 4→5 层：评审"5 层 MCP Guard 缺第 5 层"直接失分
- 不做 7 表面逐项防护：评审"MCP spec 表面覆盖率 < 100%"直接失分
- 不评估阿里云 Flink AI Native Ops：评审"自建 vs 商业对比缺"直接失分
- 不评估 SOC AI 行业整合：评审"市场路线分析缺"直接失分

---

## 9 · 总结（v7 重写）

本轮 v7 升级的核心定位（与 v6 不同）：

1. **v6 是"v5 的事实核验"**——6 类修正 + 7 类新增；**v7 是"v6 的盲点扫荡"**——**6 类修正**（v6 评估时漏读 8fd0357 OTel 提交 / v6 漏报 5 个 2026-08 MCP CVE / v6 漏报阿里云 Flink AI Native Ops / v6 漏报等保 2.0 动态合规 / v6 漏报 SOC AI 行业整合 / v6 漏报厂商 99% 自报数字反例）**+ 7 类新增**（v6 漏的 MCP 5 个新 CVE + 阿里云 Flink AI Native Ops + 等保 2.0 动态合规 + Cribl-Radiant 整合 + MCP Pitfall Lab 6 类失败模式 + 7 个 spec text-injection 表面 + 8 维度末轮）
2. **v6 §6 提"4 层 MCP Guard"**——**v7 升级为"5 层 MCP Guard"**（+ 第 5 层 MCP Server 漏洞管理）
3. **v6 §2 反例 10 提"6 大失败模式防护"**——**v7 升级为"12 大失败模式防护"**（6 类 v6 基础 + 6 类 Pitfall Lab）
4. **v6 §4 提"等保三级必检 10 项"**——**v7 升级为"动态合规 4 转变 + 33 条红线 + 测评三级判定"**
5. **v6 §6 集成架构图"3 层合规 → 4 层合规"**——**v7 升级为"3 层合规 → 5 层合规"**（+ 动态合规层 + 33 条红线层）
6. **v6 没提 5 个 2026-08 MCP CVE**——**v7 新增反例 15-19**（CVE-2026-27825 / 75130 / 76404 / 53965 / 33032 + STDIO Transport 设计缺陷）
7. **v6 没提阿里云 Flink AI Native Ops 2026-08-20 GA**——**v7 必报"自建 vs 阿里云包年 决策树"**
8. **v6 没提 Cribl 收购 Radiant Security 2026-08-19**——**v7 必报"SOC AI 三种市场路线 + 行业整合期"**
9. **v6 没提等保 2.0 公安监督检查新规 2026-10 落地**——**v7 必报"动态合规 4 转变"**
10. **v6 7 维度交叉验证**——**v7 8 维度**（+ 8.1 MCP 漏洞趋势 + 8.2 阿里云 Flink AI Native Ops 对比）

**v7 的验证基础**：
- 6 类修正中，**1 类来自直接读代码核验**（8fd0357 OTel 提交 32 文件 +1829 行 / backend/observability/ 3 个子模块 / config/otel-collector.yaml / config/tempo/tempo.yaml / init.sql / docker-compose.yml 等）
- **1 类来自 MCP 2026-07-28 spec census**（digitalapplied.com 2026-08-22 7 个 text-injection 表面）
- **1 类来自 2026-08 MCP 漏洞披露**（5 个新 CVE + STDIO Transport 设计缺陷）
- **3 类来自 2026-08 行业一手资料**（阿里云 Flink 2026-08-20 release notes / D3 Security Cribl-Radiant 2026-08-19 / 黑龙江等保测评 2026-08）
- 7 类新增 = 5 类 v7 §1-2 反例 + 2 类 v7 §3 行业动向 + 0 类堆叠新项（按 memory 教训"v6 不堆新项"）

**给揭榜挂帅评审的"7-30 天必做"清单**（v6 18 项 + v7 6 项 = 24 项）：

**v6 已列 18 项**（保留）：OCSF 1.9 字段映射 / Langfuse / MCP 错误码 / phishing_guard LLM / Flink 1.20.5 / DPoP / 6 大失败模式 / 等保 2.0 自评 / AI 系统自评 / TCO / IOC / EDR / v6 必做 13-18（AI 训练数据 + AI 系统监测 + audit_trail 链式哈希 + field_cipher SM4 + 等保三级 10 项 + migrate 评估）。

**v7 新增 6 项**：
- **v7 必做 19**：本项目 OTel 7 个 trace span 实现 + 评审演示用 TraceTab 截图
- **v7 必做 20**：本项目 MCP 7 表面逐项防护（v7 §1.2 + 反例 15-19）
- **v7 必做 21**：本项目等保 2.0 动态合规 4 转变自评（v7 §3.1）
- **v7 必做 22**：本项目 LLM 启用前的"集成 MCP server 漏洞管理流程"（v7 §1.4 + 反例 15-19）
- **v7 必做 23**：本项目自建 vs 阿里云包年 Flink 决策树（v7 §3.2）
- **v7 必做 24**：本项目 SOC AI 路线选型（AI SOC 平台 vs Hyperautomation vs AI Triage，v7 §3.3）

---

## 附录 A · v6 → v7 关键变更对照表

| 维度 | v6 章节 | v7 章节 | 变更摘要 |
|------|--------|--------|----------|
| OTel 实装 | v6 §6 提"OTel + Tempo + Jaeger"无文件路径 | **v7 §1.1** | **+ 5 核心文件 + 11 相关文件清单**（8fd0357 提交 32 文件 +1829 行） |
| MCP 7 表面 | v6 没提 | **v7 §1.2** | **+ MCP 2026-07-28 spec 详定义 7 个 text-injection 表面** |
| 健康分滑窗 | v6 §6 提"健康监控"无算法 | **v7 §1.3** | **+ 阿里云 Flink 2026-08-20 修复"只降不升"必查** |
| MCP 漏洞管理 | v6 §1.2 提"AI 训练数据来源合规" | **v7 §1.4** | **+ LLM 启用前必报"集成 MCP server 漏洞管理流程"** |
| MCP CVE 群 | v6 §2 反例 13 提"MCP 2026-07-28 spec" | **v7 §2.1-2.5** | **+ 5 个 2026-08 MCP CVE + STDIO 设计缺陷**（反例 15-19） |
| 等保 2.0 动态合规 | v6 §4 提"10 项必检" | **v7 §3.1** | **+ 动态合规 4 转变 + 33 条红线 + 测评三级判定** |
| 阿里云 Flink AI Native Ops | v6 §6 没提 | **v7 §3.2** | **+ 2026-08-20 GA 完整功能 + 自建 vs 商业决策树** |
| SOC AI 行业整合 | v6 §3.2 提 TCO 估算 | **v7 §3.3** | **+ Cribl 收购 Radiant 2026-08-19 + 三种市场路线** |
| 厂商 99% 自报数字 | v6 §3.2 提"自建 ~$76K/年" | **v7 §3.4** | **+ 公开基准（D3 Morpheus 95% + 24/7 <2min）+ Avasant 60% 探索** |
| MCP Guard 层数 | v6 §6 提"4 层 MCP Guard + DPoP" | **v7 §6** | **升级 4→5 层**（+ 第 5 层 MCP Server 漏洞管理） |
| 失败模式防护 | v6 §2 反例 10 提"6 大失败模式" | **v7 §2.5** | **升级 6→12 类**（+ MCP Pitfall Lab 6 类） |
| 合规层 | v6 §6 提"3 层合规 → 4 层合规" | **v7 §6** | **升级 4→5 层**（+ 动态合规层 + 33 条红线层） |
| 集成架构图 | v6 §6 10 集成关键点 | **v7 §6 14 集成关键点** | **+ 5 项 v7 必补**（RAG 注入 / SSE 限 / 滑窗 / Nginx 限 / OTel 7 span） |
| 8 维度交叉验证 | v6 §7 7 维度 | **v7 §6 8 维度** | **+ 8.1 MCP 漏洞趋势 + 8.2 阿里云 Flink AI Native Ops 对比** |
| 决策树 | v6 §5 P0 14 项 / P1 6 项 | **v7 §5 P0 18 项 / P1 10 项** | **+ 4 项 v7 必做** |
| 总结必做清单 | v6 §9 18 项必做 | **v7 §9 24 项必做** | **+ 6 项 v7 必做** |

---

## 附录 B · v7 在 v6 基础上新增/修正的来源（v6 附录 B 95-118 基础上 + 16 个）

### v6 已列 118 个来源（保留）

1-118：见 v6 文档附录 B。

### v7 新增（2026-08-25 末轮 15:40）

119. Check Point. *CPAI-2026-9606: MCP Atlassian Arbitrary File Write (CVE-2026-27825)*. 2026-08-03（**v7 §2.1 反例 15**）。
120. AI Governance Institute. *Critical MCP Atlassian Flaw Enables Arbitrary File Write and Code Execution*. 2026-08（**v7 §2.1**）。
121. National Vulnerability Database. *CVE-2026-27825: MCP Atlassian Arbitrary File Write*. 2026-08-03。
122. National Vulnerability Database. *CVE-2026-75130: Context7 Prompt Injection (CVSS 3.1 9.0 / CVSS 4.0 6.4)*. 2026-08-18（**v7 §2.2 反例 16**）。
123. VulnCheck. *Context7 Advisory*. 2026-08-22（**v7 §2.2**）。
124. Digital Applied. *We Audited What MCP Servers Put in Your Agent's Context — A Census of 7 text-injection surfaces defined by the MCP 2026-07-28 spec*. 2026-08-22（**v7 §1.2 + §6.2.1**）。
125. National Vulnerability Database. *CVE-2026-76404: Splunk MCP Server RCE (CVSS 9.1)*. 2026-08-19（**v7 §2.3 反例 17**）。
126. Cisco/Splunk. *VULN-84459: Splunk MCP Server Arbitrary Command Execution*. 2026-08-19。
127. Cybersecurity News. *Splunk Patches Critical MCP Server RCE and 16 Other Security Flaws*. 2026-08（**v7 §2.3**）。
128. Forkast. *CVE-2026-76404: The MCP Security Wave Reaches Enterprise Infrastructure*. 2026-08（**v7 §2.3**）。
129. GitLab Advisory. *CVE-2026-53965: MCP PHP SDK SSE Buffer DoS*. 2026-08（**v7 §2.4 反例 18**）。
130. modelcontextprotocol/php-sdk. *Release v0.7.1*. 2026-08。
131. dev.to mrclaw207. *MCP Security in 2026: The Vulnerabilities You're Probably Running Right Now*. 2026-08（**v7 §2.5 反例 19**）。
132. Adversa AI. *MCP Pitfall Lab: A Six-Class Taxonomy for MCP Tool Server Security (P1-P6)*. 2026-08（**v7 §2.5**）。
133. D3 Security. *Radiant Security Alternatives in 2026: Torq vs. Dropzone AI vs. D3 Morpheus*. 2026-08（**v7 §3.3**）。
134. D3 Security. *Cribl Just Acquired Radiant Security's AI SOC Technology*. 2026-08-19（**v7 §3.3**）。
135. 阿里云. *2026-08-20 release — Flink AI Native Ops*. 2026-08-20（**v7 §3.2**）。
136. 黑龙江等保测评 hljdengbao.com. *2026 新版等保二级、三级合规落地终极指南*. 2026-08（**v7 §3.1**）。
137. zpedu.com. *等保 2.0 通关指南*. 2026-07-24（**v7 §3.1**）。
138. CN-SEC cn-sec.com. *等保 2.0 通关指南（2025 新规 11.30 前重新备案 + 测评三级判定）*. 2026-08（**v7 §3.1**）。
139. Avasant. *SOC 3.0: Reimagining Security Operations for the AI Era — 60% 探索 / 30% 试点 / 10% 部署 governed AI workflow*. 2026-08（**v7 §3.4**）。
140. Larridin. *CrowdStrike AI Adoption Tracker (Last updated 2026-08-20)*. 2026-08-20（**v7 §3.4**）。
141. Global Security Mag. *CrowdStrike unveiled Charlotte AI Agentic Response and Charlotte AI Agentic Workflows*. 2026-08（**v7 §3.3**）。
142. 本项目 backend/otel_setup.py. *OTel 初始化 + exporter 配置*. 2026-08-25 15:21:38（**v7 §1.1 修正**）。
143. 本项目 backend/trace_context.py. *trace context 注入 / 提取*. 2026-08-25 15:21:38（**v7 §1.1 修正**）。
144. 本项目 config/otel/otel-collector.yaml. *OTel Collector 配置*. 2026-08-25 15:21:38（**v7 §1.1 修正**）。
145. 本项目 config/tempo/tempo.yaml. *Grafana Tempo 配置*. 2026-08-25 15:21:38（**v7 §1.1 修正**）。
146. 本项目 backend/observability/pipeline_tracer.py. *管道级 tracer*. 2026-08-24 3:26:57（**v7 §1.1 修订**）。
147. 本项目 backend/observability/watchdog.py. *看门狗*. 2026-08-24 21:27:17（**v7 §1.1 修订**）。
148. 本项目 backend/observability/health_monitor.py. *健康监控（待评估是否需要滑窗升级）*. 2026-08-01 23:00:32（**v7 §1.3 修正**）。
149. git commit 8fd0357. *feat(observability): 标准 OpenTelemetry + Grafana Tempo 全链路追踪 (Phase 0-5)*. 2026-08-25 15:21:38（**v7 §1.1 关键提交**）。

---

**文档版本**：v7.0（2026-08-25 15:40）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-09-25（M+1）对照 2026-Q4 SOC 行业新动向（重点：5 个 2026-08 MCP CVE 修复进度 / 阿里云 Flink AI Native Ops Q4 迭代 / Cribl-Radiant 整合后路线变化 / 等保 2.0 2026-10 落地后实测 / 本项目 LLM 启用决策）

**前置版本**：
- v6.0（`2026-q3-tech-stack-upgrade-v6.md`，2026-08-25 15:34）
- v5.0（`2026-q3-tech-stack-upgrade-v5.md`，2026-08-25 15:25）
- v4.0（`2026-q3-tech-stack-upgrade-v4.md`，2026-08-25 15:14）
- v3.0（`2026-q3-tech-stack-upgrade-v3.md`，2026-08-25 15:02）
- v2.0（`2026-q3-tech-stack-upgrade-v2.md`，2026-08-25 14:53）
- v1.0（`2026-q3-tech-stack-upgrade.md`，2026-08-25 14:38）
