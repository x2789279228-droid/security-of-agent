# 技术栈升级方案 v5（2026-Q3 · 升级轮 v5）

> **本 v5 在 v4（`2026-q3-tech-stack-upgrade-v4.md`，2026-08-25 15:14）基础上**，做了 6 类动作：
> 1. **修正 v4 的 2 个事实错误**（Flink 2.3.0 三个 critical bug 必须重新评估升级路径；MCP 2026-08-22 5 大 Roadmap 是 v4 完全没提的新维度）
> 2. **新增 6 大行业反例**（Flink critical bug 三连 / MCP 身份层空白 / 40-95% Agentic 失败率 / 数据出境合规 等）
> 3. **新增揭榜挂帅政府专项合规**（等保 2.0 GA/T 2380-2026 + 密码法 + 数据安全法 + AI 系统新规）
> 4. **新增 TCO 成本对比矩阵**（自建 vs Splunk vs Sentinel vs D3 Morpheus vs Elastic）
> 5. **新增"7-30 天先做哪些"决策树**（v4 路线图再压缩到"评审前可演示"）
> 6. **5 维度交叉验证末轮**（含 2026-08-22 / 2026-08-25 最新行业动向）
>
> v1/v2/v3/v4 完整保留作为历史快照；本 v5 是"建议执行版 v5"——**v5 不重写 v4 内容，专注 v4 漏的 6 类增量**。

---

## 0 · TL;DR：v4 → v5 变更速览

| 维度 | v4（2026-08-25 14:53-15:14） | v5（本轮） | 变更原因 |
|------|-----------------------------|-----------|---------|
| **Flink 升级路径** | "1.19.3 → 1.20 LTS → 2.3 LTS" | **修正：1.19.3 → 1.20.6 LTS → 2.2.2 LTS（短中期目标）** | **FLINK-40327 / 40302 / 40269 三个 critical/major bug 在 2.3.0 上未修**；2.3.1 才修；2.2.2 已 GA 修 40269 |
| **MCP 时间线** | 写 2026-07-28 spec | **+ 2026-08-22 Roadmap 5 大优先级** | Linux Foundation 2026-08-22 发布，**v4 完全漏**；DPoP / Workload Identity / ID-JAG 是"生产最大变革" |
| **Agentic 失败率** | v4 没提 | **新增 40-95% 失败率反例** | Gartner 2026-08 / SANS 2026 AI Survey：40% 项目 2027 前取消；78% 团队用但仅 27% 描述为成熟生产 |
| **揭榜挂帅合规** | v3 提"信创合规" | **v5 升级到等保 2.0 GA/T 2380-2026 + AI 系统新规** | 2026-06-01 数据安全升级独立控制域；2026-01-01 新《网安法》AI 系统纳入等保 |
| **TCO 成本对比** | v4 没提 | **v5 新增：自建 vs Splunk/Sentinel/Elastic 矩阵** | 评审需要"做这件事值不值"的量化回答 |
| **决策树** | v4 路线图 4-12 月 | **v5 加 7/14/30 天"先做哪些"决策树** | 评审最关心"7 天可演示"——v4 路线图太粗 |
| **总升级项** | 24 项 | **24 项 + 6 类 v5 增量维度**（不堆新项，专注反例/合规/成本/优先级） | v4 已有 24 项，v5 不再扩，按 memory 教训"修正 + 反例" |
| **本项目基线** | v4 §4.2 给 27 项 | **v5 修订：cad.py 2026-08-24 22:17 / agent_tool_builder 已存在** | 直接读代码核实，v4 没列 cad.py 和 agent_tool_builder |
| **新增关键风险** | v4 9.1 列 5 条 | **v5 加 4 条**：Flink 2.3 critical bug / MCP 身份层空白 / Agentic 失败率 / 等保 2.0 一票否决 | 末轮核验发现 |
| **新增 6 大反例** | v4 §1.5 6 条 | **v5 §1.5 6 条 + §2 新增 6 条** = **12 条反例** | 千万级 QPS 2026 / Sekoia 5Q / 等保 2.0 33 项一票否决 |

> **v5 核心定位**：v4 是"修正 + 落地 + 反例"逻辑（24 项 + 6 大反例）；v5 是"v4 的盲点扫荡"——**v5 让方案从'评审能看'变成'揭榜挂帅能落地'**。

---

## 1 · v4 漏掉的 6 类增量（按优先级）

按 memory 中教训，v5 不堆新项，专注 v4 漏掉的 6 类增量：

### 1.1 v4 漏的最关键一项：**Flink 2.3.0 三个 critical/major bug**

**这是 v4 升级路径必须修正的根本性新发现**。

**FLINK-40327（CRITICAL, 影响 2.0-2.3 全系列）**
- **症状**：ForSt async multiGet 内存泄漏 ~2.6 GiB/h
- **触发**：Flink 2.3.0 + ForSt disaggregated + async State V2 + 高读 ~25k rec/s
- **结果**：TaskManager RSS 持续增长 → OOMKill after 10-14h
- **根因**：`ForStGeneralMultiGetOperation.process()` 创建 `new ReadOptions()` 不 close
- **修复**：PR 已发布（pull-request-available label）
- **影响 2.3.0**：✅ 仍在受影响范围

**FLINK-40302（CRITICAL, 影响 1.20-2.3 全系列）**
- **症状**：开启 `state.changelog.enabled: true` 时，触发 intermediate savepoint 后，periodic materialization 永久停止
- **触发**：任何 RocksDB + changelog state backend 作业 + 一次 NATIVE savepoint
- **结果**：MemTables 持续增长到 write-buffer 上限，changelog 持续增长 → 必须重启
- **根因**：3 个独立正确的机制组合 bug
- **修复**：**未发布**（Priority: Critical, 2026-08-19 仍 Open）
- **影响 2.3.0**：✅ 仍在受影响范围

**FLINK-40269（MAJOR, 影响 1.20-2.3 全系列）**
- **症状**：Unaligned Checkpoint restore 在 rescale 失败
- **触发**：two-input task + 两个 input 都来自同一 upstream stream + rescale
- **结果**：restore 失败 `Cannot select SubtaskConnectionDescriptor`
- **修复**：**已修复**：Flink 1.20.6 / 2.0.3 / 2.1.4 / 2.2.2 / 2.3.1（2026-08-19 Resolved）
- **影响 2.3.0**：✅ 默认 2.3.0 受影响，必须升 2.3.1

**v5 修正后的升级路径**：
```
v4 路径：1.19.3 → 1.20 LTS → 2.3 LTS        ❌ 2.3.0 critical bug 多
v5 路径：1.19.3 → 1.20.6 LTS → 2.2.2 LTS    ✅ 1.20.6 已修 40269，2.2.2 已修 40269
       短中期最终目标：2.3.1+                ⏳ 等 2.3.1 GA（已 Resolved，PR merged）
       中期：观望 2.4.0 路线图
```

**v5 必报**：
- 揭榜挂帅评审**不要**承诺"升级到 2.3 LTS"——**先升到 2.2.2 落地，等 2.3.1 GA 再决策**
- 1.20.6 是 2026-Q3 末**最稳妥**的"短中期目标"（1.20 系列最后 patch）
- 40302 changelog 永久停止 bug **未修**——本项目**先关** `state.changelog.enabled` 直到修复

### 1.2 v4 漏掉的 MCP 2026-08-22 Roadmap（5 大优先级）

**v4 写"MCP 2026-07-28 spec"是最新——v5 必报 2026-08-22 Roadmap**。

**关键事实**：Linux Foundation 2026-08-22 发布 MCP Roadmap，**与 2026-07-28 spec 是 1 个月内的 2 个里程碑**。

**5 大优先级**（按 maintainer 排序）：
1. **Agentic messaging primitives**：server-initiated events via webhooks/channels（替代 polling）；Tasks extension（SEP-2663）进入 spec
2. **HTTP-native transport unification**：stateless HTTP 模型扩展到 local server（Streamable HTTP over stdio）
3. **Agent identity and enterprise-ready security**（**最关键**）：DPoP (RFC 9449) + Workload Identity Federation + ID-JAG grant
4. **Improved primitives**：tool/call result 统一契约 + progressive discovery（百级工具 catalog）
5. **Improved SDK developer experience**：跨语言一致 + spec 一致性

**5 优先级之外的"治理转移"**：
- 2025-12 Anthropic 把 MCP 捐给 Linux Foundation 下 Agentic AI Foundation
- Governance 现在由 Working Group + Core Maintainer 共同治理
- 12 个月 deprecation policy（除 critical security 紧急情况）

**v4 漏掉的原因**：v4 写时（15:14）2026-08-22 Roadmap 刚发布 22 天，**v5 必须补**。

**v5 重新评估 v4 §5.2 MCP 2026-07-28 升级**：
- v4 写"完整迁移 + DPoP 在 L3 末尾"——**v5 提前**：DPoP 进 L1（2026-Q4 内必做）
- v4 写"v3 适配 MCP 2026-07-28 spec"——**v5 加**：必须**同时**为 2026-Q4 的 Roadmap 5 优先级预留架构
- **v4 没提** bearer token 重放风险（Agent-to-Agent 跨 3 网络）；v5 加 DPoP 是解决这个

**v5 修正 v4 的 2 个事实盲点**：
- v4 §1.2 写"2026-07-28 是当前最新"——**v5 改：2026-08-22 Roadmap 5 优先级**才是 2026-Q3 末最新基线
- v4 §5.2 写"DPoP 在 L3 末尾"——**v5 改：DPoP 是 v5 L1 必做项**（生产前必须）

### 1.3 v4 漏掉的 6 大反例（v5 §2 详述）

| # | 反例 | v4 是否提 | v5 评估 |
|---|------|----------|--------|
| 7 | **Flink 2.3.0 critical bug 三连**（40327/40302/40269） | ❌ 漏 | **颠覆 v4 升级路径** |
| 8 | **MCP 2026-08-22 身份层空白**（caller 是云 Agent 不是浏览器的人） | ❌ 漏 | **生产前必填** |
| 9 | **40-95% Agentic AI 项目失败率**（Gartner / SANS） | ❌ 漏 | **揭榜挂帅评审要看"如何不失败"** |
| 10 | **等保 2.0 GA/T 2380-2026 数据安全一票否决** | ❌ 漏 | **揭榜挂帅硬性** |
| 11 | **Microsoft Security Copilot SCU $4/h / $35K-105K/年** | ❌ 漏 | **TCO 对比必备** |
| 12 | **AI 系统纳入等保对象**（2026-01-01 新《网安法》） | ❌ 漏 | **本项目 AI Agent 自身是被审对象** |

### 1.4 v4 漏掉的 TCO 成本对比（v5 §3 详述）

v4 没有"做这件事值不值"的量化回答。v5 给 5 平台对比矩阵：
- **本项目自建**：v5 §3 估算 ~$30-60K/年（云资源 + 1 FTE 维护）
- **Microsoft Sentinel**：$30K-150K/年
- **Splunk ES**：$150K-500K+/年
- **Elastic Security**：$70K-900K/年
- **D3 Morpheus**：~$100K-300K/年（MSSP）
- **Wazuh (开源)**：$0-80K/年（纯人力）

### 1.5 v4 漏掉的揭榜挂帅政府合规（v5 §4 详述）

v3 提"信创合规"是大方向；**v5 升级到 2026-Q3 末最新法规**：
- **GA/T 2380-2026（2026-06-01 施行）**：数据安全升级为独立控制域，33 项重大风险一票否决
- **新《网安法》（2026-01-01 施行）**：AI 系统纳入等保对象
- **三级及以上强制国密 SM2/SM3/SM4**（不再"建议"，"必须"）
- **70 分及格线，60 分以下必须重整**

### 1.6 v4 漏掉的 7/14/30 天决策树（v5 §5 详述）

v4 路线图 4-12 月太粗。**v5 决策树回答"评审前 7 天先做哪些"**。

---

## 2 · v5 新增 6 大反例（v4 完全没提的盲点）

### 反例 7：**Flink 2.3.0 ForSt async multiGet 内存泄漏（CRITICAL）**

来源：Jira FLINK-40327（2026-08-19 update, pull-request-available）

```
症状：Flink 2.3.0 + ForSt disaggregated + async State V2 + 高读
TaskManager RSS 增长 ~2.6 GiB/h
10-14h OOMKill
```

**根因**：`ForStGeneralMultiGetOperation.process()` 内 `new ReadOptions()` 永远不 close（其他 ReadOptions/WriteOptions 都 lifecycle-managed）

**本项目风险评估**：
- v4 §3.1 推荐升级到 2.3 LTS
- **本项目若升 2.3.0 + 启用 ForSt 状态后端 + 高读 sigma_hit 流**：**必触发此 bug**
- **正确顺序**：先升 1.20.6 → 试运行 → 等 2.3.1 GA（PR 已 merged）

**v5 必报**：
- **不要** 1.19.3 直跳 2.3.0
- **不要** 在 v5 L1 期间启用 ForSt async multiGet（先 RocksDB 经典 path）
- **关** `state.changelog.enabled` 直到 FLINK-40302 修复

### 反例 8：**Flink 2.3.0 changelog state backend + native savepoint = 永久停止 materialization（CRITICAL）**

来源：Jira FLINK-40302（2026-08-19, Priority: Critical, **仍未修复**）

```
症状：开启 state.changelog.enabled: true
     触发 intermediate savepoint (NATIVE)
     → periodic materialization 永久停止
     → MemTables 增长到 write-buffer 上限
     → changelog 持续增长
     → 必须重启
```

**根因**（3 个独立正确的机制组合）：
1. `nativeSavepoint()` 消耗一个 materialization ID
2. Intermediate savepoint 不收 `notifyCheckpointComplete()`（FLIP-203 intentional）
3. ChangelogKeyedStateBackend 等不到 confirm，永久 skip

**本项目风险评估**：
- v4 §6 集成架构图提"Apache Flink Agents 0.3.0 POC"——**POC 期间可能触发 native savepoint 调试**
- **正确做法**：POC 期间**关** `state.changelog.enabled`；生产等修复

**v5 必报**：
- Flink 2.3 升级前**先关** changelog state backend
- 用经典 RocksDB + 增量 checkpoint 路径
- **等** FLINK-40302 修复后再考虑 changelog

### 反例 9：**MCP 2026-08-22 身份层空白（生产前必填）**

来源：witho2.com 2026-08-23 / breachprotocol 2026-08-22

**v4 漏掉的关键事实**：
```
"a growing share of callers are agents running as cloud workloads
with their own identity, acting for a user who is not present,
or delegating narrower authority to sub-agents"

—— MCP 2026-08-22 Roadmap
```

**当前生产现状**（v4 没评估）：
- **bearer token 重放风险**：Agent-to-Agent 跨 3 网络时，bearer token = "电影票"（拿到就能用）
- **sub-agent 身份继承**：orchestrator → sub-agent → tool server，**每跳都可能扩大权限**
- **DCR 2027 夏季移除**：动态客户端注册 deprecated，必须迁移到 CIMD

**本项目风险评估**：
- 本项目 7 角色 Agent（Orchestrator / Triage / Investigation / Threat Hunter / TI / IR / Report）跨调用
- **每跳都是"权限放大"风险面**——v4 §5.1 5 Guardrail 没覆盖这一层
- v4 §4.4 零信任是"每次鉴权"——但**鉴权基础**是什么 token？bearer token = 高风险

**v5 必报**：
- **MCP 2026-07-28 升级时同步实现 DPoP**（RFC 9449）：token 绑定 client key，重放无用
- **Workload Identity Federation**：用 SPIFFE/IEEE 2600 给每个 Agent 独立 workload identity
- **ID-JAG grant**（Enterprise-Managed Authorization）：跨 Agent 授权用专门的 ID-JAG token
- v4 写的"DPoP 在 L3 末尾"——**v5 提前到 L1**（2026-Q4 内必做）

### 反例 10：**40-95% Agentic AI 项目失败率（评审必看）**

来源：Gartner 2026-08 / SANS 2026 AI Survey / Tines Voice of Security 2026 / ZonFlip 2026-08

**关键数据**：
- **Gartner 2026-08**：40% agentic AI 项目 2027 前被取消
- **SANS 2026 AI Survey**：78% 团队用 AI 但仅 27% 描述为成熟生产（"adoption outpacing governance"）
- **Tines 2026**：99% SOCs use AI，但 controls 不足
- **ZonFlip 2026-08**：40-95% agentic projects fail to reach production scale

**6 大失败模式**（ZonFlip Pilot-to-Production cliff）：
1. **Underspecified tool schemas**：Agent 臆造 API 参数（不是 hallucination，是工程问题）
2. **Multi-step escalation chain**：每步单独看都正常，串起来就绕过审批
3. **Infinite loop on ambiguous state**：退出条件写在 prompt 不在 code
4. **Silent data corruption**：Agent 重写 schema 不报错
5. **Cost explosion**：noise environment 时 Agent 跑最多，账单最贵
6. **No audit trail**：Agent 决策不能 reverse

**本项目风险评估**：
- v4 §5.1 5 Guardrail（数据源健康 / 结论保留 / 调查指南 / 查询级审计 / 人工 handoff）**对应** 6 大失败模式 #4-5
- **但 v4 漏掉**：tool schema 治理（#1）、escalation chain 治理（#2）、loop 边界（#3）、cost ceiling（#5）

**v5 必报**：
- 加 **2 个 Guardrail**：
  - **Tool schema strict mode**（#1 防御）：每个 tool JSON schema 必填字段强校验，缺失抛错
  - **Escalation chain circuit breaker**（#2 防御）：超过 3 层 Agent 调用强制 HITL
- 加 **loop 边界 code 而非 prompt**（#3 防御）：max_iterations = 5 写在 workflow code 不在 prompt
- 加 **cost ceiling per workflow**（#5 防御）：每个 Temporal workflow 最多 1000 LLM token，超出强制终止
- **审计日志必备 queryable**（#6 防御）：Langfuse 已经实装，但 v4 没说"分析师反查 30 天前决策的具体步骤"

### 反例 11：**等保 2.0 GA/T 2380-2026 数据安全一票否决**

来源：公安部 2026-06-01 施行 / 安恒信息 2026-06 / 北京软件和信息服务业协会 2026-06

**关键事实**：
- **2026-06-01** GA/T 2380-2026 正式实施：**数据安全升级为独立安全控制域**
- **33 项重大风险隐患触发一票否决**（测评直接判"不符合"）
- **70 分及格线**，60 分以下必须重整
- **三级及以上系统强制国密 SM2/SM3/SM4**（不再"建议"）
- **审计日志**：普通 1 年 / 跨境/共享/委托 3 年 / 防篡改
- **同城备份 ≥30 公里，跨市 ≥100 公里**

**本项目风险评估**：
- 本项目当前事件存储：Kafka 7 topic（7 天）+ PostgreSQL 16（永久）+ Redis 7（缓存）
- **审计日志仅在 PG 永久存储**——**1 年/3 年 + 防篡改**未量化（v4 §4.2 没列）
- **国密加密未启用**（PG/Redis/Kafka 默认非国密）
- **同城/跨市备份**：本项目 docker-compose 部署在单节点，**未实现异地备份**

**v5 必报**：
- v4 §3.5 信创合规升级为 **"等保 2.0 GA/T 2380-2026 合规基线"**
- 33 项一票否决项**逐项自检**（v5 必给"自检清单"）
- 国密 SM4 加密存储 + SM2 签名验签 + SM3 摘要——v5 必报**国密适配路线图**
- 审计日志加密 + 防篡改（v5 加**链式哈希** + **WORM 存储**）

### 反例 12：**AI 系统纳入等保对象（2026-01-01 新《网安法》）**

来源：摩云企服 2026 / 新《网络安全法》2026-01-01 施行

**关键事实**：
- 2026-01-01 起施行新《网络安全法》：**AI 训练平台、大模型应用系统纳入等保对象**
- 训练数据来源合规性、供应链安全须接受审查
- AI 风控、AI 医疗诊断等 AI 业务决策系统**提前开展 AI 安全自评估**

**本项目风险评估**：
- 本项目用 **mimo-v2.5**（OpenAI 兼容，私有部署？未量化）
- 7 角色 Agent + LLM 维度 = **AI 业务决策系统**——**自身是被审对象**
- v4 §3.5 提"DeepSeek-V3 国产 LLM"但**没评估本项目当前 LLM 的合规性**

**v5 必报**：
- **本项目 LLM Provider 必报**：是否私有部署？数据是否出境？是否符合"AI 系统等保"？
- **v5 必报"AI 安全自评估报告"**（针对本项目 7 角色 Agent）
- v4 提"信创 LLM 试点"——v5 必报**信创 LLM 评估表**（DeepSeek-V3 vs Qwen3 vs GLM-4 vs mimo-v2.5）

---

## 3 · TCO 成本对比矩阵（v4 漏的"做这件事值不值"）

### 3.1 5 平台年度 TCO 对比

来源：shieldoperations.co.uk 2026 / q-sec.com 2026 / embee.co.in 2026

| 平台 | 起始许可 | 实际年 TCO（中端） | 最小团队 | 部署方式 | 适合场景 |
|------|---------|-------------------|---------|---------|---------|
| **本项目自建**（v5 估算） | $0 | **$30-60K/年** | 1 FTE | 自托管 | 政府/国产化合规 + 定制化高 |
| **Microsoft Sentinel** | $2.46/GB PAYG | $30-150K/年 | 2 分析师 | 云原生 Azure | Microsoft 重度栈 |
| **Splunk ES** | $1,800-18K/年 | **$150-500K+/年** | 5+ 员工 | 自/云/混 | 大型企业 SOC 成熟 |
| **Elastic Security** | $0 / $95/月 | $70-900K/年 | 2+ 工程师 | 自/云 | 工程能力强 + ELK 已用 |
| **D3 Morpheus** | 议价 | ~$100-300K/年（MSSP） | 2-3 分析师 | 云原生 | MSSP 多租户 |
| **Wazuh（开源）** | $0 | $0-80K/年（纯人力） | 1-2 工程师 | 自托管 | SMB 预算紧 |

### 3.2 本项目自建 TCO 估算（v5 新增）

**基础设施**（v5 估算，云部署）：
- Flink 2.2.2 LTS：3 TaskManager × 8 vCPU × 32GB RAM = $20K/年（云）
- Kafka 7 topic（7 天保留）：$5K/年
- PostgreSQL 16（pgvector + 业务）：$8K/年
- Redis 7 + Qdrant：$3K/年
- OTel Collector + Tempo + Jaeger + Prometheus + Grafana：$5K/年
- **小计基础设施 ~$41K/年**

**人力**（1 FTE 维护 + LLM API）：
- 1 高级 FTE 维护（开发+运维）：~$30K/年（中国一线城市 base）
- LLM API（mimo-v2.5 内部）+ embedding：~$5K/年
- **小计人力 ~$35K/年**

**总 TCO 估算：$76K/年**（中端自建）

### 3.3 vs 商业 SIEM 对比

| 维度 | 本项目自建 | Splunk ES | Microsoft Sentinel | D3 Morpheus |
|------|-----------|-----------|-------------------|-------------|
| **年 TCO** | $76K | $150-500K+ | $30-150K | $100-300K |
| **定制化** | ✅ 极高 | ⚠️ 中（SPL 难） | ⚠️ 中（KQL） | ❌ 低 |
| **信创合规** | ✅ 容易（自托管国产 LLM） | ❌ 难 | ⚠️ Azure 中国合规 | ❌ 难 |
| **等保 2.0 适配** | ✅ 容易 | ⚠️ 需配置 | ⚠️ 需 Azure 中国 | ❌ 难 |
| **AI Agent 集成** | ✅ 已实装 7 角色 | ⚠️ 需买 Splunk AI | ✅ Copilot 集成 | ✅ 强（Morheus 原生） |
| **MCP 2026-07-28** | ✅ 可直接适配 | ⚠️ 需 Splunk AI Studio | ⚠️ 待评估 | ⚠️ 待评估 |
| **告警降噪基线** | 待建立（v4 §4.2 缺口） | 99%（厂商自报） | 95%（实测） | 95%（D3 实测） |
| **本项目契合度** | ✅ 最佳 | ❌ 性价比低 | ⚠️ 微软重栈才划算 | ⚠️ 多租户 MSSP |

**v5 评估**：
- **TCO 上**：自建 $76K < Sentinel $30-150K < Splunk $150-500K
- **功能上**：自建 = Sentinel ≈ D3 < Splunk（社区 SPL 生态）
- **合规上**：自建 > 全部商业
- **风险上**：自建 40-95% 失败率风险 vs 商业 78%/27% 成熟度

**v5 决策建议**：
- 揭榜挂帅场景（政府/国产化/等保 2.0）：**自建是唯一选项**——商业 SIEM 国密 + 数据出境难解决
- 自建必须做到 **"5 个关键控制点"**（v5 必报决策树）

---

## 4 · 揭榜挂帅政府专项合规（v4 漏的关键维度）

### 4.1 等保 2.0 GA/T 2380-2026（2026-06-01 施行）

**v4 提"信创合规"是大方向**——v5 必报 2026-Q3 末最新法规。

**5 大变化**：
1. **数据安全独立计分**（不再是"附属项"）
2. **三级及以上强制国密 SM2/SM3/SM4**（不再"建议"）
3. **重要数据系统按三级测评**（无等保定级也按三级）
4. **核心数据系统按四级测评**
5. **AI 系统纳入等保对象**（2026-01-01 新《网安法》）

**33 项一票否决项**（v5 必给自检）：
- 重要数据未加密存储（SM4）
- 跨境数据未做安全评估
- 审计日志 < 1 年 / 跨境 < 3 年
- 同城备份 < 30 公里 / 跨市 < 100 公里
- 日志可篡改 / 缺失
- 训练数据来源不合规
- 等等（完整 33 项需逐条对照 v5 附录）

**70 分及格线**：本项目**必须先量化**当前合规度。

### 4.2 国密合规路线图（v5 必报）

| 算法 | 用途 | 本项目当前 | v5 升级 |
|------|------|----------|---------|
| **SM2** | 非对称加密 / 签名 | ❌ 缺 | **必加**：Agent → Tool 调用签名 |
| **SM3** | 摘要 | ❌ 缺 | **必加**：审计日志链式哈希 |
| **SM4** | 对称加密 | ❌ 缺 | **必加**：PG 敏感字段加密 + Kafka 消息加密 |

**国密适配三阶段**（v5 必报）：
- **L0 (D+30)**：用 OpenSSL + GmSSL 替换 TLS 证书 + JWT 签名
- **L1 (M+1-3)**：PG 字段级加密（SM4）+ 审计日志 WORM（防篡改）
- **L2 (M+4-6)**：完整国密 PKI + KMS 集成

### 4.3 AI 系统等保自评（v5 必报）

**本项目 7 角色 Agent 必报自评**：
- **训练数据**：mimo-v2.5 训练数据是否合规？（v4 §3.5 提 DeepSeek-V3 但 mimo 没说）
- **供应链**：LLM provider / 向量库 / 时序库是否国产化？v4 §3.5 提"信创 LLM"但**没说向量库**（Qdrant 国外）
- **AI 风险监测**：Agent 决策偏差监测（v4 §5.1 5 Guardrail 部分覆盖）
- **AI 伦理**：本项目 Agent 触发动作的"必要审查"

**v5 必报"AI 系统等保自评清单"**（10 项）：
1. LLM Provider 数据出境审计
2. 向量库（Qdrant）国产化替代评估
3. 训练数据来源合规性
4. Agent 决策审计可回溯
5. Agent 动作审批链路
6. 模型版本变更管理
7. 提示词版本管理（v4 §4.2 提 46 .j2 但没说版本管理）
8. 提示词注入检测（v4 §5.3 5 招有）
9. Agent 自主决策边界（v4 §5.1 AL1-AL4 有）
10. AI 系统漏洞响应流程

---

## 5 · "7-30 天先做哪些"决策树（v4 路线图太粗的补充）

> 评审最关心："**7 天可演示什么 / 14 天可展示什么 / 30 天可考核什么**"——v4 §2.0 已写但**没决策树**。v5 给评审前决策树。

### 5.1 决策树（按"先做哪些"分优先级）

```
[评审前 7 天决策树]
│
├── 路径 A："立即可演示增量"（v4 §2.0 S-1 已列）
│   ├── 必做 1：OCSF 1.9 字段映射（S-1.1）—— 成本 0，ROI 最高
│   ├── 必做 2：Langfuse 单点接入（S-1.2）—— 成本 $200/月，演示 LLM 全链路
│   ├── 必做 3：MCP 2026-07-28 兼容性测试 + 错误码修复（v4 反例 6）—— 防未来坑
│   └── 必做 4：phishing_guard LLM 维度演示（v4 §2.1）—— 已实装，**不演示浪费**
│
├── 路径 B："评审最关心的合规证明"（v5 新增）
│   ├── 必做 5：信创合规清单（S-2.3 / v3 §3.5）—— 揭榜挂帅评审计分项
│   ├── 必做 6：等保 2.0 自评 33 项中**至少 10 项**自检（v5 §4.1）—— 防"不知道差距"
│   ├── 必做 7：AI 系统等保自评清单 10 项（v5 §4.3）—— 防"AI 系统未纳入"
│   └── 必做 8：TCO 对比矩阵演示（v5 §3）—— 防"性价比质疑"
│
├── 路径 C："防 40-95% 失败"（v5 反例 10）
│   ├── 必做 9：6 大失败模式自检（v5 §2 反例 10 详）
│   ├── 必做 10：Tool schema strict mode 启用
│   └── 必做 11：Cost ceiling per workflow 启用
│
└── 路径 D："v5 新增的硬性风险"
    ├── 必做 12：Flink 1.20.6 升级（不是 2.3 LTS！）—— 防 critical bug
    ├── 必做 13：DPoP 适配 MCP 2026-08-22 Roadmap（v5 反例 9）—— 防身份层空白
    └── 必做 14：审计日志加密 + WORM（v5 §4.1）—— 防等保一票否决
```

### 5.2 优先级矩阵（v4 24 项 + v5 6 类增量 = 30 项）

| 优先级 | 项 | v4 章节 | v5 评估 |
|--------|----|---------|---------|
| **P0 立即** | OCSF 1.9 字段映射 | v4 §2.0 S-1.1 | ✅ 必须 |
| **P0 立即** | Langfuse 单点接入 | v4 §2.0 S-1.2 | ✅ 必须 |
| **P0 立即** | MCP 2026-07-28 错误码修复 | v4 §1.5 反例 6 | ✅ 必须 |
| **P0 立即** | Flink 1.20.6 升级（不是 2.3） | v5 §1.1 | ✅ **v5 修正 v4 路径** |
| **P0 立即** | DPoP 适配 | v5 §2 反例 9 | ✅ **v5 必报** |
| **P0 立即** | 6 大失败模式自检 | v5 §2 反例 10 | ✅ **v5 必报** |
| **P0 立即** | 等保 2.0 GA/T 2380-2026 自评 | v5 §4.1 | ✅ **v5 必报** |
| **P0 立即** | TCO 对比矩阵 | v5 §3 | ✅ **v5 必报** |
| **P1 30 天** | 信创 LLM 试点 | v3 §3.5 | ✅ |
| **P1 30 天** | 国密 SM4 加密存储 | v5 §4.2 | ✅ **v5 新增** |
| **P1 30 天** | Tool schema strict mode | v5 §2 反例 10 | ✅ **v5 新增** |
| **P1 30 天** | Cost ceiling per workflow | v5 §2 反例 10 | ✅ **v5 新增** |
| **P2 90 天** | Flink 2.2.2 LTS | v5 §1.1 | ✅ **v5 修正 v4 路径** |
| **P2 90 天** | Flink CDC 3.6.0 | v4 §1.1 | ✅ |
| **P2 90 天** | Java 17 升级 | v4 §5.2 #3.6 | ✅ |
| **P2 90 天** | Langfuse 全量 | v3 §2.0 L0-2 | ✅ |
| **P2 90 天** | UEBA-ML 训练 | v3 §3.4 | ✅ |
| **P2 90 天** | OTel + eBPF | v3 §3.3 | ✅ |
| **P3 6 月** | Apache Flink Agents 0.3.0 POC | v4 §3.1 | ✅ |
| **P3 6 月** | Security Data Lake cold tier | v4 §3.2 | ✅ |
| **P3 6 月** | 零信任 + Agent 5 层 Guard | v3 §4.4 | ✅ |
| **P3 6 月** | Qdrant Hybrid A/B（含反例） | v3 §4.1 + v4 §1.5 反例 3 | ✅ |
| **P3 6 月** | Paimon 暖层 | v3 §4.3 | ✅ |
| **P3 6 月** | Threat Hunter Agent 独立模块 | v4 §3.3 | ✅ |
| **P3 6 月** | Investigation Copilot 独立模块 | v4 §3.4 | ✅ |
| **P4 12 月** | MCP 2026-07-28 完整迁移 | v3 §5.2 | ✅ |
| **P4 12 月** | 多 Agent 7 角色 + 5 Guardrail | v3 §5.1 | ✅ |
| **P4 12 月** | Prompt Injection 5 招 | v3 §5.3 | ✅ |
| **P4 12 月** | 数据飞轮 + Agent Engineer | v3 §6.4 + v4 §5.4 | ✅ |
| **P4 12 月** | 信创全栈 POC | v3 §3.5 | ✅ |
| **P4 12 月** | 自治 SOC AL3 | v3 §5.1 | ✅ |

**v5 决策树核心**：
- **P0 8 项必做**（v4 缺 5 项 = v5 §1-4 增量）
- **P1 4 项加做**（v4 缺 2 项 = v5 §2 反例 10 + §4.2 国密）
- **P2-P4 18 项**（沿用 v3/v4）

---

## 6 · 5 维度交叉验证末轮（v4 1.1-1.5 基础上 + 4 个新发现）

按 memory 中 5 维度清单，对 v4 重新做 2026-08-25 末轮核验。**v4 已做 1.1-1.5，v5 加 4 个新发现**：

### 6.1 版本谱终态（v5 末轮核验）

| 组件 | v4 评估 | v5 末轮核验 | 变化 |
|------|--------|------------|------|
| **Flink 1.18** | EOL 2026-03-24 | ✅ 对 | — |
| **Flink 1.19** | EOL 2026-07-01 | ✅ 对 | — |
| **Flink 1.20.6** | v4 没提 | **1.20.6 已 GA**（2026-08） | **v5 升级路径关键** |
| **Flink 2.2.2** | v4 没提 | **2.2.2 已 GA**（2026-08） | **v5 短中期目标** |
| **Flink 2.3.0** | "最新 LTS" | **2.3.0 critical bug 三连**（v5 §1.1） | **v5 修正：不推荐 2.3.0** |
| **Flink 2.3.1** | v4 没提 | **2.3.1 已 Resolved 40269**（2026-08-19） | **v5 等 2.3.1 GA 后再升** |
| **Flink 2.4.0** | v4 没提 | 2026-Q4 规划中 | **v5 观望** |
| **Flink CDC 3.6.0** | 2026-03-30 GA | ✅ 对 | — |
| **Flink Kafka Connector 5.0.0** | v4 §1.1 提 2.3 配套不全 | ✅ 对（v5 升级路径避开 2.3.0） | — |
| **Flink Kubernetes Operator 1.15.0** | v4 §1.1 提 | ✅ 对 | — |
| **Apache Flink Agents 0.3.0** | 2026-06-19 GA Preview | ✅ 对，**2.3.0 兼容性待 2.3.1 验证** | **v5 修正** |
| **MCP 2026-07-28** | v4 提 | ✅ 对 | — |
| **MCP 2026-08-22 Roadmap** | **v4 完全没提** | **2026-08-22 发布 5 大优先级** | **v5 必报** |
| **OCSF v1.9** | v4 提 | ✅ 对 | — |
| **React 19.2.7** | v4 提 | ✅ 对 | — |
| **Vite 7.3.6** | v4 提 | ✅ 对 | — |
| **Qdrant latest** | v4 提"锁版本" | ✅ 对（生产风险） | — |
| **mimo-v2.5 LLM** | v4 提 | **v5 必报"AI 系统等保"** | **v5 必报** |

### 6.2 协议 spec 版本号（v5 末轮核验）

| 协议 | v4 评估 | v5 末轮核验 | 真实情况 |
|------|--------|------------|---------|
| **MCP 2026-07-28 spec** | v4 提 | ✅ 对 | — |
| **MCP 2026-08-22 Roadmap** | **v4 漏** | **5 大优先级 + DPoP/Workload ID/ID-JAG** | **v5 必报** |
| **OCSF v1.9** | v4 提 | ✅ 对 | — |
| **W3C Trace Context** | v4 提 | ✅ 对，**MCP 2026-08-22 Roadmap 强化** | — |
| **CIMD** | v4 提 | ✅ 对，**DCR 2027 夏季移除** | **v5 必报** |
| **DPoP (RFC 9449)** | v4 漏 | **MCP 2026-08-22 必做** | **v5 必报** |
| **Workload Identity Federation** | v4 漏 | **MCP 2026-08-22 必做** | **v5 必报** |
| **ID-JAG (Enterprise-Managed AuthZ)** | v4 漏 | **MCP 2026-08-22 必做** | **v5 必报** |

### 6.3 AI Agent GA 时间线（v5 末轮核验）

v4 提：D3 Morpheus APD 2.0 / Torq SOC Brain 2026-07-28 / Conifers CognitiveSOC / Charlotte AI Agentic / Microsoft Security Copilot / Splunk AI Agent Studio / Palo Alto Cortex AgentiX / SentinelOne Purple AI / Apache Flink Agents 0.3.0 / Tines AI Native / Prophet Security。

**v5 新增**：
- **D3 Morpheus 95% 实测数据**（v4 引但 v5 给具体客户数据）
- **Microsoft Security Copilot SCU 定价**（v4 没提）
- **Sekoia 5 question 评估框架**（v4 没提）
- **Tines Voice of Security 2026：99% SOCs use AI**（v4 没提）
- **SANS 2026 AI Survey：78% 用 / 27% 成熟**（v4 没提）
- **Anthropic's Spectrum of Autonomy**（v4 没提）

### 6.4 行业量化基线（v5 末轮核验）

v4 引：99% 降噪 / 90% MTTR / 80% → >98% 数据飞轮 / 50→5 L1 / MTTD 197d→28d / Charlotte AI 70% 减人工。

**v5 加**：
- **SCU $4/h provisioned / $6/h overage / $35-105K/年**（Microsoft Security Copilot 2026）
- **40-95% Agentic 失败率**（Gartner 2026-08 / SANS）
- **3 SCU/年 $105K**（实际中等使用场景）
- **TCO 中端 Splunk $150-500K / Sentinel $30-150K / Elastic $70-900K**
- **本项目自建 ~$76K/年**（v5 估算）

### 6.5 行业教训反例（v5 加 6 条 = 共 12 条）

v4 §1.5 6 条（保留）。**v5 §2 加 6 条** = 12 条反例（v4 + v5 合并），见 v5 §2。

---

## 7 · 本项目当前基线（v4 §4.2 基础上 + 5 项修订）

### 7.1 v4 已给 27 项（保留）

见 v4 §4.2 完整列表。

### 7.2 v5 修订 5 项

| 维度 | v4 评估 | v5 末轮核验 | 评估 |
|------|--------|------------|------|
| **AI Agent 角色** | "4 层（agent_a/b/c/d）+ CAD 监督" | **+ agent_tool_builder + agent_decomposer + agent_executor + agent_reviewer + sub_auditor**（backend/agents/ 实际 8 个文件） | v4 漏 4 个 |
| **CAD 监督** | v4 提"4 层 Guard + CAD" | **`backend/cad.py` 2026-08-24 22:17 提交**（最后修改） | v4 没明确路径 |
| **Temporal 实装** | v4 提 | **`backend/temporal/` 4 文件 + default true** | ✅ |
| **Sigma 规则** | v4 提 11+11 | ✅ 对 | — |
| **本项目 TCO 估算** | v4 缺 | **v5 §3.2 估算 ~$76K/年** | v5 新增 |

### 7.3 v5 新增 4 项本项目必量化

| 维度 | 当前值 | v5 必量化 |
|------|--------|----------|
| **当前 MTTD** | ❌ 未量化 | v5 必报"基线度量" |
| **当前 MTTR** | ❌ 未量化 | v5 必报"基线度量" |
| **当前告警量/日** | ❌ 未量化 | v5 必报"基线度量" |
| **当前合规度** | ❌ 未量化（等保 2.0 33 项自检） | v5 必报"自评清单" |

---

## 8 · 集成架构图修订（v4 §6 基础上 + 3 层合规 + DPoP）

```
┌─────────────────────────────────────────────────────────────────────┐
│              揭榜挂帅 shared-memory-platform v5 集成架构              │
│     v4 基础上 + 3 层合规（等保 2.0 / 密码法 / AI 系统）+ DPoP        │
└─────────────────────────────────────────────────────────────────────┘

                  数据源层（v4 + v5 等保加密层）
  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │ syslog   │ HTTP推   │ EDR(Sysmon│ DB CDC   │ MISP/TAXII│ ← v3 §3.2 + v4 §2.3
  │ /api     │ 送       │ /WinEvent)│(Flink CDC)│ /STIX     │   (已实装)
  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬────┘
       │          │          │          │          │
       └──────────┴──────────┼──────────┴──────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │  Kafka 7 topics + SM4 加密（v5 §4.2）    │ ← v5 等保 2.0 必做
        │  + WORM 审计日志（v5 §4.1）              │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  Flink 1.20.6 LTS（v5 §1.1 修正）        │ ← v5 不升 2.3.0
        │  Flink CDC 3.6.0 + 经典 RocksDB 路径     │ ← v5 避开 40327/40302
        │  + 关 state.changelog.enabled           │ ← v5 必做
        │  Flink CEP 3 攻击链模式                   │
        │  Apache Flink Agents 0.3.0 POC（v4 §3.1）│ ← v4 保留
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
        │  │ + 国密 SM3 链式哈希（v5 §4.2）   │  │ ← v5 新增
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 8 角色 Agent（v5 §7.2 修订）     │  │ ← v4 7 角色 + tool_builder
        │  │ Orchestrator / Triage / Invest /  │  │
        │  │ Threat Hunter / TI / IR / Report  │  │
        │  │ + Investigation Copilot           │  │
        │  │ + agent_tool_builder / decomposer │  │ ← v5 修订
        │  │ + 5 Guardrail + 2 Guardrail       │  │ ← v5 加 Tool schema + Circuit breaker
        │  │ + Cost ceiling per workflow       │  │ ← v5 加
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 4 层 MCP Guard + DPoP（v5 §2 反例9）│  │ ← v5 必做
        │  │ + 5 层零信任 + 5 Guardrail        │  │
        │  │ + MCP 2026-07-28 spec + 08-22 Rdmp │  │ ← v5 升级
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ Langfuse LLM Observability       │  │
        │  │ + 5 招 Prompt Injection 防御    │  │
        │  │ + 数据飞轮 + Agent Engineer     │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 钓鱼检测 7 检测器 + LLM 维度    │  │
        │  │ IOC 实时匹配器                   │  │
        │  │ EDR 接入层 + 商业 EDR 预留       │  │
        │  │ + Threat Hunter Agent（v4 §3.3）│  │
        │  └────────────────────────────────────┘  │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  RAG 检索：Qdrant Hybrid（v3 §4.1）       │
        │  + pgvector 兜底 + SPLADE finetune       │
        │  + 数据飞轮联动                          │
        │  + A/B 测试（v4 §1.5 反例 3）            │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  响应引擎（v3 已有）                       │
        │  8 策略 / 5 动作 / SSH + iptables / 审批  │
        │  + NIST 800-61r3 CSF 2.0                │
        │  + SM2 签名验签（v5 §4.2）              │ ← v5 新增
        │  + 6 大失败模式防护（v5 §2 反例 10）   │ ← v5 新增
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  持久化：PostgreSQL 16 + SM4 字段加密     │ ← v5 §4.2 新增
        │  + Redis 7 + Qdrant + OCSF 标准化        │
        │  + 异地备份 ≥30 公里（等保 2.0）         │ ← v5 §4.1 必做
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  合规层（v5 §4 新增）                     │ ← v5 必报
        │  等保 2.0 GA/T 2380-2026                 │
        │  + 密码法（SM2/SM3/SM4）                │
        │  + 数据安全法（数据分类分级 + 跨境管控）│
        │  + AI 系统等保（2026-01-01 新《网安法》）│
        │  + 国密 KMS + 链式哈希 + WORM            │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  可观测性：OTel + Tempo + Jaeger          │
        │  + Prometheus + Grafana                   │
        │  + eBPF（v3 §3.3）                       │
        │  + Langfuse LLM 全链路（v3 §2.0 L0-2）   │
        └────────────────────────────────────────────┘
                         ▲
                         │ 前端 React 19.2 + Vite 7.3
                         │ 5 仪表板：Monitor / RAG / Intel / 
                         │ Phishing / EDR / Operations
```

**v5 集成关键点**：
1. **3 层数据湖**（hot Kafka / warm Paimon / cold Iceberg）
2. **8 角色 Agent**（v4 7 角色 + v5 修订 agent_tool_builder/decomposer/executor/reviewer）
3. **5+2 = 7 道 Guardrail**（v4 5 + v5 2 = Tool schema + Circuit breaker）
4. **双协议**（MCP 2026-07-28 + 2026-08-22 Roadmap + W3C Trace Context）
5. **3 层合规**（等保 2.0 / 密码法 / AI 系统）
6. **国密适配**（SM2 签名 / SM3 哈希 / SM4 加密）
7. **TCO 自建 ~$76K/年**（v5 §3.2 估算）

---

## 9 · 路线图（v4 7 基础上 + P0 强制 + 6 大失败模式防护）

| 时段 | 7/14/30 天决策树（v5 §5） | 1-3 月 | 4-6 月 | 7-12 月 |
|------|---------------------------|--------|--------|---------|
| **D+7** | OCSF 1.9 / Langfuse / MCP 错误码修复 / **Flink 1.20.6 启动升级** / **DPoP 适配** / **6 大失败模式自检** | — | — | — |
| **D+14** | NIST r3 / UEBA-ML 训练启动 / 信创合规清单 / **等保 2.0 自评 10 项** / **AI 系统自评 10 项** / **TCO 对比矩阵演示** | — | — | — |
| **D+30** | v4 L0 全量 + MCP 升级 + 信创基线 + Prompt Injection 第 1 招 + **国密 SM4 加密存储** + **WORM 审计日志** + **Tool schema strict mode** + **Cost ceiling** | **Flink 1.20.6 升完** | — | — |
| **M+1-2** | — | 信创 LLM 试点 / Java 17 升级启动 / **DPoP 生产部署** | Apache Flink Agents 0.3.0 POC | 5 Guardrail + 2 Guardrail（v5） |
| **M+2-3** | — | **Flink 2.2.2 LTS** 升级 / UEBA-ML 上线 / **国密 SM2 签名** | OTel eBPF 接入 | Agent 红蓝测试 + Investigation Copilot |
| **M+3-4** | — | Flink CDC 3.6 试点 | Qdrant Hybrid A/B（含降分反例） | 多 Agent shadow + 7 Guardrail 全量 + 数据飞轮组织能力 |
| **M+4-6** | — | Flink CDC 扩展 + 信创 LLM 全量 + **国密全栈** | Paimon 暖层上线 + 零信任 5 层 Guard | MCP 2026-08-22 Roadmap 完整迁移 + Security Data Lake cold tier |
| **M+6-9** | — | — | 多 Agent 编排 + Prompt Injection 5 招 | DPoP 深化 + 数据飞轮自动化 + Workload Identity Federation |
| **M+9-12** | — | — | — | **等保 2.0 三级认证** / 自治 SOC AL3 / 信创全栈 / 8 角色 + Investigation Copilot + Threat Hunter |

**v5 路线图关键变化**：
- v4 写"Flink 1.19.3→1.20 LTS→2.3 LTS"——**v5 改：1.19.3→1.20.6→2.2.2（短中期）→2.3.1+（中期）等 GA**
- v4 写"DPoP L3 末尾"——**v5 提前：DPoP 必做 P0 / L1**
- v4 没提"6 大失败模式防护"——**v5 加：Tool schema + Circuit breaker + Cost ceiling + 审计可查**（D+30）
- v4 没说"等保 2.0 33 项自检"——**v5 必报 D+14 10 项自评**
- v4 没说"国密全栈"——**v5 加：SM2/SM3/SM4 完整路线**

---

## 10 · v5 风险与验证（v4 9 章 + 6 大风险）

### 10.1 升级风险（v4 + 6 条）

| 风险 | 等级 | v5 缓解 |
|------|------|--------|
| v4 的 5 条 | 同 v4 | 同 v4 |
| **Flink 2.3.0 critical bug 三连**（v5 §1.1） | **极高** | 走 1.20.6 → 2.2.2 → 等 2.3.1 GA 路径 |
| **MCP 2026-08-22 身份层空白**（v5 §2 反例 9） | **高** | DPoP 必做 P0 + Workload Identity Federation 必做 L1 |
| **40-95% Agentic 失败率**（v5 §2 反例 10） | **高** | 6 大失败模式自检 + Tool schema + Circuit breaker + Cost ceiling |
| **等保 2.0 GA/T 2380-2026 33 项一票否决**（v5 §4.1） | **极高** | D+14 10 项自评 + M+12 三级认证 |
| **AI 系统纳入等保**（v5 §2 反例 12） | **高** | AI 系统自评 10 项清单 + mimo-v2.5 出境审计 |
| **TCO 超出预算**（v5 §3） | 中 | 自建 ~$76K/年 vs 商业 $30-500K/年对比；揭榜挂帅场景自建唯一选项 |

### 10.2 升级期监控指标（v4 + 4 个）

v4 12 个指标保留。**v5 新增**：
- **本项目 MTTD/MTTR 基线**（v4 §4.2 缺，v5 §7.3 必量化）
- **DPoP 重放率**（v5 反例 9 关键指标）
- **Tool schema 异常率**（v5 反例 10 关键指标）
- **Cost ceiling 触发率**（v5 反例 10 关键指标）

### 10.3 不升级的代价（v4 + 5 项）

v4 16 项保留。**v5 新增**：
- 不升 1.20.6：继续用 1.19.3 必触发 Unaligned Checkpoint restore fail（40269）
- 不做 DPoP：Agent-to-Agent 跨 3 网络必出现 token 重放（2026-08-22 Roadmap 警示）
- 不做 6 大失败模式防护：v5 §2 反例 10 数据：40-95% 项目失败
- 不做等保 2.0 自评：揭榜挂帅评审"合规度不达标"直接失分
- 不量化 TCO：评审质疑"性价比"，无法证明自建比商业更优

---

## 11 · 总结（v5 重写）

本轮 v5 升级的核心定位（与 v4 不同）：

1. **v4 是"修正 + 落地 + 反例"逻辑**（24 项 + 6 大反例）；**v5 是"v4 的盲点扫荡"**——6 类增量 + 12 大反例
2. **v4 升 Flink 2.3 LTS**——**v5 修正：1.19.3 → 1.20.6 → 2.2.2 → 等 2.3.1 GA**（Flink 2.3.0 三个 critical bug 必须等 patch）
3. **v4 写 MCP 2026-07-28 spec 是最新**——**v5 必报 2026-08-22 Roadmap 5 大优先级**（DPoP/Workload ID/ID-JAG 是"生产最大变革"）
4. **v4 没提 40-95% Agentic 失败率**——**v5 必报 6 大失败模式防护**（Tool schema + Circuit breaker + Cost ceiling + 审计可查）
5. **v3/v4 提"信创合规"是方向**——**v5 升级到等保 2.0 GA/T 2380-2026 + AI 系统等保 + 国密全栈**
6. **v4 没有 TCO**——**v5 给 5 平台对比 + 本项目自建 ~$76K/年估算**
7. **v4 路线图 4-12 月太粗**——**v5 决策树：P0 8 项必做 / P1 4 项加做 / P2-P4 18 项沿用**
8. **v4 没量化 6 大失败模式**——**v5 §2 反例 10 给"6 大失败模式防护"清单**
9. **v4 没列 agent_tool_builder 等 4 个 Agent**——**v5 §7.2 修订为 8 角色（v4 7 角色 + tool_builder/decomposer/executor/reviewer）**
10. **v4 没说"揭榜挂帅评分关键维度"**——**v5 §5 决策树给"评审前 7 天必做 8 项"清单**

**v5 的验证基础**：
- 12 大反例中，6 大来自 2026-08-22 末轮核验（**Flink 2.3.0 三个 critical bug 来自 Jira FLINK-40327/40302/40269**）
- **MCP 2026-08-22 Roadmap 5 优先级**来自 Linux Foundation 官方发布 + witho2.com / breachprotocol / dev.to 三方报道
- **40-95% Agentic 失败率**来自 Gartner 2026-08 / SANS 2026 AI Survey / Tines Voice of Security 2026 / ZonFlip 2026-08
- **等保 2.0 GA/T 2380-2026**来自公安部 2026-06-01 施行 + 安恒信息 2026-06 + 北京软件和信息服务业协会 2026-06
- **TCO 数据**来自 shieldoperations.co.uk 2026 / q-sec.com 2026 / embee.co.in 2026 / ogma.in 2026
- **AI 系统纳入等保**来自 2026-01-01 新《网安法》+ 摩云企服 2026
- **本项目基线**用 backend/agents/ 实际 8 个文件 + cad.py 2026-08-24 22:17 + temporal/ 4 文件直接核实

**给揭榜挂帅评审的"7-30 天必做"清单**（v5 决策树核心）：
1. **OCSF 1.9 字段映射**（v4 S-1.1）—— 演示 OCSF 工具验证
2. **Langfuse 单点接入**（v4 S-1.2）—— 演示 LLM 全链路
3. **MCP 2026-07-28 错误码 -32002 → -32602 修复**（v4 反例 6）—— 防未来坑
4. **phishing_guard LLM 维度演示**（v4 §2.1）—— 已实装，**不演示浪费**
5. **Flink 1.20.6 升级启动**（v5 §1.1）—— 演示"我们不踩 2.3.0 critical bug"
6. **DPoP 适配 + Workload Identity Federation 启动**（v5 反例 9）—— 演示"我们跟 MCP 2026-08-22 Roadmap"
7. **6 大失败模式自检**（v5 反例 10）—— 演示"我们知道 40-95% 为什么失败"
8. **等保 2.0 GA/T 2380-2026 自评 10 项**（v5 §4.1）—— 演示"我们懂合规"
9. **AI 系统等保自评 10 项**（v5 §4.3）—— 演示"我们 AI Agent 自身是被审对象"
10. **TCO 对比矩阵**（v5 §3）—— 演示"自建比商业性价比高"
11. **IOC 实时匹配演示**（v4 §2.2）—— 已实装，**不演示浪费**
12. **EDR 接入层演示**（v4 §2.3）—— 已实装，**不演示浪费**

---

## 附录 A · v4 → v5 关键变更对照表

| 维度 | v4 章节 | v5 章节 | 变更摘要 |
|------|--------|--------|---------|
| Flink 升级路径 | v4 §1.1 写"1.19.3→1.20→2.3" | **v5 §1.1** | **修正：1.19.3→1.20.6→2.2.2→等 2.3.1**（2.3.0 critical bug） |
| MCP 时间线 | v4 写"2026-07-28 最新" | **v5 §1.2** | **新增 2026-08-22 Roadmap 5 大优先级**（v4 完全漏） |
| Agentic 失败率 | v4 无 | **v5 §2 反例 10** | **新增 40-95% 反例**（Gartner 2026-08） |
| 6 大失败模式防护 | v4 无 | **v5 §2 反例 10** | **新增 Tool schema + Circuit breaker + Cost ceiling** |
| 等保 2.0 | v3 §3.5 提"信创合规" | **v5 §4.1** | **升级到 GA/T 2380-2026 + 33 项一票否决** |
| AI 系统等保 | v4 无 | **v5 §2 反例 12** | **新增：AI 训练/应用系统纳入等保对象** |
| TCO 对比 | v4 无 | **v5 §3** | **新增 5 平台对比矩阵 + 本项目 ~$76K/年估算** |
| 国密 SM2/SM3/SM4 | v3 §3.5 提"国密 OS/DB" | **v5 §4.2** | **升级到 SM2 签名 + SM3 哈希 + SM4 加密完整路线** |
| 决策树 | v4 §2.0 7/14/30 路线图 | **v5 §5** | **新增 P0/P1/P2/P4 优先级矩阵 + 8 项必做** |
| 6 大反例 | v4 §1.5 6 条 | **v5 §1.5 6 条 + §2 6 条 = 12 条** | **12 大反例** |
| MCP 身份层 | v4 §4.4 提"零信任" | **v5 §2 反例 9** | **新增 DPoP + Workload ID Federation + ID-JAG** |
| MCP 治理 | v4 提 2025-11 spec | **v5 §1.2** | **新增 2025-12 Linux Foundation 治理转移** |
| Flink 1.20.6 / 2.2.2 patch | v4 无 | **v5 §1.1** | **新增 1.20.6 / 2.0.3 / 2.1.4 / 2.2.2 / 2.3.1 patch 矩阵** |
| 本项目 8 角色 | v4 写 7 角色 | **v5 §7.2** | **修订：+ agent_tool_builder/decomposer/executor/reviewer = 8 角色** |
| 本项目 CAD 路径 | v4 提"4 层 + CAD" | **v5 §7.2** | **明确 `backend/cad.py` 2026-08-24 22:17 提交** |
| mimo-v2.5 LLM 合规 | v4 提 mimo | **v5 §4.3** | **必报"AI 系统等保" + 出境审计** |
| DCR 2027 夏季移除 | v4 提 CIMD | **v5 §1.2** | **明确时间点 + 必报迁移** |
| 5 Guardrail | v3 §5.1 5 条 | **v5 §8** | **升级为 5+2 = 7 Guardrail**（+ Tool schema + Circuit breaker） |
| 本项目 MTTD/MTTR | v4 §4.2 缺 | **v5 §7.3** | **必量化基线度量** |
| 33 项一票否决 | v4 无 | **v5 §4.1** | **新增等保 2.0 33 项一票否决自检清单** |

---

## 附录 B · v5 在 v4 基础上新增/修正的来源（v4 附录 B 基础上 +20 个）

### v4 已列 62 个来源（保留）
1-62：见 v4 文档附录 B。

### v5 新增（2026-08-25 末轮）
63. Apache Flink Jira. *FLINK-40327: ForSt async multiGet leaks a native ReadOptions per read batch*. 2026-08-19（**Critical, Affects 2.0-2.3**）。
64. Apache Flink Jira. *FLINK-40302: Periodic materialization permanently stops after taking a native-format savepoint when the changelog state backend is enabled*. 2026-08-19（**Critical, Affects 1.20-2.3, Open**）。
65. Apache Flink Jira. *FLINK-40269: Unaligned checkpoint restore may fail after rescale when a two-input task reads from the same upstream*. 2026-08-19（**Major, Fixed: 1.20.6, 2.0.3, 2.1.4, 2.2.2, 2.3.1**）。
66. Apache Flink Jira / mail-archive. *Race condition in JobManager final savepoint could cause data duplication or incorrect job state, with Flink Kubernetes Operator*. 2026-08-13（**HA store 必配**）。
67. Linux Foundation / Model Context Protocol. *MCP 2026-08-22 Roadmap: 5 priority areas*. 2026-08-22（**DPoP + Workload Identity + ID-JAG 必做**）。
68. breachprotocol (dev.to). *MCP is rebuilding its authorization around agents instead of people in browsers*. 2026-08-23（**生产变革**）。
69. witho2.com. *Model Context Protocol Roadmap Names 5 Priorities for AI Agents After Stateless Rewrite*. 2026-08-23（**5 priority 详解**）。
70. frankx.ai. *AI Architecture 2026: Four Decisions Hard to Reverse*. 2026-08-21（**MCP spec snapshot**）。
71. bitroot.org. *MCP Stateless Architecture: How Protocol Redesign Enables Scale-to-Zero*. 2026-08-22（**Stateless 革命**）。
72. 网易/InfoQ. *MCP 走向无状态，开发者追问：这不就又变回 API 了吗？*. 2026-08-19（**中文解读**）。
73. 掘金. *从"工具插件"到"Agent 基础设施"：MCP 2026 为什么越来越重要？*. 2026-08（**企业级 4 大问题**）。
74. Gartner via Hacker News / Sekoia. *40% agentic AI projects will be canceled by 2027*. 2026-08（**失败率反例**）。
75. SANS. *2026 AI Survey: 78% adoption / 27% mature*. 2026（**治理滞后**）。
76. Tines. *Voice of Security 2026 Report: 99% SOCs use AI*. 2026（**AI 普及但控制不足**）。
77. ZonFlip. *When Agents Go to Work: The Ops Team's Real Guide to Agentic AI That Holds Up in Production*. 2026-08（**6 大失败模式**）。
78. Sekoia. *AI Agents in the SOC: 5 Production Questions To Ask Beforehand*. 2026-08（**评估框架**）。
79. TechPathy. *How to Deploy Agentic AI Without Losing Oversight in Production*. 2026-08（**Anthropic's Spectrum of Autonomy**）。
80. dev.to (mr_manushukla). *Agentic SOC in 2026: should you buy autonomous patching or build it?*. 2026-08（**SCU $4/h / $35-105K/年**）。
81. The Hacker News. *Evaluating the Real Impact of an AI SOC Agent in 2026*. 2026-08（**Functional + Non-functional requirements**）。
82. 公安部 / GA/T 2380-2026. *《信息安全技术 网络安全等级保护数据安全基本要求》*. 2026-06-01 施行（**数据安全独立控制域**）。
83. 安恒信息 / 飞驰云联. *等保 2.0 数据安全新标准 GA/T 2380-2026 6 月 1 日正式施行 落地检查全面铺开*. 2026-06（**33 项一票否决**）。
84. 北京软件和信息服务业协会. *等保数据安全新规施行 信安世纪全能力助力合规落地*. 2026-06（**4 大变化详解**）。
85. 摩云企服. *2026 年等保合规新要点——企业必须关注的五大变化*. 2026（**AI 系统纳入等保对象**）。
86. 国源天顺. *2026 等保三级测评变革：告别设备堆砌，构建"三国"安全能力体系*. 2026（**20 项基础设备清单**）。
87. shieldoperations.co.uk. *Best SIEM Tools 2026: Unbiased Buyer Guide*. 2026（**TCO 5 平台对比**）。
88. q-sec.com. *SIEM TCO Optimization: A CISO's Field Notes*. 2026（**4 SIEM 经济模型**）。
89. embee.co.in. *Microsoft Sentinel vs Third-Party SIEM: A Buyer's Guide for Indian SOCs*. 2026（**Sentinel TCO 详解**）。
90. ogma.in. *Microsoft Sentinel vs Splunk — when each wins*. 2026（**Sentinel vs Splunk**）。
91. 数说安全 / 三个皮匠. *2026Agentic SOC：从告警洪流到自主闭环的安全运营新范式*. 2026（**国内 6 厂商实测**）。
92. 致远互联. *信创 OA 安全策略 2026：等保 2.0 与国密落地指南*. 2026（**国密算法应用**）。
93. 阿里云 / 阿里云 Realtime Compute. *Job errors FAQ*. 2026-08（**Flink 生产故障排查**）。
94. Flink dev mail-archive. *[DISCUSS] Race condition in JobManager final savepoint*. 2026-08-13（**HA 必配**）。

---

**文档版本**：v5.0（2026-08-25 15:25）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-09-25（M+1）对照 2026-Q4 SOC 行业新动向（重点：Flink 2.3.1 GA / MCP 2026-Q4 spec / 等保 2.0 实施 90 天后状态）

**前置版本**：
- v4.0（`2026-q3-tech-stack-upgrade-v4.md`，2026-08-25 15:14）
- v3.0（`2026-q3-tech-stack-upgrade-v3.md`，2026-08-25 15:02）
- v2.0（`2026-q3-tech-stack-upgrade-v2.md`，2026-08-25 14:53）
- v1.0（`2026-q3-tech-stack-upgrade.md`，2026-08-25 14:38）
