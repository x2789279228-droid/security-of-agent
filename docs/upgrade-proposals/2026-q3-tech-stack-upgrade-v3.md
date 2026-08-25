# 技术栈升级方案 v3（2026-Q3 · 升级轮 v3）

> **本 v3 在 v2（`2026-q3-tech-stack-upgrade-v2.md`）基础上**，做了 4 类动作：
> 1. **修正 5 个事实性错误**（Flink 目标版本、MCP spec 版本、OCSF 版本、Autonomy 模型、Dropzone 角色划分）
> 2. **补齐 6 个 v2 漏掉的升级项**（信创合规、零信任、Prompt Injection 防御、Agent 红蓝测试、数据飞轮、Agentic SOAR 编排）
> 3. **重新量化**（用 RSAC 2026 / CrowdStrike 2026-Q3 / D3 Morpheus APD 2.0 / 国内深信服 99% 降噪等最新数据替换 v2 数字）
> 4. **加 7/14/30 天"立即可做"超短期路线**（v2 的 L0 起点再压缩到一周可上线）
>
> v1/v2 文档完整保留作为历史快照；本 v3 是"建议执行版 v3"。

---

## 0 · TL;DR：v2 → v3 变更速览

| 维度 | v2（2026-08-25 二版） | v3（本轮） | 变更原因 |
|------|----------------------|-----------|---------|
| Flink 目标 LTS | 2.2 LTS | **2.3 LTS**（2.3.0，2026-06-23 GA） | endoflife.date 2026-08-13 刷新：2.3 已是最新 LTS（2.2 仍 active 但已被 2.3 替代） |
| MCP spec | 2025-11 | **2026-07-28**（stateless 革命） | 2026-07-28 spec 已发布：移除 `initialize` 握手 / `Mcp-Session-Id` / 协议 session；新增 MRTR、header 路由、cache hint、OAuth 强化、扩展框架 |
| OCSF 版本 | 1.8.0（2026-03-16） | **1.9 范围**（v1.9.x 持续迭代） | AppScale Blog 2026 评估：v1.9 是 2026 当前迭代版本；Datadog / SentinelOne / Palo Alto / Rapid7 已 OCSF v1.9 兼容 |
| Autonomy 模型 | 4 级 AL1-AL4 | **4 级 AL + 5 大 Guardrail**（D3 Morpheus APD 2.0 模式） | RSAC 2026 行业共识：单谈"AL 等级"已不够，必须配套"数据源健康检查 / 结论保留 / 调查指南 / 查询级审计 / 人工 handoff" 5 大 Guardrail |
| 多 Agent 角色 | Orchestrator / Triage / Investigation / TI / IR / Report 6 角色（CSDN 版） | **6 角色 + Dropzone 5 专家角色映射**（威胁猎手/检测工程师/取证分析师/TI 分析师/数据架构师） | Dropzone AI 已扩展到 5 专家角色，2026 行业 5-6 角色均成立；v3 给"两套映射表" |
| 告警降噪数字 | 80% / 70% 减人工 | **99% 降噪 / 90% MTTR 压缩 / L1 50→5 人**（国内 RSAC 2026 实测） | 火山引擎 Circle / 深信服安全 GPT / 奇安信 AISOC / 360 / 绿盟 2026 实测数据 |
| 总升级项 | 14 项 | **20 项** | 补信创合规、零信任、Prompt Injection 防御、Agent 红蓝测试、数据飞轮、Agentic SOAR 编排 6 项 |
| 路线图粒度 | 30 天 / 3 月 / 6 月 / 12 月 | **+ 7 天 / 14 天"超短期"**（v2 没有） | 把"立即见 ROI"再压缩到一周可上线，让揭榜挂帅评审看到"7 天可演示增量" |

---

## 1 · 互联网 SOC 现状对照（2026-Q3 视角 · v3 刷新版）

### 1.1 行业基准（v3 在 v2 基础上做"硬数据刷新"）

| 维度 | 行业主流 2026-Q3（v3 数据） | v2 引用数据 | v3 评价 |
|------|---------------------------|------------|---------|
| **AI 原生层** | 14+ Agentic SOC 平台 GA（v2 是 12；v3 加 Torq SOC Brain 2026-07-28、Microsoft Security Agent Studio 2026-Q2 GA、Palo Alto Cortex AgentiX 2025-12、D3 Morpheus APD 2.0 2026-Q3） | 12 个 | 行业继续扩张，v2 已不新 |
| **告警降噪** | **99%（国内深信服 / 360 / 火山引擎 / 绿盟 2026 实测）**；MSSP 1 分析师日均看 2,000+ 告警降至 200 | v2 写 "80% 自动化" | **v2 数据偏低估**；v3 用 99% 更准确 |
| **MTTR 压缩** | **90-98%**（Dropzone AI：40min→3min；奇安信 AISOC：98% 减；v2 写"3x MTTR" 偏保守） | 3x MTTR | **v2 数据偏低估** |
| **L1 减员** | **90% 缩编**（RSAC 2026 国内案例：50→5 人） | v2 写 "24→8" 偏保守 | v2 数据偏保守 |
| **AI Agent 自主级别** | AL1-AL4 + **5 大 Guardrail**（D3 Morpheus APD 2.0 模式：数据源健康检查 / 结论保留 / 调查指南 / 查询级审计 / 人工 handoff） | v2 写 4 级 AL | **v2 缺 Guardrail 维度**（这是 2026 RSAC 最热的"防止 AI 瞎猜"机制） |
| **流处理内核** | Flink **2.3 LTS**（2026-06-23 GA）；2.2 / 2.1 / 1.20 LTS 仍 active；1.18 EOL（2025-03-24） | v2 写 2.2 LTS | **v2 落后 1 个大版本**（2.3 是 2026-08 当前最新） |
| **MCP 协议** | **MCP 2026-07-28 spec**（stateless 革命：移除 `initialize` 握手 + `Mcp-Session-Id` + 协议 session；新增 MRTR / header 路由 / cache hint / OAuth 强化 / 扩展框架） | v2 写 2025-11 spec | **v2 落后 1 个 spec 版本**（8 个月内 2 次 breaking change） |
| **OCSF** | **v1.9 范围**（持续迭代，v1.9.x） | v2 写 1.8.0（2026-03-16） | **v2 落后 1 个小版本** |
| **向量检索** | Qdrant Hybrid + **先 finetune sparse 再 hybrid**；finetune SPLADE nDCG 0.413 vs hybrid 0.405 | 同 v2 | 不变（v2 已正确） |
| **湖仓** | Paimon Catalog + Iceberg（开放性） | 同 v2 | 不变 |
| **MCP 生态规模** | **4.5 亿月下载**（TypeScript + Python SDK 跨 10 亿次）；2026-06 已有"Agent 应用商店" | v2 写"6,400+ 公开 server" | v2 数字偏旧 |
| **多 Agent 角色** | 6 角色（CSDN 共识）+ 5 专家（Dropzone AI 实测） | v2 写 6 角色 | **v3 补 Dropzone 5 专家映射** |
| **信创合规**（**v3 新增**） | 国内 Agentic SOC 强需求：DeepSeek / Qwen / GLM 国产 LLM + 信创 OS + 国产数据库；2026 国内厂商（深信服 / 奇安信 / 360 / 绿盟 / 亚信 / 安恒）全部信创路径 | v2 未识别 | **v2 漏掉的关键维度**（揭榜挂帅是政府项目，国产化合规是必检项） |
| **零信任**（**v3 新增**） | CrowdStrike Falcon Zero Trust / Microsoft Zero Trust SOC / Palo Alto Prisma SASE 集成；2026 趋势：Agent 调用工具的"零信任授权" | v2 未识别 | v2 漏掉（Agent 调用工具的零信任授权是 2026 新维度） |
| **数据飞轮**（**v3 新增**） | CrowdStrike 公开数据：反馈循环让准确率从 ~80% → >98%；D3 Morpheus"租户级 memory"是护城河 | v2 §9.4 简略提"反馈循环" | v2 缺"数据飞轮"系统化设计 |
| **Prompt Injection 防御**（**v3 新增**） | OWASP 2025 LLM Top 10 第一；2026 实战案例：日志/邮件/工单藏指令致 SOC Agent 误判 | v2 §5.1 简略提"OWASP 2025 第一" | v2 缺"具体防御 5 招" |
| **Agent 红蓝测试**（**v3 新增**） | D3 Morpheus 5 个对抗场景；Torq HyperAgents 公开红队测试；2026 行业开始要求"Agent 部署前必过 5 个对抗" | v2 未识别 | v2 漏掉（生产前必检项） |
| **Agentic SOAR 编排**（**v3 新增**） | Torq HyperAgents 2026-07-28 SOC Brain / Tines AI Native / Splunk AI Agent Studio 2025-09 是 Agent 编排工具的事实标准 | v2 §4.2 略提 Temporal AI | v2 缺"Agent 编排工具选型对比" |

> **v3 总评**：本平台在 **"CAD 独立监督 + 4 层 Guard + 工具调用审计"** 仍为行业前沿；
> 但 v3 新增发现 5 个**v2 没识别**的差距：信创合规 / 零信任 / Prompt Injection 防御 / Agent 红蓝测试 / 数据飞轮系统化。
> 本轮升级针对 **20 个差距**（v2 的 14 + v3 新增 6）。

### 1.2 行业不容忽视的代价（v3 在 v2 基础上加 3 条新风险）

v2 已识别的 8 条风险继续保留，v3 加 3 条：

- **MCP 2026-07-28 是 breaking change**：移除 `initialize` 握手、移除 `Mcp-Session-Id` 头；**任何仍用 2025-11 spec 的部署在客户端升级后会断连**（依据 Cloudflare Blog 2026-07-28 / TrueFoundry / Octane Solutions 三方报道）。
- **OCSF v1.9 已成事实标准**：Datadog / SentinelOne / Palo Alto / Rapid7 / AWS Security Lake 全部 v1.9 兼容；**v1.8.0 部署在 6 个月内会出现"新字段对不上"问题**。
- **信创合规 = 揭榜挂帅评审计分项**：政府项目必须有"国产 LLM / 信创 OS / 国产数据库"全栈证明；v2 没提，**v3 必须补**。
- **Agent 自动隔离误伤**：2026 RSAC 已有公开案例：Agent 误隔离生产机导致业务中断 4 小时；**必须 HITL 强制 + 30 天可撤回**。
- **D3 Morpheus APD 2.0 五大 Guardrail = 行业新基线**：4 级 AL 已不够，必须配套"5 大 Guardrail"——**v2 完全没提**。

---

## 2 · 超短期路线（v3 新增 · 7/14/30 天可演示增量）

> v2 的 L0（30 天）再细化成"7 天可上线 / 14 天可演示 / 30 天可考核"三个时段。
> **揭榜挂帅评审通常要求"7 天可见增量"**——这一节是给评审的"立即可上"清单。

### 2.0 S-1 · 7 天可上线（评审展示用）

#### S-1.1 OCSF 1.9 字段映射（最易见 ROI）
- 升级 `backend/connectors/` 输出带 OCSF v1.9 metadata 的事件（**不替换原 schema**）
- 复用 v2 §2.0 L0-1 的双写策略；只是 v1.8.0 → v1.9.0
- **评审展示**：用 Datadog OCSF 工具读本平台 Kafka topic，验证 v1.9 字段正确

#### S-1.2 Langfuse 单点接入（最低成本看 LLM 全链路）
- 在 `backend/audit_llm/` 单点接入 Langfuse（不动其他模块）
- 跑 1 次真实审计，演示 trace / token / cost / score 4 个维度
- **评审展示**：Langfuse UI 截图，**证明"每个 LLM 决策可回放"**

#### S-1.3 Tier 1 分诊 Agent POC（30 分钟演示）
- 拿 100 条历史告警（含已知真阳/误报标签）跑分诊 Agent
- 输出混淆矩阵：精确率 / 召回率 / 误报率
- **评审展示**：>85% 准确率即视为"超过 Charlotte AI 客户初值"

#### S-1.4 MCP 2026-07-28 兼容性测试
- 升级 MCP SDK 到 v1.0+（2026-07-28 spec）
- 跑兼容性测试脚本，验证 `initialize` 握手移除后本平台仍正常
- **评审展示**："提前 30 天适配 2026-Q3 spec"作为前瞻性证明

### 2.0 S-2 · 14 天可演示（中期增量）

#### S-2.1 NIST 800-61r3 6 函数 Playbook 重构
- 拿 5 个核心响应剧本（封禁 / 隔离 / 凭证轮换 / 数据擦除 / 通信）改写为 r3 六函数
- `backend/tests/test_response.py` 加 r3 合规测试
- **评审展示**：r3 合规自评报告

#### S-2.2 UEBA-ML 30 天基线训练（启动）
- 启动 `AnomalyDetection` 作业的 ML 评分模块（用 scikit-learn 离线训练）
- 30 天基线数据收集（与揭榜挂帅赛期匹配）
- **评审展示**：训练进度条 + 基线分布

#### S-2.3 信创合规清单（揭榜挂帅评审计分项）
- 列出本平台所有组件 + 对应国产替代：
  - LLM：GPT-4 → DeepSeek-V3 / Qwen3 / GLM-4（任选其一）
  - OS：Ubuntu → 麒麟 / UOS
  - DB：PostgreSQL → 人大金仓 / 神通 / 达梦
  - 消息队列：Kafka → Apache RocketMQ（国产生态更广）
- 制定"国产化迁移路线图"（**不立即执行，但要证明"能换"**）

### 2.0 S-3 · 30 天可考核（接续 v2 L0）

| 项 | 状态 |
|----|------|
| OCSF 1.9 全量接入 | v2 L0-1 已规划，v3 用 1.9 版 |
| Langfuse 全量接入 | v2 L0-2 已规划，v3 不变 |
| Tier 1 分诊 Agent 全量 | v2 L0-3 已规划，v3 不变 |
| NIST r3 Playbook 全量 | v2 L0-4 已规划，v3 不变 |
| **MCP 2026-07-28 升级**（v3 新增） | 新增项 |
| **信创合规基线**（v3 新增） | 新增项 |
| **Prompt Injection 防御第一招**（v3 新增） | 新增项（详见 §6.4） |

---

## 3 · L1 升级项（3 个月内完成 · 主流对齐 · v3 修正版）

### 3.1 流处理内核：Flink 1.18 → **Flink 2.3 LTS**（v2 2.2 → v3 2.3）

**v2 → v3 关键修正**：
- endoflife.date 2026-08-13 刷新：**Flink 2.3.0 已 GA（2026-06-23）**，是当前最新 LTS
- 2.2 仍 active，但已被 2.3 替代
- **v3 推荐路径**：1.18 → 1.20 LTS（短期过渡）→ 2.3 LTS（最终目标）；跳过 2.0 / 2.1 / 2.2

**与 v2 的差异**：
| 维度 | v2（2.2 LTS） | v3（2.3 LTS） | 影响 |
|------|---------------|---------------|------|
| 状态后端 | ForStDB | ForStDB（2.3 优化） | 性能 +5-10% |
| Async State API | State V2 | State V2.1 | 更细粒度 |
| CDC 3.x | 支持 | **3.4.0**（2026-07-09 新版） | connector +5 |
| 维护期 | 2026-Q3 仍 active | **2.3 LTS 至 2028-Q3（估算）** | 多 1 年 |

**效益/不足/对比、回滚策略**：同 v2 §3.1，**仅版本号修正为 2.3**。

### 3.2 业务事件接入：Flink CDC 3.4.0（v2 升级 v3 跟着升）

- v2 写 CDC 3.0；v3 升 3.4.0（2026-07-09 发布）
- 核心能力不变（整库同步 / Schema Evolution / 断点续传）
- 新增：3.4 优化 MySQL 8.0 性能 + 新增 OceanBase CDC

### 3.3 OTel + eBPF（v2 不变）

- 同 v2 §3.3；v3 强调"OTel Collector 自身安全"——必须以最小权限运行 eBPF receiver
- 加：OTel Collector 配置 CIS Benchmark 自检

### 3.4 UEBA-ML（v2 不变）

- 同 v2 §3.4；v3 加：UEBA 评分必须 **可解释**（SHAP / LIME）——这是 2026 RSAC 的可解释 AI 新要求

### 3.5 **信创合规基线**（v3 新增 · 揭榜挂帅评审计分项）

**目标**：让本平台具备"全栈国产化"能力，揭榜挂帅评审的国产化合规分项拿满。

**方案**：
- **LLM 国产化**：
  - 主选 **DeepSeek-V3**（2026 国产 LLM SOC 场景最热门）
  - 备选 Qwen3 / GLM-4 / 文心 4.0
  - 跑分对比：DeepSeek-V3 在中文 IOC / ATT&CK 中文描述上 > GPT-4o（依据 CSDN 2026 / 阿里云 2026 测评）
- **OS 国产化**：麒麟 V10 / UOS
- **DB 国产化**：人大金仓（PG 兼容）/ 达梦（Oracle 兼容）
- **MQ 国产化**：RocketMQ（取代 Kafka，国产生态更广）

**效益**（依据 CSDN 2026 / 国产 LLM 行业横评 / 揭榜挂帅公开评分标准）：
- ✅ **揭榜挂帅国产化合规分项满分**（评审硬性要求）
- ✅ **数据不出境**（国产 LLM 自托管）
- ✅ **DeepSeek-V3 中文场景 > GPT-4**（行业共识）
- ✅ **国产化迁移成本可控**（PG 兼容、PGVector 兼容让达梦/金仓切换几乎零代码）

**不足**：
- ❌ 国产 LLM 工具调用 / function call 能力 < GPT-4o（**关键差距**）
- ❌ 国产化 DB 性能 < PG（部分场景）
- ❌ 国产化生态文档不完善

**与原栈对比**：

| 维度 | GPT-4o + PG（现） | DeepSeek-V3 + 金仓（v3 升级） |
|------|-------------------|-------------------------------|
| 中文场景 | 良好 | **优秀**（> GPT-4） |
| 工具调用 | 强 | **中**（需 prompt 调优） |
| 数据出境 | 需合同约束 | **零**（自托管） |
| 成本 | 高 | **低 30-50%**（国产 API） |
| 国产化合规 | ❌ | **✅** |
| 评审计分 | 0 | **满分** |

**回滚策略**：LLM 抽象层（`backend/llm_enhancer.py`）已支持多 provider；切换 = 改 config；DB 切换 = 改连接串。

---

## 4 · L2 升级项（6 个月内完成 · 竞争力建设 · v3 修正版）

### 4.1 Qdrant Hybrid（v2 不变）

- 同 v2 §4.1；v3 强调：finetune SPLADE 训练数据要"持续追加"（**数据飞轮**，详见 §6.5）

### 4.2 Temporal AI 子工作流（v2 不变）

- 同 v2 §4.2；v3 强调：Temporal 1.30+ 已支持 **Multi-Agent 编排**（与 v3 §6.2 多 Agent 联动）

### 4.3 Paimon Catalog + Iceberg 备选（v2 不变）

- 同 v2 §4.3；v3 加：**Paimon 已支持 Flink 2.3 一等公民**（用 2.3 时无需额外配置）

### 4.4 **零信任 + Agent 调用**（v3 新增 · 2026 RSAC 趋势）

**目标**：让 Agent 调用工具走"零信任授权"路径，避免"Agent 拿到 token 就能调用任何工具"。

**方案**：
- **NIST SP 800-207 零信任架构**：
  - **持续验证**（Continuous Verification）：每次 Agent 调用工具都重新鉴权
  - **最小权限**（Least Privilege）：Agent 默认只能访问白名单资源
  - **微分段**（Microsegmentation）：Agent 调用工具按"工具 + 数据 + 时间"三维度授权
- **SpiceDB / OpenFGA**（授权策略引擎）：
  ```python
  # Agent X 在 09:00-18:00 可调用工具 Y，访问资源 Z
  can_call_agent_x_tool_y = (agent_id == X) AND (time_in(9, 18)) AND (resource_in(Z))
  ```
- **持续审计**：所有 Agent 调用走 OTel + Langfuse（v2 已规划）
- **Token 轮换**：Agent API key 每 15 分钟轮换（避免长期 token 泄漏）

**效益**（依据 CrowdStrike Falcon Zero Trust 2026 / Microsoft Zero Trust SOC 2026 / Palo Alto Prisma SASE 2026）：
- ✅ **符合 2026 行业新基线**（RSAC 2026 共识）
- ✅ **防止 Agent token 泄漏**（避免"一泄漏就全开放"）
- ✅ **满足等保 2.0 / GDPR 审计**（最小权限可证）
- ✅ **支撑 AL3 自治 SOC**（零信任是 AL3 的前提）

**不足**：
- ❌ 每次调用都鉴权 = **性能开销 5-15%**
- ❌ SpiceDB 需自托管（PG 后端）
- ❌ 策略调试比传统 RBAC 复杂

**与原栈对比**：

| 维度 | 4 层 Guard（v1/v2 现） | 零信任 + 5 层 Guard（v3 升级） |
|------|----------------------|-------------------------------|
| 鉴权时机 | 一次 | **每次调用** |
| 权限粒度 | 角色 | **角色 + 时间 + 资源** |
| Token 轮换 | 长期 | **15 分钟** |
| 审计粒度 | 调用 | **调用 + 鉴权过程** |
| 行业基线 | 2024-2025 | **2026 RSAC 共识** |

**回滚策略**：零信任是 `auth_z=v2` flag 切换；旧路径保留。

---

## 5 · L3 升级项（12 个月内完成 · 战略储备 · v3 修正版）

### 5.1 多 Agent 调查 + 攻击图（v2 升级 v3 加 5 Guardrails）

**v2 → v3 关键修正**：
- v2 写 6 角色（CSDN 共识）
- v3 补 **Dropzone AI 5 专家角色映射**（威胁猎手 / 检测工程师 / 取证分析师 / TI 分析师 / 数据架构师）
- v2 写 AL1-AL4 4 级；v3 加 **5 大 Guardrail**（D3 Morpheus APD 2.0 模式）

**5 大 Guardrail（v3 新增 · 关键）**：

| Guardrail | 作用 | 本平台实现 |
|-----------|------|-----------|
| **1. 数据源健康检查** | 每次查询前验证数据源可用 | `backend/connectors/health_check.py` |
| **2. 结论保留** | 证据不足时禁止给"无威胁"结论 | `backend/agents/base.py#should_withhold_verdict` |
| **3. 调查指南** | 用户自定义策略（如"每个 SIEM 查询必须含客户名"） | `backend/agents/investigation_guidelines.yaml` |
| **4. 查询级审计** | 每个 SIEM 查询都记日志，summary 由日志生成 | `backend/audit_trail.py#query_log` |
| **5. 人工 handoff** | Guardrail 触发时，附原因升级到分析师 | `backend/case_manager.py#escalate_with_reason` |

**效益**（依据 D3 Security 2026-08 实战测试，5 场景全过）：
- ✅ **零 false all-clear**（5 个对抗场景，APD 2.0 100% 通过）
- ✅ **审计可证**（查询 summary 与实际查询 100% 匹配）
- ✅ **防止 AI 瞎猜**（证据不足时直接说"无法确认"）

**与原栈对比**：

| 维度 | 6 角色无 Guardrail（v2 现） | 6 角色 + 5 Guardrail（v3 升级） |
|------|---------------------------|-------------------------------|
| AI 瞎猜防护 | ❌ | **✅ 5 道闸** |
| 审计可证 | 部分 | **100% 查询级** |
| 误隔离防护 | 弱 | **强**（证据不足禁止） |
| 行业对标 | CSDN 共识 | **D3 Morpheus APD 2.0 模式** |

### 5.2 标准化 MCP + 2026-07-28 spec 适配（v2 升级 v3 强制）

**v2 → v3 关键修正**：
- v2 写 MCP 2025-11 spec；**v3 升 2026-07-28**（2026-08 当前最新，stateless 革命）
- 2026-07-28 是 breaking change：
  - 移除 `initialize` / `notifications/initialized` 握手
  - 移除 `Mcp-Session-Id` 头
  - 移除协议 session 概念（变 stateless）
  - 新增 `Mcp-Method` / `Mcp-Name` HTTP header
  - 新增 cache hint（`ttlMs` / `cacheScope`）
  - 新增 **MRTR**（Multi Round-Trip Requests，处理 elicitation）
  - 强化 OAuth（CIMD 替代 DCR）
  - 新增扩展框架（reverse-DNS identifiers，Tasks 移到 io.modelcontextprotocol/tasks 扩展）

**v3 适配方案**：
- **升级 MCP SDK** 到支持 2026-07-28 spec 的版本（TypeScript / Python SDK 已发布）
- **抽象层**：保留 v2 写的"spec 抽象层"，但加上"version 协商"（每个请求带 `io.modelcontextprotocol/protocolVersion`）
- **灰度**：v2 的 2025-11 spec path 保留作为"老客户端 fallback"
- **DPoP**（Demonstrating Proof of Possession）：2026 路线图要求，v3 L3 末尾实现

**效益/不足**：v2 已分析，v3 加"**2025-11 spec 部署在 6 个月内会被新 SDK 强制要求升级**"。

**与原栈对比**：

| 维度 | 自建 JSON-RPC（v1/v2 现） | MCP 2025-11（v2 升级） | MCP 2026-07-28（v3 升级） |
|------|--------------------------|----------------------|------------------------|
| 协议 | 自定 | MCP 2025-11 | **MCP 2026-07-28** |
| Session | 需自管 | 协议层 session | **stateless**（无 session） |
| HTTP 路由 | 自定 | 协议协商 | **header 路由**（WAF 可识别） |
| Caching | 无 | 无 | **ttlMs / cacheScope hint** |
| 扩展 | 无 | 实验性 | **正式扩展框架** |
| OAuth | 自建 | OAuth 2.1 | **OAuth + DPoP** |
| 维护期 | N/A | 6 个月内必升级 | **当前主流** |

### 5.3 **Prompt Injection 防御体系**（v3 新增 · OWASP 2025 LLM Top 10 第一）

**目标**：防止攻击者在日志 / 邮件 / 工单中藏指令，致 SOC Agent 误判。

**5 招防御（v3 设计）**：

1. **输入清洗与隔离**：
   - 所有"用户可控输入"（日志字段 / 邮件标题 / 工单描述）走独立 token 上下文
   - 不与系统 Prompt 共用 context window
   - 实施：`<user_input>` 标签包裹，prompt template 强约束

2. **权限分级（与 §4.4 零信任联动）**：
   - Agent 默认只读，不能直接执行高危动作（隔离/封禁/删除）
   - 高危动作必须 HITL 审批
   - LLM "建议权" 与 "执行权" 分离

3. **结构化输出约束**：
   - 强制 Agent 输出 JSON schema（`tool_call` / `verdict` / `confidence` / `evidence`）
   - 字段不匹配 = 直接 reject
   - 防止"Agent 被诱导输出'关闭所有告警'"等结构

4. **Prompt 红蓝测试（v3 联动 §6.3）**：
   - 定期跑注入攻击模拟（OWASP LLM Top 10 攻击向量）
   - 失败案例入库，作为 regression test

5. **审计 + 检测**：
   - Langfuse 记录所有 prompt + completion
   - 用 LLM-as-a-Judge 检测"异常指令模式"（如"ignore previous"、"你是管理员"等）
   - 异常告警升级到安全团队

**效益**（依据 OWASP 2025 / Cloudflare AI Gateway 2026 / Microsoft Prompt Shield 2026）：
- ✅ **防 OWASP 2025 第一风险**（已识别 5+ 起公开 SOC 误判事故）
- ✅ **满足 RSAC 2026 评审标准**（Prompt 注入测试是 2026 部署前必检）
- ✅ **降低 LLM "被利用"风险**（避免 Agent 变攻击者工具）

**不足**：
- ❌ 输入清洗可能误伤正常数据（**需调优阈值**）
- ❌ LLM-as-a-Judge 检测本身需要 LLM 调用（成本 +5%）
- ❌ 新型注入方式持续出现（**持续红蓝测试是刚需**）

**与原栈对比**：

| 维度 | 无防御（v1/v2 现） | 5 招防御（v3 升级） |
|------|------------------|-------------------|
| 输入清洗 | 无 | **✅ token 隔离** |
| 权限分级 | Agent 可执行高危 | **HITL 强制** |
| 结构化输出 | 弱 | **JSON schema 强约束** |
| 红蓝测试 | 无 | **OWASP Top 10 模拟** |
| 异常检测 | 无 | **LLM-as-a-Judge** |

### 5.4 **Agentic SOAR 编排工具选型**（v3 新增）

**目标**：从"自建 Temporal workflow"演进到"行业 Agentic SOAR 编排工具"。

**v3 选型对比**（依据 Torq 2026-07-28 SOC Brain / Tines AI / Splunk AI Agent Studio 2025-09）：

| 工具 | 自主级别 | 多 Agent | MCP 2026-07-28 兼容 | 集成数 | 适合场景 |
|------|---------|---------|---------------------|--------|---------|
| **Torq HyperAgents** | AL3 | ✅ 5 角色 | ✅ | 800+ | 大型 SOC |
| **Tines AI** | AL2 | ✅ 4 角色 | ✅ | 600+ | 中型 SOC |
| **Splunk AI Agent Studio** | AL2 | ✅ 5 角色 | ✅ | 300+ | Splunk 生态 |
| **CrowdStrike Charlotte Workflows** | AL2-3 | ✅ 5 角色 | ✅ | Falcon 生态 | CrowdStrike 生态 |
| **Microsoft Security Agent Studio** | AL2 | ✅ 6 角色 | ✅ | 800+ | M365 生态 |
| **D3 Morpheus** | AL3-4 | ✅ 5 角色 + 5 Guardrail | ✅ | 800+ | MSSP 首选 |
| **本平台 Temporal 自建** | AL1-2 | ✅ 6 角色 | 需升级 | 自建集成 | 高度定制 |

**v3 建议**：
- **不替换 Temporal**（本平台已自建 4 层 Agent 编排）
- **采纳 D3 Morpheus 的"5 Guardrail"模式**（v3 §5.1）
- **采纳 Torq HyperAgents 的"租户级 memory"模式**（v3 §6.5 数据飞轮）
- **不引入商业 SOAR**（避免 vendor lock-in；但预留 MCP Server 接口供未来接入）

**效益**：
- ✅ **不增加 vendor 风险**（保持自建）
- ✅ **吸收行业最佳实践**（5 Guardrail / 租户 memory）
- ✅ **MCP 兼容 = 未来可接**（不锁定）

**不足**：
- ❌ 商业 SOAR 的"开箱即用 800 集成"优势失去
- ❌ 自建持续维护成本

---

## 6 · v3 全新升级项（L0 补漏 + 长期建设）

### 6.1 **信创合规深度（接 §3.5 启动）**

- v3 §3.5 启动国产化基线；v3 §6.1 在 L3 完成"全栈国产化 POC"
- 重点：**国产 LLM 工具调用能力补齐**（与 GPT-4 差距是关键）
- 与 5 Guardrail 联动：信创 LLM 也必须走 Guardrail 体系

### 6.2 **MCP 2026-07-28 完整迁移**

- v3 §5.2 已规划；v3 §6.2 加"DPoP 实现 + MRTR 处理 + 扩展框架使用"
- 关键是：**所有自建 MCP server 升级到 2026-07-28 SDK**

### 6.3 **Agent 红蓝测试平台**（v3 新增 · 必检项）

**目标**：Agent 部署前必过 5 个对抗场景（D3 Morpheus 模式）。

**5 个必过场景**：
1. **数据源断连测试**：切断 Sentinel 鉴权，Agent 不得给出"无威胁"结论
2. **数据源漂移测试**：CrowdStrike API 返回部分结果，Agent 必须 flag
3. **查询审计测试**：审计 Agent 实际查询 vs 报告查询 100% 匹配
4. **多租户隔离测试**：跨租户数据不得混入
5. **错误恢复测试**：恢复数据源后 Agent 重新查询并得出正确结论

**实施**：
- 用 `pytest` + Atomic Red Team 模拟
- CI 流水线集成（每次 PR 必过 5 场景）
- 失败案例入库，季度回归

**效益**（依据 D3 Morpheus 2026-08 测试报告）：
- ✅ **生产前必检**（避免"上线就出事"）
- ✅ **审计可证**（5/5 通过可作为合规证据）
- ✅ **持续改进**（失败案例驱动代码修复）

**与原栈对比**：

| 维度 | 无红蓝测试（v1/v2 现） | 5 场景红蓝（v3 升级） |
|------|----------------------|---------------------|
| 部署风险 | 高 | **低** |
| 审计证据 | 无 | **5/5 通过** |
| 故障注入 | 手动 | **CI 自动化** |

### 6.4 **数据飞轮系统化**（v3 新增 · D3 租户 memory 模式）

**目标**：让"分析师反馈 → 训练集 → 下一版更准"成为系统级能力。

**4 阶段飞轮**（依据 CrowdStrike 公开数据：飞轮让准确率 80% → >98%）：

1. **收集阶段**：
   - 分析师对 Agent 结论 👍/👎 + 注释（v2 §9.4 已有）
   - Langfuse 自动记录"决策 → 结果"对

2. **标注阶段**：
   - LLM-as-a-Judge 自动评估（v2 §2.0 L0-2 已有）
   - 人工 spot-check（每周 50 条抽样）
   - 误报聚类（同类误报自动打 tag）

3. **训练阶段**：
   - **小模型持续微调**（LoRA，14B 模型）
   - 每周 1 次微调
   - A/B 测试新模型 vs 旧模型

4. **部署阶段**：
   - 新模型先 shadow 模式跑 1 周
   - 准确率 > 老模型 +2% 才切默认
   - Langfuse 持续监控

**效益**（依据 CrowdStrike 2026 Global Threat Report / D3 Morpheus tenant memory / Charlotte AI >98% 准确率）：
- ✅ **准确率持续提升**（CrowdStrike 公开数据：80% → >98%）
- ✅ **租户级 memory**（不跨客户，符合 MSSP / 政府合规）
- ✅ **D3 Morpheus 模式复用**

**不足**：
- ❌ 训练成本（GPU 持续运行）
- ❌ 冷启动困难（需 30+ 天历史数据）
- ❌ 数据飞轮是"组织能力"而非纯技术

**与原栈对比**：

| 维度 | 反馈循环（v2 §9.4 简版） | 数据飞轮系统化（v3） |
|------|------------------------|---------------------|
| 收集 | 手动 | **系统化 + 自动** |
| 标注 | 人工 | **LLM + 人工 spot-check** |
| 训练 | 无 | **每周 LoRA** |
| 部署 | 一次性 | **A/B 持续** |
| 准确率 | 静态 | **持续提升** |

### 6.5 **Zero Trust for Agents（接 §4.4 深化）**

- v3 §4.4 启动零信任 + 5 层 Guard；v3 §6.5 完成 DPoP + 持续验证 + 策略引擎（SpiceDB）

---

## 7 · 升级路线图（v3 重排：含 7/14/30 天超短期）

| 时段 | 超短期（7/14/30 天） | L1（3 月） | L2（6 月） | L3（12 月） |
|------|---------------------|-----------|-----------|------------|
| **D+7** | OCSF 1.9 接入 / Langfuse 单点 / Tier 1 分诊 POC / MCP 2026-07-28 兼容测试 | — | — | — |
| **D+14** | NIST r3 5 个核心 Playbook / UEBA-ML 启动训练 / 信创合规清单 | — | — | — |
| **D+30** | v2 L0 全量 + **MCP 2026-07-28** 升级 + **信创合规基线** + **Prompt Injection 第一招** | UEBA-ML 训练 | Temporal AI 子工作流 | 多 Agent POC + 5 Guardrail |
| **M+1-2** | — | Flink 1.20 LTS + 信创 LLM 试点 | Qdrant SPLADE finetune | 5 Guardrail 实现 + 数据飞轮启动 |
| **M+2-3** | — | **Flink 2.3 LTS** 升级（蓝绿）/ UEBA-ML 上线 | OTel eBPF 接入 | Agent 红蓝测试平台 + 知识图谱 POC |
| **M+3-4** | — | Flink CDC 3.4 试点 | Qdrant Hybrid A/B | 多 Agent shadow 模式 + 5 Guardrail 全量 |
| **M+4-6** | — | Flink CDC 扩展 + 信创 LLM 全量 | **Paimon Catalog 上线** + 零信任（§4.4） | **MCP 2026-07-28** 完整迁移 + Agentic SOAR 编排 |
| **M+6-9** | — | — | 多 Agent 编排 + Prompt Injection 5 招 | DPoP + 零信任深化 + 数据飞轮自动化 |
| **M+9-12** | — | — | — | GNN 异常路径检测 / 自治 SOC AL3 / 信创全栈 POC |

> **关键节点**：D+7（评审展示）/ D+30（v2 L0 复盘）/ M+3 / M+6 / M+9 对照 2026-Q4 SOC 行业新动向。

---

## 8 · 风险与"不升级的代价"（v3 在 v2 基础上加 5 条新风险）

### 8.1 升级风险（v3 增 5 条）

| 风险 | 等级 | 缓解 |
|------|------|------|
| v2 的 12 条风险（v2 §7.1） | 同 v2 | 同 v2 |
| **MCP 2026-07-28 是 breaking change**（v3 新增） | 高 | 灰度 + 抽象层 + 老 SDK fallback 6 个月 |
| **信创 LLM 工具调用能力 < GPT-4**（v3 新增） | 中 | prompt 调优 + 双 LLM 路由（重要任务 GPT-4 + 普通任务国产） |
| **零信任鉴权性能开销 5-15%**（v3 新增） | 中 | 缓存 + 鉴权合并批处理 |
| **Agent 红蓝测试需要持续投入**（v3 新增） | 中 | CI 自动化 + 季度回归 |
| **数据飞轮需要组织能力配套**（v3 新增） | 中 | 设立 Agent Engineer 岗位（v2 已提） |

### 8.2 不升级的代价（一年内 · v3 增 3 项）

v2 的 13 项继续保留，v3 加 3 项：

- 不用 **MCP 2026-07-28 spec**：客户端升级后本平台 MCP 部署断连；OAuth 不兼容 DPoP，新一代 Agent 无法接入
- 不用 **信创合规**：揭榜挂帅评审计分项 0 分；政府 / 国企客户无投标资格
- 不用 **5 Guardrail / 数据飞轮**：D3 Morpheus / Torq 已成行业基线，缺这两项 = 落后一代

---

## 9 · 验证与回滚机制（v3 在 v2 基础上加 3 条新基准）

### 9.1 升级期验证流程（v3 增 3 条基线）

v2 的 9 条继续保留，v3 加：

10. **v3 新增 · 信创合规自检**：DeepSeek-V3 + 麒麟 OS + 人大金仓，全链路国产 POC 通过
11. **v3 新增 · Agent 红蓝 5 场景**：CI 必过 5/5
12. **v3 新增 · 数据飞轮指标**：飞轮运行 30 天后，准确率提升 ≥ +2%

### 9.2 升级期监控指标（v3 增 3 个维度）

- 升级前 baseline：+ **MCP 2026-07-28 兼容性** / **信创 LLM 准确率** / **数据飞轮每周准确率变化**

---

## 10 · 配套升级（治理与流程 · v3 增量）

v2 §9 的 4 项（DaC / Playbook / 紫队 / 反馈循环）继续保留，v3 加：

### 10.1 **Agent 部署审批流程**（v3 新增）

- 任何 Agent 上生产前必过 5 Guardrail 红蓝测试
- 提交"Agent 部署申请单"（含风险评估 + 5/5 测试报告 + HITL 设计）
- 安全负责人 + SOC 负责人双签

### 10.2 **数据飞轮运营机制**（v3 新增 · 接 §6.4）

- 设 Agent Engineer 岗位（专职）
- 每周飞轮会议：误报聚类、TTP 新趋势、新模型 A/B 结果
- 季度飞轮报告（给 CISO）

### 10.3 **国产化合规专项**（v3 新增 · 揭榜挂帅必检）

- 季度国产化进度报告
- 国产 LLM 工具调用能力补齐专项
- 国产 DB 性能优化专项

---

## 11 · 总结（v3 重写）

本轮 v3 升级的核心判断：

1. **v2 已扎实，但 v3 在 5 维度做了关键修正**：Flink 2.2→2.3、MCP 2025-11→2026-07-28、OCSF 1.8.0→1.9、AL 4 级→5 Guardrail、99% 降噪 / 90% MTTR 真实数据替换。
2. **v3 新增 6 项 v2 漏掉的升级**：信创合规、零信任、Prompt Injection 防御、Agent 红蓝测试、数据飞轮、Agentic SOAR 编排——**这些是揭榜挂帅评审 2026 新加的"必检项"**。
3. **v3 路线图加"7/14 天超短期"**：让揭榜挂帅评审看到"7 天可演示增量、14 天可中期考核、30 天可 L0 全量"——**评审节奏对齐**。
4. **v3 与 v2 的最大差异**：
   - **5 个事实修正**（不修 = 落后）
   - **6 个新增项**（不补 = 评审失分）
   - **数据飞轮 + 5 Guardrail** 系统化（v2 简略提，v3 详细设计）
   - **信创合规**（v2 完全没提，v3 必检）
   - **零信任 for Agents**（v2 没提，v3 必补）
   - **Agent 红蓝测试**（v2 没提，v3 部署前必过）

**v3 的验证基础**：
- 20 项升级中，**14 项**有 v2 之外的 2026-08 最新数据验证（D3 Morpheus APD 2.0 / Torq SOC Brain 2026-07-28 / Cloudflare MCP v2 / Flink 2.3.0 GA / OCSF v1.9 / RSAC 2026 国内案例 / 数说安全 294 页报告）
- **6 项**沿用 v2（OCSF / Langfuse / Tier 1 分诊 / NIST r3 / Qdrant / Paimon），但 v3 补最新数据

**给揭榜挂帅评审的"7 天可演示"清单**（v3 新增）：
1. OCSF 1.9 字段映射（用 Datadog OCSF 工具验证）
2. Langfuse 单点接入（演示 LLM 全链路可回放）
3. Tier 1 分诊 Agent POC（100 条历史告警混淆矩阵）
4. MCP 2026-07-28 兼容性测试（证明前瞻性）
5. 信创合规清单（证明"能国产化"）
6. Agent 红蓝测试 1 场景（数据源断连测试，证明防护）
7. 数据飞轮基线（证明有"学习力"）

---

## 附录 A · 与 v2 文档的逐项对照（v3 新增）

| 升级项 | v2 章节 | v3 章节 | 变更摘要 |
|--------|--------|--------|---------|
| 流处理内核 | v2 §3.1 | v3 §3.1 | **目标版本 2.2 → 2.3 LTS**（2.3 2026-06-23 GA） |
| 业务事件 CDC | v2 §3.2 | v3 §3.2 | **CDC 3.0 → 3.4.0**（2026-07-09） |
| OTel + eBPF | v2 §3.3 | v3 §3.3 | 加 CIS Benchmark 自检 |
| UEBA-ML | v2 §3.4 | v3 §3.4 | 加可解释 AI（SHAP/LIME） |
| **信创合规** | （v2 无） | **v3 §3.5** | **新增**（揭榜挂帅评审计分项） |
| Qdrant Hybrid | v2 §4.1 | v3 §4.1 | 加数据飞轮联动（§6.4） |
| Temporal AI | v2 §4.2 | v3 §4.2 | 加 Multi-Agent 编排 |
| Paimon 湖仓 | v2 §4.3 | v3 §4.3 | 加 Flink 2.3 一等公民说明 |
| **零信任 + Agent** | （v2 无） | **v3 §4.4** | **新增**（2026 RSAC 趋势） |
| 多 Agent 调查 | v2 §5.1 | v3 §5.1 | **+ 5 Guardrail**（D3 Morpheus 模式）+ Dropzone 5 专家角色映射 |
| 标准化 MCP | v2 §5.2 | v3 §5.2 | **spec 2025-11 → 2026-07-28** + DPoP + MRTR |
| **Prompt Injection 防御** | （v2 无） | **v3 §5.3** | **新增 5 招**（OWASP 2025 LLM Top 10 第一） |
| **Agentic SOAR 编排** | （v2 无） | **v3 §5.4** | **新增选型对比**（不自建商业 SOAR 但吸收最佳实践） |
| 配套升级 | v2 §9 | v3 §10 | 加 Agent 部署审批 + 数据飞轮运营 + 国产化合规专项 |
| **超短期路线** | （v2 无） | **v3 §2** | **新增 7/14 天**（评审节奏对齐） |

---

## 附录 B · 参考资料（v3 在 v2 基础上加 12 个新来源）

### v2 已列（保留）
1-37：见 v2 文档附录 B（37 个来源）。

### v3 新增（2026-Q3 截止）
38. endoflife.date / eosl.date. *Apache Flink End of Life Dates*. 2026-08-13 刷新（Flink 2.3.0 2026-06-23 GA）。
39. Cloudflare Blog. *The next generation of MCP*. 2026-07-28（MCP 2026-07-28 spec 全面解读）。
40. TrueFoundry. *MCP 2026-07-28 Ships: Revisiting Apps, Tasks, and Gateway Governance Under the Largest Protocol Revision Since Launch*. 2026-08.
41. AgenticPlug. *MCP 2026-07-28: What Changed in the Stateless Spec Rewrite*. 2026-08.
42. Octane Solutions. *MCP 2026-07-28: The Shift Toward Stateless, Scalable AI Agent Infrastructure*. 2026-08.
43. Model Context Protocol Official. *Specification 2026-07-28 / Roadmap*. 2026-07-28.
44. D3 Security. *The 10 Best Torq Alternatives in 2026: Agentic SOC Platforms Compared After the SOC Brain Launch*. 2026-08.
45. D3 Security. *The Agentic SOC That Refuses to Guess: Morpheus APD 2.0*. 2026-08（5 Guardrail 实战测试报告）。
46. D3 Security. *The Best Agentic SOC Platforms for MSSPs in 2026: Multi-Tenancy, Margin Math, and a Full Comparison*. 2026-08.
47. Anomali. *OCSF, Explained: Why a Common Schema Changes How Security Teams Work*. 2026-07（OCSF 现状 + v1.9 评估）。
48. AppScale Blog. *Your SIEM Bill Is a Data Architecture Problem, Not a Security One*. 2026（OCSF v1.9 + tiered retention 模式）。
49. CSDN. *2026，被认为是 Agentic SOC 的真正元年*. 2026-08（国内 6 厂商 + 99% 降噪 / 90% MTTR 数据）。
50. 数说安全. *2026 Agentic SOC: 从告警洪流到自主闭环的安全运营新范式*. 2026（294 页报告，66 厂商问卷 + 11 场 Briefing）。

---

**文档版本**：v3.0（2026-08-25）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-11-25（M+3）对照 2026-Q4 SOC 行业新动向
**前置版本**：
- v2.0（`2026-q3-tech-stack-upgrade-v2.md`，2026-08-25）
- v1.0（`2026-q3-tech-stack-upgrade.md`，2026-08-25）
