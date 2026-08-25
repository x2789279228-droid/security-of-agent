# 技术栈升级方案 v4（2026-Q3 · 升级轮 v4）

> **本 v4 在 v3（`2026-q3-tech-stack-upgrade-v3.md`，2026-08-25 15:02）基础上**，做了 4 类动作：
> 1. **修正 v3 的 3 个事实错误**（Flink 1.19 EOL 时间、CDC 最新版本、Flink 2.3 早期 connector 覆盖不全）
> 2. **纠正 v3 的 3 项"未落地"误判**（phishing LLM 维度、IOC 匹配器、EDR 接入层都已实装）
> 3. **补 v3 漏掉的 6 大行业反例**（生产教训，比"再加新项"更值钱）
> 4. **补 v3 漏掉的 4 个行业新趋势**（Apache Flink Agents 0.3.0 / Security Data Lake 模式 / 威胁狩猎 Agent / 调查辅助 Agent 独立场景）
>
> v1/v2/v3 完整保留作为历史快照；本 v4 是"建议执行版 v4"——**v4 不重写 v3 内容，专注 v3 的盲区与修正**。

---

## 0 · TL;DR：v3 → v4 变更速览

| 维度 | v3（2026-08-25 三版） | v4（本轮） | 变更原因 |
|------|----------------------|-----------|---------|
| **Flink 1.18 EOL** | 写"1.18 已 EOL（2026-03-24）" | **修正：1.19 也已 EOL（2026-07-01）；本项目 pom.xml 实际是 1.19.3 → 比 v3 评估更落后 1 个版本** | endoflife.date 2026-08-13 刷新：1.19 LTS EOL 2026-07-01 |
| **Flink CDC 版本** | 写 3.4.0（2026-07-09） | **升 3.6.0**（2026-03-30 GA，兼容 Flink 1.20.x 和 2.2.x） | 官方 downloads 页：3.6.0 已是 latest stable，3.4.0 已非主推 |
| **Flink 2.3 升级风险** | v3 简化假设"2.3 升级路径" | **加"connector/operator 覆盖不全"反例**：Flink Kafka Connector 5.0.0 兼容 2.1/2.2.x，**2.3 早期没有 5.0 配套**；Operator 1.15.0 兼容 2.1/2.2，**2.3 早期也没明确覆盖** | 千万级 QPS 实战 2026 / Apache Flink downloads：生产升级必须按"核心+connector+operator+Java"整体评估 |
| **phishing LLM 维度** | v3 §3.4 评估"未落地" | **修正：已实装**（`phishing_guard/scoring.py::aggregate_with_llm` + `phishing_guard/llm_dimension.py`，2026-08-24/25 提交；P0.S 升级完成） | 直接读代码核实，v3 误判 |
| **EDR 接入层** | v3 隐含"未接入" | **修正：已实装**（`edr_fusion/edr_adapter.py` 2026-08-25 提交；Kafka + HTTP + 商业 EDR 预留 + 跨源关联每分钟 1 次） | 直接读代码核实 |
| **IOC 匹配器** | v3 没提 | **新增：已实装**（`threat_intel/ioc_matcher.py` 2026-08-25 提交；精确+CIDR+通配，5min 内存缓存，命中 metrics 计数） | 直接读代码核实 |
| **6 大反例** | v3 完全没提 | **新增**：rebalance+keyBy 不解热 Key、Unaligned Checkpoint 不修反压、ClickHouse At-Least-Once、Nacos 不能在线改窗口、Qdrant hybrid 反而掉分（nDCG 0.405 < finetune 0.413）、L1 减员真实数字 24→8 非 50→5 | 千万级 QPS 实战 / Qdrant 2026 benchmark Part 3-4 / CSDN 2026 综述 |
| **4 个新趋势** | v3 完全没提 | **新增**：Apache Flink Agents 0.3.0（2026-06-19 GA，可在 Flink 内做 LLM Agent）/ Security Data Lake 模式 hot-warm-cold 三层（AWS Security Lake 2023 GA）/ 威胁狩猎 Agent 独立场景 / 调查辅助 Agent 独立场景 | 千万级 QPS 实战 / AppScale Blog 2026 / CSDN 2026 |
| **本项目基线** | v3 完全没量化 | **新增**：Flink 1.19.3（落后 4 个大版本）、React 19.2.7/Vite 7.3.6（前沿）、Temporal 已实装（1.24-1.x）、11 条 Sigma 规则、46 个 .j2 模板、195 单测通过、v2 已在 6 个事实修正 / 6 个新增项 | 直接读代码/配置核实 |
| **集成架构图** | v3 无 | **新增**：v4 §6 给"v3 升级项 + v3 漏项 + 现有实装项"三色集成图 | 评审需要"一眼看懂整体方案" |
| **20 项落地度评估** | v3 无 | **新增**：v4 §8 逐项标注"本项目已实装 / 部分实装 / 待启动" | 评审需要"哪些不用做 / 哪些在做了 / 哪些没做" |
| **总升级项** | 20 项 | **24 项**（v3 的 20 + 4 个新增：Apache Flink Agents / Security Data Lake / 威胁狩猎 Agent / 调查辅助 Agent） | 4 个新趋势 + v3 漏项 |

> **v4 核心定位**：v3 已扎实，但 v3 是"再加新项"的逻辑，v4 是"修正 + 落地 + 反例"——**v4 让方案从'概念清单'变成'可执行路线'**。

---

## 1 · 5 维度交叉验证的 4 个新发现（v3 漏掉的）

按 memory 中 5 维度交叉验证清单，对 v3 重新做 2026-08-25 末轮核验：

### 1.1 版本谱终态（endoflife.date / 官方 downloads）

| 组件 | v3 评估 | v4 重新核验 | 真实情况 |
|------|--------|------------|---------|
| **Flink 1.18** | "已 EOL（2026-03-24）" | ✅ 对（eosl.date 2026-08-13 确认） | — |
| **Flink 1.19** | v3 完全没提 | **EOL 2026-07-01**（1.19 LTS 也已停更） | **本项目 pom.xml 是 1.19.3 → 比 v3 评估更落后 1 个版本** |
| **Flink 2.3** | "最新 LTS" | ✅ 对（2026-06-25 GA） | — |
| **Flink CDC** | "3.4.0" | **最新 3.6.0**（2026-03-30 GA，兼容 1.20.x + 2.2.x） | v3 落后 1 个小版本 |
| **Flink Kafka Connector** | v3 没提 | **5.0.0 兼容 2.1.x/2.2.x；2.3.x 早期没有 5.0 配套** | 关键反例：升级 2.3 不能同步升 connector |
| **Flink Kubernetes Operator** | v3 没提 | **1.15.0 兼容 2.1.x/2.2.x；2.3.x 早期覆盖未明** | 同上 |
| **Flink ML** | v3 没提 | **2.3.0**（2023-07-01，兼容 1.17.x） | 2026 行业 UEBA-ML 可直接用 Flink ML |
| **Apache Flink Agents** | v3 完全没提 | **0.3.0 Preview**（2026-06-19 GA，兼容 1.20/2.0/2.1/2.2） | **v4 必报新趋势**（详见 §4.1） |
| **React** | "React 19" | **19.2.7**（2026 主流 ✅） | — |
| **Vite** | v3 没提 | **7.3.6**（2026 主流 ✅） | — |
| **Temporal** | "升级 1.30+" | **本项目已实装 temporalio 1.24-1.x**，默认 `temporal_enabled=true`（docker-compose.yml 第 282-285 行） | v3 误以为"从无到有"，实际"已部署→升级" |
| **Qdrant 镜像** | v3 没提 | **`qdrant/qdrant:latest`**（应锁定版本！） | v4 必报：latest 标签生产风险 |
| **Kafka 镜像** | v3 没提 | `confluentinc/cp-kafka:7.6.0`（2024-2025 主推） | 当前 OK，但 Kafka 4.0 已 GA（2024-07） |

**v4 修正建议**：
- v3 §3.1 改为 **"1.19.3 → 1.20 LTS → 2.3 LTS（跳 2.0/2.1/2.2）"**——更准确反映本项目当前状态
- 升级路径必须 **"先升 1.20 LTS（短过渡）+ 紧跟 2.3 LTS（最终目标）"**，**1.20 LTS 期间可以同步升 connector/operator 到 5.0/1.15**（覆盖矩阵更稳）
- **2.3 升级风险提示**：核心到 2.3 但 connector/operator 可能仍用 2.2 配套，**这是行业 2026-Q3 真实痛点**（不是 1.18→1.20 那种"全家桶齐步走"）

### 1.2 协议 spec 版本号

| 协议 | v3 评估 | v4 重新核验 | 真实情况 |
|------|--------|------------|---------|
| **MCP spec** | 2026-07-28 | ✅ 对（Cloudflare / byteiota / Octane 三方报道一致） | — |
| **OCSF** | v1.9 范围 | ✅ 对（Anomali / AppScale / AWS 2026 评估一致） | — |
| **W3C Trace Context** | v3 提"OTel SDK 标准 trace" | ✅ 对，**MCP 2026-07-28 spec 同时把 W3C Trace Context 标准化在 `_meta`**（SEP-414） | **v4 必报**：`Mcp-Method` + `Mcp-Name` header + W3C Trace Context 在 MCP 层打通 = 端到端 trace 一次到位 |
| **CIMD** | v3 没提 | **Client ID Metadata Documents** 替代 OAuth DCR（2026-07-28 spec） | 揭榜挂帅信创场景下，CIMD 比 DCR 更适合国产 OAuth（OIDC） |
| **ClickHouse At-Least-Once** | v3 没提 | **官方 Flink Sink 当前仍 At-Least-Once**（2026 现实） | **本项目用 PG，未用 ClickHouse，影响小；但未来要切 ClickHouse 时 v4 必报** |

### 1.3 AI Agent GA 时间线

v3 已识别：D3 Morpheus APD 2.0 / Torq SOC Brain 2026-07-28 / Conifers CognitiveSOC / Charlotte AI Agentic / Microsoft Security Copilot / Splunk AI Agent Studio / Palo Alto Cortex AgentiX / SentinelOne Purple AI。

**v4 新增 4 个 2026-Q3 趋势**（详见 §4）：
- **Apache Flink Agents 0.3.0**（2026-06-19 GA，Apache 官方做 Flink 内 LLM Agent）
- **Conifers CognitiveSOC**（$25M Series A from SYN Ventures 2025-01，2-4h tenant onboarding）
- **Tines AI Native**（新一代 SOAR）
- **Prophet Security**（mid-market multi-agent mesh）

**反例警示**：
- v3 写"国内 RSAC 2026 实测 L1 50→5 人"过于激进。CSDN 2026 综述真实案例：**"2025 某大型金融机构 SOC, Tier 1 从 24 压到 8, 转做 Agent 质量监督; 同时新增 5 个 Agent Engineer 岗位"**——24→8（-67%）是真实数字，50→5（-90%）是行业 PPT 数字。
- v4 应取更保守的 **"L1 减员 60-70%，新增 Agent Engineer 岗位（占总 SOC 20-30%）"** 作为 ROI 基线。

### 1.4 行业量化基线

v3 引用的数字：99% 降噪 / 90% MTTR / 80% → >98% 数据飞轮 / 50→5 L1 / MTTD 197d→28d / Charlotte AI 70% 减人工。

**v4 校准**：
- **MTTD 197d→28d**（Gartner 2025 via Cynet/Securonix）：✅ 行业一致
- **MTTR 自动化省 108d**（IBM 2025 breach lifecycle 241d→133d）：✅ 行业一致
- **99% 降噪**：v3 引用 RSAC 2026 国内案例——**这是厂商自报数字**，实际 D3 Morpheus 公开数据是"**95% alerts auto-investigated in <2min at L2+ depth**"（D3 Jul 2026 客户实测）。**v4 取 95% 为基线，99% 为上限**
- **80% → >98% 数据飞轮**：CrowdStrike 公开数据 ✅
- **L1 50→5**：**反例**——真实案例 24→8（-67%）。**v4 取 60-70% 减员 + Agent Engineer 新增**
- **本项目基线**（v3 缺！v4 必报）：
  - 当前 11 条 Sigma 规则
  - 当前 8 角色 / 4 层 Agent 编排
  - 195 单元测试通过（2026-08-24 验证）
  - 46 个 .j2 模板（v3 修正后）
  - 12 个 PySigma 规则 + 11 条 legacy 兜底
  - 实际 MTTD/MTTR 数字未量化（**v4 必报：建立基线度量**）

### 1.5 行业教训反例（**v4 核心新增**）

> 这是 v4 相对 v3 最关键的差异化价值——**v3 几乎全是"应该加什么"，v4 把"哪些不该加 / 哪些会踩坑"说清楚**。

**反例 1：Flink `rebalance() + keyBy()` 不能解决热 Key**

来源：千万级 QPS 实战 2026（v4 必报）
```
stream.rebalance().keyBy(productId)  ← rebalance 只在 keyBy 前生效
```
- **rebalance 只能让 keyBy 前的数据均匀分发**
- **keyBy 后相同 Key 仍进同一 Subtask**——爆款商品仍由 1 个并行实例处理
- **正确做法**：确定性加盐 + 两阶段聚合（按 `eventId.hashCode() % shardCount` 分片，二阶段合并）
- **v4 影响**：本项目 sigma_hit 聚合若按 srcIp 分组，受 DDoS 攻击时单 TM CPU 打满——v4 启动 "热 Key 监测 + 自动分片"

**反例 2：Unaligned Checkpoint 不修反压**

来源：Apache Flink 2.3 Checkpoint 文档
- Unaligned Checkpoint 让 Barrier 绕过排队数据，**降低反压下 Checkpoint 等待**
- 但 **不会修复**：ClickHouse 写入慢 / 热 Key CPU / 序列化慢 / 外部接口超时 / Kafka 分区不足
- **正确顺序**：定位反压源头 → 优化瓶颈算子 → 启 Buffer Debloating → 评估 Unaligned Checkpoint → aligned timeout fallback
- **v4 影响**：本项目现有 Flink 作业若启 Unaligned Checkpoint 但不解决反压根因，Checkpoint 仍超时——v4 启动"反压根因自检"

**反例 3：Qdrant Hybrid 检索反而掉分**

来源：Qdrant 2026 电商检索 benchmark Part 3-4
- **finetune SPLADE 单独 nDCG = 0.413**
- **hybrid（dense + SPLADE）nDCG = 0.405**（hybrid 反而掉 0.008）
- **正确做法**：**先 finetune sparse 模型**，**A/B 测试**确认 hybrid 优于单一模式后**才**切换
- v3 §4.1 提了"先 finetune 再 hybrid"但**没有警告"hybrid 可能掉分"**——v4 强调
- **v4 影响**：本项目 RAG 检索升级必须 A/B 测试，禁止"默认上 hybrid"

**反例 4：Nacos 不能在线改标准窗口大小**

来源：千万级 QPS 实战 2026
- 标准 DataStream Window 在 JobGraph 构建时已确定
- **window.size / watermark.delay / allowedLateness** 不能通过 Nacos 运行时修改
- 改这些参数需要：Savepoint → 更新配置 → 从 Savepoint 恢复
- **可动态改的只有**：黑白名单 / 热 Key 列表 / 维度映射 / 告警阈值 / 业务过滤规则
- **v4 影响**：本项目未来要做"动态窗口"必须自实现 KeyedProcessFunction + MapState + EventTime Timer，**不是配 Nacos**

**反例 5：ClickHouse Flink Sink 仍 At-Least-Once**

来源：ClickHouse 官方 2026
- 即使 Flink Checkpoint 保证"内部状态 Exactly-Once"，**外部 Sink 仍需幂等设计**
- **ClickHouse 官方 Flink Sink 当前仍 At-Least-Once**
- **必须**在表模型层用 `ReplacingMergeTree(revision)` + `argMax()` 取最新
- **v4 影响**：本项目暂未用 ClickHouse（用 PG），但**未来扩展湖仓时**v4 必报：ClickHouse 写入必须 resultId + revision 幂等

**反例 6：MCP 2026-07-28 错误码改了**

来源：byteiota 2026 / Cloudflare Blog
- **-32002 → -32602**（Invalid parameters 错误码变了）
- 硬编码 -32002 的代码会"静默不再匹配"
- **错误码 bug 只在错误条件下触发**，**生产难发现**
- **v4 影响**：v3 适配 MCP 2026-07-28 spec 时只提了"移除 initialize / 移除 Session"——**v4 必报"错误码 -32002 → -32602"**

---

## 2 · v3 评估"未落地"的 3 项本项目已实装

v3 在 §3.4 提"UEBA-ML 未落地"、隐含"EDR 未接入"、完全没提 IOC 匹配。**v4 直接读代码核实，发现 3 项已实装**——**v3 评估过时**：

### 2.1 phishing_guard LLM 维度（v3 评估"未落地" → 实际已实装）

**实装位置**：
- `backend/phishing_guard/scoring.py::aggregate_with_llm()`（2026-08-25 提交）
- `backend/phishing_guard/llm_dimension.py`（2026-08-24 21:17:48 提交）
- `backend/phishing_guard/__init__.py`（2026-08-03 整合）

**实装能力**：
1. **规则 verdict 与 LLM verdict 二次聚合**（`aggregate_with_llm(rule_verdict, llm_indicator)`）
   - 合并指标列表 → 按 category 重新分组 → 同类最高分 + 0.3 衰减叠加 → 加权求和 → 归一化 0-100
   - LLM 失败 → 返回原 verdict（0 副作用）
   - LLM 仅在 `risk_level in {suspicious, phishing}` 时调用（**节省 token**）
2. **LLM 维度触发特殊响应**：
   - `category == "llm_semantic"` 时追加"LLM 复核产出的语义判定需人工 review 后入库"
3. **指标排序**：按 score 降序，便于审计

**v3 评估错误的修正**：
- v3 §3.4 写"UEBA-ML 未落地"——但 phishing 场景的 LLM 维度二次聚合**已实装**！
- v3 §3.5 没把 phishing_guard/scoring.py 的 `aggregate_with_llm` 列为"P0.S 已落地"基线

**v4 重新评估**：
- ✅ **本项目 phishing_guard 的 LLM 维度 = P0.S 实装**（v4 §8 标注"已实装"）
- 📊 **基线数字**（v4 新增）：
  - 当前 LLM 维度触发条件：`suspicious` / `phishing` 两类
  - 当前 LLM 失败行为：0 副作用降级
  - 当前 LLM 指标存储：与规则指标合并，score 保留 LLM 自评
  - **缺口**：没有"LLM 复核准确率"反馈到训练——v4 §5 加"LLM-as-a-Judge 评估"

### 2.2 threat_intel IOC 匹配器（v3 完全没提 → 已实装）

**实装位置**：`backend/threat_intel/ioc_matcher.py`（2026-08-25 提交，193 行）

**实装能力**：
1. **三类匹配**：
   - 精确匹配（IP / Hash / Domain / URL）
   - CIDR 匹配（IP 属于已知恶意网段）
   - 域名通配（`*.evil.com` 匹配 `sub.evil.com`）
2. **缓存机制**：
   - 内存 dict cache（精确 + CIDR + 后缀三段）
   - 5 分钟自动 refresh（`refresh_interval = 300`）
   - 命中 metrics 计数
3. **异步 DB 加载**：从 `threat_iocs` 表（active=true）拉取
4. **多字段联合匹配**：`match(ip=, domain=, file_hash=, url=, session=)` 一次返回所有命中

**v3 漏掉的原因**：v3 写时（15:02）此模块刚提交（0:07），**v3 没及时纳入**

**v4 重新评估**：
- ✅ **本项目 IOC 实时匹配 = P0 实装**（v4 §8 标注"已实装"）
- 📊 **基线数字**（v4 新增）：
  - 当前 `ioc_match_threshold = 0.8`（settings.ioc_match_threshold）
  - 当前 refresh 间隔 5 分钟（可调到 1 分钟）
  - 当前 cache 类型：进程内 dict（单实例 OK，多实例需共享）
  - **缺口 1**：多实例 cache 共享（**v4 启动**：用 Redis 替代进程 dict）
  - **缺口 2**：MISP / TAXII 实时拉取（已有 `intel_enricher.py` 但 v3 没引用）
  - **缺口 3**：STIX 2.1 标准化（`stix_taxii.py` 已有基础）

### 2.3 edr_fusion 接入层（v3 隐含"未接入" → 已实装）

**实装位置**：
- `backend/edr_fusion/edr_adapter.py`（2026-08-25 提交，285 行）
- `backend/edr_fusion/sysmon_parser.py`（9.7K）+ `winevent_parser.py`（8.9K）
- `backend/edr_fusion/cross_correlator.py`（10.8K）
- `backend/edr_fusion/llm_correlation.py`（2.4K，2026-08-24 21:19:20 提交）

**实装能力**：
1. **统一接入层**（`EdrAdapter`）：
   - Kafka 消费（`edr-sysmon` / `edr-winevent` Topic）
   - HTTP API（Winlogbeat / NXLog / 自定义 Agent 推送）
   - **插件化**：预留商业 EDR（CrowdStrike / Carbon Black）API 适配器
2. **自动识别来源**：根据字段判断 sysmon vs winevent（`if "Image" in ed`）
3. **跨源关联**：每 60 秒跑 `cross_correlator.correlate()`，高置信度（≥0.7）推送 `event_bus`
4. **统计埋点**：sysmon_events / winevent_events / correlations / errors
5. **LLM 关联叙事**：`llm_correlation.py`（v4 必报 P0 已落地）

**v3 漏掉的原因**：v3 §3.4 写"EDR 接入未实现"——但实际 2026-08-25 凌晨 0:07 已提交，v3 15:02 写时已存在

**v4 重新评估**：
- ✅ **本项目 EDR 接入 = P0 实装**（v4 §8 标注"已实装"）
- 📊 **基线数字**（v4 新增）：
  - 当前 Kafka topic：`edr-sysmon` / `edr-winevent`
  - 当前关联窗口：60 秒（v4 可调到 300 秒匹配 `edr_correlation_window`）
  - 当前置信度阈值：0.7
  - 当前 LLM 关联：已实装（`llm_correlation.py`）
  - **缺口 1**：商业 EDR（Carbon Black / CrowdStrike）适配器未实装（`edr_adapter.py` 注释"预留"）
  - **缺口 2**：MISP / TAXII 实时拉取（`threat_intel/intel_enricher.py` 有基础但未联动到 EDR）

---

## 3 · v3 漏掉的 4 个行业新趋势

### 3.1 **Apache Flink Agents 0.3.0**（2026-06-19 GA，**v4 必报重大新趋势**）

**关键事实**：Apache 官方 2026-06-19 发布 **Apache Flink Agents 0.3.0 Preview**——**直接在 Flink DataStream API 内做 LLM Agent 工作流**（无需外部 Temporal / LangGraph）

**关键能力**：
- Java Release for Flink 1.20 / 2.0 / 2.1 / 2.2（**2.3 早期无 0.3.0 配套**）
- Python Release（Wheel）for Flink 1.20
- 把 LLM 调用、Tool Use、Memory、Reflection 封装为 Flink Operator

**对 v3 升级方案的颠覆**：
- v3 §4.2 写"Temporal AI 子工作流"——但 **Flink 内 LLM Agent = 不用 Temporal 也能做 Agent 工作流**！
- 优势：状态在 Flink 内自然持久化、Checkpoint 覆盖、Exactly-Once 由 Flink 保证
- 劣势：生态不成熟（0.3.0 Preview），LLM Provider 适配不全

**v4 重新评估**：
- v3 §4.2 "Temporal AI 子工作流" 改为 **"Flink Agents 0.3.0（生产试水）+ Temporal AI 子工作流（跨语言/复杂审批）双轨"**
- **本项目 Flink 已部署**（pom.xml 1.19.3）→ 升级到 1.20 LTS 后**直接试水 Flink Agents 0.3.0**
- **不要**"全押 Temporal"——v3 单一推荐有 vendor lock-in 风险

**与本项目契合度**：
- ✅ 已用 Flink 1.19.3（升级到 1.20 / 2.0 即可）
- ✅ 已有 4 层 Agent 编排（可平滑迁移到 Flink Agents Operator）
- ✅ 已有 LLM Enhancer（`llm_enhancer.py`）可作为 Provider
- ⚠️ 0.3.0 Preview = 不上生产关键路径，先做 POC

### 3.2 **Security Data Lake 模式（hot + warm + cold 三层）**

**来源**：AppScale Blog 2026 / AWS Security Lake（2023 GA）

**关键事实**：
- **2-3 倍成本下降**：传统 SIEM 价 $2-5/GB/day；Object storage cents/GB
- **三层架构**：
  - **Hot（SIEM，30-90 天）**：实时检测、Active IR
  - **Warm（Lake OCSF on Iceberg，6-18 月）**：威胁狩猎、长期调查、审计
  - **Cold（Object storage archival，1-7+ 年）**：合规保留
- **Routing tier**（Cribl / Vector / OTel collector）做 per-event 路由决策
- **Apache Iceberg** 是 v3 没提的关键——**OCSF on Iceberg** 是 cold tier 的事实标准

**对 v3 升级方案的补漏**：
- v3 §3.3 写"Paimon 流表 + Kafka/Paimon 湖仓分层"——只覆盖 1 层（Paimon 暖层）
- **v3 漏 cold tier 长期合规层**
- **v3 漏 Iceberg**（v3 §4.3 一句话提"Iceberg 备选"——不充分）

**v4 重新评估**：
- v3 §4.3 改为 **"3 层湖仓"**：
  - **Hot**：现有 Kafka 7 个 topic（不变）
  - **Warm**：Paimon 流表（Flink 2.x 一等公民）—— v3 保留
  - **Cold**：**S3/OSS/MinIO + Apache Iceberg + OCSF v1.9 标准化**（v4 新增）
- **必报反例**：Cribl 路由费用 0.32 credits/GB processed——v4 必报"自建 Vector/OTel collector vs Cribl Stream 成本对比"

**与本项目契合度**：
- ✅ 已有 Kafka + PG + Qdrant
- ✅ 已有 OCSF 接入规划（v3 §2.0 L0-1）
- ⚠️ 当前 PG 是事实表，**Iceberg 引入会引入"双写一致性"问题**——v4 必报：用 CDC 同步 PG → Iceberg
- ❌ **缺 cold tier**——**v4 必报项**

### 3.3 **威胁狩猎 Agent（独立场景，v3 完全漏掉）**

**来源**：CSDN 2026 综述（国内 6 厂商） / CrowdStrike Charlotte AI Threat Hunter（2026-Q1 推）

**关键事实**：
- **CSDN 综述场景 4**："威胁狩猎"是 Agentic SOC 独立场景，**ROI 评分 ⭐⭐⭐**
- **特点**：Agent 主动用最新 IOC/TTP 去内网回扫，**比分析师手动狩猎快 5-10x**
- **代表产品**：CrowdStrike Charlotte AI Threat Hunter Agent / Microsoft Security Copilot Threat Hunting / SentinelOne Purple AI Hunt
- **关键能力**：
  - 自动生成狩猎假设（"这个用户的访问模式是否异常"）
  - 自动写 SPL / KQL / 平台查询
  - 自动汇总结果 + 提建议
  - **HITL 强制**：狩猎结论需分析师确认

**v3 漏掉**：v3 §5.1 列 6 角色（Orchestrator / Triage / Investigation / TI / IR / Report）——**没列"Threat Hunter Agent"作为独立角色**

**v4 重新评估**：
- v3 §5.1 6 角色改为 **"7 角色"**：
  - Orchestrator（总调度） ✅
  - Triage（告警分诊） ✅
  - Investigation（深度调查） ✅
  - **Threat Hunter（威胁狩猎，主动发起）** ← v4 新增
  - TI（情报查询和富化） ✅
  - IR（应急响应） ✅
  - Report（报告） ✅
- **本项目契合度**：⚠️ 缺独立 Threat Hunter 模块——v4 启动 `agents/threat_hunter.py`（基于现有 `zeroday_detect/` + `threat_intel/`）

### 3.4 **调查辅助 Agent（独立场景，v3 完全漏掉）**

**来源**：CSDN 2026 综述

**关键事实**：
- **CSDN 综述场景 2**："调查辅助"是 Agentic SOC 独立场景，**ROI 评分 ⭐⭐⭐⭐**
- **特点**：分析师问"这批告警是不是相关的攻击？"，Agent 自动跨数据源拉证据、出时间线、列假设
- **减少 50% 调查时间**（CSDN 数据）
- **本项目已有基础**：`agent_a.py`（分诊）/ `agent_b.py`（决策）/ `agent_c.py`（报告）/ `agent_d.py`（审计）—— 4 层流水线**就是 v3 §5.1 调查的雏形**

**v3 漏掉**：v3 §5.1 6 角色没区分"告警分诊"和"调查辅助"——但**这两个场景 ROI 完全不同**

**v4 重新评估**：
- v3 §5.1 Investigation 角色拆为 **"Tier 1 Investigation（自动）" + "Tier 2 Investigation（人机协作）"**
  - Tier 1 = `agent_a.py`（已有）
  - Tier 2 = 新建 `agents/investigation_copilot.py`（基于现有 4 层流水线 + LLM 增强）
- **本项目契合度**：✅ 已有 agent_a-d.py 基础——v4 加 `investigation_copilot.py` 是平滑扩展

---

## 4 · 本项目当前基线（v3 缺，v4 必报）

### 4.1 真实技术栈版本（从配置文件核实）

| 组件 | 实际版本 | 评估 | 来源 |
|------|---------|------|------|
| **Flink** | 1.19.3（pom.xml） | ⚠️ **落后 4 个大版本**（v3 写 1.18 漏 1.19） | pom.xml:19 |
| **Kafka** | confluentinc/cp-kafka:7.6.0 | ✅ 2024-2025 主推，OK | docker-compose.yml:56 |
| **PostgreSQL** | pgvector/pgvector:pg16 | ✅ 主流 | docker-compose.yml:3 |
| **Qdrant** | `qdrant/qdrant:latest` | ⚠️ latest 标签生产风险（v4 必报：锁版本） | docker-compose.yml:39 |
| **Redis** | redis:7-alpine | ✅ 主流 | docker-compose.yml:22 |
| **Backend Python** | 3.12-slim | ✅ 主流 | Dockerfile:1 |
| **Backend Framework** | FastAPI 0.115+ | ✅ 主流 | requirements.txt:1 |
| **Pydantic** | 2.10+ | ✅ 主流 | requirements.txt:10 |
| **Temporal** | temporalio 1.24-1.x | ✅ 已实装（docker-compose 282-285 行默认 true） | requirements.txt:24 + docker-compose.yml |
| **pySigma** | 0.11-2.x | ✅ 主流 | requirements.txt:29 |
| **OTel Python** | 1.27-1.x | ✅ 主流 | requirements.txt:19-22 |
| **React** | 19.2.7 | ✅ 前沿 | package.json:28 |
| **Vite** | 7.3.6 | ✅ 前沿 | package.json:42 |
| **TypeScript** | 5.9.3 | ✅ 主流 | package.json:41 |
| **Tailwind CSS** | 4.3.3 | ✅ 主流 | package.json:31 |
| **Zustand** | 5.0.14 | ✅ 主流 | package.json:33 |
| **OTel Web SDK** | 2.10.0 | ✅ 主流 | package.json:18-22 |
| **Java** | 11（Flink + Connector） | ⚠️ Flink 2.x 推荐 17（v4 必报：升 Java 17） | pom.xml:17-18 |
| **Maven** | 3.11+ | ✅ 主流 | pom.xml:144 |
| **Kotlin** | 1.9.3 / 2.1+ | ✅ 主流 | pom.xml:144 |
| **Kafka UI** | provectuslabs/kafka-ui:v0.7.2 | ⚠️ v0.7.2 是 2023 版本，新版 1.x 应升（v4 可报：监控升级） | docker-compose.yml:116 |
| **Schema Registry** | confluentinc/cp-schema-registry:7.6.0 | ✅ 主流 | docker-compose.yml:136 |
| **Jaeger** | jaegertracing/jaeger:2.7.0 | ✅ 主流 | docker-compose.yml:404 |
| **OTel Collector** | otel/opentelemetry-collector-contrib:0.159.0 | ✅ 主流 | docker-compose.yml:380 |
| **Tempo** | grafana/tempo:2.10.8 | ✅ 主流 | docker-compose.yml:392 |

### 4.2 业务能力基线（v3 缺量化，v4 必报）

| 维度 | 实际值 | 评估 |
|------|--------|------|
| **Sigma 规则数** | 11 条（pySigma） + 11 条（legacy 兜底） | v3 修正后基线 |
| **.j2 模板数** | 46 个 | v3 修正后基线 |
| **单元测试数** | 195 passed（2026-08-24 验证） | ✅ |
| **Agent 角色** | 4 层（agent_a/b/c/d）+ CAD 监督 + 5 个 .j2 子角色 = 实际 5+ 角色 | v3 评估"5 角色"基本对 |
| **MCP Guard** | 4 层（Registry / RBAC / ParamValidator / PolicyEngine） | ✅ 已有 |
| **MCP 协议** | 自建 JSON-RPC（v3 §5.2 升级到 2026-07-28 spec） | ⚠️ 待升级 |
| **事件协议** | 自建 JSON | ⚠️ v3 §2.0 L0-1 升 OCSF 1.9 |
| **RAG 检索** | Qdrant dense + pgvector 兜底 | ✅ v3 修正后 |
| **向量维度** | 768（embedding_dim） | ✅ 主流 |
| **LLM Provider** | mimo-v2.5（OpenAI 兼容） | ✅ |
| **可观测性** | OTel + Tempo + Jaeger + Prometheus + Grafana | ✅ 主流 |
| **响应引擎** | 8 策略、5 动作、SSH + iptables | ✅ |
| **威胁情报** | MISP + TAXII + STIX（intel_enricher） | ✅ 已有 |
| **EDR 融合** | edr_adapter + sysmon + winevent + cross_correlator | ✅ **v3 评估错误** |
| **反钓鱼** | 7 个检测器 + LLM 维度 + scoring | ✅ **v3 评估错误** |
| **加密流量** | JA3 + JA3S + JA4 + 可选 mitmproxy | ✅ |
| **数据飞轮** | feedback_loop.py + summary_compression | ⚠️ 基础有但未系统化 |
| **零信任 for Agents** | ❌ 4 层 Guard 但非"每次调用鉴权" | v3 §4.4 必报项 |
| **MCP 2026-07-28** | ❌ 自建 JSON-RPC | v3 §5.2 必报项 |
| **5 Guardrail** | ❌ CAD 监督但无 5 道闸 | v3 §5.1 必报项 |
| **数据飞轮系统化** | ⚠️ 基础有（feedback_loop） | v3 §6.4 必报项 |
| **Paimon 湖仓** | ❌ 仅 7 个 Kafka topic | v3 §4.3 必报项 |
| **Flink CDC** | ❌ 仅 syslog/HTTP 推 | v3 §3.2 必报项 |
| **Security Data Lake** | ❌ 无 cold tier | v4 §3.2 必报项 |
| **Apache Flink Agents** | ❌ 4 层 Agent 走 Temporal | v4 §3.1 必报项 |
| **Threat Hunter Agent** | ❌ 无独立模块 | v4 §3.3 必报项 |
| **Investigation Copilot** | ⚠️ agent_a-d 基础在，缺独立模块 | v4 §3.4 必报项 |

---

## 5 · v4 推荐 24 项升级

> v3 的 20 项升级 v4 全部保留（修正版本号 + 重新评估落地度）。
> v4 新增 4 项：Apache Flink Agents / Security Data Lake / Threat Hunter Agent / Investigation Copilot。
> v4 重要修正：升级路径必须**按"核心+connector+operator+Java"整体评估**，禁止"只升主版本"。

### 5.1 L0 · 7/14/30 天超短期（沿用 v3 框架 + 修正）

| 项 | v3 描述 | v4 修正 |
|----|--------|---------|
| S-1.1 OCSF 1.9 字段映射 | 双写 OCSF 1.9 metadata | ✅ 不变 |
| S-1.2 Langfuse 单点接入 | audit_llm 接入 Langfuse | ✅ 不变 |
| S-1.3 Tier 1 分诊 Agent POC | 100 条历史告警 POC | ✅ 不变 |
| S-1.4 MCP 2026-07-28 兼容性测试 | 升级 SDK 跑兼容测试 | **+ 错误码 -32002 → -32602 修复** |
| S-2.1 NIST 800-61r3 6 函数 Playbook | 5 个核心剧本改写 | ✅ 不变 |
| S-2.2 UEBA-ML 30 天基线训练 | scikit-learn 离线训练 | ✅ 不变 |
| S-2.3 信创合规清单 | 国产 LLM / OS / DB 列表 | ✅ 不变 |
| S-3 MCP 2026-07-28 升级 | SDK v1.0+ 适配 | **+ error code 修复 + 移除 initialize 握手** |
| S-3 信创合规基线 | 国产化迁移路线图 | ✅ 不变 |
| S-3 Prompt Injection 第一招 | 输入清洗 + token 隔离 | ✅ 不变 |

### 5.2 L1 · 3 个月内（v3 基础上修正版本号）

| v3 项 | v3 版本 | v4 修正版本 | 原因 |
|------|--------|-----------|------|
| 3.1 流处理内核 | Flink 2.3 LTS | **2.3 LTS** ✅ | endoflife.date 2026-08-13 确认 |
| 3.2 CDC | 3.4.0 | **3.6.0** | 官方 2026-03-30 GA |
| 3.3 OTel + eBPF | v2 不变 | ✅ 不变 |
| 3.4 UEBA-ML | v2 不变 | ✅ 不变 |
| 3.5 信创合规 | DeepSeek-V3 + 麒麟 + 人大金仓 | ✅ 不变 |
| **3.6 Java 升级**（v4 新增） | — | **JDK 11 → JDK 17**（Flink 2.x 必备） | Flink 2.x 最低 JDK 17 |

**v4 关键提示**：
- **Flink 2.3 升级路径必须分两步**：1.19.3 → 1.20 LTS（connector/operator 覆盖全）→ 2.3 LTS（最终目标，跳 2.0/2.1/2.2）
- **1.20 LTS 期间可同步升** Flink Kafka Connector 5.0.0 + Flink Kubernetes Operator 1.15.0
- **2.3 升级必须配 Java 17**（pom.xml 当前 Java 11 → 17）
- **2.3 早期 connector/operator 覆盖不全**——**生产升级必须按"核心+connector+operator+Java"整体评估**

### 5.3 L2 · 6 个月内（v3 基础上 v4 加 1 项）

| v3 项 | v3 描述 | v4 修正/补充 |
|------|--------|------------|
| 4.1 Qdrant Hybrid | 先 finetune 再 hybrid | **+ A/B 测试**（hybrid 反而掉分 0.008） |
| 4.2 Temporal AI 子工作流 | 升级 1.30+ 启 Update/Signal | **+ Apache Flink Agents 0.3.0 POC**（v4 新增） |
| 4.3 Paimon 湖仓 | Paimon + Kafka/Paimon | **+ Iceberg cold tier**（v4 新增 Security Data Lake 模式） |
| 4.4 零信任 + Agent | SpiceDB / OpenFGA + 5 层 Guard | ✅ 不变 |

**v4 新增 4.2-b：Apache Flink Agents 0.3.0 POC**
- 目标：验证 Flink 内 LLM Agent 工作流可行性
- 范围：`backend/flink_agents_poc/` 1 个简单 case（如"Agent 调 Qdrant 检索 ATT&CK"）
- 评估指标：与 Temporal 路径对比（开发成本、运行成本、可观测性）
- **不替代** Temporal，但**给 v5 选型留依据**

**v4 新增 4.3-b：Security Data Lake 模式（cold tier）**
- 目标：从 7 天 Kafka + PG 永久 → 7 天 Kafka + 90 天 Paimon + 1 年 Iceberg/S3
- 方案：
  - Cold tier：S3/OSS/MinIO + Apache Iceberg + OCSF v1.9 标准化
  - Routing tier：用 Vector / OTel collector 替代 Cribl（开源）
  - PG 仍是事实表，Iceberg 作"分析副本"（CDC 同步 PG → Iceberg）
- **反例警示**：Cribl 0.32 credits/GB processed——v4 必报"自建 Vector vs Cribl 成本对比"
- **不立即执行**，先做 7-天 PoC（写 100 万条事件到 Iceberg，查询性能对比）

### 5.4 L3 · 12 个月内（v3 基础上 v4 加 2 项）

| v3 项 | v3 描述 | v4 修正/补充 |
|------|--------|------------|
| 5.1 多 Agent 调查 + 5 Guardrail | 6 角色 + Dropzone 5 专家 | **+ Threat Hunter Agent 独立角色**（v4 新增） |
| 5.2 MCP 2026-07-28 | 完整迁移 + DPoP | ✅ 不变 |
| 5.3 Prompt Injection 防御 | 5 招 | ✅ 不变 |
| 5.4 Agentic SOAR 编排 | 选型对比 | ✅ 不变 |
| **5.5 Investigation Copilot**（v4 新增） | — | 独立模块（基于 agent_a-d 4 层） |
| 6.4 数据飞轮 | 4 阶段 | ✅ 不变（v4 加"组织能力"维度） |
| 6.5 Zero Trust for Agents | 5 层 Guard | ✅ 不变 |

**v4 新增 5.5：Investigation Copilot（独立 Agent 角色）**
- 目标：把现有 `agent_a-d.py` 4 层流水线**升级**为"Tier 2 调查助手"
- 关键能力：
  - 分析师问"这批告警是不是相关攻击"
  - Agent 自动跨数据源拉证据（EDR + NDR + Auth + NetFlow + TI）
  - 出时间线、列假设、推荐下一步
  - **HITL 强制**：结论由分析师确认
- 复用：v3 §5.1 6 角色的 Investigation Agent
- ROI：**CSDN 2026 数据：减少 50% 调查时间**

**v4 新增 5.6：Threat Hunter Agent 独立角色**
- 目标：把现有 `zeroday_detect/` + `threat_intel/` 整合为独立"主动狩猎"角色
- 关键能力：
  - 自动生成狩猎假设（基于最新 TI / 行业事件）
  - 自动写查询（SPL / KQL / 自家 SQL）
  - 自动汇总 + HITL 确认
- ROI：⭐⭐⭐（CSDN 2026 评分）

### 5.5 v4 总升级项 = v3 的 20 + v4 新增 4 项 = **24 项**

---

## 6 · 集成架构图（v3 缺，v4 必报）

> v3 20 项升级散在多个章节，**评审需要"一眼看懂"**——v4 给一张集成架构图。

```
┌─────────────────────────────────────────────────────────────────────┐
│              揭榜挂帅 shared-memory-platform v4 集成架构              │
└─────────────────────────────────────────────────────────────────────┘

                  数据源层（v3 §3.2 + v4 §3.2 数据湖）
  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │ syslog   │ HTTP推   │ EDR(Sysmon│ DB CDC   │ MISP/TAXII│ ← v3 §3.2 + v4 §2.3
  │ /api     │ 送       │ /WinEvent)│(Flink CDC)│ /STIX     │   (已实装)
  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘
       │          │          │          │          │
       └──────────┴──────────┼──────────┴──────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │  Kafka 7 topics + Schema Registry (AVRO)   │ ← v3 已有
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  Flink 2.3 LTS（v3 §3.1）+ ForStDB        │ ← v3 L1，v4 加 Java 17
        │  Flink CDC 3.6.0（v3 §3.2）                 │ ← v3 L1，v4 升 3.6
        │  Flink CEP 3 攻击链模式（v3 已有）          │
        │  Flink Agents 0.3.0 POC（v4 §5.3）         │ ← v4 新增
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  hot 7d Kafka / warm 90d Paimon / cold 1y  │ ← v3 §4.3 + v4 §5.3
        │  Iceberg on S3 + OCSF v1.9                 │ ← v4 新增 cold tier
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  Backend (FastAPI + Python 3.12)           │
        │  ┌────────────────────────────────────┐  │
        │  │ pySigma 0.11 + 11 rules（v3 §3.1）│  │ ← v3 已有
        │  │ Anomaly Detection 11 维评分（已有） │  │
        │  │ UEBA-ML（v3 §3.4 scikit-learn）    │  │ ← v3 L1
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 7 角色 Agent（含 v4 新增 2 角色）│  │ ← v3 §5.1 + v4 §5.4
        │  │ Orchestrator / Triage / Invest /  │  │
        │  │ Threat Hunter(v4) / TI / IR /     │  │
        │  │ Report + Investigation Copilot(v4) │  │
        │  │ + 5 Guardrail（v3 §5.1）          │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 4 层 MCP Guard + SecurityGuard    │  │ ← v3 §4.4 + v4 §5.3
        │  │ + 5 层零信任（v3 §4.4）          │  │
        │  │ + MCP 2026-07-28 spec（v3 §5.2） │  │
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ Langfuse LLM Observability       │  │ ← v3 §2.0 L0-2
        │  │ + 5 招 Prompt Injection 防御    │  │ ← v3 §5.3
        │  │ + 数据飞轮（v3 §6.4）            │  │ ← v3 L3
        │  └────────────────────────────────────┘  │
        │  ┌────────────────────────────────────┐  │
        │  │ 钓鱼检测 7 检测器 + LLM 维度    │  │ ← v4 §2.1 已实装
        │  │ IOC 实时匹配器（精确+CIDR+通配） │  │ ← v4 §2.2 已实装
        │  │ EDR 接入层（Kafka+HTTP+商业预留） │  │ ← v4 §2.3 已实装
        │  └────────────────────────────────────┘  │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  RAG 检索：Qdrant Hybrid（v3 §4.1）       │ ← v3 L2，v4 加 A/B
        │  + pgvector 兜底 + SPLADE finetune       │
        │  + 数据飞轮联动（v3 §6.4）                │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  响应引擎（v3 已有）                       │
        │  8 策略 / 5 动作 / SSH + iptables / 审批  │
        │  + NIST 800-61r3 CSF 2.0（v3 §2.0 L0-4）│ ← v3 L0
        │  + 信创合规执行（v3 §3.5）                │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  持久化：PostgreSQL 16 + Redis 7          │
        │  （事实表）                                 │
        └────────────────┬───────────────────────────┘
                         ▼
        ┌────────────────────────────────────────────┐
        │  可观测性：OTel + Tempo + Jaeger          │ ← v3 §3.3
        │  + Prometheus + Grafana                   │   已有
        │  + eBPF（v3 §3.3）                       │   v3 L1
        └────────────────────────────────────────────┘
                         ▲
                         │ 前端 React 19.2 + Vite 7.3
                         │ 5 仪表板：Monitor / RAG / Intel / 
                         │ Phishing / EDR / Operations
```

**v4 集成关键点**：
1. **3 层数据湖**（hot Kafka / warm Paimon / cold Iceberg）—— 行业 Security Data Lake 模式
2. **7 角色 Agent**（含 v4 新增 2 个）—— 实际 SOC 完整闭环
3. **5 道 Guardrail**—— D3 Morpheus 模式
4. **双协议**（MCP 2026-07-28 + W3C Trace Context）—— 端到端 trace 一次到位
5. **信创 + 零信任**—— 揭榜挂帅评审硬性要求

---

## 7 · 路线图（沿用 v3 7/14/30 + 加 4-12 月延展）

| 时段 | 7/14/30 天超短期（沿用 v3） | 1-3 月 | 4-6 月 | 7-12 月 |
|------|---------------------------|--------|--------|---------|
| **D+7** | OCSF 1.9 / Langfuse / Tier 1 POC / MCP 2026-07-28 兼容测试 / **错误码 -32002 → -32602 修复** | — | — | — |
| **D+14** | NIST r3 5 Playbook / UEBA-ML 训练启动 / 信创合规清单 | — | — | — |
| **D+30** | v3 L0 全量 + MCP 升级 + 信创基线 + Prompt Injection 第 1 招 + **本项目基线度量**（v4 §4.2） | Java 17 升级启动 | — | — |
| **M+1-2** | — | **Flink 1.19.3 → 1.20 LTS**（connector 5.0 + operator 1.15 同步升）+ 信创 LLM 试点 | **Apache Flink Agents 0.3.0 POC** | 5 Guardrail 实现 + 数据飞轮启动 + **Threat Hunter Agent 独立模块** |
| **M+2-3** | — | **Flink 2.3 LTS** 升级（蓝绿 + Java 17）/ UEBA-ML 上线 | OTel eBPF 接入 | Agent 红蓝测试 + **Investigation Copilot** 独立模块 |
| **M+3-4** | — | Flink CDC 3.6 试点 | Qdrant Hybrid A/B（含降分反例） | 多 Agent shadow + 5 Guardrail 全量 + **数据飞轮组织能力配套**（v4 新增） |
| **M+4-6** | — | Flink CDC 扩展 + 信创 LLM 全量 | **Paimon 暖层上线** + 零信任 5 层 Guard | **MCP 2026-07-28** 完整迁移 + Agentic SOAR 编排 + **Security Data Lake cold tier 试点**（v4 新增） |
| **M+6-9** | — | — | 多 Agent 编排 + Prompt Injection 5 招 | DPoP + 零信任深化 + 数据飞轮自动化 |
| **M+9-12** | — | — | — | GNN 异常路径检测 / 自治 SOC AL3 / 信创全栈 POC / **7 角色 + Investigation Copilot + Threat Hunter 上线** |

**v4 路线图关键变化**：
- v3 写"Java 17 升级"隐含在 Flink 2.x 升级里——v4 显式拆为单独时点
- v4 加"**数据飞轮组织能力配套**"——v3 漏掉"组织维度"
- v4 加"**Security Data Lake cold tier 试点**"——v3 完全漏

---

## 8 · v3 20 项的本项目落地度评估（v3 缺，v4 必报）

> 评审最关心："**哪些不用做 / 哪些在做了 / 哪些没做**"——v4 给逐项评估表。

| # | v3 升级项 | 本项目落地度 | 评估 | v4 建议 |
|---|---------|-----------|------|---------|
| 1 | OCSF 1.9（v3 §2.0 L0-1） | ❌ 未做 | 待启动 | S-1.1 |
| 2 | Langfuse（v3 §2.0 L0-2） | ❌ 未做 | 待启动 | S-1.2 |
| 3 | Tier 1 分诊 Agent（v3 §2.0 L0-3） | ⚠️ 基础在（agent_a） | 部分 | S-1.3 |
| 4 | NIST r3（v3 §2.0 L0-4） | ❌ 未做 | 待启动 | S-2.1 |
| 5 | Flink 1.18→2.3 LTS（v3 §3.1） | ❌ 未做 | 待启动 | **修正路径：1.19.3→1.20 LTS→2.3** |
| 6 | Flink CDC 3.6（v3 §3.2） | ❌ 未做 | 待启动 | M+3-4 |
| 7 | OTel + eBPF（v3 §3.3） | ⚠️ OTel 已做 / eBPF 未做 | 部分 | M+2-3 |
| 8 | UEBA-ML（v3 §3.4） | ❌ 未做 | 待启动 | S-2.2 + M+2-3 |
| 9 | 信创合规（v3 §3.5） | ❌ 未做（仅清单） | 待启动 | S-2.3 + M+1-2 |
| 10 | Qdrant Hybrid（v3 §4.1） | ❌ 未做 | 待启动 | M+3-4（含 A/B 反例） |
| 11 | Temporal AI 子工作流（v3 §4.2） | ⚠️ Temporal 已实装 / AI 子工作流未启 | 部分 | M+1-2（启 1.30+ Update/Signal） |
| 12 | Paimon 湖仓（v3 §4.3） | ❌ 未做 | 待启动 | M+4-6 |
| 13 | 零信任 + Agent（v3 §4.4） | ❌ 未做 | 待启动 | M+4-6 |
| 14 | 多 Agent + 5 Guardrail（v3 §5.1） | ⚠️ 4 层 + CAD / 5 Guardrail 未启 | 部分 | M+6-9 |
| 15 | MCP 2026-07-28（v3 §5.2） | ❌ 未做 | 待启动 | D+30 + M+4-6 |
| 16 | Prompt Injection 防御（v3 §5.3） | ❌ 未做 | 待启动 | D+30 + M+6-9 |
| 17 | Agentic SOAR 编排（v3 §5.4） | ❌ 未做（已有 Temporal） | 不直接做 | 选 D3 Morpheus 模式 |
| 18 | Agent 红蓝测试（v3 §6.3） | ❌ 未做 | 待启动 | M+3-4 |
| 19 | 数据飞轮（v3 §6.4） | ⚠️ feedback_loop 在 | 部分 | M+1-2 + 启动组织能力 |
| 20 | Agent 部署审批流程（v3 §10.1） | ❌ 未做 | 待启动 | M+1-2 |
| **21**（v4 新增） | **Apache Flink Agents 0.3.0** | ❌ 未做 | 待启动 | M+1-2 POC |
| **22**（v4 新增） | **Security Data Lake cold tier** | ❌ 未做 | 待启动 | M+4-6 试点 |
| **23**（v4 新增） | **Threat Hunter Agent 独立模块** | ❌ 未做 | 待启动 | M+1-2 |
| **24**（v4 新增） | **Investigation Copilot 独立模块** | ⚠️ agent_a-d 在 | 部分 | M+2-3 |
| **+1** | **phishing LLM 维度**（v4 §2.1 修正） | ✅ **已实装**（2026-08-25） | **完成** | 仅加 LLM-as-a-Judge 评估 |
| **+2** | **IOC 实时匹配**（v4 §2.2 修正） | ✅ **已实装**（2026-08-25） | **完成** | 仅补多实例 Redis 共享 |
| **+3** | **EDR 接入层**（v4 §2.3 修正） | ✅ **已实装**（2026-08-25） | **完成** | 仅补商业 EDR 适配器 |
| **+4** | **Qdrant 主路径** | ✅ **已实装** | **完成** | 仅 A/B Hybrid 反例测试 |
| **+5** | **pySigma 引擎** | ✅ **已实装**（默认引擎） | **完成** | 持续加规则 |
| **+6** | **Prompts 集中化** | ✅ **已实装**（46 个 .j2） | **完成** | 持续追加 |
| **+7** | **MCP Guard 4 层** | ✅ **已实装** | **完成** | 升 MCP 2026-07-28 spec |
| **+8** | **Temporal 基础** | ✅ **已实装**（默认 true） | **完成** | 启 AI 子工作流 |

**v4 评估结论**：
- **已实装**：8 项（phishing LLM / IOC / EDR / Qdrant / pySigma / Prompts / MCP Guard / Temporal 基础）
- **部分实装**：4 项（Tier 1 分诊 / OTel+eBPF / Temporal AI 子工作流 / 多 Agent / 数据飞轮 / Investigation Copilot）
- **未做（v3 升级项）**：12 项
- **未做（v4 新增）**：4 项（Apache Flink Agents / Security Data Lake / Threat Hunter / Investigation Copilot 独立模块）

---

## 9 · 风险与验证（v3 基础上加 3 条）

### 9.1 升级风险（v4 在 v3 §8.1 基础上加 3 条）

| 风险 | 等级 | v4 缓解 |
|------|------|--------|
| v3 的 17 条风险 | 同 v3 | 同 v3 |
| **Flink 2.3 早期 connector/operator 覆盖不全**（v4 新增） | 高 | 走"1.20 LTS 过渡 + connector 5.0/operator 1.15 同步"路径，**不直接 1.19.3→2.3 跳** |
| **Qdrant Hybrid 反而掉分**（v4 新增，反例） | 中 | A/B 测试必须有，**默认上 hybrid 是 v3 假设错误** |
| **数据飞轮需要组织能力配套**（v4 加维度） | 中 | 设 Agent Engineer 岗位（v3 §10.2 已提），**v4 加"周飞轮会议"机制** |
| **MCP 2026-07-28 错误码 -32002 → -32602 静默 bug**（v4 新增） | 中 | 加 5 招防御的同时，**写"错误码变更回归测试"** |
| **Apache Flink Agents 0.3.0 Preview 不上生产关键路径**（v4 新增） | 低 | 只做 POC，不替代 Temporal |

### 9.2 升级期监控指标（v4 在 v3 §9.2 基础上加 3 个）

- v3 的 12 个指标
- **v4 新增**：
  - **本项目基线 MTTD/MTTR/告警量**（v4 §4.2 度量必须先建立）
  - **7 角色 Agent 的人均修改率**（Agent 结论被分析师改多少 %；CSDN 2026 数据：< 30% 算"真用起来"）
  - **数据飞轮每周准确率变化**（v3 §9.2 已提，v4 加"组织能力"维度：周飞轮会议出席率）

### 9.3 不升级的代价（v4 在 v3 §8.2 基础上加 2 项）

- v3 的 16 项
- **v4 新增**：
  - 不用 **Apache Flink Agents**：Flink 内 Agent 工作流被 4 层流水线替代——但 Temporal AI 子工作流有 vendor lock-in 风险
  - 不用 **Security Data Lake cold tier**：合规审计 1 年保留需靠 PG 永久存储——**成本高 + 性能差**

---

## 10 · 总结（v4 重写）

本轮 v4 升级的核心定位（与 v3 不同）：

1. **v3 是"加新项"逻辑**（20 项升级）；**v4 是"修正 + 落地"逻辑**（24 项但重点在 6 个反例 + 3 个事实修正 + 3 个误判纠正 + 4 个新趋势）
2. **v3 评估滞后 1 个版本**（写 Flink 1.18 EOL 但本项目 1.19.3 EOL 2026-07-01）；**v4 修正为本项目实际 1.19.3→1.20 LTS→2.3 LTS 路径**
3. **v3 评估"未落地"的 3 项实际已实装**（phishing LLM / IOC / EDR 接入层——2026-08-25 提交，v3 写时已存在但漏检）
4. **v3 完全没提 6 大生产反例**（rebalance+keyBy / Unaligned Checkpoint / ClickHouse At-Least-Once / Nacos 改窗口 / Qdrant hybrid 掉分 / MCP 错误码静默）——v4 必报
5. **v3 漏 4 个 2026-Q3 新趋势**（Apache Flink Agents 0.3.0 / Security Data Lake 模式 / 威胁狩猎 Agent / 调查辅助 Agent 独立场景）——v4 新增
6. **v3 没有"本项目当前基线"量化**——v4 §4 给 24 项配置 + 27 项能力基线
7. **v3 没有"集成架构图"**——v4 §6 给一张图让评审"一眼看懂"
8. **v3 没有"20 项落地度评估表"**——v4 §8 给"已实装 8 / 部分实装 4 / 未做 12 / 新增 4"清单
9. **v3 没有 1.20 LTS 中间过渡**——v4 加"1.20 LTS 短过渡（connector/operator 覆盖全）→ 2.3 LTS 终态"
10. **v3 数据飞轮缺"组织能力"维度**——v4 §5.4 + §9.2 加"Agent Engineer 岗位 + 周飞轮会议 + CISO 季度报告"

**v4 的验证基础**：
- 24 项升级中，**20 项沿用 v3**（v3 已用 endoflife.date / MCP 2026-07-28 / D3 Morpheus APD 2.0 / 数说安全 294 页报告 / RSAC 2026 国内案例验证）
- **4 项新增**用 2026-Q3 末轮核验（Apache Flink Agents 0.3.0 / Security Data Lake 模式 / CSDN 6 场景 / 千万级 QPS 实战 2026 验证）
- **6 大反例**用 Apache Flink docs / Qdrant 2026 benchmark / CSDN 综述 / Cloudflare Blog 2026-07-28 验证
- **本项目基线**用 pom.xml / docker-compose.yml / requirements.txt / package.json / 195 单测 / 46 .j2 模板 / 11 Sigma 规则 直接核实

**给揭榜挂帅评审的"7 天可演示"清单**（v4 沿用 v3 框架 + 加本项目已实装项）：
1. OCSF 1.9 字段映射（用 Datadog OCSF 工具验证）
2. Langfuse 单点接入（演示 LLM 全链路可回放）
3. Tier 1 分诊 Agent POC（100 条历史告警混淆矩阵）
4. MCP 2026-07-28 兼容性测试 + **错误码 -32002 → -32602 修复验证**（v4 新增）
5. 信创合规清单（证明"能国产化"）
6. Agent 红蓝测试 1 场景（数据源断连测试，证明防护）
7. 数据飞轮基线（证明有"学习力"）
8. **phishing_guard LLM 维度演示**（v4 新增：v3 误判"未落地"，实际已实装）
9. **IOC 实时匹配演示**（v4 新增：v3 漏提，已实装）
10. **EDR 接入层演示**（v4 新增：v3 隐含"未接入"，实际已实装）

---

## 附录 A · v3 → v4 关键变更对照表

| 维度 | v3 章节 | v4 章节 | 变更摘要 |
|------|--------|--------|---------|
| Flink 1.19 EOL | v3 §3.1 漏提 | **v4 §1.1** | **新增**（本项目 1.19.3 实际 EOL 2026-07-01） |
| Flink CDC 版本 | v3 §3.2 写 3.4.0 | **v4 §1.1** | **升 3.6.0**（官方 2026-03-30 GA） |
| Flink 2.3 升级风险 | v3 简化假设 | **v4 §1.5 反例 1-3** | **connector/operator 覆盖不全**反例 + 1.20 LTS 中间过渡 |
| Apache Flink Agents | v3 无 | **v4 §3.1 + §5.3 + §5.4 #21** | **新增 24 项之一** |
| Security Data Lake | v3 §4.3 简略 | **v4 §3.2 + §5.3 #22** | **新增 cold tier Iceberg on S3** |
| 威胁狩猎 Agent | v3 6 角色没列 | **v4 §3.3 + §5.4 #23** | **新增 7 角色** |
| 调查辅助 Agent | v3 6 角色没列 | **v4 §3.4 + §5.4 #24** | **新增 Investigation Copilot** |
| phishing LLM 维度 | v3 评估"未落地" | **v4 §2.1 + §8** | **修正：已实装**（2026-08-25 提交） |
| EDR 接入层 | v3 隐含"未接入" | **v4 §2.3 + §8** | **修正：已实装**（2026-08-25 提交） |
| IOC 匹配器 | v3 完全没提 | **v4 §2.2 + §8** | **新增：已实装**（2026-08-25 提交） |
| 6 大反例 | v3 完全没提 | **v4 §1.5** | **新增**（rebalance+keyBy / Unaligned Checkpoint / ClickHouse At-Least-Once / Nacos 改窗口 / Qdrant hybrid 掉分 / MCP 错误码） |
| MCP 2026-07-28 错误码 | v3 漏 | **v4 §1.5 反例 6** | **-32002 → -32602 静默 bug** |
| 本项目基线 | v3 无 | **v4 §4** | **24 项配置 + 27 项能力基线** |
| 集成架构图 | v3 无 | **v4 §6** | **新增 3 层数据湖 + 7 角色 + 5 Guardrail 集成图** |
| 20 项落地度评估 | v3 无 | **v4 §8** | **已实装 8 / 部分 4 / 未做 12 / 新增 4** |
| 升级路径 | v3 写 1.18→1.20→2.3 | **v4 改为 1.19.3→1.20 LTS→2.3 LTS** | 反映本项目实际状态 |
| 数据飞轮 | v3 提"训练" | **v4 §5.4 + §9.2 加"组织能力"** | **Agent Engineer + 周飞轮会议 + CISO 季度报告** |
| L1 减员数字 | v3 写"50→5" | **v4 §1.4 改为"24→8（-67%）+ Agent Engineer 新增"** | 真实案例数字（反例） |
| 告警降噪数字 | v3 写"99%" | **v4 §1.4 改为"95%（D3 实测）/ 99%（上限）"** | 行业实测 vs 厂商自报 |

---

## 附录 B · v4 在 v3 基础上新增/修正的来源（v3 附录 B 基础上 +12 个）

### v3 已列 50 个来源（保留）
1-50：见 v3 文档附录 B。

### v4 新增（2026-08-25 末轮）
51. eosl.date. *Apache Flink End of Life (EOL) Dates*. 2026-08-13 刷新（**1.19 EOL 2026-07-01 新发现**）。
52. Apache Flink Official. *Downloads / Connectors / CDC / Agents*. 2026-08 查（**Flink CDC 3.6.0 / Flink Agents 0.3.0 / Flink Kafka Connector 5.0.0 最新状态**）。
53. 今日头条/CSDN. *千万级 QPS 实时指标计算：Flink DataStream 窗口、乱序、热 Key 与端到端一致性实战*. 2026-08（**6 大反例关键来源**）。
54. AppScale Blog. *Your SIEM Bill Is a Data Architecture Problem, Not a Security One*. 2026（**Security Data Lake hot-warm-cold 三层模式**）。
55. CSDN. *2026，被认为是 Agentic SOC 的真正元年*. 2026-08（**6 大落地场景：Tier 1 分诊 / 调查辅助 / 报告生成 / 威胁狩猎 / 响应执行 / 战略情报**）。
56. D3 Security. *The Best Agentic SOC Platforms for MSSPs in 2026*. 2026-08（**Conifers CognitiveSOC 2-4h tenant onboarding / Tines AI / D3 Morpheus 95% 真实数字**）。
57. byteiota. *MCP 2026-07-28: What Broke, What to Fix*. 2026-08（**错误码 -32002 → -32602 静默 bug**）。
58. byteiota. *MCP Goes Stateless: What the 2026-07-28 Spec Breaks and How to Fix It*. 2026-08（**SDK 迁移路径**）。
59. blog.yeyupiaoling.cn. *Model Context Protocol 发布 2026-07-28 版*. 2026-08（**中文深度解读**）。
60. Qdrant. *Hybrid Search Benchmark Part 3-4*. 2026（**finetune SPLADE 0.413 vs hybrid 0.405 反例数据**）。
61. ClickHouse. *Apache Flink Connector 官方文档*. 2026（**At-Least-Once 现实**）。
62. Apache Flink. *Checkpointing under Backpressure*. 2026-08（**Unaligned Checkpoint 不修反压**）。

---

**文档版本**：v4.0（2026-08-25）
**作者**：shared-memory-platform 升级评估组
**审阅人**：TODO（待补充）
**下次复审**：2026-11-25（M+3）对照 2026-Q4 SOC 行业新动向

**前置版本**：
- v3.0（`2026-q3-tech-stack-upgrade-v3.md`，2026-08-25 15:02）
- v2.0（`2026-q3-tech-stack-upgrade-v2.md`，2026-08-25 14:53）
- v1.0（`2026-q3-tech-stack-upgrade.md`，2026-08-25 14:38）
