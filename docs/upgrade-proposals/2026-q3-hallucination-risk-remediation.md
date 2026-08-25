# 幻觉 / 误报五风险核实报告与修复计划

> 范围：`shared-memory-platform` 全链路（日志接入 → Sigma/CEP/异常检测 → Audit-LLM 四层 → CAD/Grounding → 记忆树/向量记忆/RAG → 响应引擎）
> 日期：2026-08-25
> 原则：先核实论文数字，再对照本仓库代码，最后只列能落地的修复。不把厂商 PPT 当证据。

---

## 0 · 核实总表

| # | 用户陈述 | 核实结论 | 准确数字（带出处） | 对本项目 |
|---|---------|---------|-------------------|---------|
| 1 | 基线 4–9% + 长尾 15–40% + 截止日期后 30–60%（Vectara / Stanford） | **方向成立，数字需分层引用** | 见 §1 | **P0**：忠实度评测过弱，Grounding 只降权不剥主张 |
| 2 | 安全垂直 ×3–5：SOC 误报 36–86%（DeepTempo） | **成立，且正中本产品** | 见 §2 | **P0**：LLM 增强检测路径无 FP 硬闸；多轮 OR 合并放大误报 |
| 3 | Reasoning 反向放大：推理训练 + 工具调用 = 幻觉翻倍（ICLR 2026） | **机制成立，“翻倍”是部分配置的简化** | 见 §3 | **P0**：Stabilizer 模糊匹配 = 干扰工具；deep_analyze/Reviewer 无弃权 |
| 4 | 多步累乘：7 步 ≈ 1−0.95⁷ = 30%（AgentHallu） | **公式成立；AgentHallu 论文本身测的是归因，不是这条公式** | 见 §4 | **P0**：deep 路径 8–12 次 LLM hop，无逐步错误预算 |
| 5 | Memory 投毒 89–99.8% 成功（ICML 2026） | **写入成功率成立；端到端 ASR 更低但仍不可接受** | 见 §5 | **P0**：`store_memory` / RAG / 日志进记忆树均无写时校验 |

**一句话**：本仓库已有 Grounding、CAD、确定性 ToolBuilder、Sigma/CEP 非 LLM 检测，**不是裸 Agent**。但五条风险全部在现网路径上有对应缺口，且多数只做了“打分/降权”，没有“否决/剥离/拒写”。

---

## 1 · 风险 1：基线幻觉（Vectara / Stanford）

### 1.1 核实

分层后的数字（不要混成一个“4–9%”）：

| 任务类型 | 幻觉率 | 出处 | 是否可当本项目基线 |
|---------|--------|------|------------------|
| 有文档摘要（Vectara HHEM，答案在文中） | 顶尖模型 **<2%**；常见 1.8–4.3%；推理模型常 **>10%**（Gemini-3-pro 13.6%） | [Vectara HHEM leaderboard](https://github.com/vectara/hallucination-leaderboard)（更新至 2026-05-11）；Vectara 2025-11 新数据集 | **偏乐观**。本项目不是“摘要给定文档”，是安全研判 |
| RAG 忠实度 | **4–9%** | AI Business Weekly / Seekr 2026 从业者分层 | **最接近 Audit-LLM 的“有证据仍编造”层** |
| 长尾事实（冷门技术/局部知识） | **15–40%** | [presenc.ai 2026](https://presenc.ai/research/ai-hallucination-rate-benchmarks-2026)；AI Business Weekly | **对应冷门 TTP / 非标准日志源 / 内部资产别名** |
| 训练截止日期后事件 | **~30–60%**（另有“近期事件 +~20%”） | 同上；sqmagazine 2026 | **对应新 CVE、新家族、知识库未更新的 MITRE/CAPEC** |
| Stanford 法律高风险查询 | **58–88%**（不是 30–60%） | Stanford HAI / RegLab 法律幻觉研究 | **类比用**：高风险垂直 + 引用生成会远差于 HHEM |

**修正表述**：4–9% 是 RAG 忠实度，不是 HHEM 摘要榜。长尾 15–40%、截止后 30–60% 是公开综述分层，不是 Stanford 原文。Stanford 法律任务更差（58–88%）。对本 SOC 产品，**应假设：有证据摘要 ~5–10%；冷门 TTP 15–40%；知识库过期 30%+。**

### 1.2 本仓库现状

已有：

- `grounding_verifier.py`：Layer 1–7 程序化溯源（ID / quote 子串 / IP·severity / KB 类型 / 新鲜度 / 跨源 / 链完整性）
- `sub_auditor.py`：强制 `evidence_ids` + `evidence_quotes` + schema 重试
- `eval_service.evaluate_faithfulness`：词法重叠忠实度
- CAD 熔断：`MAX_HALLUCINATION_RISK` 默认 **0.5**（偏松）

缺口（代码级）：

| 缺口 | 文件 | 后果 |
|------|------|------|
| Grounding 只做 **大小写不敏感子串匹配**，不是 NLI/HHEM | `grounding_verifier.py` | “quote 里有这几个字”≠“主张被证据蕴含”。长尾/改写句过关 |
| 未 grounding 的主张 **只惩罚 confidence（最多 ×0.4 grounding 项）**，不从结论中剥离 | `agent_executor.py` ~578–617 | `threat_detected` 仍可由 LLM 合成器输出 True |
| 人审阈值：`avg_hallucination_risk > 0.6` 或 `avg_grounding < 0.4` | 同上 | 中等幻觉（0.3–0.6）直接出结论 |
| 忠实度评测是 **词法 Jaccard，阈值 0.18** | `eval_metrics.py` / `eval_service.py` | 同义词、改写、否定句全部失真；且只挂在 RAG 路由，**未接入 Audit-LLM 主路径** |
| EvidenceVerifier 用 **同一类 LLM 当裁判** | `rag/evidence_verifier.py` | 用会幻觉的模型验证幻觉（循环） |
| RAG 无知识截止 / 文档生效日 | `rag/knowledge_base.py`、`mitre_importer.py` | 截止后 30–60% 场景无防护 |
| Layer 4 在 `knowledge_chunks` 为空时视为通过 | `sub_auditor.py` 注释 + `grounding_verifier` | 没检索到知识 = 知识一致性满分 |

### 1.3 修复（P0–P2）

**P0-1 主张剥离，不只降权**

- `ChunkVerdict` / `Executor._synthesize_from_chunks`：`verdict==ungrounded` 的 claim **不得进入** `threat_detected` 投票。
- 合成 prompt 只接收 `grounded | partially_grounded`；ungrounded 进 `discarded_claims` 审计日志。
- 规则：无 grounded claim → `threat_detected=false`，`needs_human_review=true`（可疑但不可确认）。

**P0-2 主路径接入忠实度闸**

- 每次 Audit 结束后调用 `evaluate_faithfulness`（context = 原始事件 + 工具返回，answer = 最终 summary）。
- `faithfulness < 0.75` 或 `unsupported_claim_ratio` 失败 → 强制人审，禁止自动响应。
- 把词法阈值从 0.18 提高到 0.35，并加 **程序化蕴含**：claim 中的 IP/端口/CVE/ATT&CK ID 必须出现在 evidence。

**P1-1 知识新鲜度**

- `KnowledgeDoc` 加 `published_at` / `valid_until` / `cutoff_policy`。
- Grounding Layer 5 已有证据新鲜度；对 KB 同样：过期文档不得作为 `knowledge_supported=true`。
- 无检索命中时 Layer 4 记 `unknown`，**不得记 1.0**。

**P2-1 评测集**

- 用本项目日志样本建 200 条：有文档摘要 / 长尾 TTP / 故意过期 IOC。目标：摘要层 <5%，研判层 faithfulness ≥0.85，过期 IOC 必须拒答或标 `stale`。

---

## 2 · 风险 2：安全垂直误报（DeepTempo SOCBench）

### 2.1 核实

[DeepTempo《The 36 Percent False Positive Problem》，2026-06-30](https://www.deeptempo.ai/blogs/the-36-percent-false-positive-problem-with-llm-in-the-soc) + [SOCBench](https://github.com/DeepTempo/socbench)：

| 模型 | 混有恶意的良性流 FP | 纯良性捕获 FP |
|------|---------------------|---------------|
| Anthropic | 36% | 39% |
| OpenAI | 53% | 43% |
| Gemini | 41% | **86%** |
| LogLM（垂直编码器） | <1% | <2% |

配套发现（同一文）：

- LLM **verdict F1 0.86–0.93**（会喊“有事”），但 **per-flow F1 掉 27–42 点**（说不出哪条流有事）。
- 高 Recall、低 Precision：赢在“全报”，输在 SOC 不可上线。
- DeepTempo 自己的结论：**检测应是编码器/规则的活；调查、叙事、规则合成才是 LLM 的活。**

“×3–5”：相对 HHEM 4–9% 的 RAG 幻觉，SOC 误报 36–86% 大约是 **4–10 倍**，不是严格 3–5，但量级正确。

### 2.2 本仓库现状

**好的分层**（符合 DeepTempo 建议）：

- 检测主路径是 **Sigma + Flink CEP + 统计异常**，不是 LLM 对每条流做 verdict。
- Audit-LLM 定位是研判，不是 inline 检测。

**坏的耦合**：

| 缺口 | 文件 | 为何会被 36–86% 击中 |
|------|------|---------------------|
| 合成器可把弱证据判成 `threat_detected=true` | `agent_executor.py` | 与 SOCBench “高 Recall 全报警”同一偏差 |
| `_merge_rounds`：**任意一轮发现威胁 → 最终有威胁** | `log_ingestion.py:44–60` | n 轮独立 5% 误报 → `1-0.95^n`；这是 FP 放大器 |
| CAD 只验证 **证据 ID 是否存在**，不验证“是否恶意” | `cad.py` PenetratingVerifier | 存在的日志 ≠ 威胁。无法压 SOC FP |
| LLM Enhancer 直接打垂直流量/钓鱼/加密/EDR | `llm_enhancer.py` + `phishing_guard/` `encrypted_traffic/` `edr_fusion/` | 正是 “generic LLM on logs” |
| 反馈闭环依赖人工点误报 | `feedback_loop.py` | FP 阈值 50% 才建议关规则，远高于可运营水平 |
| 无 SOCBench 类评测 | `backend/tests/` | 测了模块，没测“良性流量安静度” |

### 2.3 修复

**P0-3 检测与叙事解耦（硬约束）**

- `threat_detected` 的 **必要条件**：Sigma 命中 **或** CEP 链 **或** 异常分 ≥ 阈值 **或** 威胁情报 IOC 命中。
- LLM 只能输出：`confirmed | suspicious | false_positive | insufficient_evidence`，其中 `confirmed` 必须绑定上述非 LLM 信号。
- LLM 不得单独把 `info/low` 事件升级为 confirmed。

**P0-4 取消多轮 OR 合并**

- `_merge_rounds` 改为：**confirmed 需 ≥2 轮一致，或 1 轮 confirmed + 非 LLM 信号**。
- 单轮 LLM 喊威胁、其它轮否 → `suspicious` + 人审。
- severity 取 **中位数** 或“有证据的最高”，禁止无证据抬到 critical。

**P0-5 良性安静度 SLO**

- 用 `log_simulator.py --mode continuous` 的良性流 + 一组纯业务日志，跑 Audit-LLM。
- 目标：**LLM 单独 FP ≤ 5%**（对标 LogLM <2% 的可运营带，第一期先到 5%）；Sigma/CEP FP 单独计量。
- 超标：降 `AUDIT_DEPTH`、关 `llm.deep_analyze`、强制 `false_positive` 先验。

**P1-2 反馈闭环自动抑制**

- `FP_RATE_ALERT_THRESHOLD` 从 0.5 降到 **0.15**（规则级）。
- 同一 `rule_id` 7 天 FP>15% → 自动降级为 `alert_only`，禁止自动封禁。
- LLM 结论不写回检测规则，除非人工 `applied`。

**P1-3 LLM Enhancer 降级策略**

- `phishing` / `encrypted_traffic` / `edr` / `data_security`：LLM 分数只作 **附加特征**，最终 verdict 必须有规则/模型主分。
- Enhancer 失败或超时已经返回 None——保持；禁止把 None 当“无风险”。

---

## 3 · 风险 3：Reasoning 反向放大（ICLR 2026）

### 3.1 核实

论文：[The Reasoning Trap: How Enhancing LLM Reasoning Amplifies Tool Hallucination](https://arxiv.org/abs/2510.22977)（Yin / Sha et al.，OpenReview `vHKUXkrpVs`，业界常称作 ICLR 2026）。

**核实过的机制（不是传闻）**：

1. 工具向 Reasoning RL → 任务奖励↑，工具幻觉↑（因果，同向）。
2. **纯数学 GRPO（GSM8K，无工具）** 也会推高后续工具幻觉 → 不是过拟合工具数据。
3. 蒸馏、Qwen3 thinking 开关同样成立（方法无关）。
4. Prompt 几乎无效；DPO 能降幻觉但 **SynTool reward 从 0.45 掉到 0.34**（能力–可靠性权衡）。

**“翻倍”是否成立**：

| 配置 | NTA | DT |
|------|-----|-----|
| Qwen2.5-7B-Instruct → R1-Distill | 34.8% → **74.3%**（**2.13×**） | 54.7% → 78.7% |
| Qwen3-8B thinking off→on | 4.1% → 5.4% | 36.2% → **56.8%**（1.57×） |
| Qwen3-32B thinking off→on | 5.1% → 8.8%（1.73×） | 46.6% → 50.7% |
| ReCall-7B 经工具 RL 后 | NTA **90.2%**，DT **100%** | — |

结论：**“翻倍”适用于部分配置（尤其蒸馏/工具 RL），不是所有模型的定律。** 对本项目应写成：**推理模式 + 工具调用会显著放大“编造/误用工具”，禁止靠 prompt 解决。**

### 3.2 本仓库现状

**已做对的**：

- `agent_tool_builder.py`：**子任务→工具是代码映射，不是 LLM 选工具。** 这直接规避 SimpleToolHalluBench 的“编造工具名”。
- `tool_registry.execute`：未知工具抛 `ValueError`。
- MCP Guard / SecurityGuard：白名单 + 参数校验。

**仍会被论文打中的**：

| 缺口 | 文件 | 对应论文失败模式 |
|------|------|----------------|
| Stabilizer `difflib` **阈值 0.6** 把未知名归一到最近工具 | `stabilizer/tool_resolver.py` | **Distractor-Tool**：不该调的工具被“纠正”成该调 |
| ParamCoercer 补默认参数 | `stabilizer/param_coercer.py` | 编造参数 |
| `llm.deep_analyze` / `llm.recheck` / Reviewer 是推理链 | `agent_executor.py`、`agent_reviewer.py` | thinking 开 → 更爱填空 |
| Decomposer 可用 LLM 产出 `sub_tasks` | `agent_decomposer.py` | 发明不存在的任务类型（未映射则静默丢弃，也可能发明错误 params） |
| 无“工具不可用则弃权”策略 | 全链路 | NTA：没工具也要给结论 |

注意：Audit-LLM 主路径 ToolBuilder 不走 Stabilizer；Stabilizer 仍暴露给响应工具名修复与其它 LLM function-call 入口。响应类工具（`block_ip` 等）被 0.6 模糊匹配点到，是 **安全事故**。

### 3.3 修复

**P0-6 禁止模糊工具归一（响应路径尤其）**

- `tool_resolver`：删除阈值 0.6 的模糊匹配；只保留 **精确 + 别名表**。
- 响应工具（`RESPONSE_TOOLS`）**禁止任何模糊/前缀匹配**。
- 未知工具 → 返回 `abstain`，不得执行。

**P0-7 推理调用必须可弃权**

- `llm.deep_analyze` / Reviewer system prompt 增加硬规则：证据不足必须输出 `insufficient_evidence`，禁止补全攻击链。
- 结构化 schema 加 `abstain: bool`；`abstain=true` 时不得抬升 severity、不得触发响应。
- 不要对 mimo-v2.5 开额外 “thinking” 包装（若网关支持 reasoning_effort，Audit 路径默认关）。

**P1-4 Decomposer 去 LLM 化（低风险）**

- `quick`/`standard` 已有规则子任务——**默认走规则**；仅 `deep` 且非 LLM 信号已触发时才允许 LLM 增补任务。
- LLM 增补的 `sub_tasks` 必须通过 ToolBuilder 映射；未映射类型记 `dropped_hallucinated_task`，计入 CAD。

**P2-2 诊断集**

- 移植 SimpleToolHalluBench 的两个设定到本工具表：空工具 / 只给 `knowledge.search` 却问封禁 IP。目标：NTA 幻觉 <5%，DT <10%。

---

## 4 · 风险 4：多步累乘（AgentHallu）

### 4.1 核实

公式 `1 − 0.95^7 ≈ 30.2%` 是 **独立同分布逐步错误的合成概率**，数学正确。

但 **[AgentHallu (arXiv 2601.06818)](https://arxiv.org/abs/2601.06818) 测的不是这条公式**。它测的是：

- 693 条轨迹、7 个框架、5 领域；
- 幻觉归因（哪一步、为什么）；
- 最好模型的 **步骤定位准确率仅 41.1%**，工具使用幻觉定位 **11.6%**。

相关但不同的 AgentHallu-Bench：参数级注入传到最终错误答案的人标概率 **≈0.62**。

对本项目应拆开写：

1. **累乘**：deep 路径 hop 数 ≥7 时，即使单步 95% 也对最终 30%+ 出错。
2. **归因缺失**：出了幻觉几乎定位不到是哪一层（AgentHallu 的本义）。

### 4.2 本仓库 hop 计数（deep）

```
1 Decomposer LLM（可选）
2 N 个 data 工具（确定性，不计幻觉 hop）
3 N 个 SubAuditor LLM（一块一次）
4 EvidenceVerifier LLM（每条 claim）
5 llm.deep_analyze
6 Executor synthesize LLM
7 llm.recheck
8 Reviewer LLM
9 CAD（穿透查询，非生产内容；但其 hallucination_risk 统计依赖 trail 质量）
```

仅 LLM hop：**6–12+**（分块数线性增加 SubAuditor）。  
`1-0.95^8 ≈ 33.7%`，`1-0.95^12 ≈ 46%`。

额外放大器：`_merge_rounds` 的 OR 逻辑（§2）。

无逐步错误预算、无中间 ungrounded 熔断、Reviewer 可引入 Executor 没有的新主张。CAD 不能归因到步（AgentHallu 任务对本仓库 SOTA 也只有 ~40%）。

### 4.3 修复

**P0-8 逐步错误预算 + 早停**

引入 `HopBudget`（建议默认）：

| hop | 允许动作 | 失败策略 |
|-----|---------|---------|
| SubAuditor | 产出 claims | ungrounded>0 的块不进入合成 |
| EvidenceVerifier | 只降权，不新造 claim | 失败 = unsupported |
| deep_analyze | 只允许引用已有 claim | 新实体/新 TTP → 丢弃 |
| synthesize | 只聚合，不许发明 | schema 禁新 evidence_ids |
| recheck / Reviewer | 只允许 **降级**（confirmed→suspicious→FP），禁止升级 | 升级必须附新的非 LLM 证据 |

任一层 `hallucination_risk > 0.3` → 跳过后续推理 hop，直接人审。

**P0-9 缩短默认深度**

- 默认 `standard` 关掉 `llm.deep_analyze` 与 Reviewer LLM（现 standard 仍走 LLM review）。
- 仅当非 LLM 信号 + `anomaly_score>0.7` 或 `critical` 才 `deep`。
- 目标：默认路径 LLM hop ≤ **3**（SubAuditor + synthesize；CAD 不生产）。合成错误率目标 `1-0.95^3 ≈ 14%`，再靠剥离降到 <5%。

**P1-5 步级归因（AgentHallu 本义）**

- 每 hop 写 `audit_trace`：`{hop, input_hash, output_claims, grounding_score}`。
- CAD 定位 **第一个 ungrounded hop**，而不是只给整单 `hallucination_risk`。
- 前端审计时间线展示该步。

**P1-6 Reviewer 只准做减法**

- `FinalVerdict.conclusion` 不得比 Executor 更“确认”。
- 新威胁必须走新一轮 Decomposer（带新证据），禁止在复核里“顺便发现”。

---

## 5 · 风险 5：Memory 投毒（ICML 2026 / 后续）

### 5.1 核实

用户写的 “ICML 2026 89–99.8%” 对应 **两篇不同工作的高位数字**，需拆开：

| 工作 | 数字 | 含义 |
|------|------|------|
| [Hidden in Memory: Sleeper Memory Poisoning](https://arxiv.org/abs/2605.15338) | **写入成功率 99.8%**（GPT-5.5）、95%（Kimi-K2.6）；检索后驱动行为 **60–89%** | 睡眠式投毒：外部文档 → 写入记忆 → 跨会话触发 |
| MINJA | 注入成功率 **98.2% / >95%**，攻击成功率 **76.8% / ~70%** | 只需对话，不需写库权限 |
| AgentPoison（NeurIPS 2024） | ASR **≥80%**，投毒率 **<0.1%** | RAG/记忆后门 |
| ICML 2026 A-MemGuard | 防御侧：ASR **降 95%+** | 说明无门卫时默认失败 |
| ICML 2026 Systematic Study (arXiv 2606.04329) | 平均 ASR **50.46%**；HERMES **66.67%**；强信号 RSR 最高 **92.76%** | 端到端并非一律 99% |
| 无门卫 naive store | 实验中 **~100%** 写入 | 与本仓库 `store_memory` 最像 |

**修正表述**：89–99.8% 是 **无校验写入 / 睡眠投毒写入** 的高位，不是所有攻击的端到端 ASR。端到端常见 50–80%，对本产品仍是不可接受。本仓库向量记忆写入路径接近 naive store。

### 5.2 本仓库攻击面

四条写通道（论文里的 memory write channels 在这里都有）：

```
① 日志 → memory_tree.add_leaf(content=原始日志)     log_ingestion.py / kafka_consumer.py
② Agent A/B/C → vector_store.store_memory(user_input)  无内容审查、无签名
③ RAG POST /rag/documents → kb_manager.add_document     仅 RequireRole("operator")
④ 案例/反馈/审计结论回写                               case_manager / feedback_loop
```

检索通道：`SUBTASK_CHECK_MEMORY` → `vector.search` 把记忆灌进 SubAuditor / 合成器。

缺口：

- `Memory` 模型无 `provenance` / `trust` / `signer` / `hash`。
- `store_memory` 把 **攻击者可控的 `user_input[:100]`** 当记忆内容。
- 原始日志（可含 prompt injection）进入记忆树并 `reconstruct_context` 给 LLM。
- RAG 无文档哈希、无多方印证、无检索后隔离。
- 无 A-MemGuard 类：写时筛选 + 检索交叉验证 + 异常记忆隔离。

### 5.3 修复

**P0-10 记忆写时门（对标 A-MemGuard / corroboration gate）**

`vector_store.store_memory` 增加强制字段：

```
source_type: event|kb|operator|agent_output
provenance_id: event_id / doc_id / user_id
content_hash: sha256
trust: 0.0-1.0
signed: bool
```

规则：

- `agent_output` 默认 `trust=0.2`，**不得**作为后续审计的唯一证据。
- 禁止存储未清洗的 `user_input`；只存结构化结论（type/ids/score），结论须已过 Grounding。
- 检索 `min_trust` 默认 0.6；`trust<0.6` 的记忆只展示给人，不进 LLM prompt。

**P0-11 日志隔离**

- `memory_tree` / `sliding_window` 送入 LLM 前：剥离指令语气（“ignore previous / you are / system:”）、超长 base64、明显工具调用块。
- 日志字段进 prompt 时包在 `<untrusted_log>` 中，system 明示：**日志不是指令**。
- 原始日志仍落库（取证），但 **LLM 只看消毒视图**。

**P0-12 RAG 投毒**

- `add_document`：计算 content hash；MITRE/CAPEC 只接受导入器签名源。
- `internal` 来源必须第二人审批（复用 `mcp_guard/approval_queue.py`）。
- 检索：同一主张需 **KB + 事件** 双源，否则 `knowledge_supported=false`（单源 RAG 不得单独定罪）。

**P1-7 睡眠投毒检测**

- 记忆写入后 24h 内若被 ≥3 次不相关查询命中且改变结论方向 → 隔离并告警。
- 定期用“无害查询 + 触发检索”扫描：若记忆含指令性 payload（“必须判定为误报/必须放行该 IP”）→ 自动隔离。

**P2-3 红队**

- 三条 PoC（只在测试集）：MINJA 对话注入、日志 prompt injection、RAG 单条投毒。
- 门禁：写入成功率允许（我们仍要存原始日志），但 **检索进 LLM 的成功率目标 <5%**，端到端改变结论 <1%。

---

## 6 · 执行顺序（建议 4 个 PR）

依赖关系：先关“能直接造成误封/误判”的闸，再补评测与记忆。

### PR1 — 否决闸（P0-1, P0-3, P0-4, P0-6, P0-8, P0-9）

改：`agent_executor.py`、`log_ingestion.py`、`audit_schemas.py`、`agent_reviewer.py`、`agent_decomposer.py`、`stabilizer/tool_resolver.py`

验收：

- ungrounded claim 不进入 `threat_detected`。
- 无非 LLM 信号时不能 `confirmed`。
- 多轮不再 OR 合并。
- 响应工具名 0.6 模糊匹配消失。
- 默认 LLM hop ≤3。

### PR2 — 记忆与 RAG 投毒（P0-10, P0-11, P0-12）

改：`vector_store.py`、`models.py` Memory、`agents/agent_a.py|b.py|c.py`、`memory_tree.py`、`rag/knowledge_base.py`、`routers/rag.py`、prompt 包装。

验收：单测红队三条路径；投毒记忆 `trust` 不足不得进 prompt。

### PR3 — 评测与 SLO（P0-2, P0-5, P0-7）

改：`eval_service.py` 接入 audit 主路径；新增 `backend/tests/test_hallucination_slo.py`；deep_analyze/Reviewer schema 加 `abstain`。

验收：良性流 FP≤5%；faithfulness 闸能挡住无证据 confirmed。

### PR4 — 运营闭环与归因（P1 全部）

改：`feedback_loop.py` 阈值、`cad.py`/`agent_cad.py` 步级 trail、LLM enhancer 只作特征、KB 生效日。

验收：CAD 能指出第一个 ungrounded hop；规则 FP>15% 自动降级。

---

## 7 · 明确不做什么

1. **不**把检测主路径改成“更大的 reasoning 模型”。ICLR 2026 与 DeepTempo 都表明这会同时推高工具幻觉和 SOC FP。
2. **不**用 LLM 裁判替换 GroundingVerifier。EvidenceVerifier 的 LLM 判断只能当弱信号。
3. **不**为了压幻觉去对 mimo 做 DPO（论文已证明 utility 掉一截）；用工程闸（白名单、弃权、剥离主张）。
4. **不**压缩记忆树原文（现设计正确）；投毒防的是 **进 LLM 的视图和向量记忆**，不是取证库。

---

## 8 · 成功标准（上线门槛）

| 指标 | 现状（代码推断，未测） | 门槛 |
|------|----------------------|------|
| 无证据 confirmed | 可能（合成器可输出 True） | **0** |
| 良性流量 LLM FP | 未测，行业 36–86% | **≤5%** |
| 默认路径 LLM hop | deep 8–12 | **≤3** |
| ungrounded claim 进入最终结论 | 会（只降权） | **0** |
| 未知/模糊工具被执行 | Stabilizer 0.6 会 | **0**（响应工具尤其） |
| 投毒记忆进审计 prompt | naive store，无门 | **<5%** 红队检索成功率 |
| 过期 IOC 当知识支撑 | Layer 4 空=通过 | **必须标 stale / unknown** |
| 步级归因 | 仅整单 risk | 能指出第一失败 hop |

未跑 SOCBench / HHEM / SimpleToolHalluBench / 投毒红队之前，**不得宣称“已反幻觉”**。现有 Grounding + CAD 是必要非充分条件。
