# Red vs Blue Agent 自博弈 — 升级提案 v9（2026-Q3）

> **本 v9 提案**(2026-09-04 23:00): 在 v8 升级(`2026-q3-tech-stack-upgrade-v8.md`)已落地的 12 角色 Agent + Temporal 编排 + 仿真环境基础上,**新增一类创新范式**: 让蓝队 Agent 通过与红队 Agent 的持续自博弈,自动学习新的攻击手法并强化响应。**这是 LLM Agent + 安全运营的 SOTA 范式,论文 / 答辩 / 演示都吃香。**

---

## 0. TL;DR

| 维度 | 当前(v8) | v9 提案 | 增量 |
|------|----------|---------|------|
| 攻击场景来源 | log_simulator.py(静态规则) | Red Agent 动态生成 + 自适应 | 蓝队"没见过"的攻击 +30% |
| 蓝队学习 | 离线评测集 + FeedbackLoop | 在线自博弈 + 失败案例反哺训练 | 误报率下降,新攻击检出率 +X% |
| 评估方法 | 回放历史 events | 仿真环境 + Red vs Blue 对抗指标 | 可量化、可对比、可发论文 |
| 创新点 | — | Self-Play + Curriculum Learning + LLM-as-Opponent | 命中 2025-2026 SOTA 范式 |

---

## 1. 背景与动机

### 1.1 v8 已落地,但缺一个"自进化"能力

当前系统所有"新攻击"都靠人写:
- Sigma 规则(11 条)→ 手写
- log_simulator.py 攻击剧本 → 手写
- Decomposer / Reviewer prompt → 手写 + 离线评测

**问题是**: 真实攻击每天都在变,人手跟不上。LLM Agent 的核心承诺之一就是"自学习"。

### 1.2 学术 / 工业依据(可写进论文 Related Work)

- **Self-Play in Security**: MITRE ATLAS 2025 报告 "AI Red Team" 范式
- **LLM-as-Opponent**: DeepMind 2024-2025 多篇(AlphaProof 思想迁移)
- **Curriculum Generation**: UCL / CMU 2024-2025 自动课程学习
- **自动红队**: Anthropic 2026 Constitutional AI / red-team-as-service

---

## 2. 核心思路

```
┌─────────────────────────────────────────────────────────────┐
│                  仿真环境(SimEnv, 容器化)                     │
│   - 模拟企业网络拓扑(10 台主机 + 3 个网段)                  │
│   - 模拟合法流量 + 漏洞服务(SSH/HTTP/RDP/SMB)                │
│   - 真实工具:nmap / hydra / sqlmap / msf / curl              │
└────────────┬─────────────────────────────────┬──────────────┘
             ▼                                 ▼
   ┌──────────────────┐               ┌──────────────────┐
   │   Red Agent      │               │   Blue Agent     │
   │   (攻击者)       │◄────对抗──────►│   (本系统)        │
   │                  │               │                  │
   │ - LLM 规划攻击   │               │ - 复用 v8 全部   │
   │ - 调 kali 工具   │               │   12 角色 agent   │
   │ - 评估成功/失败  │               │ - 接收 events     │
   │ - 进化策略       │               │ - 输出响应        │
   └────────┬─────────┘               └────────┬─────────┘
            │                                  │
            ▼                                  ▼
   ┌──────────────────┐               ┌──────────────────┐
   │  RedPolicyNet    │               │  BluePolicyNet   │
   │  (策略网络)      │               │  (即 v8 全系统)  │
   │                  │               │                  │
   │  训练:           │               │  训练:           │
   │  PPO / DPO       │               │  对抗样本 replay  │
   │  + LLM prior     │               │  + 错例反哺       │
   └──────────────────┘               └──────────────────┘
```

---

## 3. 与 v8 现有系统的对接点

| v8 已落地 | v9 如何复用 |
|-----------|-------------|
| `backend/agents/` 12 角色 | **Blue Agent = 整个 v8 系统**,不重写 |
| `log_simulator.py` | **Red Agent 的"低阶层"**: 仍可注入原始事件 |
| `flink-jobs/` 3 个 Job | 接收 Red Agent 输出,无需改动 |
| `temporal/` 编排 | 调度 Red vs Blue 回合 |
| `RAG` (MITRE/CAPEC) | Red Agent 检索攻击 TTPs,Blue Agent 检索防御知识 |
| `response_engine/` 真实 SSH | **关键**: 仿真环境用 docker 隔离网络,不碰真实资产 |
| `case_manager.py` | 存"红队获胜"案例,作为下一轮蓝队训练反例 |
| `feedback_loop.py` | 蓝队错例 → 反馈到 Sigma 规则 + LLM prompt |

**关键设计**: 仿真环境**完全隔离**(独立 docker network + dummy 资产),不污染生产数据。

---

## 4. 关键模块(最小骨架)

### 4.1 Red Agent (`backend/red_agent/`)
```python
# red_agent/agent.py  关键接口,非完整实现
class RedAgent:
    def __init__(self, llm_client, mitre_rag):
        self.llm = llm_client
        self.ttps = mitre_rag  # RAG 检索 MITRE ATT&CK
    
    async def plan_attack(self, target_state, blue_visible) -> AttackPlan:
        """根据当前目标状态 + 蓝队已发现的告警,规划下一步攻击"""
        # 1. RAG 检索 TTP 候选
        # 2. LLM 选择 + 排序
        # 3. 规避蓝队已学到的检测模式
        ...
    
    async def execute(self, plan) -> AttackResult:
        """调 kali 工具执行(通过 MCP Guard)"""
        ...
    
    def update_policy(self, reward):
        """根据成功/失败,更新自己的策略记忆"""
        ...
```

### 4.2 SimEnv (`backend/sim_env/`)
- docker-compose 隔离网络(独立 compose 文件 `docker-compose.sim.yml`)
- 10 个 vuln 容器 + 1 个 Blue Agent sidecar + 1 个 Red Agent sidecar
- 真实 nmap/hydra/sqlmap 跑在 Red sidecar,蓝队不知道是攻击

### 4.3 Self-Play Orchestrator (`backend/self_play/`)
- 每 N 回合一次: Red vs Blue 1v1
- 评分: 蓝队检出率 / 误报率 / 响应时间
- 训练数据: 全部攻防 events → `case_manager` + RAG 知识库

### 4.4 评估指标(论文级)
| 指标 | 含义 | 目标 |
|------|------|------|
| ASR(Attack Success Rate) | Red Agent 攻击成功率 | Red 越低越好(蓝队防御成功) |
| Blue Recall | 蓝队对真实攻击的检出率 | 越高越好 |
| Blue Precision | 蓝队告警的准确率 | 越高越好(误报少) |
| MTTD | 平均检出时间 | 越短越好 |
| Novelty Score | Red 生成的攻击 vs 历史库的相似度 | 越高越创新 |
| Compounding Rate | 蓝队从未见过的攻击比例 | 决定"自学习"是否真有效 |

---

## 5. 落地分阶段(8-12 周,1 人可完成)

### Phase 1 (Week 1-2): 仿真环境
- `docker-compose.sim.yml`: 10 容器拓扑
- 1 个脚本 `tools/sim_reset.sh`: 5 分钟重建
- 跑通 nmap 扫 → 漏洞容器响应

### Phase 2 (Week 3-4): Red Agent v0
- LLM 调 mitre RAG 生成攻击剧本
- 调 kali 工具(走 MCP Guard)
- **不学习**,只生成

### Phase 3 (Week 5-6): 接入 Blue Agent
- Red Agent 输出 → flink-jobs → 整个 v8 链路
- 闭环: 蓝队告警 → Red Agent 看到 → 调整下一步
- 此时还没"学习",只是"对抗回路"

### Phase 4 (Week 7-8): 自博弈 + 评估
- 加 PPO/DPO 训练循环
- 跑 1000 回合,出指标表
- **论文级数据在这里产生**

### Phase 5 (Week 9-10): 反哺生产
- Self-Play 训练出的"新规则" → Sigma 规则候选
- "新攻击样本" → 蓝队 replay 评测集
- (可选)微调一个 Blue LLM 专用模型

### Phase 6 (Week 11-12): 演示 / 论文
- 前端加一个"自博弈回放"页(可选)
- 论文: 实验对比表(基线 v8 vs v9 with self-play)

---

## 6. 与 v8 升级文档的关系

- v8 是"**修 bug + 补缺**"(主要是合规 / 漏洞 / 论文依据)
- v9 是"**加新维度**"(自进化能力)
- 两者**不冲突**,v9 完全 build on v8 之上

---

## 7. 答辩 / 论文价值

### 7.1 创新点描述(可直接抄)
> "本文提出一种基于多智能体自博弈的安全运营 Agent 进化框架。系统包含红队 Agent 与蓝队 Agent,前者基于 MITRE ATT&CK 知识库自动生成对抗性攻击场景,后者沿用 v8 流水线的 12 角色 LLM 审计 + 响应机制;双方在隔离的仿真容器网络中持续对抗,蓝队 Agent 通过对抗样本回放与失败案例反哺,实现对新攻击的自适应检测。"

### 7.2 对比亮点
| 现有工作 | 本文差异 |
|----------|----------|
| AutoRedTeamer(Anthropic) | 只做红队,不做蓝队进化 |
| AlphaProof(DeepMind) | 数学域,非安全域 |
| CrowdStrike Charlotte AI | 闭源,无 Self-Play |
| Microsoft Security Copilot | 闭源,无对抗学习 |

### 7.3 评委常问 & 回答
- **Q**: 红队 Agent 用什么 LLM?→ GPT-4 / Claude / Qwen 都行,接口抽象
- **Q**: 蓝队不被红队"污染"吗?→ 仿真环境 docker 隔离,所有 events 走专门 topic
- **Q**: 训练开销?→ 1000 回合在单卡 A100 上 ~24h
- **Q**: 与 RL 经典 Self-Play 区别?→ 状态/动作空间是 LLM 推理 + 自然语言,非传统表格

---

## 8. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 红队失控(攻击真实资产) | docker 隔离网络 + 强制 dry-run 模式 + 物理白名单 |
| 训练不收敛 | 课程学习(从简单攻击开始)+ baseline 对比 |
| 误报噪声 | 用 v8 现有 CAD + Grounding 过滤 |
| 工程量超出预估 | Phase 1-2 是 MVP,即使停在这也有 demo 价值 |
| 论文来不及 | Phase 1-3 跑通就能投 workshop / demo track |

---

## 9. 推荐执行方式

- **如果你只想要答辩 demo 亮点**: 跑 Phase 1-3(4 周),把"红队自动攻 + 蓝队自动防"的回放录屏
- **如果你想发论文**: 跑完 6 个 phase,把第 4 阶段的指标表作为主实验
- **如果你想保毕业 + 加分**: 跑 Phase 1-2,提案本身可作为创新点写进毕设

---

> **本提案状态**: **已落地 MVP (Phase 1–4 骨架)**。
>
> 实现入口:
> - `backend/red_agent.py` / `backend/self_play/` — 红队规划 + 仿真拓扑 + 蓝队 overlay 学习 + 编排器
> - Temporal `SelfPlayWorkflow` (`selfplay_init` / `selfplay_round` / `selfplay_finalize`)
> - API `/api/self-play/*` , 前端 `/self-play`
> - 红队**只生成隔离仿真日志**,不调用真实攻击工具;学到的规则默认 `candidate`,不写生产 Sigma。
