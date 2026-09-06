# Self-Play 训练闭环质量升级 — 方案与验收标准

> 日期：2026-09-06
> 范围：`shared-memory-platform/backend/self_play/` + 配套测试 + SelfPlay 页雷达
> 目标：把演示级红蓝闭环升级为可稳定训练蓝队检测能力的回路

## 0. 总目标

保留现有闭环（攻击 → 仿真 → 检测 → 学习 → 评分 → 课程推进），修正五类会破坏训练信号的问题：

1. 蓝队规则缺少验证就进检测（过拟合 / 规则膨胀）
2. 课程粒度粗，LLM 路径不受课程约束
3. 仿真拓扑固定，蓝队记忆环境
4. 胜负只靠 ASR/recall 硬阈值，忽略 precision 与其它指标
5. 红队几乎不学习，对抗平衡会失效

## 1. 目标拆解与验收标准

### P1 蓝队规则生命周期（最高优先）

**行为**

```
miss → candidate（本回合不计入评分）
     → generalize（去掉具体命令行 / IP）
     → dedup
     → validate（独立负样本 FPR + 非源样本 TP 或 provisional）
     → overlay（仅下一回合及以后参与评分）
     → reviewer shadow → promoted
```

**验收**

| ID | 标准 |
|---|---|
| P1-A | `learn_from_misses` 产出 `status=candidate`，**不得**把本回合刚学到的规则用于本回合 `score_round` 的 TP/FN |
| P1-B | overlay 默认评分只认 `overlay/shadow/promoted/production`；candidate 走 `detect(..., for_scoring=False)` 仅评估 |
| P1-C | 独立验证：decoy + 历史 benign 上 FPR < 0.05 才升 overlay；源 miss 不能当唯一正样本宣称泛化成功 |
| P1-D | 泛化：去掉 src/dst IP、超长命令行、base64；保留 event 族 + 1–2 个行为 token |
| P1-E | Jaccard≥0.8 或同 mitre+event 去重合并，不产生碎片规则 |
| P1-F | 规则带 `version` / `parent_rule_id` / `validation` |
| P1-G | 旧测试 `test_three_rounds_learn_evasion` 仍成立：R2 学到并验证后，R3 overlay 能抓住同族变体 |

### P2 课程控制统一化

**行为**

```
CurriculumPolicy.select_goal(state) → RoundGoal(technique, sub_technique, scenario, difficulty)
RedAgent.plan_attack(goal=...)      → 无论 LLM / 目录都必须围绕 goal
planner.materialize_goal(goal, topo)→ 映射到当前 SimEnv 可执行 AttackStep
```

**验收**

| ID | 标准 |
|---|---|
| P2-A | `use_llm=True/False` 两条路径都消费同一个 `RoundGoal` |
| P2-B | LLM 输出的 TTP 若不在 goal 允许集或不在当前拓扑可执行集，被 planner 拒绝并回退到 goal 金标 |
| P2-C | 课程粒度到 sub-technique（至少 T1059.001 / T1059.006 与 T1059 父技术可区分） |
| P2-D | 升级不再是「连续 2 次 blue_win」：`rounds_at_level≥3` 且 `P(level_clear)>0.8`（当前 level 目标技术 mean recall≥0.7、mean ASR≤0.35、近 N 轮蓝胜率≥0.6） |
| P2-E | 能力过差可降级：`rounds_at_level≥4` 且 `P(level_clear)<0.25` |

### P3 仿真环境多样性

**验收**

| ID | 标准 |
|---|---|
| P3-A | 默认 `SimEnv()` / `topology()` **仍是** 10 主机固定拓扑（兼容旧测试） |
| P3-B | `diverse=True` 时主机数 8–30，角色/分区随机（web/db/ad/fs/dev/ws/jump/dmz/lan/user/isolated） |
| P3-C | `background_traffic=True` 时每回合附加 DNS / 内部 HTTP / 文件访问 / 登录等 benign 事件，且 `is_attack=False` |
| P3-D | 即使不出网，也有内部 DNS、HTTP 代理、主机间通信事件 |
| P3-E | 物化后的 src/dst IP 不再恒等于 `10.0.0.3→10.0.0.7` 或固定 `ws-01=10.0.30.11`（diverse 模式下） |
| P3-F | 日志仍是 SOC 描述，不含真实 exploit payload |

### P4 多指标评估

**验收**

| ID | 标准 |
|---|---|
| P4-A | `score_round` 输出 recall / precision / Fβ(β=1.5) / ASR / MTTD / MTTC / layered novelty / compounding / blue_score / radar |
| P4-B | match winner 用加权综合分 + 间隔阈值，不再只靠 `recall≥0.7 ∧ asr≤0.35` |
| P4-C | `inject` 审计通道与仿真通道分列：默认评分用 sim（sigma+overlay）；audit 命中写入 `audit_detected`，不混进 TP/FN |
| P4-D | finalize 返回 `radar` 六维：coverage、precision、mttd、novelty_response、compounding、robustness |

### P5 红队学习

**验收**

| ID | 标准 |
|---|---|
| P5-A | `RedAgent.observe_gaps(missed_ttps, covered)` 更新盲区记忆 |
| P5-B | 无 goal 强制时，优先选择低蓝队覆盖 / 高 FN 的 technique |
| P5-C | 有 RoundGoal 时仍必须打 goal，盲区只影响 variant / 参数，不推翻课程 |

### Novelty 分层

**验收**

| ID | 标准 |
|---|---|
| N-A | `NoveltyIndex.score_layered` 分开 technique / parameter / sequence / scenario |
| N-B | 旧 `score()` 仍可用，语义为四层加权组合，旧测试 `unseen=1 then drops` 仍过 |

## 2. 文件范围（防抢文件）

### Reasonix（P1+P4）

- NEW `backend/self_play/rule_lifecycle.py`
- MOD `backend/self_play/blue_learner.py`
- MOD `backend/self_play/overlay.py`
- MOD `backend/self_play/metrics.py`
- MOD `backend/self_play/blue_observer.py`
- MOD `backend/self_play/store.py`（仅 `load_candidate_rules` 分层）
- NEW `backend/tests/test_self_play_lifecycle.py`
- NEW `backend/tests/test_self_play_scoring.py`

**禁止改**：`red_agent.py` `sim_env.py` `catalog.py` `novelty.py` `orchestrator.py` `curriculum.py` `planner.py`

### OpenCode（P2+P3+P5+Novelty）

- NEW `backend/self_play/curriculum.py`
- NEW `backend/self_play/planner.py`
- MOD `backend/self_play/red_agent.py`
- MOD `backend/self_play/sim_env.py`
- MOD `backend/self_play/novelty.py`
- MOD `backend/self_play/catalog.py`（sub-technique，不改 L0 唯一 PORT_SCAN）
- NEW `backend/tests/test_self_play_curriculum.py`
- NEW `backend/tests/test_self_play_sim_diversity.py`

**禁止改**：`blue_learner.py` `overlay.py` `metrics.py` `blue_observer.py` `store.py` `orchestrator.py` `rule_lifecycle.py`

### 主管后续接线

- `backend/self_play/orchestrator.py`
- `backend/self_play/__init__.py`
- `backend/self_play/types.py`（契约已锁，只允许修 bug）
- `backend/tests/test_self_play.py`（兼容旧断言）
- `backend/config.py`（如需新开关）
- `frontend/src/pages/SelfPlay.tsx`（雷达）

## 3. 契约（`types.py`）

已落地的关键类型：`RoundGoal` `CapabilityState` `LayeredNovelty` `LearnedRule.validation/version` `RoundMetrics.blue_score/radar/fbeta/...` `MatchConfig.diverse_env/eval_channel` `EventObservation.candidate_detected/audit_detected`。

实现必须 JSON 可序列化，供 Temporal activity 使用。

## 4. 闭环（接线后）

```
init_match
  CurriculumPolicy 选 RoundGoal
  RedAgent.generate_plan(goal) + planner 映射
  SimEnv 执行（可选 diverse + 背景流量）
  BlueObserver：production Sigma + stable overlay 评分
                candidate 仅评估
  BlueLearner → lifecycle.validate → overlay（下回合）
  NoveltyIndex 分层更新
  score_round 多指标（sim 通道）
  CurriculumPolicy 更新能力模型
finalize：雷达 + winner(综合分) + 规则增量
```
