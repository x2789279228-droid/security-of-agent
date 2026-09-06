# MiniMax QA：SOC Self-Play 仿真验收报告

- **执行日期**：2026-09-06
- **授权范围**：本机 SOC lab；仅检查 `host.docker.internal` / `127.0.0.1` 对应平台服务
- **总体结论**：**FAIL（端到端契约未完全通过）**

本地源码验收测试全部通过，Kali 注入与平台端口检查也通过；但容器内 API 实际返回的对局结果缺少验收标准要求的 P4 指标字段，且 P1-C 的 source-only miss 仍允许 provisional overlay。因此不能给出全量 PASS。

## 1. pytest

从 `backend/` 执行：

```text
python -m pytest -q tests/test_self_play*.py
95 passed in 1.70s
```

为覆盖验收配套模块，另执行 self-play/lifecycle/scoring/curriculum/diversity/wired/review、Sigma 加载与 prompt 完整性测试：

```text
104 passed in 2.27s
```

**结论：PASS。**

## 2. Kali 平台端口检查

执行限定命令：

```text
nmap -sT -Pn -T4 -p 8001,3001,2222,9093 host.docker.internal
```

结果：

| 端口 | 状态 |
|---|---|
| 8001/tcp | open |
| 3001/tcp | open |
| 2222/tcp | open |
| 9093/tcp | open |

`kali_sim_perf.py` 内的重复 TCP connect 也得到相同结果。未执行端口全扫描、子网扫描或禁用工具。

## 3. Kali 注入与 API 健康

使用 `SOC_TOKEN` 进行认证后执行同一注入脚本：

| 项目 | 结果 |
|---|---|
| `/api/health` | HTTP 200，`status=ok` |
| ingest batch | HTTP 200 |
| ingest ok | 8 |
| ingest fail | 0 |
| 平均延迟 | 11.9 ms |
| p95 延迟 | 11.9 ms |
| log status | HTTP 200 |
| 立即查询的日志计数 | `total_events=0, analyzed=0, pending=0` |

未认证的首次尝试按脚本预期返回 HTTP 401；补入认证令牌后重试成功，因此没有将其计为 ingest 失败。日志状态是脚本结束时的即时检查，未等待异步分析完成。

## 4. 指定 self-play 实测

请求参数：

```json
{
  "rounds": 4,
  "curriculum": true,
  "inject": false,
  "use_llm": false,
  "decoy_ratio": 0.2,
  "diverse_env": false
}
```

结果：

- **match_id**：`sp-a86abb05cefc`
- **via**：`temporal`
- **状态**：`completed`
- **总回合 / 完成回合**：4 / 4
- **耗时**：约 29 秒
- **winner**：`blue`
- **radar**：`null`（API 未返回）
- **blue_score**：`null`（API 未返回）
- **recall**：`1.0`
- **precision**：`1.0`
- **asr**：`0.0`
- **level**：`null`
- **可观察的 curriculum_level**：`1`
- **累计 round metrics**：`tp=4, fp=0, fn=0, tn=4, mttd_ms=38.5817, novelty=0.6667, compounding=0.75, overlay_hits=3, sigma_hits=1`

`/api/self-play/metrics` 聚合值：

- `matches=11`，`completed=11`
- winners：red 0、blue 5、draw 6
- `avg_asr=0.2589355`
- `avg_recall=0.7410645`
- `avg_precision=1.0`
- `avg_novelty=0.5774552`
- `avg_compounding=0.5659091`

## 5. P1–P5 / N 验收

判定以 `test_self_play*.py` 的 95 个测试及补充的 104 个测试为基础；P4 同时要求容器内 API 返回完整契约。

| 类别 | ID | 结论 | 证据 / 说明 |
|---|---|---|---|
| P1 | P1-A | **PASS** | 当前回合先评分再学习；candidate 不进入本回合 TP/FN，单测通过。 |
| P1 | P1-B | **PASS** | 评分通道只纳入 overlay/shadow/promoted/production，单测通过。 |
| P1 | P1-C | **PARTIAL（严格验收计 FAIL 风险）** | FPR `<0.05` 门和 source miss 不得算独立正样本已通过；但 source-only miss 仍可形成 `provisional` 并直接 overlay。 |
| P1 | P1-D | **PASS** | IP、超长 token、base64 泛化与行为 token 保留测试通过。 |
| P1 | P1-E | **PASS** | Jaccard / mitre+event 去重测试通过。 |
| P1 | P1-F | **PASS** | `version`、`parent_rule_id`、`validation` 字段测试通过。 |
| P1 | P1-G | **PASS** | 三回合学习与同族变体 overlay 命中测试通过。 |
| P2 | P2-A | **PASS** | curriculum 的目录与 LLM 路径共享同一个 `RoundGoal`。 |
| P2 | P2-B | **PASS** | 非 goal 家族 TTP 被 planner 拒绝并回退。 |
| P2 | P2-C | **PASS** | T1059、T1059.001、T1059.006 可区分，相关测试通过。 |
| P2 | P2-D | **PASS（单测）；端到端证据不完整** | `rounds_at_level` 与概率升级逻辑测试通过；本次 API 仅返回最终 `curriculum_level=1`，未返回每回合 level。 |
| P2 | P2-E | **PASS（单测）** | 低能力降级条件测试通过。 |
| P3 | P3-A | **PASS** | 默认 10 主机固定拓扑保持不变。 |
| P3 | P3-B | **PASS** | 8–30 主机与角色/分区生成测试通过。 |
| P3 | P3-C | **PASS** | DNS、内部 HTTP、文件访问、登录等 benign 背景事件测试通过。 |
| P3 | P3-D | **PASS** | 内部 DNS / HTTP / 主机通信场景测试通过。 |
| P3 | P3-E | **PASS** | diverse 模式源/目标不再固定于默认地址，测试通过。 |
| P3 | P3-F | **PASS** | 生成日志不含真实 exploit payload，相关断言通过。 |
| P4 | P4-A | **FAIL（端到端）** | 单元评分测试通过，但 live API 的累计与逐回合 metrics 都没有 `fbeta`、`mttc_ms`、`blue_score`、`red_score`、radar 或分层 novelty 字段。 |
| P4 | P4-B | **PASS（单测）** | 综合分胜负测试通过；本次 winner 与低 ASR/high recall 结果一致。 |
| P4 | P4-C | **PARTIAL** | `eval_channel` 分离单测通过；live API 未返回 `eval_channel`，本轮未启用 audit，无法通过本轮端到端证明。 |
| P4 | P4-D | **FAIL（端到端）** | 验收要求返回六维 radar；live API 明确返回 `radar=null`。 |
| P5 | P5-A | **PASS** | `observe_gaps` 更新漏检/覆盖记忆，测试通过。 |
| P5 | P5-B | **PASS** | 无 goal 时按低覆盖 / 高 FN 选型，测试通过。 |
| P5 | P5-C | **PASS** | 有 goal 时不因盲区推翻课程技术，测试通过。 |
| N | N-A | **PASS** | technique/parameter/sequence/scenario 分层 novelty 测试通过。 |
| N | N-B | **PASS** | 旧 `score()` 保留，unseen 后下降语义测试通过。 |

## 6. 缺陷与遗留风险

1. **P4 运行时契约缺失**：指定的 4 回合已完成，但 API 没有暴露验收标准要求的 `blue_score`、`radar`、`fbeta`、`mttc_ms`、分层 novelty 等字段；累计 metrics 仅保留旧版基础字段。需要核对运行中的 backend/Temporal worker 是否包含当前源码版本及其序列化路径。
2. **level 字段缺失**：匹配记录返回 `curriculum_level=1`，但顶层 `level=null`，四个回合记录中的 `level` 也为 `null`；课程升级的运行时证据不完整。
3. **P1-C 仍是 provisional 缺口**：source-only miss 可以 provisional 升为 overlay，虽然不是宣称独立正样本，但严格按“独立验证后才升 overlay”解读仍不满足。
4. **配置回显不完整**：live match config 未回显 `diverse_env`、`env_seed`、`background_traffic`、`eval_channel` 等字段。本轮 `diverse_env=false`，不影响本次默认拓扑执行，但不利于验证完整参数传递。
5. **异步日志状态未等待**：`log_status=200` 时即时结果仍为 0 个事件；本次只确认了入队成功，不能据此断言后续分析已消费完成。
6. **前端雷达未做浏览器交互验收**；本报告结论仅覆盖后端、Kali 注入和 API 响应。

## 7. 最终判定

- **测试：PASS**（95 个自博弈测试；补充验收套件 104 个）
- **Kali 端口 / 注入：PASS**（限定端口均 open；8 条全部入队）
- **指定 self-play 基础结果：PASS**（4/4 completed，blue 胜，recall/precision=1，ASR=0）
- **P1-P5/N 端到端验收：FAIL**，主要由 live API 缺少 P4-A/P4-D 字段及 `level` 证据不足导致。
