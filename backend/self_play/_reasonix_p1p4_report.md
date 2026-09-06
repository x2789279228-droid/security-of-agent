# Reasonix — P1 蓝队规则生命周期 + P4 多指标评分 实施报告

> 日期: 2026-09-06
> 范围: P1-* / P4-* (按 `docs/upgrade-proposals/2026-q3-selfplay-training-quality.md`)
> 未触碰: `red_agent.py` `sim_env.py` `catalog.py` `novelty.py` `orchestrator.py` `curriculum.py` `planner.py` `types.py` `frontend/**` `tests/test_self_play.py` `tests/test_self_play_review.py` `tests/test_self_play_curriculum.py` `tests/test_self_play_sim_diversity.py` 以及上一会话(OpenCode P2/P3/P5)的全部产出。

## 1. 文件变更

| 文件 | 类型 | 摘要 |
|---|---|---|
| `backend/self_play/rule_lifecycle.py` | NEW | 同步生命周期: `generalize_rule` / `dedup_rule` / `validate_rule` / `ingest_learned_rule`(无 LLM、无网络)。 |
| `backend/self_play/overlay.py` | MOD | 新增 `SCORING_STATUSES`(`overlay/shadow/promoted/production`)、`CANDIDATE_STATUSES`(`candidate`);`detect(..., for_scoring=None/True/False, statuses=...)`,`for_scoring=None` 保持旧行为(全部除 dismissed,向后兼容 `test_miss_then_learn_then_hit`);新增 `detect_scoring()` / `detect_candidates()`。 |
| `backend/self_play/blue_learner.py` | MOD | `learn_from_misses` 在 `rule_from_miss`(+可选 LLM enrich)之后改走 `ingest_learned_rule`(`existing_rules=overlay.rules_for(match_id)`,新增可选 `history_events`);`distinctive_tokens` / `rule_from_miss` 保持不变。 |
| `backend/self_play/blue_observer.py` | MOD | 评分用 `overlay.detect_scoring`(obs.detected / overlay detector 标签);candidate 用 `detect_candidates` → `obs.candidate_detected` / `obs.candidate_rule_ids`,不设置 `obs.detected`;inject+wait_audit 威胁 → `obs.audit_detected=True`,仅当 `eval_channel=="audit"`(新 kwarg,observe_one/observe_many,默认 `"sim"`)才置 `obs.detected`。 |
| `backend/self_play/metrics.py` | MOD | 保留 ASR/recall/precision/MTTD/novelty/compounding;新增 `fbeta(β=1.5)`、`blue_score`(0.30 recall + 0.20 precision + 0.25 (1-asr) + 0.10 mttd + 0.10 compounding + 0.05 novelty,clip 0..1)、`red_score`(0.7 asr + 0.3 (1-recall))、`radar` 六维、分层 novelty(有 `score_layered` 用分层,否则 technique=score/其余=1.0)、`candidate_tp`(不进 tp/fn)、`mttc_ms`(overlay 命中平均 mttd)、`eval_channel`(events[0])、`round_metrics_from_dict`(缺失键用 dataclass 默认值,radar 恒 dict)、`merge_metrics`(保留旧键,radar 恒为 dict,不把 0 塞进 dict 字段)、`decide_winner`(综合分+间隔阈值)与 `decide_winner_legacy`(旧 recall/asr 阈值)。 |
| `backend/self_play/store.py` | MOD | 仅 `load_candidate_rules`:status 过滤改为 `("candidate", "overlay", "shadow", "promoted")`。 |
| `backend/tests/test_self_play_lifecycle.py` | NEW | 生命周期 7 个用例(见 §3)。 |
| `backend/tests/test_self_play_scoring.py` | NEW | 评分 13 个用例(见 §3)。 |

## 2. 验收映射

### P1(蓝队规则生命周期)

| ID | 状态 | 实现位置 |
|---|---|---|
| P1-A | ✅ | `learn_from_misses` 发生在 observe/score 之后,本回合刚学的规则不影响本回合 TP/FN;本回合内 candidate 只出现在评估通道(`detect_candidates` → `candidate_detected`,不计 TP/FN)。ⓘ 状态语义按主管决议调整:验证通过的规则直接 `status=overlay`(见 §4 风险 1),而非停留 candidate。 |
| P1-B | ✅ | `overlay.SCORING_STATUSES` + `detect(for_scoring=True)` / `detect_scoring`;`detect(for_scoring=False)` / `detect_candidates` 仅 candidate;默认 `for_scoring=None` 保持旧行为。`store.load_candidate_rules` 含 overlay,跨对局播种兼容。 |
| P1-C | ✅ | `validate_rule`:≥24 条 `DECOY_TEMPLATES` 负样本 + 历史 benign(`is_attack=False` / `_ground_truth=benign`),FPR<0.05;独立 TP = 历史 ATTACK 且指纹(或内容身份)≠源;无独立 TP 时仅 provisional(FPR ok ∧ 命中源事件);源 miss 永不计入独立 TP。使用 `overlay.match_rule`。 |
| P1-D | ✅ | `generalize_rule`:保 event 族;丢 src/dst IP(IPv4 形态)、len>40、`[A-Za-z0-9+/]{20,}` base64-ish、长 hex(`[a-fA-F0-9]{16,}`);`message_contains` 只留前 1–2 个幸存行为 token。 |
| P1-E | ✅ | `dedup_rule`:条件 token Jaccard≥0.8 或 同 mitre_id+同 event 族 → 重复;重复 → `status="dismissed"`,validation 写入 `duplicate:<rule_id>`。跳过自身与 dismissed。 |
| P1-F | ✅ | `validation` 每次摄取都写入;条件被泛化改变时 `parent_rule_id`(原为空时置原 rule_id)+ `version+=1`;`generalized=True` 恒置。 |
| P1-G | ✅ | `test_three_rounds_learn_evasion` 通过:R1 PORT_SCAN sigma 命中;R2 SYN_ENUM 规避 miss → ingest 验证(provisional)→ `status=overlay`;R3 同族变体被 `detect_scoring` 命中 → blue_win,`overlay_hits≥1`。`test_next_match_seeds_overlay_from_db` 亦通过(默认 detect 含 candidate;overlay status 已入 load_candidate_rules)。 |

### P4(多指标评估)

| ID | 状态 | 实现位置 |
|---|---|---|
| P4-A | ✅ | `score_round` 输出 recall / precision / `fbeta`(β=1.5) / ASR / MTTD / `mttc_ms` / 分层 novelty(`novelty_technique/parameter/sequence/scenario`,`novelty` 为 combined) / compounding / `blue_score` / `red_score` / `radar`。 |
| P4-B | ✅ | `decide_winner(cum)`:blue ≥0.62 且领先 ≥0.08;red ≥0.55 且领先 ≥0.08;否则 draw;缺 `blue_score/red_score` 键时从 recall/precision/asr/mttd/compounding/novelty 推导。`decide_winner_legacy` 保留旧阈值(orchestrator `_winner` 未动,接线由主管完成)。 |
| P4-C | ✅ | observer 通道分列:默认 sim(σ+overlay) 进 TP/FN;audit 威胁写 `audit_detected`,仅 `eval_channel="audit"` 时才计入 `obs.detected`;candidate 命中只写 `candidate_detected/candidate_rule_ids`。`metrics.eval_channel` 取 `events[0].eval_channel`。 |
| P4-D | ✅ | `radar`:coverage(=recall) / precision / mttd(1-min(mttd/5000,1)) / novelty_response(evasion 用 compounding,否则 novelty) / compounding / robustness(precision·(1-asr))。finalize 兼容:`merge_metrics` 恒回 dict `radar`;`round_metrics_from_dict` 供接线用(orchestrator 现有 `r.get(k, 0)` 路径下 radar 缺失时也不会把 0 传入 dict 字段——`merge_metrics` 内部已归一)。 |

## 3. 测试与结果

命令(自 `backend/`):

```
python -m pytest tests/test_self_play_lifecycle.py tests/test_self_play_scoring.py tests/test_self_play.py tests/test_self_play_curriculum.py tests/test_self_play_sim_diversity.py -q --tb=short
```

**结果: 76 passed, 1 failed** — 唯一失败为 `test_self_play.py::TestPersist::test_persist_writes_rounds_and_learned_rules` 中的 `assert all(r.status == "candidate" for r in rules)`(见 §4 风险 1,按主管决议保留 lifecycle 行为)。`test_three_rounds_learn_evasion`、`test_next_match_seeds_overlay_from_db`、`test_miss_then_learn_then_hit`、Sigma observer、curriculum、sim_diversity、review 全部通过。

新增测试清单:

- `tests/test_self_play_lifecycle.py`(7):摄取 miss→overlay(provisional)+ 前后 `detect_scoring` 对照;源 miss 不算独立 TP(空历史/仅源/不相关攻击/真独立变体四态);宽规则 FPR 失败留 candidate 且评分通道不命中、评估通道命中;重复 ingest dismissed 且不进评分命中;BlueLearner 走 lifecycle;泛化丢 IP+base64 留 2 个行为 token(version/parent 校验);条件未变时 version 不 bump。
- `tests/test_self_play_scoring.py`(13):复现 TestMetrics 口径(tp=2/fn=0/tn=1/recall=1/asr=0/precision=1/compounding=1,另验 fbeta/blue/red/radar/mttc/eval_channel);Fβ 落在 precision 与 recall 之间且 β>1 偏向 recall;decide_winner 蓝/红/平(分量推导 + 显式分数双路径)+ legacy 阈值;candidate_detected 不进 tp/fn(有 `candidate_tp`);merge_metrics radar 恒 dict、rounds==len(rows)、dict/缺键不炸、空列表;`round_metrics_from_dict` 默认值填充。

## 4. 遗留风险 / 待主管接线

1. **persist 状态断言(预期失败,待主管补丁)**: `test_persist_writes_rounds_and_learned_rules` 断言 DB 内全部规则 `status=="candidate"`;lifecycle 下验证通过的规则落库为 `"overlay"`(R2 学习的那条)。二者不可兼得(该断言与 `test_three_rounds_learn_evasion` 的 R3 overlay 命中互斥),按主管决议优先 lifecycle。建议断言改为 `all(r.status in {"candidate", "overlay", "dismissed"})` 或校验 `overlay` 规则带 `validation.passed`。其余断言(3 轮落库、miss 回合有 learned)均通过。
2. **orchestrator 仍用旧接线**(禁止改动文件): `_winner` 用 recall/asr 硬阈值、升级用 `consecutive_blue_wins`、合并用内联推导。`metrics.decide_winner` / `blue_score` / `round_metrics_from_dict` 已就绪,主管接线时:finalize 的 winner 换 `decide_winner(cum)`,dict→RoundMetrics 换 `round_metrics_from_dict`(radar 缺失安全);`play_round` 的 merge 已天然兼容(现传法 radar 为 dict)。
3. **eval_channel 接线**: observer 新 kwarg `eval_channel` 默认 `"sim"`,orchestrator 未传 → 全 sim 通道;主管把 `cfg.eval_channel` 传入 `observe_many(..., eval_channel=cfg.eval_channel)` 即可启用 audit 通道。
4. **generalize 截断顺序**: `rule_from_miss` 的 message token 顺序里 mitre 形 token("T1046"/"t1046")排在中文行为短语前,截断到 2 个时中文短语可能被裁掉;家族匹配由 `event_contains` 兜底(R3 仍命中),若要优先保留中文 token 需调 `distinctive_tokens` 排序(本次未动)。
5. **浮点误差**: `NoveltyIndex.score_layered` combined 对全 1.0 层返回 0.9999999999999999(novelty.py 权重求和,未改动),新测试用 `pytest.approx`。
6. **蓝方综合分口径**: `merge_metrics` 的 blue/red/fbeta 由合并后的 recall/precision/asr/mttd/compounding/novelty 重算,而非逐回合均分;`novelty_response` 在合并时用 `compounding>0` 近似"存在规避样本"(逐回合 `evasion_n` 不进 RoundMetrics 契约)。
7. **dismissed 落库**: 重复规则以 `status="dismissed"` 落库并写入 match overlay 桶(detect 全部跳过 dismissed,无评分影响;`load_candidate_rules` 不回灌)。
