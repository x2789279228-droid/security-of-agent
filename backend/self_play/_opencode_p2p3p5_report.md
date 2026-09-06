# OpenCode 实施报告 — P2 统一课程 / P3 仿真多样性 / P5 红队学习 / 分层 Novelty

> 日期: 2026-09-06
> 范围: `backend/self_play/` (OpenCode 分工部分) — 未触碰 Reasonix 分工文件与 orchestrator

## 1. 文件变更

| 文件 | 类型 | 内容 |
|---|---|---|
| `backend/self_play/catalog.py` | MOD | `TTPSpec` 新增可选字段 `sub_technique_id` / `behaviors` / `data_sources`(带默认值,冻结数据类兼容);新增两条 L3 子技术规格: `T1059.001`(POSH_EXEC, ttp-t1059-001-ps, behaviors 含 powershell)、`T1059.006`(PY_INTERPRETER, ttp-t1059-006-py, behaviors 含 python)。L0 未动,`ttps_at_level(0)` 事件类型仍恰为 `["PORT_SCAN"]`;`get_ttp("T1059")` 仍返回父技术 SCRIPT_EXEC;`get_ttp("T1059.001")`/`get_ttp("T1059.006")` 可解析。message 均为 SOC 日志描述,无利用 payload |
| `backend/self_play/curriculum.py` | NEW | `CurriculumPolicy.select_goal / update / p_level_clear / maybe_advance` |
| `backend/self_play/planner.py` | NEW | `ExecutablePlanner.bind/__init__(env) / executable / map_spec / constrain_steps` |
| `backend/self_play/red_agent.py` | MOD | `plan_attack(..., goal=None)`;`_choose_spec` 优先 `get_ttp(goal.ttp_id/sub/technique)`;`_llm_pick` 把 goal JSON 挂进既有 `blue_view` prompt 字段(模板未改,保持 strict_render 兼容);LLM 步骤经 `ExecutablePlanner.constrain_steps` 约束,空则回退 goal 金标;新增 `observe_gaps(missed, covered)`、`prefer_gap_specs(pool)`;`_choose_spec` 在无 blue 复用命中且 memory 非空时按盲区重排(空 memory 时稳定排序,行为不变);`_step_from_spec` 携带 sub_technique/behaviors/data_sources;goal=None 路径行为保持(含 BlueView last_missed 复用) |
| `backend/self_play/sim_env.py` | MOD | 模块级 `HOSTS`(10 台)、`ATTACKER_IP`、`topology()`、`host_by_role()`、`host_by_id()` 不变;新增 `generate_topology(seed, n_hosts)`(8–30 台,角色 web/app/db/dc/fs/ws/jump/vpn/mail/dev,分区 dmz/lan/user/isolated,IP 落在 `10.{100..250}.x.x`,与默认拓扑不重叠,确定性可复现,保证 web/ws/dc/fs 存在);`SimEnv(diverse, seed, n_hosts)`,实例化 `self.hosts`,内部源=实例首个 ws(默认仍 ws-01/10.0.30.11);新增 `background_events(n)`(DNS/内部 HTTP 代理/FILE_ACCESS/USER_LOGIN,`is_attack=False`,`eval_channel=sim`,不出网,HTTP 目标优先 proxy 角色否则 web);`materialize_plan(..., background_n=0)` 追加背景事件;materialize 填充 `sub_technique_id` |
| `backend/self_play/novelty.py` | MOD | 保留 `tokenize/fingerprint/jaccard/score/observe/dump/load` 原语义;新增 `layered_fingerprint(evt)`(technique=MITRE 父技术 T1059.001→T1059 且含完整 id;parameter=message+protocol 词法−技术 id;sequence=event_type+kill_chain(extra._kill_chain);scenario=src_host/dst_host/protocol/zone)、`NoveltyIndex.observe_event / score_layered(0.4/0.3/0.2/0.1 合成) / dump_layered / load_layered` |
| `backend/tests/test_self_play_curriculum.py` | NEW | 17 个用例(见 §3) |
| `backend/tests/test_self_play_sim_diversity.py` | NEW | 12 个用例(见 §3) |
| `backend/self_play/_opencode_p2p3p5_report.md` | NEW | 本报告 |

**未触碰**(按分工约束): `blue_learner.py` `overlay.py` `metrics.py` `blue_observer.py` `store.py` `orchestrator.py` `rule_lifecycle.py` `types.py` `frontend/**` `tests/test_self_play.py` `tests/test_self_play_review.py` `prompts/**/*.j2`

## 2. 测试与结果

```
python -m pytest tests/test_self_play_curriculum.py tests/test_self_play_sim_diversity.py tests/test_self_play.py -q --tb=short
→ 57 passed in 0.99s
```

追加回归(邻居模块):

```
python -m pytest tests/test_prompts_integrity.py tests/test_self_play_review.py tests/test_sigma_selfplay_load.py \
  tests/test_self_play.py tests/test_self_play_curriculum.py tests/test_self_play_sim_diversity.py -q --tb=short
→ 78 passed in 2.02s
```

原有 `tests/test_self_play.py` 20 个用例全部原样通过(未弱化任何断言),包括:
`test_topology_has_ten_hosts_and_isolation_note`、`test_llm_multi_step_kill_chain`(goal=None 时 3 步 T1046/T1059/T1021 物化,首步 src 203.0.113.50、次步 10.0.30.11)、`test_enterprise_pool_covers_attack_parent_techniques`(L0 唯一 PORT_SCAN、`get_ttp("T1059").mitre_id=="T1059"`)、`test_unseen_is_one_then_drops`。

## 3. 新测试覆盖点

`test_self_play_curriculum.py`:
1. L0 select_goal → T1046 / PORT_SCAN 家族
2. L3 + 父事件已覆盖 → sub_technique ∈ {T1059.001, T1059.006},allowed_ttps 含两条子技术
3. L3 下 last_missed=T1046 不跳级(prefer_gap=False,仍选 L3 子技术)
4. 当前等级内的 miss(T1110@L1)被优先(prefer_gap=True)
5. constraints 填充(dst_role/protocol/kill_chain/require_variant)
6. planner 只保留 goal 家族步骤(T1021 被拒);全拒时合成 goal 金标一步;executable + 缺失角色重映射
7. RedAgent goal 覆盖 BlueView.last_missed(plan.steps[0].mitre_id=="T1059.001",plan.goal 带出)
8. 假 LLM 输出 T1021 → 被约束回 goal 家族并可在默认拓扑物化(dst=ws-01)
9. update: EMA α=0.4(recall 1.0→0.6, asr 0→0.4)、recent_outcomes 滚动保留 5、rounds_at_level、p_level_clear 重算(手工状态 0.93)
10. maybe_advance: 3 轮 p=0.9 升级(且 recent_outcomes 全 red_win 也升——证明不看连续 blue_win);2 轮 p=0.9 不升;4 轮 p=0.1 降级;3 轮 p=0.1 不降
11. observe_gaps 更新 memory(missed→detected False + count,covered→detected True);prefer_gap_specs 排序;goal=None 时盲区驱动选型(T1068);同一记忆 + goal 时仍打 goal(P5-C)

`test_self_play_sim_diversity.py`:
1. topology() 仍 10 主机 + in-process-sim
2. generate_topology(seed=1, n_hosts=16): 16 台、角色≥3 种、分区≥2 种、IP 与默认拓扑不相交、确定性、seed 敏感、8/30 边界钳制
3. SimEnv(diverse=True, seed=2): 内部跳板 ∈ 实例 ws 集合且 ≠10.0.30.11,dst 来自实例主机;物化日志仍无 exploit payload
4. background_events(8): 全部 is_attack=False、eval_channel=sim、含 DNS 与 HTTP、目标不出网;默认拓扑背景事件同样落内部主机;materialize_plan(background_n=4) 追加 4 条 benign
5. 默认 SimEnv: 首步 src=203.0.113.50,foothold 步 src=10.0.30.11
6. 分层 Novelty: 同技术不同 message → technique≈0 且 parameter>technique;四层指纹内容;combined=0.4/0.3/0.2/0.1 加权(T1059.001 vs T1059.006 同父技术,technique=2/3);旧 score unseen=1→0;dump/load tokens + dump_layered/load_layered

## 4. 验收对照

### P2 课程控制统一化
- **P2-A ✅** `CurriculumPolicy.select_goal` 产出唯一 `RoundGoal`;`RedAgent.plan_attack(goal=...)` 下 LLM 路径(goal 进 prompt blue_view 字段 + `_steps_from_llm` 后 `constrain_steps`)与目录路径(`_spec_from_goal` 先取 goal)都消费同一 goal。
- **P2-B ✅** LLM 输出 TTP 不在 goal 家族(== technique / == sub / 父技术点分子技术 / goal.allowed_ttps / allowed 中属 goal 家族的条目)即被 `constrain_steps` 拒绝;全拒时回退 `get_ttp(goal.ttp_id/sub/technique)` 金标,而不是放开目录。测试:假 LLM T1021 → T1059.001。
- **P2-C ✅** 课程粒度到 sub-technique:T1059.001 / T1059.006 与父技术 T1059 在目录、RoundGoal、AttackStep/MaterializedEvent、allowed_ttps、novelty technique 层全链路可区分。
- **P2-D ✅(按实现规格)** 升级条件 = `rounds_at_level>=3 ∧ p_level_clear>0.8`;p = 0.4*mean_recall + 0.3*(1-mean_asr) + 0.3*blue_win_rate(recent_outcomes 窗口 5),clip 0..1。不再使用 consecutive_blue_wins(测试显式覆盖:red_win 序列也升级)。
- **P2-E ✅** 降级 = `rounds_at_level>=4 ∧ p_level_clear<0.25 ∧ level>0`;升级/降级都会重置 rounds_at_level/recent_outcomes/blue_win_rate/p_level_clear。

### P3 仿真环境多样性
- **P3-A ✅** 默认 `SimEnv()` / `topology()` / `HOSTS` / `ATTACKER_IP` 完全不变,旧测试原样通过。
- **P3-B ✅** `generate_topology` 主机数 8–30(越界钳制),角色/分区来自规定集合,保证 web/ws/dc/fs 存在,确定性(seed 可复现)。
- **P3-C ✅** `background_events` 附加 DNS / 内部 HTTP / FILE_ACCESS / USER_LOGIN,全部 `is_attack=False`、`eval_channel="sim"`;`materialize_plan(background_n=N)` 挂载。
- **P3-D ✅** 不出网:DNS 指向内部 dc(缺则回退),HTTP 指向内部 proxy 角色(若无则 web),全部 dst ∈ 拓扑内主机。
- **P3-E ✅** diverse 模式 IP 落在 `10.{100..250}.x.x`,与 `10.0.x`/`10.30.x` 默认集合不相交;内部跳板取实例 ws 主机,不再恒为 10.0.30.11(测试断言)。
- **P3-F ✅** 所有新生成 message 均为 SOC 日志描述,无 exploit payload(测试对 diverse 物化日志断言无 `or 1=1`/`sqlmap`/`msfvenom`)。

### P5 红队学习
- **P5-A ✅** `observe_gaps(missed, covered)` 更新 `self.memory`:missed → `{detected: False, count+1}`,covered → `{detected: True, count+1}`。
- **P5-B ✅** `prefer_gap_specs` 按 (未检出优先, count 高优先) 排序;`_choose_spec` 在无 blue 复用命中且 memory 非空时用该排序选型(测试: 盲区 T1068 驱动 L3 选型)。空 memory 时排序稳定 → 旧行为不变。
- **P5-C ✅** 有 RoundGoal 时 `_spec_from_goal` 先于任何盲区逻辑;盲区/覆盖率只决定 force_evasion(变体),不推翻 goal 技术(测试: 同一 memory 下 goal=T1059.001 仍打 T1059.001)。

### Novelty 分层
- **N-A ✅** `score_layered` 分开 technique / parameter / sequence / scenario,各层对该层历史做 `1 - max jaccard`,空 token 层计 0,组合 0.4/0.3/0.2/0.1。
- **N-B ✅** 旧 `score()` 语义保留(token 级 1-max Jaccard),`dump/load` 仍只管 token 历史,`unseen=1 → observe 后 0 → SYN_ENUM vs PORT_SCAN > 0.3` 原测试通过;`observe_event` 同时更新分层历史与 token 历史(含 mitre id)。

## 5. 遗留风险 / 说明

1. **接线未做(按分工)**: `orchestrator.py` 仍由主管接线。当前 orchestrator 的升级仍是旧 consecutive_blue_wins 逻辑(只读文件,未动);`CurriculumPolicy`/`goal`/`diverse_env`/`background_traffic`/`score_layered` 需在接线后进入 `play_round`。本模块已按 `MatchConfig.diverse_env/env_seed/background_traffic/eval_channel` 契约预留参数。
2. **p_level_clear 的“本等级”范围**: 依赖 `CurriculumPolicy` 进程内 `_seen[level]` 簿记。若跨进程反序列化 CapabilityState 且新策略实例无簿记,则回退为对全部 technique key 求均值(会混入历史等级,直到新等级有 update 观测)。缓解: 接线时每回合都调用 `update()`。
3. **P2-D 括注阈值与强制公式**: 规格同时给了合成公式(0.4/0.3/0.3)与括注阈值(mean recall≥0.7、ASR≤0.35、win≥0.6)。两者不完全等价(如 0.7/0.35/0.6 组合 p=0.655<0.8 不升级)。已严格按公式实现;括注视为 p 的语义解释而非额外与门。
4. **technique 层含完整子技术 id**: `layered_fingerprint.technique = {父, 完整 id}`,因此同父不同子技术(如 T1059.001 vs T1059.006)technique 新颖度为 2/3 而非 0 —— 有意为之,支持 P2-C 的子技术区分;若希望同父视为同技术,去掉完整 id 即可。
5. **LLM goal 注入位置**: goal JSON 挂在既有 `blue_view` prompt 字段(`round_goal` 键),未改 `red_plan.j2` —— 因为 `test_prompts_integrity` 对该模板做 strict_render 且其 mock 上下文没有 goal 变量;模板加变量会使该测试失败。后续若主管想给模板加 `{{ round_goal }}`,需同步更新 `_TEMPLATE_VARS["security/red_plan"]`。
6. **constrain_steps 原地改 dst_role**: env 绑定时对保留步骤原地重映射角色(AttackStep 为可变 dataclass,计划内对象,无共享风险);未绑 env 时不改写。
7. **background_events 确定性**: 模板按索引循环、主机按确定性公式挑选,无随机源 —— 可复现但表达力有限;如需"更像真实背景"可换 seed 驱动随机(属增强,非缺口)。
8. **diverse + 蓝队规则迁移**: diverse 拓扑换 IP 后,依赖 P1-D(泛化去 IP)的 overlay 规则才可迁移;该保证属 P1/Reasonix 范围,此处未验证。
