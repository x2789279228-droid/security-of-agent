# Self-Play 红蓝攻防模块：架构剖析

> 工作区：`D:/揭榜挂帅/shared-memory-platform/backend/self_play/`
> 性质：只读探索报告

---

## 1. 模块定位 + 一句话定义

**Self-Play 是 SOC 平台在隔离仿真里跑"红队 vs 蓝队"对抗循环的子模块：红队从 MITRE 课程目录里规划攻击场景并物化成带 ground-truth 的安全日志，蓝队复用生产环境的 Sigma/Overlay（及可选 Audit-LLM）做检测，漏报样本反哺为 overlay 候选规则，经审核与影子期后落地为 Sigma YAML。**

边界条件：
- 仿真在 in-process sim 拓扑里完成，**不**真正启动漏洞容器 / 调用 nmap·hydra·sqlmap（`sim_env.py:5-6` 注释）
- 候选规则默认不写生产 Sigma（`blue_learner.py:2-3`），需经 `reviewer` 多道硬门 + LLM 软门
- 影子期默认 24h（`self_play_shadow_hours=24` `config.py:299`），通过 scheduler 周期审核 + promote

---

## 2. 顶层架构图（对局视角 + 反馈回路）

```
            ┌───────────────────────────────────────────────────────────┐
            │                触发面 (Trigger Plane)                       │
            │  HTTP: POST /api/self-play/matches (routers/self_play.py)│
            │  CLI:  python -m self_play --rounds 8  (self_play/__main__)│
            │  Boot: app.py startup → seed_global_overlay()  (app.py:195)│
            │  Cron: scheduler._selfplay_review_loop 每 900s drain       │
            └────────────┬──────────────────────────────────────────────┘
                         │ start_match(req)
                         ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  SelfPlayOrchestrator.run_match (orchestrator.py:362)                 │
   │                                                                      │
   │  init_match ──► loop play_round(cfg.rounds) ──► finalize              │
   │      │              │                              │                 │
   │      │              │  ┌─ Red Agent.plan_attack ───► AttackPlan       │
   │      │              │  │  (课程 L0..6 / RAG+LLM / 词法兜底)          │
   │      │              │  │                                              │
   │      │              │  ├─ SimEnv.materialize_plan ──► MaterializedEvent│
   │      │              │  │  (10 主机拓扑，无真实工具，带 fingerprint)   │
   │      │              │  │                                              │
   │      │              │  ├─ BlueObserver.observe_many                   │
   │      │              │  │   ├─ Sigma detect (sigma_detector)          │
   │      │              │  │   ├─ Overlay detect (overlay.detect)         │
   │      │              │  │   └─ 可选 ingest→SecurityEvent→Audit-LLM     │
   │      │              │  │                                              │
   │      │              │  ├─ NoveltyIndex(score,observe) ──► 历史指纹    │
   │      │              │  │                                              │
   │      │              │  ├─ BlueLearner.learn_from_misses              │
   │      │              │  │   (从 FN 样本生成 LearnedRule 写 overlay)    │
   │      │              │  │                                              │
   │      │              │  └─ score_round / merge_metrics                │
   │      │              │      (ASR/recall/precision/MTTD/novelty)       │
   │      │              │                                              │
   │      │              ├─ 课程等级提升：连续 2 次 blue_win → level+1    │
   │      │              ├─ publish("selfplay_round", ...) 走 event_bus  │
   │      │              └─ store.save_round / save_learned_rules         │
   │      │                                                                 │
   │      └─ overlay.seed(prior candidate rules from DB)                  │
   │                                                                      │
   │  finalize: merge cumulative metrics, _winner(recall+asr 阈值),     │
   │            store.save_match_end, publish("selfplay_match", done)     │
   └──────────────────────────────────────────────────────────────────────┘
                         │
                         │ 学到的 rules 落到
                         ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  self_play_learned_rules (status=candidate|shadow|promoted|dismissed)│
   │                                                                      │
   │   scheduler._selfplay_review_loop  每 900s:                          │
   │     reviewer.drain(limit=batch) → review_one → apply_review           │
   │       ├─ G0 degenerate (tautology/empty/全合成ID)                    │
   │       ├─ G1 duplicate (Jaccard≥0.8 vs 同伴)                         │
   │       ├─ G1b sigma_duplicate (Jaccard≥0.8 vs 已写 Sigma token)      │
   │       ├─ G2 fp_replay (1 positive vs 24 decoys+生产 low/info 负样本)│
   │       ├─ G3 transferable (至少 1 个非合成的 message/url token)      │
   │       ├─ G4 llm  (meaningful & production_useful & 无 duplicate_risk)│
   │       └─ G5 replay_ab (历史对局 attacks 上命中数≥1)                 │
   │                                                                      │
   │   pass → status=shadow → sigma_export 写 rules_selfplay_shadow/*.yml│
   │   24h 后 → promote_due_shadows 重跑 G2 → pass→promoted / 否→dismissed│
   └──────────────────────────────────────────────────────────────────────┘
```

---

## 3. 配置全景（`config.py:285-301` 的 self_play_* 系列）

| Key | Default | 含义 | 引用 |
|---|---|---|---|
| `self_play_enabled` | True | 总开关，API 入口校验 | `config.py:285` / `routers/self_play.py:113` |
| `self_play_default_rounds` | 8 | 单局回合数 | `config.py:286` |
| `self_play_inject` | False | 把仿真事件**真正**送进 ingest（打 `_self_play=True` 标签） | `config.py:287` |
| `self_play_use_llm` | False | Red/Blue 规划是否烧 LLM（默认走课程目录） | `config.py:288` |
| `self_play_wait_audit` | False | 蓝队是否等 Audit-LLM 完成 verdict（演示/论文 full 模式） | `config.py:289` |
| `self_play_wait_audit_s` | 8.0 | 等审计的硬上限秒 | `config.py:290` |
| `self_play_decoy_ratio` | 0.2 | 一轮里 benign 诱饵事件占比 | `config.py:291` |
| `self_play_max_inflight` | 1 | **同一时刻最多 1 局** | `config.py:292` / `routers/self_play.py:117` |
| `self_play_rag_top_k` | 8 | Red Agent RAG 召回条数 | `config.py:293` / `red_agent.py:25` |
| `self_play_llm_timeout_s` | 20.0 | Red Agent LLM 规划超时 | `config.py:294` / `red_agent.py:46` |
| `self_play_review_enabled` | True | scheduler 周期审核总开关 | `config.py:295` / `scheduler.py:770` |
| `self_play_review_fp_max` | 0.05 | G2 FP 率硬门 | `config.py:296` / `reviewer.py:31` |
| `self_play_review_llm` | True | 是否跑 G4 LLM 软门 | `config.py:297` / `reviewer.py:38` |
| `self_play_review_replay` | True | 是否跑 G5 历史回放 | `config.py:298` / `reviewer.py:43` |
| `self_play_shadow_hours` | 24.0 | 影子期小时数 | `config.py:299` / `reviewer.py:49` |
| `self_play_review_interval_s` | 900 | 周期审核间隔（15 分钟） | `config.py:300` / `scheduler.py:768` |
| `self_play_review_batch` | 20 | 周期审核每批上限 | `config.py:301` / `scheduler.py:773` |

派生常量（非配置）：
- `MAX_CURRICULUM_LEVEL = 6` — `catalog.py:15`
- `KILL_CHAIN_ORDER` 8 阶段 — `catalog.py:17`
- `_MAX_CHAIN = 5` — `red_agent.py:24`
- `GLOBAL_KEY = "*"` — `overlay.py:10`
- `SELFPLAY_DIR = backend/sigma_engine/rules_selfplay_shadow/` — `sigma_export.py:15`
- `ATTACKER_IP = "203.0.113.50"`（RFC 5737 文档 IP）— `sim_env.py:13`
- FP window：24 decoys + 80 SecurityEvent(low/info) — `reviewer.py:151-165, 288-308`

---

## 4. 启动与触发

### 4.1 4 条触发路径

1. **HTTP 端点（主要）** — `routers/self_play.py:108 POST /api/self-play/matches`
   - 鉴权：`RequireRole("admin", "operator")`（`routers/self_play.py:111`）
   - 守卫：`self_play_enabled` 总开关（`routers/self_play.py:113`）+ `live_matches` 数量 ≥ `self_play_max_inflight` 拒绝（`routers/self_play.py:116-118`）
   - 优先走 Temporal `start_selfplay_workflow(cfg)`（`temporal/client.py:215`），失败回退 `asyncio.create_task(orchestrator.run_match(...))`（`routers/self_play.py:138-148`）
   - 响应 `via: "temporal"|"async"`（`routers/self_play.py:153`）

2. **CLI** — `python -m self_play --rounds 8`（`self_play/__main__.py`）
   - 同进程直接调 `orchestrator.run_match`，不走 HTTP/Temporal
   - 入口可注入 `--inject --llm --full-attack --no-persist --decoy`（`__main__:17-22`）

3. **启动期 seed** — `app.py:194-199`
   - 进程启动时 `seed_global_overlay()` 把 DB 里 status=shadow/promoted 的 rules 灌进 in-memory `overlay`（`reviewer.py:463-472`）
   - 失败只 `logger.warning`，不阻塞启动

4. **周期审核** — `scheduler._selfplay_review_loop`（`scheduler.py:763-783`）
   - 默认 900s 一轮，可配
   - 跑 `reviewer.drain(limit=batch)` → `promote_due_shadows`
   - 这是**唯一**会调 `apply_review` → 写 Sigma YAML 的代码路径（手动 API 也能调）

### 4.2 `self_play_max_inflight=1` 的实现

两处共同保证：
- **HTTP 入口软检查**：`len(running) >= int(settings.self_play_max_inflight or 1)` 直接 409（`routers/self_play.py:117`）
- **Orchestrator 计数器**：全局 `_RUNNING` + `_LOCK`（`orchestrator.py:22-25, 363-367, 386-387`）
  - `run_match` 入口 `async with _LOCK: _RUNNING += 1`，`finally: _RUNNING -= 1`
  - `_LOCK` 实际上只保护了 `_RUNNING` 自增，**不**串行化 match 本身 — 多个 `_RUNNING > 1` 可以并行推进（目前 router 层已先挡掉，所以是双保险）

`request_stop(match_id)` 走 `_STOP` 集合 + `_LIVE[match_id]["status"]="stopping"` 软标记（`orchestrator.py:36-41`），`play_round` 开头 `if match_id in _STOP: state["stopped"]=True; return state`（`orchestrator.py:126-128`）—— 在下一回合边界才生效。

### 4.3 Temporal 路径

- 入口：`temporal/client.py:215 start_selfplay_workflow`
- Workflow 类：`temporal/workflows.py:171 SelfPlayWorkflow` —— 串行 `init → round×N → finalize`，每步 `execute_activity`（`workflows.py:195-217`）
- 单 round 超时 = `180s if (wait_audit or use_llm) else 60s`（`workflows.py:207`）
- Workflow 总超时 = `max(120, rounds*90)` 秒（`client.py:244`）
- Activities 注册在 `worker.py:76 selfplay_init, selfplay_round, selfplay_finalize`（`worker.py:55-79`）

---

## 5. 一场 match 完整生命周期

### 5.1 状态机（以 `status` 字段为锚）

```
        ┌────────┐  POST /matches         ┌────────┐
        │ pending│ ────────────────────► │running │   ←── 同时在 _LIVE[match_id]
        └────────┘  router pre-persist    └───┬────┘
                                            │
                          每回合循环 play_round
                          ┌─────────────────┘
                          ▼
                ┌───────────────────┐
                │  round payload    │  cumulative metrics 更新
                │  publish(round)   │  curriculum level 提升条件触发
                │  store.save_round │
                └─────────┬─────────┘
                          │ run_match 退出
                          ▼
        ┌──────────┬──────────────┬──────────────┐
        │completed │  stopped     │  failed      │  ←── finalize 决定
        └──────────┴──────────────┴──────────────┘
```

注：status 只有 5 个值（`pending|running|completed|stopped|failed`），但**路由器**额外定义 `stopping` 过渡态（`orchestrator.py:40` / `routers/self_play.py:166`），二者未完全对齐，见脆弱点。

`winner` 字段在 `completed` 时计算（`orchestrator.py:335`），`stopped/failed` 留空。

### 5.2 标识与命名

- `match_id` 格式：`sp-{uuid.uuid4().hex[:12]}` —— 12 字符 hex，共 48 bit 熵（`orchestrator.py:44-45`）
- `plan_id`：`plan-{uuid.uuid4().hex[:10]}`（`red_agent.py:392`）
- `step_id`：`s-{uuid.uuid4().hex[:8]}` 攻击 / `d-{uuid.uuid4().hex[:8]}` 诱饵（`red_agent.py:145, 166`）
- `rule_id`（学到的）：`SP-{slug}-{seq:03d}`，slug = match_id 末 8 位去非字母数字（`blue_learner.py:60-62`）
- `sigma_uuid_for(rule_id)` 用 `uuid5(NAMESPACE_URL, "soc:selfplay:{safe_id}")` 派生稳定 UUID（`sigma_export.py:24-26`）

### 5.3 单 round 主路径（`orchestrator.py:123-324`）

```
play_round(state):
  1. STOP 检查 → return
  2. overlay.add(match_id, rule) 把状态里的候选规则塞进 in-memory overlay
  3. round_num += 1
  4. 构造 BlueView(覆盖、上次 outcome、漏报、learned_tokens)
  5. RedAgent.plan_attack(...)
       ├─ use_llm=True:  RAG(retriever.mitre-attack) → 词法兜底
       │   → LLM(system="security/red_plan_system", user="security/red_plan")
       │   → _steps_from_llm(2..5 步, _MAX_CHAIN=5)
       ├─ use_llm=False: 课程目录 _choose_spec (规避已覆盖 event_type)
       └─ always 加 1 个 decoy
  6. SimEnv.materialize_plan(steps, decoys)
       - chain_index 控制 src_ip（foothold=True 后切到 ws-01 / 10.0.30.11）
       - 给每条事件算 fingerprint
  7. BlueObserver.observe_many
       - 每条: sigma_detect + overlay.detect
       - inject=True: log_ingestor.ingest() → SecurityEvent(analyzed=False)
       - wait_audit=True: 轮询 SecurityEvent.analyzed=True 拉 _audit_llm
  8. NoveltyIndex.observe(attacker token set) → 更新 history
  9. BlueLearner.learn_from_misses
       - 遍历 (evt, detected) 找 is_attack and not detected
       - 抽 distinctive_tokens（剔除 _GENERIC 停用词 + 大写 event 重名）
       - 可选 LLM enrich(_llm_enrich → prompt "security/blue_learn")
       - overlay.add(match_id, rule) + persist_kb 时入 KB
  10. red.remember(event, ttp_id, detected=...) → 红队记忆
  11. 更新 blue_coverage(检出 event / rule_ids)
  12. 算 outcome = _outcome(metrics)
       - attacks==0: "decoy_only"
       - fn>0 && tp==0: "red_win"
       - fn==0 && tp>0: "blue_win"
       - else: "mixed"
  13. 课程: 连续 2 次 blue_win → level+1，consecutive 重置
  14. publish("selfplay_round", ...) 走 event_bus
  15. persist: store.save_round + store.save_learned_rules(每条)
```

### 5.4 时间预算

| 阶段 | 默认超时 | 引用 |
|---|---|---|
| Red LLM 规划 | 20s（`self_play_llm_timeout_s`） | `red_agent.py:46` / `config.py:294` |
| 单 round 整体（Temporal） | 60s / 180s（audit/llm 模式） | `workflows.py:207` |
| Blue 轮询 Audit 完成 | 8s（`self_play_wait_audit_s`） | `blue_observer.py:107` |
| Match 整体（Temporal） | `max(120, rounds*90)` | `client.py:244` |
| 周期审核间隔 | 900s | `config.py:300` / `scheduler.py:768` |
| 影子期 | 24h | `config.py:299` |

### 5.5 异常处理路径

- **`run_match` try/except**（`orchestrator.py:375-384`）：任意异常 → `finalize(status="failed")`，再次失败返回兜底 dict
- **persist 失败**：所有 `store.*` 调用都包在 try/except，只 `logger.info` 不影响主流程（`orchestrator.py:106-107, 312-323, 354-359`）
- **LLM 失败**：`red_agent.py:287-289` / `blue_learner.py:127-128` / `reviewer.py:243-244` / `gate_replay_ab:283-285` 全部 **fail-open**（LLM 错就当 G4/G5 pass）
- **RAG 失败**：`red_agent.py:239-240` 退回词法召回
- **RAG chunks<3**：词法补足（`red_agent.py:242-251`）
- **`_STOP` 标志**：下一 round 边界检测，本 round 不会中断（`orchestrator.py:126-128`）
- **Temporal activity retry**：`RetryPolicy(initial_interval=2, max_interval=20, max_attempts=2)`（`workflows.py:177-181`）

---

## 6. 红队（Red Agent + sim_env）

### 6.1 TTP 选择逻辑

- **课程目录**：`catalog.py:41-204`，9 条**手写**金标（MITRE T1046 / T1110 / T1190 / T1059 / T1068 / T1021 / T1071 / T1048 / T1027），跨 7 个 kill_chain 阶段，level 0..6 分布
- **企业池**：`enterprise_pool()` 从 `self_play/data/enterprise_techniques.json` 快照（约 200 条父技术），按 `TACTIC_META` 映射到课程 level（`catalog.py:222-237, 248-298`）
  - 变体故意带 `_OBF` 后缀，message 标注"未使用库存检测关键字"（`catalog.py:271-275`）
- **选择策略** `_choose_spec`（`red_agent.py:98-119`）：
  1. `blue.last_outcome == "red_win"` 且 `blue.last_missed` 不空 → 直接复用上次漏报 TTP
  2. 在当前 level（含）内，找 `event_type` 不在 coverage 里的第一个
  3. 整个 src 池从后往前扫，再不行 fallback 到 `current[0]`
- **企业池启用条件**（`use_enterprise`）：`want_llm or (not curriculum)`（`red_agent.py:347-348`）
  - 即：**走 LLM / 关课程** 才用 200 条企业池，否则只走 9 条金标

### 6.2 变体 / 规避

`_pick_variant`（`red_agent.py:76-96`）和 `_wants_evasion`（`red_agent.py:70-74`）：
- 红队 memory 里 `detected=True` 或当前 coverage 包含该 `event_type` → 触发规避
- 从 `spec.variants` 里顺序挑一个**不在 coverage 里**的 event
- 没有变体或都被覆盖 → 用最后一个变体，标记 `evasion=True`
- LLM 路径可显式 `use_evasion: true` + `variant_index: N`（`red_agent.py:312-321`）

### 6.3 RAG + LLM 编排（`use_llm=True`）

`_rag_hints_and_specs`（`red_agent.py:212-252`）：
1. 走 `rag.retriever.retrieve(query, source="mitre-attack", top_k=8, skip_llm=True, min_score=0.0)`
2. 从每个 chunk 的 `title + content` 里 regex 抽 `T\d{4}(?:\.\d{3})?` → `get_ttp(tid)` 转成 TTPSpec
3. RAG 不足 3 个候选 → `lexical_candidates(query, level, top_k, covered, prefer, use_enterprise=True)` 补足（`red_agent.py:338-368`）
4. `prefer_ids = blue.last_missed + blue.learned_tokens`，这些直接 +6 分（`red_agent.py:358-360`）

`_llm_pick`（`red_agent.py:254-289`）：
- Prompt：`security/red_plan_system` + `security/red_plan`
- 输入：level / coverage / **catalog 候选精简版（无 message/extra，只有 ttp_id/mitre_id/name/tactic/level/event_type/variants[event]）** / RAG hints / last_outcome / blue_view
- 输出：JSON `{rationale, steps:[{ttp_id, use_evasion, variant_index}], add_decoy}`
- 兼容旧 schema：单步 `ttp_id+use_evasion+variant_index` 也吃（`red_agent.py:296-301`）
- 超时 20s，失败 → `_steps_from_llm` 返回空 → 走 `_choose_spec` 兜底（`red_agent.py:374-388`）

### 6.4 模拟环境 sim_env

- **10 主机拓扑**（`sim_env.py:16-27`）：dmz（web-01/app-01/mail-01/vpn-01）+ lan（jump-01/dc-01/fs-01/db-01）+ user（ws-01/ws-02）
- **attacker** 固定 `203.0.113.50 / red-sim`（`sim_env.py:13-14`）—— RFC 5737 文档 IP，**绝不出网**
- **src 切换规则**（`sim_env.py:84-90`）：
  - 攻击 step：链索引 > 0 或 `kill_chain` ∈ {lateral, privilege, execution, evasion, c2, exfil} 或 foothold → src = `ws-01/10.0.30.11`
  - 否则：攻击 src = `203.0.113.50 / red-sim`
  - benign：固定 `ws-02 / 10.0.30.12`
- **chain 状态**：`materialize_plan` 一次 attack step 落地后 `foothold=True`，后续攻击全部从内网打（`sim_env.py:124-138`）
- **时间戳**：同一 plan 内每条间隔 1ms（`base + i * 0.001`，`sim_env.py:131, 136`）
- **confidence**：攻击 88，benign 95（`sim_env.py:116`）
- **额外元数据**（`sim_env.py:93-101`）：`_sim=True, _tool, _kill_chain, _ttp_name, _evasion, _chain_index, _foothold` + step.extra 覆盖
- **`materialize_plan` 是纯函数**，无 IO，可重入

### 6.5 与 orchestrator 接口

```
red: RedAgent(use_llm=cfg.use_llm) (orchestrator.py:159)
    red.memory = state["red_memory"]  (160)  ← 跨 round 持久化
    plan: AttackPlan = await red.plan_attack(...)  (161-171)
    events: list[MaterializedEvent] = env.materialize_plan(plan.steps, plan.decoys)  (172)
    for evt in events: evt.fingerprint = fingerprint(...)  (174)
    red.remember(evt.event, detected=obs.detected)  (211)
    red.remember(evt.ttp_id, detected=obs.detected)  (212)
    state["red_memory"] = red.memory  (220)
```

---

## 7. 蓝队（Blue Observer + Blue Learner）

### 7.1 BlueObserver 怎么"看"红队（`blue_observer.py:28-98`）

**3 个并联检测器**：
1. **Sigma**（`_sigma_detect` → `sigma_detector.detect_for_event(log)`，`blue_observer.py:18-24`）—— **生产** Sigma 规则，不写 self-play 标签
2. **Overlay**（`overlay.detect(match_id, log)`，`blue_observer.py:41`）—— **本场/全局** overlay，**已含本局刚学到的**
3. **Audit-LLM**（可选）（`_inject` → `_wait_audit`，`blue_observer.py:100-125`）—— 走完整 ingest → Decomposer→Executor→Reviewer 流水线

**观测优先级 / 覆盖关系**（`blue_observer.py:44-87`）：
- Sigma 命中 → `detector="sigma"`
- Overlay 命中且没 Sigma → `detector="overlay"`
- 两者都中 → `detector="sigma+overlay"`（优先级）
- 都不中但 inject+wait_audit 拉到 audit verdict 为 confirmed/suspicious → `detector="audit_llm"`
- MTTD：`(detected_at - t0) * 1000`，t0 = `evt.injected_at` 或 `time.time()`

**`inject` 行为**（`blue_observer.py:65-83, 100-125`）：
- `_inject` 走 `log_ingestor.ingest(session, session_id, log)`，session_id = `selfplay-{match_id}` 让安全事件**真进** `security_events` 表
- `wait_audit` 轮询 `session.get(SecurityEvent, event_id)`，等 `analyzed=True` + `raw_data._audit_llm.merged`，**最长等 `wait_audit_s`** 秒，每 0.25s 一次（`blue_observer.py:111-124`）
- 拿到 `threat_detected=True` 或 verdict∈{confirmed, suspicious} → 标记 detected=True
- **关键不变量**：注入模式下蓝队看到的是**真流量**，但 ground-truth 标签仍由 `MaterializedEvent._ground_truth` 携带（blue_observer 不读此字段，审计流水线自己读）

**蓝队看到的是不是真流量？**
- 默认（inject=False）：**仿真事件只走 Sigma/Overlay，完全不进生产 ingest**（`blue_observer.py:65` 不触发）
- inject=True：**进生产 ingest**，会触发全套审计/分诊/案例派生 —— 这条开关默认 False（`config.py:287`），**默认不污染生产**，但 repo 里 `self_play_inject` 是 `False` 防御性的设置

### 7.2 BlueLearner 学什么（`blue_learner.py`）

- **触发条件**：`evt.is_attack=True and obs.detected=False` —— 只从漏报学（`blue_learner.py:81`）
- **抽 token**（`distinctive_tokens`，`blue_learner.py:23-36`）：
  - 必有 `evt.event`
  - 从 `tokenize(event, message, mitre_id)` 排序后取最多 4 个，**剔除停用词 + 剔除与 event 同名的大写**
  - `_GENERIC` 停用词：`event, host, user, from, with, http, https, tcp, message, info, high, medium, low, critical`（`blue_learner.py:17-20`）
- **构造规则**（`rule_from_miss`，`blue_learner.py:39-57`）：
  - `event_contains = [evt.event]`
  - `message_contains = [t for t in tokens if t.upper() != evt.event.upper()]`
  - `condition_mode = "or"`
  - `source_fingerprint = evt.fingerprint`
  - `status = "candidate"`
- **LLM 富化**（`_llm_enrich`，`blue_learner.py:106-129`）—— use_llm=True 时调，prompt `security/blue_learn_{system,user}`，可选追加 `event_contains`/`message_contains`
- **写回**：`overlay.add(match_id, rule.to_dict())`（`blue_learner.py:100`）
- **可选 KB 落库**（`_persist_kb`，`blue_learner.py:131-156`）：`kb_manager.add_document(..., source="self-play", tags=["self-play","candidate",mitre], submitted_by="blue_learner", auto_signed=False)` —— `auto_signed=False` 表明**未经过审签**

---

## 8. 评分与胜负

### 8.1 单回合 `score_round`（`metrics.py:14-61`）

| 指标 | 公式 | 备注 |
|---|---|---|
| `attacks` / `decoys` | 计数 | decoys 只在 not is_attack 分支加 |
| `tp` | 攻击被检出 | |
| `fp` | 诱饵被误报 | |
| `fn` | 攻击漏报 | |
| `tn` | 诱饵未误报 | |
| `asr` | `fn / attacks` | Attack Success Rate |
| `recall` | `tp / attacks` | |
| `precision` | `tp / (tp + fp)` | |
| `mttd_ms` | TP 的 mttd 平均 | |
| `novelty` | 攻击的 `NoveltyIndex.score()` 平均 | `1 - max_jaccard` 越大越新颖 |
| `compounding` | `_evasion=True` 攻击被 overlay 抓 / `_evasion=True` 总数 | **关键：衡量自学习有效率** |
| `overlay_hits` / `sigma_hits` | 各自 detector 命中计数 | |

`_safe_div` 防 0 除（`metrics.py:10-11`）。

### 8.2 单局 `outcome`（`orchestrator.py:48-55`）

| 条件 | 值 |
|---|---|
| `attacks == 0` | `decoy_only` |
| `fn > 0 and tp == 0` | `red_win` |
| `fn == 0 and tp > 0` | `blue_win` |
| 其他 | `mixed` |

### 8.3 单局 `winner`（`orchestrator.py:58-65`）

```
if recall >= 0.7 and asr <= 0.35:  blue
elif asr >= 0.5:                   red
else:                              draw
```

仅在 `status == "completed"` 时计算（`orchestrator.py:335`）。

### 8.4 累计 `merge_metrics`（`metrics.py:64-86`）

简单把每轮 metrics **累加**算 ASR/recall/precision，`novelty/compounding` 算**平均**，`overlay_hits/sigma_hits` 算**总**（`metrics.py:73-87`）。这是**有偏的合并**（TP 求和 ≠ sum(TP)/sum(attacks)），后续分析需注意。

---

## 9. 复盘 + 学习 + 规则提升

### 9.1 reviewer 7 道门（`reviewer.py`）

| 门 ID | 函数 | 关键判定 | 行为 |
|---|---|---|---|
| **G0** | `gate_degenerate`（`reviewer.py:73-88`） | 条件 ⊆ {attack_type, mitre_id, rule_id} 或全部是合成 ID | 拒 |
| **G1** | `gate_duplicate`（`91-115`） | 与其它 candidate/shadow/promoted Jaccard ≥ 0.8 或同 mitre+同 event_contains | 拒 |
| **G1b** | `gate_duplicate_sigma`（`199-207`） | 与已写 Sigma YAML 的 token Jaccard ≥ 0.8 | 拒 |
| **G2** | `gate_fp_replay`（`168-183`） | 1 个正样本 + 24 decoy + 80 SecurityEvent(low/info) 负样本，FP<0.05 才过 | 拒 |
| **G3** | `gate_transferable`（`118-134`） | 至少 1 个 message/url token 不是 MITRE ID / 合成 ID / event 自身（避免纯 ID 规则） | 拒 |
| **G4** | `gate_llm`（`210-244`） | LLM 判 `meaningful & production_useful & !duplicate_risk`（prompt `security/blue_review_*`），**fail-open** | 软拒 |
| **G5** | `gate_replay_ab`（`247-285`） | 用历史 self-play 攻击样本估算 Δrecall，`with_rule >= 1` 过，**fail-open** | 软拒 |

G4/G5 是 fail-open（LLM/历史数据失败就 pass，`reviewer.py:243, 284`），所以 LLM 故障**不会**卡死审核。

### 9.2 `review_one` 编排（`reviewer.py:311-334`）

```python
gates = [G0, G1, G1b, G3, G2]    # 5 个硬门
hard_ok = all(g.passed for g in gates)
if hard_ok and _use_llm():  gates += [G4]    # 软门仅在硬门全过后跑
if hard_ok and _use_replay(): gates += [G5]
ok = all(g.passed for g in gates)
decision = "shadow" if ok else "dismissed"
```

### 9.3 `apply_review` 落库（`reviewer.py:365-395`）

- `dismissed` → `delete_selfplay_rule` 删 YAML， `reload_sigma` 热重载
- `shadow`/`promoted` → `write_selfplay_rule(rule, shadow=shadow)` 写 `rules_selfplay_shadow/{rule_id}.yml`，**再** `overlay.add(GLOBAL_KEY, ...)` 把规则塞全局 in-memory，**再** `reload_sigma`
- 任何路径都 `store.set_rule_status(pk, decision, sigma_yaml, review_report)` + 写 `audit_trail`（`reviewer.py:337-349`）

### 9.4 `promote_due_shadows`（`reviewer.py:424-460`）

- 拉所有 `status=shadow` 的规则（limit=100）
- 算 `now - reviewed_at` ≥ `self_play_shadow_hours (24h)` 才考虑
- 重跑 **G2 only**（FP 复检）—— pass → `apply_review(..., decision="promoted")`；fail → dismissed + 标记 `reason=shadow_fp`
- 复检用**最新** 80 条 SecurityEvent(low/info) 当负样本（`reviewer.py:288-308`）

### 9.5 `seed_global_overlay` 24h 周期（`reviewer.py:463-472`）

- **实际上** 24h 是**单条规则的影子期**，**`seed_global_overlay` 本身不是周期任务**
- 它在 `app.py` 启动时跑一次，把所有 shadow+promoted 灌进 `overlay[GLOBAL_KEY]`（`reviewer.py:467-470`）
- 真正周期跑的是 `scheduler._selfplay_review_loop` → `drain` → `apply_review` 链（可能触发新一轮 shadow/写 YAML）

### 9.6 novel detection 角色（`novelty.py`）

- **Jaccard 相似度，不用 embedding**（`novelty.py:1` 注释）—— 离线可复现
- `tokenize` 用大写 token + 停用词表（中英双语 stop）+ 强抽 `T\d{4}(\.\d{3})?`（`novelty.py:8-25`）
- `fingerprint` = sha1(`event|protocol|mitre_id|toks`) 16 字符截断（`orchestrator.py:174` 写到每条事件）
- `NoveltyIndex.score(tokens) = 1 - max_jaccard(tokens, history)`（`novelty.py:54-61`）
- **作用域**：per-match，每局开始 `novelty.load(state["history_tokens"])` 恢复（`orchestrator.py:184-192`）—— **跨 match 不共享**
- 只把 `is_attack=True` 的 token 入库，benign/decoy 不污染
- `novelty_threshold=0.5` 是 metrics.py 接收的形参，**目前 score_round 内部未直接做硬门**（`metrics.py:14-19`，仅传参未消费）

---

## 10. 持久化（`store.py` + `models.py`）

### 10.1 三张表（全部在 `models.py:783-836`）

#### `self_play_matches`（`models.py:783-800`）
```
id PK
match_id VARCHAR(64) UNIQUE INDEX
status VARCHAR(20) INDEX        # pending|running|completed|stopped|failed
mode VARCHAR(20)                # sigma|inject|full  (store._mode 计算 store.py:216-221)
curriculum_level INT
total_rounds INT
completed_rounds INT
config JSON                     # MutableJSON，完整 MatchConfig
metrics JSON                    # 最终 cumulative metrics
winner VARCHAR(20)              # red|blue|draw
started_at / finished_at / created_at INDEX / updated_at
```

#### `self_play_rounds`（`models.py:803-817`）
```
id PK
match_id VARCHAR(64) INDEX
round_num INT INDEX
curriculum_level INT
red_plan JSON                   # 完整 AttackPlan
events JSON[]                   # MaterializedEvent 数组
blue_obs JSON[]                 # EventObservation 数组
outcome VARCHAR(20)             # red_win|blue_win|mixed|decoy_only
metrics JSON
learned JSON[]                  # LearnedRule 数组
created_at INDEX
```
**注意：无 UNIQUE(match_id, round_num) 约束**，理论上重发会重复行；无外键到 matches 表。

#### `self_play_learned_rules`（`models.py:820-836`）
```
id PK
rule_id VARCHAR(50) INDEX
match_id VARCHAR(64) INDEX
source_round INT
title VARCHAR(300)
attack_type VARCHAR(50)
mitre_id VARCHAR(20)
severity VARCHAR(20)
conditions JSON
sigma_yaml TEXT                 # 影子期/正式后的 YAML 文本
status VARCHAR(20) INDEX        # candidate|shadow|promoted|dismissed
review_report JSON              # 完整 7 门报告（仅在 reviewer 跑过才填）
created_at INDEX
```
**注意：`review_report` 是** JSON 列**（MutableJSON），所以 `set_rule_status` 兼容老 schema（没列时塞进 conditions._review）（`store.py:168-175`）。

### 10.2 索引清单

- `self_play_matches.match_id` UNIQUE + `status, created_at`
- `self_play_rounds.match_id, round_num, created_at`
- `self_play_learned_rules.rule_id, match_id, status, created_at`

### 10.3 与 `security_events` 主表的关系

- **间接**：`self_play_inject=True` 时，`log_ingestor.ingest(session, session_id, log)` 走完整 ingest 路径，会写 `security_events` 行（`blue_observer.py:100-105`）
- `_self_play=True` 标签打在 payload 上（`types.py:120`，`sim_env.py` 无显式打，**但 MaterializedEvent.to_log 里有**）
- `_ground_truth=attack|benign` 也由 `to_log` 注入（`types.py:121`）—— 下游审计/评测可读
- `_wait_audit` 查的 `row.raw_data._audit_llm.merged` 是审计流水线自身的产物（`blue_observer.py:117-120`）
- **无外键**，`match_id` 在 `security_events` 里只能从 `session_id = "selfplay-{match_id}"` 字符串反推

### 10.4 历史回放/查询

- `store.get_match(match_id)` 返回 match + 全 rounds 顺序排列（`store.py:110-124`）
- `store.list_matches(limit=30)` 按 id desc（`store.py:127-134`）
- `store.list_learned_rules(status=, limit=)` 按 id desc + 可选 status 过滤（`store.py:137-145`）
- `store.aggregate_metrics()` 全表扫一遍算各 match 的 avg metrics（`store.py:180-213`）—— **没 LIMIT，大表可能慢**
- `store.load_candidate_rules(limit=200)` 给 `init_match` 灌 overlay 用，取 `status IN (candidate, shadow, promoted)` 按 id desc（`store.py:96-107`）

---

## 11. 与外部模块的接口

### 11.1 ingest 注入路径（`blue_observer.py:100-105`）

```python
async def _inject(self, log, session_id):
    from models import async_session
    from log_ingestion import log_ingestor
    async with async_session() as session:
        result = await log_ingestor.ingest(session, session_id, log)
    return int((result or {}).get("event_id") or 0)
```

`session_id = "selfplay-{match_id}"`，即 `selfplay-sp-xxxxxxxxxxxx` —— 全部 self-play 事件在同一 session，审计流水线可按 session_id 分组。

`log` 字段（`MaterializedEvent.to_log` `types.py:105-129`）携带的**自博弈专属**字段：
- `_self_play: True`
- `_ground_truth: "attack"|"benign"`
- `_ttp_id, _mitre_id, _fingerprint, _sim_src_host, _sim_dst_host`
- `_evasion` 在 step.extra 里（`sim_env.py:98`）

**Audit-LLM 怎么识别 self-play？** 应该靠 `_self_play` / `session_id` 前缀匹配 —— 在 audit_triage / audit_worker 我没找到显式处理（grep 0 命中），所以**审计 LLM 默认会把仿真事件当生产事件审计**，这就是为什么 `self_play_inject` 默认 False —— 否则会污染分析 + 浪费 LLM 预算 + 触发案例派生。

### 11.2 event_bus 事件类型

只有 2 个类型（`events.py:10-14` + `orchestrator.py:117-120, 289-310, 350-353`）：
- `selfplay_match` —— phase ∈ `init|done`，match_id, status, level/rounds/winner/metrics
- `selfplay_round` —— round_num, outcome, level/next_level, metrics/cumulative, red.{rationale,steps[event,mitre_id,evasion,message]}, blue.{detected,detectors,learned}

`publish()` 走 `event_bus.event_bus.publish(...)`，SSE 客户端订阅可见（已验证 `event_bus.py` 接受任意 type 字符串）。

### 11.3 audit_triage / sigma_detector 关系

- **sigma_detector**：`detect_for_event(log)` 是 blackbox，蓝队只调不实现（`blue_observer.py:18-24`）
- **sigma_detector.reload()** 在 `sigma_export.reload_sigma`（`sigma_export.py:180-187`）每次写新 YAML 后调，让 self-play 规则**热生效**到下一条 ingest
- **sigma_engine/engine.py:130-137** 在 engine 加载时把 `rules_selfplay_shadow/` 目录也扫入 + `repair_selfplay_yaml` 把非 UUID 的 id 改成 uuid5（防 volume 残留）
- **audit_triage / audit_worker**：grep `self_play|_self_play` 0 命中，所以**无任何显式耦合** —— 副作用全靠 session_id 字符串 + `_self_play` 标签

### 11.4 RAG / KB 引用

- **Red RAG**：`rag.retriever.retrieve(session, query, source="mitre-attack", top_k=8, skip_llm=True, min_score=0.0)`（`red_agent.py:222-227`）
- **Blue KB 落库**：`rag.knowledge_base.kb_manager.add_document(..., source="self-play", tags=["self-play","candidate",mitre], submitted_by="blue_learner", auto_signed=False)`（`blue_learner.py:131-156`）
  - `auto_signed=False` 表示**未签**，KB 检索时是否信任取决于 KB 端策略（此处不深挖）
- **没有 RAG 召回到 self-play 文档**的循环（只有"写入"，不读自己的产物）

### 11.5 蓝队学习产物如何回生产 detection

```
candidate  ──drain 7 门──►  shadow  ──24h G2 复检──►  promoted
                                  └────failed────►  dismissed

写产物:
  overlay  (in-memory, GLOBAL_KEY)
  rules_selfplay_shadow/{rule_id}.yml
  self_play_learned_rules row  (status 字段更新)

生产路径生效:
  sigma_detector.reload() ──► pySigma 重读 rules_selfplay_shadow/ 下 yml
  overlay.detect() ──► in-memory 即时生效
```

---

## 12. 并发 / 限流

### 12.1 三道闸

| 闸位 | 位置 | 行为 |
|---|---|---|
| 路由层 | `routers/self_play.py:117` | `len(running) >= self_play_max_inflight` → 409 |
| 计数器层 | `orchestrator.py:_LOCK + _RUNNING`（22-25） | 只保护 `_RUNNING` 自增，不串行化 match |
| Temporal | `client.py:244 execution_timeout` + `audit_inflight_max` 全局 | 全平台 inflight 计数（共享 Redis） |

### 12.2 多对局是否可能并行？

- 路由层：HTTP 入口直接挡，所以**正常情况下不会**
- `asyncio.create_task(_run())` 创建的是真并发任务（`orchestrator.py` 没有显式串行）
- **`_LIVE` / `_STOP` / `overlay._rules` / `BlueLearner._seq` 都未加 match 锁**，理论上 `self_play_max_inflight > 1` 时会有 race —— 比如两个 match 的 `SP-{slug}-001` 会冲突（`blue_learner.py:60-62` 同一 match_id 内是唯一的，但跨 match 不可控）
- 这是已知的脆弱点

### 12.3 状态机并发安全

- `_LIVE[match_id]` 是 dict 读写，**单 asyncio loop 内是原子的**（同一线程），但 `play_round` 内部 `snap.update(...)` 之前没有锁
- `_RUNNING` 借 `_LOCK` 保护，但只保护计数本身
- **结论**：由于路由层 + 现实 `max_inflight=1`，目前不会出问题；一旦调高，需要重新审视

---

## 13. 关键边界与降级

### 13.1 同步 vs 异步边界

- **纯同步**：`materialize_plan`、`score_round`、`merge_metrics`、`fingerprint`、所有 catalog 查询
- **asyncio 但轻量**：`overlay.detect`（in-memory）、`sigma_detect`（in-memory + 同步读 YAML）
- **asyncio 重**：`log_ingestor.ingest`（生产 ingest 全链）、`summary.llm.chat`（LLM HTTP）、`RAG.retrieve`（向量库 + 可能的 embedding）、`store.save_*`（DB 写）
- **跨进程**：Temporal activity 边界，activity 内部重新加载模块，state 在 activity 之间 dict 序列化的 JSON 传递

### 13.2 重 vs 轻

**重操作**（单 round 100ms-数秒）：
- RAG + LLM 规划（red_agent）—— 20s 超时硬门
- LLM 富化 blue rule（blue_learner._llm_enrich）
- LLM 审核 G4（reviewer.gate_llm）
- log_ingestor.ingest 整条审计链（若 inject=True）
- store.save_round（整 round payload JSON 落库）

**轻操作**：
- 课程目录选择（red_agent._choose_spec）
- 词法召回（red_agent.lexical_candidates）
- overlay.match_rule（in-memory 字符串 contains）
- sigma_detect（单事件，纯内存，无 IO）
- 7 门里除 G2/G4/G5 外的 G0/G1/G1b/G3

### 13.3 已知降级路径（可观测）

| 触发 | 降级 | 引用 |
|---|---|---|
| RAG 失败 | 词法召回兜底 | `red_agent.py:239-251` |
| LLM 规划失败/超时 | `_choose_spec` 走课程目录 | `red_agent.py:374-388` |
| LLM 富化失败 | 规则用启发式条件 | `blue_learner.py:127-128` |
| Audit-LLM 未及时 | 用 Sigma + overlay 结果 | `blue_observer.py:107-124` |
| Sigma detect 异常 | 静默返回 detected=False | `blue_observer.py:22-24` |
| store.* 失败 | 仅 log，不影响主流程 | `orchestrator.py:106-107` 等 |
| Temporal 启动失败 | asyncio.create_task 兜底 | `routers/self_play.py:130-148` |
| G4/G5 异常 | fail-open（pass） | `reviewer.py:243, 284` |

### 13.4 self-play 事件如何"防污染"生产

`self_play_inject=False` 默认（`config.py:287`） → 仿真事件**只**在 self-play session 流通，不会触发 audit/case。`self_play_wait_audit=False` 默认进一步关掉等审计。`self_play_use_llm=False` 默认连 red/blue 也不烧 LLM。**这是默认值下的零开销离线模式**。

### 13.5 双 Tag 自博弈事件

`MaterializedEvent.to_log` 打 `_self_play=True` + `_ground_truth` 是关键设计（`types.py:120-121`）：**这俩字段是唯一让下游区分"这事件是仿真/标签"的方式**。但当前 audit_triage/audit_worker 没有显式读取这俩字段（grep 0 命中），所以**一旦 inject=True 启用，审计系统并不知道这是仿真**，后果是：

- 仿真事件会进 case_manager（case_manager.py 检测 high/critical）
- 仿真事件会进 correlation_engine
- 仿真事件会消耗 LLM 预算（虽然 `llm_budget_unlimited=True` 看着不卡）
- 仿真事件会进 dashboard / 案例

所以 `self_play_inject` 是**有实际副作用**的开关，默认 False 是对的。

---

## 14. 已知脆弱点（只列，不修）

1. **match_id 在 `_LIVE`/`_STOP`/`_RUNNING`/overlay 都没有进程级锁** —— `self_play_max_inflight > 1` 时 race 会出现
2. **`status` 在 router/orchestrator/DB 三处不统一**：router 用 `stopping`、orchestrator 用 `running/stopping`、DB 用 `pending/running/completed/stopped/failed` —— 状态机有间隙
3. **蓝队学习**只从 `is_attack and not detected` 学，从不处理"诱饵被误报" —— 不会学"防误报"规则
4. **RAG 召回 chunks < 3** 触发词法兜底，词法召回本身可能挑出 MITRE ID 同名但语义无关的（spec.mitre_id 优先于 token 匹配）
5. **G2 fp_replay 负样本只有 24+80=104 条** —— 远小于生产流量代表性；`fp_max=0.05` 看似严，但 1 个 FP 就算 ≥0.05% 接近阈值
6. **`sigma_engine/engine.py:130 repair_selfplay_yaml`** 启动时会改 YAML 的 id —— 如果该文件已被 sigma_detector 加载，有极小窗口不一致
7. **审查报告 `review_report` 字段**在没有该列的旧 schema 会被塞进 `conditions._review` —— 跨升级会有数据迁移痕迹
8. **`_wait_audit` 死循环风险**：如果 `analyzed=True` 但 `raw_data._audit_llm` 不存在，`blue_observer.py:117-123` 三次 fallback 仍返回非 None，逻辑上可被哄骗
9. **`gate_replay_ab` `without` 永远 0**（`reviewer.py:273` `sum(1 for e in attacks if False)`）—— "baseline" 命中数实际是 0，G5 只看 `with_rule`，所以**任何规则 G5 都过** —— 该门实际失效
10. **审计流水线对 self-play 事件无显式识别** —— `inject=True` 即便不会改 ground-truth，但**会污染案例/KPI/告警/预算**
11. **`SelfPlayRound` 无 UNIQUE(match_id, round_num)** —— 重发 round 会产生重复行
12. **`promote_due_shadows` 拉 limit=100** —— 若同时有 >100 条 shadow 排队，只前 100 走审核
13. **课程目录只有 9 条金标** —— 红队会很快收敛到"挑没见过的 attack_type"，`blue_coverage` 填满后直接走规避路径；`learned_tokens` 长度被截到 12（`orchestrator.py:157`），回灌信息有损

---

## 15. 关键文件引用速查

| 主题 | 文件:行 |
|---|---|
| match 状态机入口 | `self_play/orchestrator.py:362 run_match` |
| 单 round 编排 | `self_play/orchestrator.py:123-324 play_round` |
| 胜负判定 | `self_play/orchestrator.py:48 _outcome` / `:58 _winner` |
| TTP 课程 | `self_play/catalog.py:41-204 _TTPS` / `:280 enterprise_pool` |
| 红队规划 | `self_play/red_agent.py:324 plan_attack` |
| RAG 召回 | `self_play/red_agent.py:212 _rag_hints_and_specs` |
| LLM 编排 prompt | `prompts/security/red_plan_system.j2` / `red_plan.j2` |
| 仿真物化 | `self_play/sim_env.py:78 materialize` / `:124 materialize_plan` |
| 蓝队观测 | `self_play/blue_observer.py:28 observe_one` / `:107 _wait_audit` |
| Sigma 接入 | `self_play/blue_observer.py:18 _sigma_detect` |
| 蓝队学习 | `self_play/blue_learner.py:69 learn_from_misses` |
| LLM 富化 prompt | `prompts/security/blue_learn_system.j2` / `blue_learn.j2` |
| 评分函数 | `self_play/metrics.py:14 score_round` / `:64 merge_metrics` |
| Overlay 命中 | `self_play/overlay.py:84 detect` / `:21 match_rule` |
| 全局 overlay 种子 | `self_play/reviewer.py:463 seed_global_overlay` |
| 7 门审核 | `self_play/reviewer.py:311 review_one` / 73/91/199/168/118/210/247 |
| 审核落库 | `self_play/reviewer.py:365 apply_review` / `:424 promote_due_shadows` |
| Sigma 编译 | `self_play/sigma_export.py:63 to_sigma_dict` / `:158 write_selfplay_rule` |
| Sigma 热重载 | `self_play/sigma_export.py:180 reload_sigma` / `sigma_engine/engine.py:130` |
| DB 模型 | `backend/models.py:783 SelfPlayMatch` / `:803 SelfPlayRound` / `:820 SelfPlayLearnedRule` |
| 持久化函数 | `self_play/store.py:11/37/61/82/96 save_*/load_*` |
| API 路由 | `routers/self_play.py:108 start_match` / `:159 stop_match` / `:178 learned-rules` / `:192 status` / `:223 review/run` |
| 总开关 | `config.py:285-301 self_play_*` |
| 启动 seed | `app.py:194-199` |
| 周期审核 | `scheduler.py:763-783 _selfplay_review_loop` |
| Temporal 入口 | `temporal/client.py:215 start_selfplay_workflow` / `temporal/workflows.py:171 SelfPlayWorkflow` |
| Temporal activity | `temporal/activities.py:550-567` |
| CLI | `self_play/__main__.py` |
| 导出 | `self_play/__init__.py` |

---

## TL;DR

Self-Play 是一个**纯仿真、不污染默认生产**的红蓝对抗引擎：9 条 MITRE 课程 + 200 条 ATT&CK Enterprise 池（快照） → RedAgent 选 TTP 并做规避变体 → SimEnv 在 10 主机 in-process 拓扑里物化为带 `_ground_truth` 的安全日志 → BlueObserver 并联 Sigma+Overlay（可选 Audit-LLM）做实时评分 → 漏报经 BlueLearner 抽 distinctive_tokens 写 in-memory overlay 并落库 candidate → scheduler 每 15 分钟跑 7 道门（G0 退化 / G1 重复 / G1b Sigma 重 / G2 FP 回放 / G3 可迁移 / G4 LLM fail-open / G5 历史回放 fail-open），pass 进 shadow 写 `sigma_engine/rules_selfplay_shadow/*.yml`，24h 后重跑 G2 → pass 则 promoted、否则 dismissed。整链路有 4 类触发（HTTP 鉴权 POST、Temporal 优先 + asyncio 兜底、CLI、scheduler 周期 + startup seed），`self_play_max_inflight=1` 路由层 + 进程内 `_RUNNING` 双保险。**默认 `inject=False/use_llm=False/wait_audit=False`** 让仿真事件不触发审计/案例/告警，不会污染生产；`MaterializedEvent.to_log` 打 `_self_play=True` + `_ground_truth` 标签是唯一让下游识别的钩子（但 audit_triage/audit_worker 当前未显式读取，一旦 inject=True 仍会污染）。
