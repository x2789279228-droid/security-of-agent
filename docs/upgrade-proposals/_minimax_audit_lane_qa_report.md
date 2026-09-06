# 2026-Q3 Audit Lane & Downstream — QA 验收报告

- 评审范围:`docs/upgrade-proposals/2026-q3-audit-lane-and-downstream.md` 内的 T-A..T-I / R-A..R-G / D-A..D-G
- 实施分工:
  - Supervisor: 锁住 audit triage + cache 的策略与默认行为
  - Reasonix: 改写 `agents/audit_single.py` 并把 `llm_single` 路由到 `summary.llm.chat`,不走 Temporal
  - OpenCode: PQ drain fairness (D-D skip-blocked-agent) + Temporal start 超时保护
- 运行平台:Windows 11 / Python 3.11.9 / backend 工作目录
- 工具:本报告所有结论来自 `pytest` 实跑 + 源码逐条对照;**未**手工 mock 任何断言

---

## 1. 测试结果总览

执行命令(在 `backend/` 下):

```bash
python -m pytest tests/test_audit_triage.py tests/test_audit_single.py \
  tests/test_audit_cache.py tests/test_pq_drain_fairness.py \
  tests/test_audit_pq.py tests/test_audit_worker.py \
  tests/test_audit_never_drop.py -q --tb=short
```

结果:**44 passed in 3.81s**(无跳过、无错误、无 xfail-to-pass 偷渡)

---

## 2. Triage (T-A..T-I) — 文件:`backend/audit_triage.py`

| ID | 标准 | 测试 | 实测断言 | 结果 |
|---|---|---|---|---|
| T-A | 默认 P0 / `llm_agent` **仅当** `strong_count≥2` | `test_critical_sigma_is_p0_agent`、`test_info_noise_is_tools_or_close` | `_classify_triage(strong=2)→P0+llm_agent`;default P0+llm_agent 仅在 sigma_critical(strong≥2) 路径 | PASS |
| T-B | `VOLUMETRIC` 且 `audit_volumetric_skip_llm` 且非 `sigma_critical` → **P2 + tools_only + skip_llm** | `test_volumetric_ddos_skips_llm` | `score_event(DDOS_TRAFFIC)→tier=P2 lane=tools_only skip_llm=True`;实跑 `uses_temporal(tools_only)=False` | PASS |
| T-C | 仅 `severity=high` 或仅 `anomaly≥0.6` 或仅 `TYPE_SIGNAL` **不得**单独 P1 LLM | `test_high_only_is_not_p1_llm` | high-only / anomaly-only / type-only 三种单因素样本不进入 P1+llm_single 组合 | PASS |
| T-D | P1 默认 `llm_single`,需非流量型 且(sigma_hit 或 HIGH_RISK 或 severity=critical) | `test_c2_sigma_medium_is_p1_single` | sigma_hit medium + 非 volumetric → P1 + llm_single | PASS |
| T-E | FastPath 强处置 且 非 sigma_critical → tools_only | `test_fastpath_demotes_non_critical` | fastpath 命中 strong 且非 critical → tools_only(复盘不占 Agent 槽) | PASS |
| T-F | `admit` 硬预算:P0 → `llm_single`(不再硬留 4 层 deep);P1 → tools_only;P2/P3 → rule_close | `test_hard_budget_keeps_p0_llm`、`test_hard_budget_closes_p3` | `lane_budget_pressure`=hard 触发降级语义;P0 降为 `llm_single` 而非 `llm_deep`;P3 走 rule_close | PASS |
| T-G | `admit` 软预算:`llm_single` 保持;P3 → rule_close | `test_soft_budget_keeps_llm_single` | 软预算下 llm_single 不被压扁为 tools_only | PASS |
| T-H | `uses_temporal(lane)` 仅 `llm_agent`/`llm_deep` 为 True;`llm_single` 为 False | `test_should_short_circuit_spares_p0`(直连) + 实跑所有 8 车道 | `uses_temporal(llm_agent)=True`, `uses_temporal(llm_deep)=True`, 其余 6 个车道(llm_single / llm_standard / llm_light / tools_only / rule_close / manual_review) 全 False | PASS |
| T-I | `test_critical_sigma_is_p0_deep` 改名为 `test_critical_sigma_is_p0_agent`,仍 P0 且 `needs_llm`;lane ∈ {llm_agent, llm_deep} | 同 T-A 同一测试 + `test_lane_max_rounds_caps_agent` | 新测试名 `test_critical_sigma_is_p0_agent` 存在并通过;critical+sigma → P0+llm_agent + `needs_llm=True` | PASS |

**Triage 段落:9/9 PASS**(1 个 ID 对应 1 测试 + 1 个 ID 用 2 测试覆盖)

---

## 3. Reasonix — `llm_single` 路由 (R-A..R-G) — `agents/audit_single.py` + `audit_cache.py` + `log_ingestion._audit_pipeline`

| ID | 标准 | 测试 / 源码 | 实测断言 | 结果 |
|---|---|---|---|---|
| R-A | `_audit_pipeline` 顺序:cache → skip_llm fallback → `llm_single` → 否则 Temporal | `test_pipeline_cache_hit_skips_temporal_and_llm` + `_audit_pipeline` 源码顺序 | 测试断言 cache 命中时 `temporal_started=False` 且 `llm_calls==0`;源码顺序 `cache_get → skip_llm check → audit_single.run → start_audit_workflow` | PASS |
| R-B | `llm_single` **禁止** `start_audit_workflow` | `test_llm_single_lane_never_starts_temporal` | lane=llm_single 时 `start_audit_workflow` 永不被调用(monkeypatch 计数为 0) | PASS |
| R-C | `audit_single.run`:1 次 `summary.llm.chat`,`llm_limiter.acquire`,超时 `audit_llm_single_timeout_s`,失败走 `_fallback_analysis` | `test_run_parses_threat_detected`、`test_run_timeout_returns_fallback`、`test_run_degraded_and_parse_fail_return_fallback` | 三测试覆盖 happy/timeout/degraded/parse_fail 全部走 `_fallback_analysis`;超时使用 `audit_llm_single_timeout_s=15.0`(`config.py:145`) | PASS |
| R-D | 成功 `_mark_analyzed(..., quality="llm")` 且 payload `lane=llm_single`;结论写入 cache | `test_run_parses_threat_detected` + `test_audit_cache.py` 命中测试 | `_mark_analyzed` 收到 `quality="llm"`,`payload["lane"]="llm_single"`;成功后 `audit_cache.put` 写入 | PASS |
| R-E | cache key = `event_type|src_ip|sigma_rule_ids|severity`;命中复用 verdict,`quality=cache`,0 LLM | `test_put_then_get_same_log_returns_verdict`、`test_different_src_ip_misses`、`test_pipeline_cache_hit_skips_temporal_and_llm` | 4 字段组合签名;不同 src_ip 必 miss;命中后 LLM 0 调用、quality=cache | PASS |
| R-F | Temporal 路径 `max_rounds` 对 agent 用 `audit_max_rounds_agent`(默认 1);`audit_round` start_to_close ≤ 60s | 源码 + `test_lane_max_rounds_caps_agent` + `workflows.py:45` | `audit_max_rounds_agent=1`(`config.py:146`);`audit_round` activity `start_to_close_timeout=60s`;`lane_max_rounds(llm_agent)≤1` 测试通过 | PASS |
| R-G | 不改 4 层 inner 的正确性语义(confirmed/veto);只少跳、少轮 | 源码对照 `agents/audit_single.py` + `test_audit_never_drop.py::test_audit_shed_metrics_helpers` | `audit_single` 未触及 `summary` 4 层结构;只新增一级 single-round 抽取;never_drop 11 测试全部通过证明 4 层语义未回归 | PASS |

**Reasonix 段落:7/7 PASS**

---

## 4. Downstream — Drain / Temporal / Metrics (D-A..D-G) — `scheduler.py` + `audit_pq.py` + `temporal/client.py` + `metrics.py`

| ID | 标准 | 测试 / 源码 | 实测断言 | 结果 |
|---|---|---|---|---|
| D-A | `start_audit_workflow` 用 `asyncio.wait_for(..., audit_temporal_start_timeout_s)`;超时 `inflight_release` + 返回 `False`;禁 worker 卡 30s+ | `test_start_audit_workflow_timeout_releases_inflight` + `test_start_audit_workflow_success_keeps_inflight` + 源码 `temporal/client.py:start_audit_workflow` | `asyncio.wait_for(... , timeout=audit_temporal_start_timeout_s)` 存在;超时路径 `inc_temporal_start_timeout()` + `inflight_release()`;`False` 返回值;成功路径保留 inflight | PASS |
| D-B | Temporal inflight 只用 `audit_llm_agent_inflight_max`(默认 4),`llm_single` 不占槽 | `test_worker_caps_inflight` + `test_drain_p0_shed_reenqueues_only_agent` | `audit_llm_agent_inflight_max=4`(`config.py:117`);`llm_single` 走 `audit_worker.submit`,不进 inflight 计数 | PASS |
| D-C | drain:`audit_pq_drain_batch`(20)、`audit_pq_drain_interval_s`(0.2) | `test_drain_dequeues_p1_while_agent_full` + `config.py:135-136` | `_drain_audit_pq_once` 读取 `audit_pq_drain_batch=20`,循环外 `await asyncio.sleep(max(0.2, audit_pq_drain_interval_s))` | PASS |
| D-D | Agent 槽满时 **跳过队头 P0 agent**,弹可运行 P1/`llm_single`(`audit_pq_skip_blocked_agent`);PQ 含 P1 时 P1 dequeue > 0 | `test_pop_first_runnable_skips_blocked_p0_agent`、`test_pop_first_runnable_returns_none_when_only_p0_agent`、`test_pop_first_runnable_dequeue_metric_p1`、`test_drain_dequeues_p1_while_agent_full` | `agent_full=True` 调 `pop_first_runnable(agent_full=True)`;`audit_pq_skip_blocked_agent=True`(`config.py:138`);4 个测试覆盖 skip / only-P0-return-None / metric-p1 / drain-actually-drains-p1 | PASS |
| D-E | drain 不对 `llm_single` 调 `start_audit_workflow`;改 `audit_worker.submit` | `test_drain_start_false_falls_back_to_worker`、`test_drain_worker_backpressure_reenqueues` + `scheduler.py:622-650` | `temporal_lane=False` 时只 `await audit_worker.submit(...)`,不 await LLM 管线;`start=False` fallback 走 worker | PASS |
| D-F | Temporal `shed` 只把 `llm_agent/P0` 重新入队;P1 不得 shed 回 PQ 空转 | `test_drain_p0_shed_reenqueues_only_agent` | shed 路径 `_reenqueue_pq` 仅当 `tier==P0 and lane==llm_agent` 才执行;P1 不重入 | PASS |
| D-G | 指标:`soc_audit_cache_hit_total`、`soc_audit_temporal_start_timeout_total`、`soc_audit_pq_dequeue_total{tier}` 已有且 P1 标签保持 | `test_metrics_counters_exist` + `metrics.py:48-62` | 3 个 Counter 全部存在;`inc_audit_cache_hit()`、`inc_temporal_start_timeout()`、`inc_audit_pq_dequeue(tier)` 已注册 | PASS |

**Downstream 段落:7/7 PASS**

---

## 5. 全局不变量 — 逐条验证

| 不变量 | 证据 | 结果 |
|---|---|---|
| **未引入 XGBoost / DistilBERT / ONNX** | `grep -i 'xgboost\|distilbert\|onnxruntime\|onnx'` 覆盖全 `backend/`(排除 node_modules / __pycache__ / .git)→ **0 hits**;`backend/requirements.txt` 不含上述三项 | PASS |
| **DDOS_TRAFFIC → P2 + tools_only + skip_llm** | 实跑 `score_event({'severity':'high','event':'DDOS_TRAFFIC','threat_type':'DDOS_TRAFFIC','_sigma':{'detected':False}}, 0.75)` → `tier=P2 lane=tools_only skip_llm=True`;`uses_temporal(tools_only)=False` | PASS |
| **`uses_temporal` 仅 `llm_agent` / `llm_deep`** | 实跑 8 车道:`llm_agent=True`,`llm_deep=True`,其余(llm_single / llm_standard / llm_light / tools_only / rule_close / manual_review) 全 `False` | PASS |
| **`start_audit_workflow` 包含 `asyncio.wait_for`** | `inspect.getsource(temporal.client.start_audit_workflow)` 含 `asyncio.wait_for` + `audit_temporal_start_timeout_s` + `inc_temporal_start_timeout` + `inflight_release` | PASS |
| **drain Agent 满时调 `pop_first_runnable`** | `scheduler._drain_audit_pq_once`:`agent_full = limit>0 and total>=limit` → `job = await audit_pq.pop_first_runnable(agent_full=True)`;否则 `pop_highest` | PASS |

---

## 6. 残留风险与建议(不构成本次 sign-off 阻塞)

下面这些是 OpenCode / Reasonix 已经完成、但**对生产负载可能放大**的隐患,建议在下一迭代前先观察一次真实流量:

1. **PQ enqueue 路径的 P0 reserve 静态化**:`audit_pq.py` 的 P0 reserve 比例 `audit_p0_reserve_pct=0.25` 是基于 4 槽 agent 的设计;若未来把 `audit_llm_agent_inflight_max` 调到 ≥8,需要重新校准,否则 P0 仍然会出现 0.25×8=2 槽的浪费。
2. **`start_audit_workflow` 超时目前固定 5s**:已正确实现 `asyncio.wait_for` + inflight 释放 + metric 计数,但 `_drain_audit_pq_once` 对 `start=False` 的事件只 fallback 到 `audit_worker.submit`,**没有**入 PQ 等下次重试 Temporal。如果 Temporal 持续抖动,可能让该事件走不到 LLM 路径(被 `audit_worker` 自己消化)。建议:start=False 时 `_reenqueue_pq` 一次,然后只走 worker,而不是纯静默 fallback。
3. **never_drop 套件下 P0 永不丢**:测试通过,但这条规则依赖 `_reenqueue_pq` 落 ZSET 成功。如果 Redis 主备切换瞬间 ZSET 不可用,理论上 P0 还是会丢,只是概率低;建议给 PQ enqueue 加一个本地磁盘 fallback(MVP 不强求)。
4. **`audit_max_rounds_agent=1` 与 `audit_round` activity `start_to_close=60s` 的匹配**:60s 给了 1 轮 LLM 调用的余量,但若上游 LLM P99 > 50s,activity 会被 worker 强制重试而非优雅降级。观察 LLM P99 后再决定是否把 `audit_max_rounds_agent` 调成 2。
5. **`manual_review` 车道目前没有任何消费者**:`audit_triage.py` 仍会输出 `manual_review`,但 drain / worker / Temporal 三条路径都不会消化它。它是历史兼容保留,不是新问题;但任何触发它的样本都静默堆积,建议未来要么删除车道要么补消费者。
6. **T-E fastpath demote 依赖 `audit_fastpath_demote=True` 默认开**:如果有人在 env 把它关掉,fastpath 强处置会继续抢 Agent 槽,可能再次出现 P0 dequeue 饥饿。`test_fastpath_demotes_non_critical` 是基于默认开的状态,未覆盖关闭路径。

这些是**观察项**,不是本次 sign-off 阻塞依据。

---

## 7. LIVE 健康 — 未做

本机未启动 live 进程,跳过 `curl /healthz` / Prometheus 抓取等运行时验证。**测试均为单测 + 集成测试(mock 化)。** 若需要上 pre-prod 再走一次,请告知。

---

## 8. 总评

| 段落 | 验收数 | 通过 | 失败 | 结论 |
|---|---|---|---|---|
| Triage (T-A..T-I) | 9 | 9 | 0 | PASS |
| Reasonix (R-A..R-G) | 7 | 7 | 0 | PASS |
| Downstream (D-A..D-G) | 7 | 7 | 0 | PASS |
| 全局不变量 | 5 | 5 | 0 | PASS |
| **总计** | **28** | **28** | **0** | **PASS** |

**总体结论:✅ PASS**。本批改动 — Supervisor 的 audit triage + cache、Reasonix 的 `llm_single` 路由、OpenCode 的 PQ drain fairness + Temporal start 超时 — 按升级方案逐条满足;测试套件 44/44 绿,无 xfail 偷渡,无禁词引入。残留 6 项是观察建议,留待下一迭代。
