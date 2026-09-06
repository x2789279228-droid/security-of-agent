# 审计分级 P2 实施报告 — llm_single 路由 / 缓存接线 / Temporal Agent 瘦身

> 实施者: Reasonix · 2026-09-06 · 验收: R-A..R-G, T-H
> 依据: `docs/upgrade-proposals/2026-q3-audit-lane-and-downstream.md` §4
> 主管已锁 triage 策略 (`audit_triage.py`, 未改动)

---

## 1. 改动文件

| 文件 | 改动 |
|---|---|
| `backend/agents/audit_single.py` | **新建**。`run(event_id, session_id, log_data, anomaly_report, timeout_s=15)` — 本进程单次 LLM 快审, 禁止 Temporal |
| `backend/log_ingestion.py` | 仅 `_audit_pipeline` 路由段: 导入 lane helper、缓存前置、`llm_single` 分支、Temporal 段注释。`_audit_pipeline_inner` / `_fallback_analysis` / `_mark_analyzed` 未动 |
| `backend/temporal/workflows.py` | `audit_round` 活动 `start_to_close_timeout` 300s → **60s**(仅此一行; retry policy 与 `save_result`/响应语义未动) |
| `backend/tests/test_audit_single.py` | **新建** 4 例 |
| `backend/tests/test_audit_cache.py` | **新建** 3 例 |
| `docs/upgrade-proposals/_reasonix_audit_lane_report.md` | 本报告 |

未触碰: `scheduler.py` / `audit_pq.py` / `temporal/client.py` / `audit_worker.py` / `metrics.py` / `config.py` / `audit_triage.py` / frontend / flink / self_play / 无 ML 模型。

---

## 2. 路由拓扑 (已生效)

```
score_event + admit (锁死) → inc_audit_lane_admit → logger
  ├─ audit_cache.get 命中   → _mark_analyzed(quality="cache") + 轻量 verdict 载荷落库, return   (R-E, 0 LLM)
  ├─ not needs_llm(lane)     → 原 _fallback_analysis + _mark_analyzed(quality=tools/rule/…)      (原样保留)
  ├─ uses_llm_single(lane) 或 (needs_llm 且非 agent)
  │                          → agents.audit_single.run(…, timeout=audit_llm_single_timeout_s)
  │                              成功: quality=llm / lane=llm_single 落库 + audit_cache.put, return  (R-B/R-C/R-D)
  │                              失败: _fallback_analysis + _mark_analyzed(quality="fallback"), return
  └─ 其余 (真 llm_agent/llm_deep) → 原 Temporal 段 (max_rounds=lane_max_rounds → agent 默认 1;
                                     shed→P0/P1 PQ、False→_audit_pipeline_inner 全部原样)            (R-F/R-G)
```

关键点: P1(及硬预算降级的 P0)在 `_audit_pipeline` 内**永远到不了** `start_audit_workflow` —
`llm_single` 分支在 Temporal 代码之前 `return`, 从结构上保证 R-B。

### 验收映射

| ID | 状态 | 说明 |
|---|---|---|
| R-A | ✅ | 缓存 → skip_llm → llm_single → Temporal, 顺序即代码顺序 |
| R-B | ✅ | `llm_single` 车道无任何 `start_audit_workflow` 调用路径; 测试用"调则抛"桩验证 |
| R-C | ✅ | `audit_single.run`: 恰好 1 次 `summary.llm.chat(messages, temperature=0.1)`, 整体 `asyncio.wait_for` 由 `run(timeout_s)` 控制(接线传 `settings.audit_llm_single_timeout_s`); 失败/降级/超时回 `_fallback_analysis` |
| R-D | ✅ | 成功 `_mark_analyzed(quality="llm")`; payload `lane=llm_single/status=completed/quality=llm`; 结论 `audit_cache.put` |
| R-E | ✅ | 缓存 key 方案未重写(`audit_cache.cache_key` 原样); 命中 `quality="cache"` 0 LLM; `inc_hit_metric()` 已调用(见风险 1) |
| R-F | ✅ | agent 轮数沿用 `lane_max_rounds`(agent 默认 `audit_max_rounds_agent=1`, 未动); `audit_round` 活动超时 300→60s |
| R-G | ✅ | 4 层 inner 语义零改动(confirmed/veto/faithfulness 全在 `_audit_pipeline_inner`/`_persist_audit_result` 原样) |
| T-H | ✅ | `audit_triage.py` 只读确认: `uses_temporal` 仅 `llm_agent/llm_deep`; triage 测试全绿 |

---

## 3. audit_single.run 设计要点 (与文档/规格的两处偏差, 有意为之)

规格片段写 `async with get_llm_limiter().acquire(...)` + `summary.chat(...)`, 两个都照抄会坏:

1. **`SummaryCompression` 没有 `chat` 方法** — 全库统一入口是 `summary.llm.chat`(`LLMClient.chat`,
   `summary_compression.py:206`)。R-C 原文即"1 次 `summary.llm.chat`(或现有 llm 客户端)", 以之为准。
2. **槽位不叠两层 acquire** — `LLMClient.chat` 内部已按 trace 上下文 tier 走
   `get_llm_limiter().acquire()` (`summary_compression.py:269-272`)。`run()` 先
   `set_trace_context(caller="audit_single", tier=triage_tier)`, 让内部 acquire 用 P0/P1 档位
   (P0 可占保留槽); 若再外层包一层 acquire, 并发打满时会"持外层等内层"互相等死, 且 inflight 双计。
   因此 `run()` 不再显式 acquire, 由 LLMClient 单一闸门实现 R-C 的"llm_limiter.acquire"语义。
3. Prompt 为**短** system+user: event type / severity / src/dst / HTTP / `message[:500]`
   (经 `memory_guard.sanitize_untrusted_text`) / sigma 命中规则 / anomaly 分与 reasons。
4. 解析: `parse_llm_json`; `is_llm_fallback` 或解析失败 → 返回 `{"fallback": True, status: failed, error: …}`
   (超时→`audit_single_timeout`, 降级→`audit_single_fallback:<reason>`, 解析失败→`audit_single_parse_error`)。
   接线对 fallback 标记与异常统一收口 `_fallback_analysis`。
5. verdict 归一 `confirmed|suspicious|benign`; 矛盾时以 verdict 为准(benign⇒非威胁, confirmed⇒威胁);
   confidence 夹到 [0,1]; severity 白名单校验。成功 payload 含 `evidence_trail`(sigma attack_types 轻量映射)。

---

## 4. 测试

```
cd backend
python -m pytest tests/test_audit_triage.py tests/test_audit_single.py tests/test_audit_cache.py tests/test_audit_worker.py -q
→ 21 passed
```

- `test_audit_triage.py` — 11 passed(主管既有, 未改)
- `test_audit_single.py`(4) — chat JSON→解析 threat_detected/verdict/confidence, 恰好 1 次 chat(temperature=0.1);
  chat 睡 30s + timeout_s=0.05 → fallback(不抛裸异常); 降级 JSON/非 JSON → fallback;
  **路由**: P1 llm_single 事件只走 `audit_single.run`,`start_audit_workflow` 调则抛;事件落 `quality=llm/lane=llm_single`, 且结论可 `audit_cache.get` 回(R-B/R-D)
- `test_audit_cache.py`(3) — put→get 同签名返回 verdict; 异 src_ip → miss; **缓存命中短路**: P0/llm_agent
  强事件预置缓存后调 `_audit_pipeline`, `start_audit_workflow` 与 `audit_single.run` 均不得调用, 事件 `quality=cache` 复用 verdict(R-A/R-E)
- `test_audit_worker.py` — 3 passed(既有, 未改)

扩展回归: `+ test_fallback_quality.py test_audit_never_drop.py` → **35 passed**。
环境注: 本机根目录 `.env`(docker-compose 变量)会触发 pydantic `extra_forbidden`, 测试必须 `cd backend` 执行。

---

## 5. 遗留风险 / 说明

1. **`metrics.inc_audit_cache_hit` 尚不存在**(只读文件禁改)。`audit_cache.inc_hit_metric()` 内部 try/except
   静默 no-op → `soc_audit_cache_hit_total`(D-G)本轮计数不到。需 P3(OpenCode, 被授权改 `metrics.py`)补 `Counter("soc_audit_cache_hit_total")` + `def inc_audit_cache_hit()`。
2. **`test_case_automation.py::test_audit_pipeline_path_creates_case` 本环境必红, 与 P2 无关**: 该测试
   `_audit_pipeline` 开头 `create_task(_auto_create_case_bg())` 后不 await 就断言 case 已建, 是任务调度竞态;
   case_manager 在 sqlite 上 advisory lock 失败仅告警不致命。已做 A/B: 还原我的全部改动(主管基线)该测试同样
   fail(HEAD 旧流水线才 pass)。建议后续把 `_auto_create_case_bg` 在入口 `await` 或测试内显式 flush。
3. **llm_single / cache 路径不触发 response_engine / CAD / faithfulness 否决闸** — 符合拓扑意图(§1:
   llm_single 是 P1 单 hop 快审; R-G 的 confirmed/veto 语义只约束 4 层 llm_agent 路径)。
   若产品要求 llm_single 命中 confirmed 也自动响应, 属新需求。
4. **Temporal(llm_agent)结论本轮不写 audit_cache** — R-D 只定义 llm_single 写缓存; 4 层结果缓存留待后续(避免放大缓存覆盖面)。
5. **trace tier**: `set_trace_context` 会丢弃 `log_data`, `LLMClient.chat` 读 `ctx.tier`; `run()` 显式置
   P0/P1 并在 finally `clear_trace_context()`, 不泄漏到调用方。
6. 接线对 `anomaly_score is None` 不设防(single 车道直接跑, run 内部 `or 0`)——与 Temporal 段的
   `anomaly_score is not None` 守卫不同, 属有意为之: llm_single 提示词只把 anomaly 当可选项。

---

## 6. 明确跳过(他方范围)

- P3 下游容量: `scheduler.py` / `audit_pq.py` / `temporal/client.py`(D-A `start` 超时 5s、D-B inflight 槽、
  D-C drain、D-D skip-blocked、D-E worker submit、D-F shed 只回 agent)= OpenCode。
- `metrics.py`(D-G 缓存/超时计数器)、`config.py`(knobs 已就位, 只读)。
- Celery / ML 模型 / 前端 / self_play — 本轮明确不做。
