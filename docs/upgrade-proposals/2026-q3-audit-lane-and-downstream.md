# 审计分级 + 下游链路 — Phase 1（无小模型）

> 日期：2026-09-06
> 不做：ML Fast Path / DistilBERT / XGBoost（用户明确无合适小模型）
> 做：规则快路径、收紧 triage、llm_single 绕开 Temporal、Agent 瘦身、PQ 公平 drain、结论缓存

---

## 0. 活体事实（用户 5 分钟窗 + 主管复核）

- 入站 triage ~12.5 ev/s，几乎全是 `llm_standard/P1`（DDOS/high/anomaly≥0.7）
- 98% shed 进 Redis PQ；P1 dequeue = 0；LLM complete ≈ 0.07%
- `audit_worker_busy=12` 但 `llm_inflight=0`：worker 卡在 Temporal start/replay，不是在调 LLM
- drain `batch=5 / 1s` < 入站；Temporal inflight=12 被 P0 占满后 P1 只会被再 shed 回 PQ

根因不是「再加 worker」，是 **P1 不该进 Temporal 4 层 Agent**，以及 **drain 在 Agent 槽满时把 P1 饿死**。

---

## 1. 目标拓扑（本轮）

```
日志 → score_event（收紧）→ Rule Fast Path
         │
         ├─ rule_close / tools_only  → fallback 收口（0 LLM，毫秒）
         ├─ cache hit                → 复用结论（0 LLM）
         ├─ llm_single (P1 及硬预算下的 P0 最小 hop)
         │     └─ 本进程 1 次 LLM，不走 Temporal
         └─ llm_agent (真 P0，≥2 个强信号)
               └─ Temporal，最多 1 轮、活动超时缩短；start 限 5s
```

人工队列 `manual_review` 本轮只占位（lane 常量 + skip_llm 走 fallback 并打标），不接工单 UI。

---

## 2. 车道与旧名映射

| 新 lane | LLM 次数 | 编排 | 适用 |
|---|---|---|---|
| `rule_close` | 0 | fallback | 噪声 / 明确误报 |
| `tools_only` | 0 | fallback（规则+sigma 结论） | 流量型、FastPath 已处置、已知攻击特征 |
| `llm_single` | 1 | 本进程 `agents/audit_single.py` | 中等不确定、原 P1 |
| `llm_agent` | 1 轮（≤2 hop 活动） | Temporal | 真 P0 |
| `manual_review` | 0 | fallback + 标记 | 本轮不启用为默认 |

旧名兼容（`needs_llm` / `lane_max_rounds` 必须认）：

- `llm_deep` → 视作 `llm_agent`
- `llm_standard` / `llm_light` → 视作 `llm_single`

`score_event` **只产出新名**。

---

## 3. Triage 验收（P1）

强信号（计 1）：`sigma_critical`；`fused≥0.85`；`event∈HIGH_RISK_EVENT_TYPES`（C2/勒索/渗出/横向/提权/注入，**不含** DDOS/PORT_SCAN）；`ioc_hit`。

流量型 `VOLUMETRIC` = `DDOS_TRAFFIC|DDOS|PORT_SCAN|SYN_FLOOD|FLOOD|HTTP_FLOOD`。

| ID | 标准 |
|---|---|
| T-A | 默认 P0 / `llm_agent` **仅当** `strong_count≥2` |
| T-B | `VOLUMETRIC` 且 `audit_volumetric_skip_llm` 且非 `sigma_critical` → **P2 + tools_only + skip_llm**（不进 PQ 等 LLM） |
| T-C | 仅 `severity=high` 或仅 `anomaly≥0.6` 或仅 `TYPE_SIGNAL` **不得**单独把事件打成 P1 LLM |
| T-D | P1 默认 `llm_single`，且需要：非流量型 且（sigma_hit 或 HIGH_RISK 或 severity=critical） |
| T-E | FastPath 强处置且非 sigma_critical → tools_only（复盘不占 Agent 槽） |
| T-F | `admit` 硬预算：P0 → `llm_single`（最小 1 hop，**不再**硬留 4 层 deep）；P1 → tools_only；P2/P3 → rule_close |
| T-G | `admit` 软预算：`llm_single` 保持；P3 → rule_close |
| T-H | `uses_temporal(lane)` 仅 `llm_agent`/`llm_deep` 为 True；`llm_single` 为 False |
| T-I | 旧测试语义更新：`test_critical_sigma_is_p0_deep` 仍 P0 且 `needs_llm`；lane 为 `llm_agent` 或兼容 `llm_deep` |

文件：`backend/audit_triage.py`（主管可先改策略函数；执行者补 helper 与测试）。

---

## 4. 路由验收（P2）— Reasonix

| ID | 标准 |
|---|---|
| R-A | `_audit_pipeline` 在 Temporal 之前：cache → skip_llm fallback → `llm_single` → 否则 Temporal |
| R-B | `llm_single` **禁止** `start_audit_workflow` |
| R-C | `audit_single.run`：1 次 `summary.llm.chat`（或现有 llm 客户端），`llm_limiter.acquire`，超时 `audit_llm_single_timeout_s`，失败走 `_fallback_analysis` |
| R-D | 成功 `_mark_analyzed(..., quality="llm")` 且 payload `lane=llm_single`；结论写入 cache |
| R-E | cache key = `event_type|src_ip|sigma_rule_ids|severity`；命中则复用 verdict，`quality=cache`，0 LLM |
| R-F | Temporal 路径 `max_rounds` 对 agent 用 `audit_max_rounds_agent`（默认 1）；`audit_round` start_to_close ≤ 60s |
| R-G | 不改 4 层 inner 的正确性语义（confirmed/veto）；只少跳、少轮 |

文件：`log_ingestion.py`（只改 `_audit_pipeline` 路由段）、`agents/audit_single.py` 新建、`audit_cache.py` 新建、`temporal/workflows.py`（超时与 max_rounds 已由调用方传入则只改 activity timeout）。

---

## 5. 下游容量验收（P3）— OpenCode

| ID | 标准 |
|---|---|
| D-A | `start_audit_workflow` 用 `asyncio.wait_for(..., audit_temporal_start_timeout_s)`；超时 `inflight_release` 并返回 `False`（调用方走 async/llm_single），**禁止**让 worker 卡 30s+ |
| D-B | Temporal inflight 只用 `audit_llm_agent_inflight_max`（默认 4），**llm_single 不占该槽** |
| D-C | drain：`audit_pq_drain_batch`（20）、`audit_pq_drain_interval_s`（0.2） |
| D-D | Agent 槽满时 **跳过队头 P0 agent**，弹出可运行的 P1/`llm_single`（`audit_pq_skip_blocked_agent`）；P1 dequeue 必须 >0 当 PQ 里有 P1 |
| D-E | drain **不要**对 `llm_single` 调 `start_audit_workflow`；改为 `audit_worker.submit`（或直接 `_audit_pipeline` 的 create_task 但不得阻塞 drain 循环） |
| D-F | Temporal `shed` 只把 **llm_agent/P0** 重新入队；P1 不得再 shed 回 PQ 空转 |
| D-G | 指标：`soc_audit_cache_hit_total`、`soc_audit_temporal_start_timeout_total`、`soc_audit_pq_dequeue_total{tier}` 已有则保持 P1 标签 |

文件：`scheduler.py`、`audit_pq.py`（peek/skip）、`temporal/client.py`、`metrics.py`。禁止改 `audit_triage.py` / `log_ingestion.py` / `agents/audit_single.py`。

---

## 6. 明确不做

- XGBoost / DistilBERT / ONNX
- 人工审核 UI
- 把 `python_process_ingest_queue` 改回 Flink
- 无限加大 `audit_workers` 当主修复
- Celery

---

## 7. 测试命令

```
cd backend
python -m pytest tests/test_audit_triage.py tests/test_audit_cache.py tests/test_audit_single.py tests/test_pq_drain_fairness.py tests/test_audit_worker.py tests/test_audit_never_drop.py -q
```
