# LLM 通道分层分流 (Audit Triage)

**日期:** 2026-09-04  
**目的:** 规则/统计与 LLM Agent 优势互补；高压降载但不关死 LLM 通道。

## 为什么需要

r6 后「日预算耗尽 → 全员 fallback」导致 **LLM 通道完全不跑**，包括 critical。  
同时 `quick` 深度仍调用 SubAuditor LLM，低价值事件继续烧预算。

## 三层互补

| 层 | 职责 | 组件 |
|---|---|---|
| L0 规则/特征 | Sigma、威胁类型 | `sigma_detector`, taxonomy |
| L1 统计/关联 | 异常分、攻击链 | `anomaly_detector`, correlation |
| L2 FastPath | 强信号即时响应 | `log_ingestion` FastPath |
| L3 LLM | 叙事、证据、遗漏、人审 | Audit-LLM / Temporal |

## 优先级与车道

见 `backend/audit_triage.py`：

- **P0 `llm_deep`**: sigma critical / 高融合置信 / critical+信号 — **硬预算下仍保留最小 LLM hop**
- **P1 `llm_standard`**: high / sigma / anomaly≥0.6
- **P2 `llm_light`**: medium；软预算可降 `tools_only`
- **P3 `tools_only`/`rule_close`**: info 噪声，不调 LLM

## 预算水位

| 水位 | 行为 |
|---|---|
| &lt; soft (70%) | 全车道 |
| soft–hard | light→tools_only |
| ≥ hard / over | **仅 P0 LLM**；P1 tools_only；P2/P3 rule_close |

## 配置

```
SHARED_MEMORY_AUDIT_SOFT_BUDGET_PCT=70
SHARED_MEMORY_AUDIT_HARD_BUDGET_PCT=95
SHARED_MEMORY_AUDIT_P0_RESERVE_PCT=0.25
SHARED_MEMORY_AUDIT_FASTPATH_DEMOTE=true
```

## Phase C — 优先级队列 + P0 预留槽 (已落地)

- **Redis ZSET** `soc:audit:pq`: inflight 满时 P0/P1 **入队等待**，P2/P3 立即降级
- **预留槽**: `audit_inflight_max * audit_p0_reserve_pct` 专供 P0（非 P0 用不了这批槽）
- **Scheduler** `_audit_pq_drain_loop`: 按间隔 `ZPOPMIN` → `start_audit_workflow`
- **Metrics**: `soc_audit_pq_enqueue_total{tier}`, `soc_audit_pq_dequeue_total{tier}`, `soc_audit_lane_admit_total{lane,tier}`

```
SHARED_MEMORY_AUDIT_PQ_TTL_S=900
SHARED_MEMORY_AUDIT_PQ_DRAIN_INTERVAL_S=1.0
```

## 后续

- Ops 面板展示 lane / PQ 深度
- PQ 超时 SLA → tools_only + 告警
