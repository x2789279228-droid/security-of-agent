# 主管审查 — 审计分级 + 下游链路 Phase 1

> 2026-09-06  不做小模型。源码验收 **44 passed**。线上需重建 backend + temporal-worker 才生效。

## 谁做了什么

| 角色 | 产出 |
|---|---|
| Grok | 标准、config 旋钮、`audit_triage.py` 门槛锁死、`audit_cache.py`、补审 OpenCode 超时后的 drain/client（OpenCode 文件已落盘） |
| Reasonix | `agents/audit_single.py`、`_audit_pipeline` 路由（cache → skip_llm → llm_single → Temporal）、workflow activity 60s |
| OpenCode | drain 公平弹出、Temporal start 5s 超时、agent inflight=4、metrics；MCP 调用超时但代码在仓库里 |
| MiniMax | 本轮未等其 QA（主管已跑 44 测） |

## 验收对照

- T-A..T-I triage：DDOS/PORT_SCAN 默认 P2 tools_only；P0 需 ≥2 强信号；P1 默认 llm_single 且不走 Temporal
- R-A..R-G：llm_single 禁止 start_audit_workflow（测试 raise-on-call）
- D-A..D-G：start wait_for 5s；agent 槽 4；drain batch 20 / 0.2s；agent 满跳过 P0 抽 P1

## 测试

```
cd backend
python -m pytest tests/test_audit_triage.py tests/test_audit_single.py tests/test_audit_cache.py tests/test_pq_drain_fairness.py tests/test_audit_pq.py tests/test_audit_worker.py tests/test_audit_never_drop.py -q
→ 44 passed
```

## 重建后预期（相对用户 5 分钟窗）

- `soc_audit_lane_admit{lane="tools_only"}` 应成为 DDOS 洪水的主车道
- `llm_standard` 应消失，改为 `llm_single` / `llm_agent`
- `soc_audit_pq_dequeue{tier="P1"}` 应 > 0
- `soc_llm_inflight` 应随 llm_single 非 0
- Temporal inflight 上限 4，不再用 12 个 worker 卡 start_workflow
