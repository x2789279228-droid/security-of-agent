# 攻击闭环热修说明（2026-08-29）

## 背景

对平台注入杀伤链 `PORT_SCAN → BRUTE_FORCE → C2_BEACON → DATA_EXFIL` 后发现：
检测（Sigma/FastPath）可用，但审计定性被忠实度闸硬降级、SecurityGuard 因字段错配全拦动作、攻击链跨主机拼不上、案例拆进历史旧案、审计 API 读热缓存空结果。

## 修复摘要

| 优先级 | 改动 | 效果 |
|--------|------|------|
| P0 | SecurityGuard 兼容 `severity`/`message`，`send_alert`≈`alert_only` | FastPath 动作可过意图审查 |
| P0 | Faithfulness 软降级：有 Sigma/异常信号时保留 `threat_detected` | 真阳性不再被抹成 False |
| P1 | 枢纽杀伤链 + 可跳过 `LATERAL_MOVE` | 跨主机链可检出 |
| P1 | 案例按 `session_id` 聚合；type/dst 加时间窗 | 同源 4 事件进同一新案 |
| P1 | EventStore `invalidate` 热缓存 | pipeline API 可读审计结果 |
| P2 | Reviewer/CAD/evidence API/schema 归一 | 解析失败降级更稳 |

## 复测证据

Session: `demo_1787977712`（事件 #552–#555）

- Audit：4/4 `threat_detected=true`，`demoted_by=faithfulness_gate_soft`
- 攻击链：`外部入侵→失陷外联(192.168.1.100)` conf=1.0
- 案例：`CASE-20260829-DA1E04F2`，`event_count=4`
- Pipeline API：`status=completed`
- 响应：`rate_limit` / `send_alert` / `block_ip` 有执行日志（stub/log 模式）
- 单元测试：21 passed（guard / faithfulness / correlation / cache）

## 部署注意

若运行容器曾用 `docker cp` 热更新，正式环境请：

```bash
docker compose up -d --build backend
```

## 运营语义变化

- `suspicious` + `threat_detected=true` + `demoted_by=faithfulness_gate_soft`：规则已背书，LLM 文案不够忠实 → 强制人审，但仍允许策略层处置（`response_blocked=false`）。
- 无非 LLM 信号时仍硬降级（`threat_detected=false`），良性 FP SLO 保持。
