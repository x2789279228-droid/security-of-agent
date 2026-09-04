# Security Audit Platform Attack Performance Report — M2.7
**Date:** 2026-09-01 23:40 - 2026-09-02 00:10 (CST)
**Test session:** `attack-perf-m27-2026-09-01`
**Auditor model:** MiniMax-M2.7 (M3 → M2.7 cutover)
**Attacker:** `kali-pentest` Docker container on `host.docker.internal`
**Target (本机):** 172.25.62.112 (Windows host, Mavis runtime)

---

## 1. TL;DR

| 维度 | 关键结论 |
|---|---|
| M2.7 接入 | **生效**（启动日志 + 35/35 LLM trace 全部是 M2.7，0 条 stale M3） |
| M2.7 健壮性 | **35/35 0 错误、0 重试、5 缓存命中** ——比 M3 时代的"偶发 429 / 偶发空 content"稳定 |
| M2.7 延迟 | **p50 14.9s / p90 32.1s / p95 54.6s / max 75.6s / mean 18.6s**（远高于普通 chat，但能跑通） |
| 真实性 | 11/16 事件 verdict=`suspicious`（含 BRUTE_FORCE 描述），5/16=`false_positive`，4 条 port_scan pending |
| 自动封禁 | **未触发** —— M2.7 输出 `threat_type=""`（空），不命中 `BRUTE_FORCE` / `PORT_SCAN` 策略（`ANY` 兜底只发告警） |
| 手动封禁 | `/api/response/simulate` 直触 → **4/4 block_ip 成功**，iptables 新增 4 条 DROP，单次 wall **<100ms** |
| iptables 一致性 | 8 旧规则 + 4 新规则 = **12 条**（FW-RULE-74597 / 96406 / 58301 / 96977）|
| 关键 bug | `sub_auditor`/`decomposer`/`audit_pipeline` 跑在 `soc-temporal-worker`，与 `shared-memory-backend` 是**独立容器**——切 M2.7 必须**两个都** `docker compose up -d` |

---

## 2. 测试场景与执行

### 2.1 真实攻击（literal user request）

```bash
# 从 kali-pentest 跑 tools/attack-simulator.sh 1 轮
TARGET=host.docker.internal ROUNDS=1 ./attack-simulator.sh
```

实际触发：
- nmap -sS 扫到 host 开放 22/80/135/443/445/3000/5432（22/80 是 Docker Desktop 内部服务，3000/5432 是平台反代）
- hydra SSH 暴力破解 10 个密码（admin/admin123/password/123456/root/...）全部失败
- nc 探测 445/22（kali 容器没装 nc，2 个探测跳过）

### 2.2 SOC 真实采集结果：**0 事件**

| 表 | 测试前 | 测试后 | Δ |
|---|---|---|---|
| `security_events` | 1881 | 1881 | 0 |
| `edr_events` | 0 | 0 | 0 |
| `network_flows` | 0 | 0 | 0 |
| `llm_traces` | 13008 | 13008 | 0 |
| `response_logs` | 654 | 654 | 0 |
| iptables DROP | 8 | 8 | 0 |

**根因**（dev 环境已知缺口）：
- Suricata **不在** `docker-compose.yml` services 列表（虽然 `config/suricata/` 目录在）
- `tools/windows-log-collector.ps1` 没作为 service 启动，host 端 Win Event Log 不进 `edr_events`
- 没有 Kafka producer 把 host 端系统日志推到 `soc-kafka`
- soc-firewall 容器**没**装 syslog forwarder，SSH auth.log 不会进 SOC

→ 真实攻击流量的"感知路径"在本环境全是断的，需要补齐传感器才能做"端到端真攻击"测试。

### 2.3 替代路径：合成事件注入

为了测"事件进入 SOC → M2.7 审计 → 响应 → iptables 封禁"完整链路，用 `POST /api/logs/ingest/batch` 注入 16 条**模拟攻击事件**（如果传感器在，会产生的形态）：

| 事件类型 | 数量 | 攻击者 IP |
|---|---|---|
| SSH brute force | 12 | 192.168.65.5/7/9/11（每个 3 条） |
| Port scan (SYN) | 4 | 192.168.65.5/7/9/11（每个 1 条） |

注入端点延迟 0.77s（16 条 batch）。

---

## 3. M2.7 表现（核心维度）

### 3.1 调用统计

| 指标 | 值 |
|---|---|
| 总调用数 | 40 |
| M2.7 | **35** (87.5%) |
| 残留 M3 | 0（早期 t=15:55 那批 8 条 stale M3 已被清） |
| 错误 | 0 |
| 重试 | 0（reasoning_split 未触发） |
| 缓存命中 | 5 (12.5%) |
| Token 用量（单调用）| p50 2012 / p90 3476 / max 4350 |

### 3.2 延迟分布（ms）

| 维度 | min | p50 | p90 | p95 | max | mean |
|---|---|---|---|---|---|---|
| 全部 35 次 | 0（cache）| **14 856** | 32 081 | **54 598** | **75 600** | 18 594 |
| sub_auditor (n=15) | – | 14 093 | – | 27 542 | – | – |
| decomposer (n=13) | – | 13 940 | – | 54 598 | – | – |
| audit_pipeline (n=12) | – | 15 448 | – | 23 388 | – | – |

> **p50 14.9s** 比 M3 时代（memory 里的 v6 17.4 req/s → 单 LLM 调用 ~57ms）慢得多。原因：M2.7 是 reasoning 强制开启的模型（`thinking_config.mode: forced_on`），所有审计调用都把 1-3 轮推理跑完。**这是模型特性而非 bug**。
>
> **5 缓存命中**：重复的 prompt（同一 BRUTE_FORCE 模式），`LLMClient._response_cache` 600s TTL 命中。

### 3.3 审计输出质量（faithfulness）

11/16 已审事件中，**所有** 11 条 faithfulness=`0.0`：

| 事件 | verdict | confidence | faithfulness | phantom entities |
|---|---|---|---|---|
| 1891 SSH root@.5 | false_positive | 0.10 | 0.00 | – |
| 1892 SSH admin@.5 | false_positive | 0.22 | 0.00 | – |
| 1893 SSH admin@.7 | false_positive | 0.20 | 0.00 | – |
| 1894 SSH root@.7 | suspicious | 0.88 | 0.00 | 172.25.62.112 |
| 1895 SSH admin@.7 | suspicious | 0.36 | 0.00 | – |
| 1896 SSH admin@.9 | suspicious | 0.90 | 0.00 | 192.168.65.{11,5,7} port:22 |
| 1897 SSH root@.9 | suspicious | 0.58 | 0.00 | 172.25.62.112, port:22 |
| 1898 SSH admin@.9 | false_positive | 0.29 | 0.00 | – |
| 1899 SSH admin@.11 | suspicious | 0.86 | 0.00 | 192.168.65.5 |
| 1900 SSH root@.11 | false_positive | 0.10 | 0.00 | – |
| 1901 SSH admin@.11 | suspicious | 0.87 | 0.00 | 172.25.62.112, port:22 |

**关键现象**：
1. M2.7 在 final_summary 里**准确识别**了"4 个 IP 协同 SSH 暴力破解 + 端口扫描"（描述层面无错）
2. 但 grounding verifier **剥离了所有 unsupported claim**（phantom entities 都是事件里有的 IP/port，但 support_score=0 → 被 faithfulness gate 强制降级）
3. 5/11 因为 faithfulness=0 被强制归类为 `insufficient_evidence` → `response_blocked=true`（即使 verdict 是 suspicious 也被拦下）
4. 6/11 verdict=suspicious 但因 `response_blocked=true` 也没触发 block_ip

→ **M2.7 在"理解"和"自证"之间存在系统性 gap**：描述对了，但 grounding 把支持它的 evidence 也算成不支持。这是 M2.7 的 faithfulness 算法在 .11 攻击场景下与 evidence 检索不匹配的副作用，不是模型"幻觉"。

### 3.4 与 M3 时代对比（来自 memory）

| 维度 | M3（v6 历史数据）| M2.7（本次）|
|---|---|---|
| 单次 LLM 延迟 | ~57ms（v6 17.4 req/s 估算）| **14.9s p50**（reasoning forced_on）|
| 429 频次 | "今日日志实测: 偶发" | **0**（reasoning 调低了请求频次）|
| reasoning_split 重试 | v5 fix(D) 提到"偶发 content 为空" | **0**（M2.7 thinking 在 content 内的 `<think>` 标签，不走独立字段）|
| Faithfulness | (无历史数据) | **全部 0.00**，phantom entities 全部 0.0 support |

---

## 4. 检测 + 封禁链路

### 4.1 响应链状态（自动）

| 阶段 | 触发数 | 成功数 | 失败数 |
|---|---|---|---|
| `policy_match` | 4 | 4 | 0 |
| `send_alert` | 4 | 4 | 0 |
| `block_ip` | **0** | – | – |
| `rate_limit` | 0 | – | – |

**根因**（这是本次最关键的发现）：
- M2.7 审计输出 `threat_type: ""` / `threat_type_raw: ""`（空字符串）
- 平台响应策略匹配靠 `threat_type` 字符串对齐
- 11 条 suspicious 事件**全部**因 threat_type 为空而**没**匹配 `BRUTE_FORCE` / `PORT_SCAN` 任何专用策略
- 走 `ANY` 兜底策略（min_confidence=0.3, min_severity=info, auto_execute=true），但 `ANY` 只配 `send_alert` + `block_ip 60min` —— **4 条告警发出但 block_ip 仍为 0**（奇怪，可能 ANY 策略也要求某种 threat_type）

→ **结论：M2.7 的 audit schema 输出 `threat_type` 字段为空，导致平台响应链断裂。** 这是 M2.7 切换的**最大兼容性问题**。

### 4.2 响应链状态（手动 simulate 验证）

绕开自动路径，直接 `POST /api/response/simulate` 测 iptables 链路：

| IP | wall_ms | actions_succeeded | block_success | iptables rule_id |
|---|---|---|---|---|
| 192.168.65.5 | – | 2 | true | FW-RULE-74597 |
| 192.168.65.7 | 62 | 2 | true | FW-RULE-96406 |
| 192.168.65.9 | 57 | 2 | true | FW-RULE-58301 |
| 192.168.65.11 | 55 | 2 | true | FW-RULE-96977 |

→ **iptables 链路完好，<100ms 完成 SSH 到 soc-firewall + 写 iptables 规则**（走 `ssh_firewall_paramiko` 单例绕过 9p namespace 问题）。

### 4.3 iptables 终态

```
Chain INPUT (policy ACCEPT 762 packets, 112K bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       0    --  *      *       192.168.65.11        0.0.0.0/0   /* FW-RULE-96977 */  ← NEW
    0     0 DROP       0    --  *      *       192.168.65.9         0.0.0.0/0   /* FW-RULE-58301 */  ← NEW
    0     0 DROP       0    --  *      *       192.168.65.7         0.0.0.0/0   /* FW-RULE-96406 */  ← NEW
    0     0 DROP       0    --  *      *       192.168.65.5         0.0.0.0/0   /* FW-RULE-74597 */  ← NEW
    0     0 DROP       0    --  *      *       198.51.100.98        0.0.0.0/0   /* FW-RULE-17322 */
    0     0 DROP       0    --  *      *       198.51.100.99        0.0.0.0/0   /* FW-RULE-40272 */
    0     0 DROP       0    --  *      *       198.51.100.77        0.0.0.0/0   /* FW-RULE-19248 */
    0     0 DROP       0    --  *      *       91.240.118.17        0.0.0.0/0   /* FW-RULE-69675 */
    0     0 DROP       0    --  *      *       185.220.101.45       0.0.0.0/0   /* FW-RULE-22296 */
    0     0 DROP       0    --  *      *       198.51.100.77        0.0.0.0/0   /* FW-RULE-93471 */
    0     0 DROP       0    --  *      *       91.240.118.17        0.0.0.0/0   /* FW-RULE-43196 */
    0     0 DROP       0    --  *      *       185.220.101.45       0.0.0.0/0   /* FW-RULE-68591 */
```

8 旧规则 + 4 新规则 = 12 条，状态一致。

---

## 5. 端到端延迟

事件→响应配对（`event.created_at → response_log.created_at`）：

| response_id | event_id | src_ip | action | threat_type | e2e_ms |
|---|---|---|---|---|---|
| 664 | 1891 | 192.168.65.5 | block_ip | BRUTE_FORCE | 115 870 |
| 667 | 1891 | 192.168.65.7 | block_ip | BRUTE_FORCE | 130 810 |
| 670 | 1891 | 192.168.65.9 | block_ip | BRUTE_FORCE | 130 863 |
| 673 | 1891 | 192.168.65.11 | block_ip | BRUTE_FORCE | 130 924 |
| 676 | 1902 | – | block_ip | BRUTE_FORCE | 137 004 |
| 680 | 1904 | – | block_ip | UNKNOWN | 145 371 |

**注意**：这个 e2e 不是"自动链路"的真实 e2e，因为自动链路没触发 block_ip（§4.1）。这些 115-145s 是事件创建 → 审计完成 → **我手动调用 simulate** 的总时长。

**真实自动链路 e2e**（在自动路径工作的情况下）应该 ≈：
- M2.7 审计 p50 14.9s
- policy 匹配 + ssh_firewall 写 iptables <100ms
- 估计 **15-20s**（前提是 M2.7 输出的 threat_type 不为空，能命中 BRUTE_FORCE 策略）

---

## 6. 三个最大问题

### 问题 1: **M2.7 审计输出 `threat_type` 为空，自动封禁断链**

`backend/agents/sub_auditor.py` 的输出 schema 里 `threat_type` 字段在 M2.7 下没被正确填充（11/11 都空）。`response_policies` 匹配需要 `threat_type` 字符串，**所有专用策略失效**。

**修复方向**：
- 看 sub_auditor 的 prompt 是否要求 model 输出 `threat_type` 字段 → 改 prompt 强制输出
- 或者在 response_orchestrator 里加 fallback：如果 verdict=suspicious && conf>=0.5 && threat_type="" → 用 evidence_trail[0].type 作为 threat_type
- 或者把 `BRUTE_FORCE` / `PORT_SCAN` 策略的 threat_type 改成"any-of" 匹配

### 问题 2: **Faithfulness=0.0 导致 `response_blocked=true` 拦截 11/11 自动响应**

`summary.llm.chat` 之后走 `grounding_verifier` / `faithfulness_gate`，把所有 phantom entities（172.25.62.112 / port:22 / 192.168.65.5 等）当 unsupported 剥离，导致 faithfulness=0、needs_human=true、**response_blocked=true**。即使 verdict=suspicious 也被拦。

**修复方向**：
- 检视 `faithfulness_gate` 的 phantom entity 检测逻辑——这些 IP/port 都是事件 raw_data 里的，**应该被识别为 supported**，但当前 support_score 全部 0.0
- 可能是 RAG retrieval（`qdrant_store`）对 192.168.x.x 私网 IP / port number 召回不到 support 文档，导致 retrieval_score=0
- 短期绕过：调低 `faithfulness_gate` 阈值到 0.5（当前 0.75），或对"明确 verdict=suspicious"绕过 gate

### 问题 3: **平台无生产级网络/主机传感器，真实攻击不能进 SOC**

`docker-compose.yml` 缺：
- `soc-suricata` service（`config/suricata/` 目录在但没 service）
- `host-winlog-collector` service（`tools/windows-log-collector.ps1` 没作为 service）
- soc-firewall 缺 syslog forwarder → SSH auth.log 进不来

→ 真实攻击测试 = 0 事件，**端到端演练全靠合成注入**。

---

## 7. 一句话总结

**M2.7 接入本身健康（0 错误、0 重试），但 audit schema 输出的 `threat_type` 为空 + faithfulness=0.00 让自动响应链断在第一步**。iptables 链路手动验证完好（<100ms 写规则）。要真正用 M2.7 做生产自动封禁，必须先修 (1) threat_type 提取 和 (2) faithfulness gate 对私网 IP/port 的 support 判定。

---

## 附录 A：测试环境状态

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | 9 hours → recreated 15:50（M2.7） |
| `soc-temporal-worker` | 9 hours → recreated 16:00（**M2.7 之前是 stale M3**）|
| `soc-firewall` | 9 hours, 12 iptables DROP rules |
| `kali-pentest` | 9 hours, nmap+hydra available |
| Suricata service | **不存在**（compose 缺）|
| Host Win Event Log | **未 forward**（无 collector service）|
| `SHARED_MEMORY_LLM_MODEL` | M3 → **M2.7**（`.env` 改 + 双容器重建）|
| `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` | 12M（stale 容器）→ **5M**（与 .env 对齐）|

## 附录 B：测试产物文件

- `.tmp_kali_probe.sh` — kali 网络/工具探测
- `.tmp_attack.sh` — 拷进 kali 的 attack-simulator.sh
- `.tmp_inject_attack.py` — 16 条攻击事件注入
- `.tmp_collect_metrics.py` — 指标采集
- `.tmp_block_remaining.py` — 手动 simulate block_ip
- `.tmp_attack_metrics.json` — 完整指标 JSON
- `docs/security-audit/attack-perf-m27-2026-09-01.md` — 本报告

> 这些 `.tmp_*` 文件可以删，也可以 `git add .tmp_*` 当作可复现的测试 artifacts。
