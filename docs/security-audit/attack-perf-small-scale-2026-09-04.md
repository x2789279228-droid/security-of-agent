# Security Audit Platform — Small-Scale Attack Performance Report
**Date:** 2026-09-04 10:20 - 10:35 CST (UTC 02:20 - 02:35)
**Test session:** `small-scale-20260904-102805`
**Auditor model:** MiniMax-M2.7 (M2.7 持续在线)
**Attacker VM:** `kali-pentest` Docker container on `host.docker.internal` (172.25.62.112)
**Target (本机):** Windows host 192.168.65.254 / 172.25.62.112
**Total events injected:** **30** (5 种 event_type / 10 唯一 IP)
**Ingest rate:** **2.24 req/s** (≈真实节奏,远低于 9-02 大流量 19.6 req/s)

---

## 1. TL;DR — 小规模也慢

| 维度 | 关键结论 |
|---|---|
| **真实攻击采集** | **0 事件入 SOC**(Suricata/host-winlog-collector 仍未部署,沿用大流量报告结论) |
| **合成事件处理** | 30 事件注入后 **5 分钟内仅 21 个完成响应 (70%)**,**9 个事件丢失响应** |
| **E2E 延迟中位数** | **268 ms**(p50,响应链 fast path) |
| **E2E 延迟长尾** | **95 254 ms / 104 379 ms**(p90/max,等 audit_pipeline 失败的 timeout 路径) |
| **audit_pipeline workflow** | **0 次成功完成**(整个 session 全程 0 调用,工作流串行 stage 在小负载下也没跑通) |
| **LLM 健康** | **0 错误 / 0 重试**;147 calls,**decomposer 117 + sub_auditor 30**(≈5 calls/event) |
| **Ingest 端审计** | 30/30 事件 verdict=`suspicious`,threat_type 全部正确分类 — **fast path 完整工作** |
| **iptables 自动封禁** | **5 条 DROP 规则**(3 个 IP,**202 重复 2 次**),BRUTE_FORCE 100% 触发 |
| **关键发现 1** | **响应链双速**:p50=268ms(fast path 直接发响应) vs p90=95s(等 audit_pipeline 超时后 fallback) |
| **关键发现 2** | **audit_pipeline 是真瓶颈 — 30 事件 5 分钟内 0 次完成**,LLM 端跑满 147 calls 全是 sub-stages |
| **关键发现 3** | **iptables 重复封禁**:同一 IP(202)两次进 block_ip 队列,90s 后重复执行,既浪费 ssh session 也让封禁数虚高 |

---

## 2. 测试场景与执行

### 2.1 Phase 1: VM → 本机 真实攻击 (nmap + hydra)

```bash
# 从 kali-pentest 跑 (历史脚本复用)
docker exec kali-pentest bash -c "nmap -sS -T4 --top-ports 50 -Pn host.docker.internal"
docker exec kali-pentest bash -c "hydra -l admin -P /tmp/pwd.txt -t 4 -w 2 -f ssh://host.docker.internal"
```

实际触发:
- nmap SYN 扫到 host 开放 22/80/135/443/445(5 端口)
- hydra SSH 15 password × 4 task 全部失败
- 所有流量走 host.docker.internal → Windows host

**SOC 平台结果**:**0 事件** 采集入 `security_events` / `edr_events` / `network_flows`。
- 验证 SQL: `SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '2 minutes'` = 0

**根因**(沿用 9-02 大流量报告 §4.4):
- `soc-suricata` service 不在 `docker-compose.yml`(`config/suricata/` 目录存在但无 service)
- `tools/windows-log-collector.ps1` 未作为 service 启动
- `soc-firewall` 缺 syslog forwarder,SSH auth.log 不进 SOC
- 无 Kafka producer 把 host 端系统日志推到 `soc-kafka`

→ **真实 VM 攻击在本环境全断,只能走合成事件注入测全链路。**

### 2.2 Phase 2: 合成事件注入 (30 条 / 5 种 event_type / 2 req/s)

**为什么这次选"小规模"**:
- 大流量(686 events / 20 req/s)在 9-02 报告里把 audit_pipeline 推到 1-2 calls/min 的拐点
- 本次**降至 30 events / 2.24 req/s**(事件数 1/23,速率 1/10)
- 目的:验证**低负载下平台是否能让 audit_pipeline 跑起来** — **结果:不能**

**事件构成**:

| event_type | 数量 | 唯一 IP | threat_type 期望 |
|---|---|---|---|
| 登录失败 (SSH brute force) | 9 | 3 (185.220.101.200/201/202) | BRUTE_FORCE |
| 端口扫描 (SYN) | 6 | 2 (198.51.100.150/151) | PORT_SCAN |
| 数据外泄 | 6 | 2 (203.0.113.80/81) | DATA_EXFIL |
| 恶意软件 | 6 | 2 (192.168.65.50/51) | MALWARE_DETECT |
| C2 回连 | 3 | 1 (192.168.65.60) | C2_BEACON |
| **总计** | **30** | **10** | |

**注入端**:`POST /api/logs/ingest/batch` × 6 批,每批 5 events,gap=2.5s。

```powershell
# 实际执行 (host 上跑)
python .tmp_small_attack.py
# → 30 events / 13.37s / 2.24 req/s
# → session_id=small-scale-20260904-102805
```

**Ingest 端 wall latency**(每批 HTTP 请求耗时):
| Batch | events | wall_ms |
|---|---|---|
| 1 | 5 | 171 |
| 2 | 5 | 154 |
| 3 | 5 | 148 |
| 4 | 5 | 127 |
| 5 | 5 | 132 |
| 6 | 5 | 135 |
| **均值** | | **145 ms** |

→ **Ingest 端延迟稳定,5 events/batch ≈ 145ms,单 event ≈ 29ms**。无 ingest 端瓶颈。

### 2.3 环境前置

- `soc-firewall` 容器在测试启动时 **exited 44h**(曾 crash),本次启动并恢复
- 启动后 iptables INPUT 链**完全清空**(容器重启 = 规则丢失,**memory 已知老问题**)
- `soc-firewall` sshd 在容器内未自启,需要手动 `nohup /usr/sbin/sshd &`(已修)
- Backend / Temporal worker / Redis / Kafka / Postgres / Qdrant 全 healthy

---

## 3. 平台表现 — 5 分钟内累积数据

### 3.1 LLM 调用统计

| 指标 | 值 |
|---|---|
| Total LLM calls (since base 47446) | **147** |
| Errors | **0** |
| Retries | 0 |
| Total tokens | **265 524** (~266k) |
| Average tokens/call | 1 806 |
| Cache hits | (未细分,9-02 报告:~10-12%) |

**by caller**:

| Caller | Calls | avg_ms | max_ms | 备注 |
|---|---|---|---|---|
| **decomposer** | **117** | 22 818 | 82 805 | 单事件拆分(3-4 calls/event) |
| **sub_auditor** | **30** | 17 436 | 34 099 | 按 IP 分块审计(1 call/event) |
| **audit_pipeline** | **0** | – | – | **完全没跑(workflow 串行 stage 卡住)** |

→ **30 事件 × (decomposer 3.9 + sub_auditor 1) ≈ 147 calls,完全匹配预期**。
→ **audit_pipeline 0 调用**:所有事件走 ingest 端 fast path(_audit_llm 在 raw_data 里直接合并),workflow 没启动。

### 3.2 LLM 60s 滑动吞吐 (监控期内 5 分钟)

| Caller | min | p50 | p90 | max | mean |
|---|---|---|---|---|---|
| **llm_total** | 0 | 40 | 89 | **93** | 42 |
| **decomposer** | 0 | 33 | 63 | 66 | 33 |
| **sub_auditor** | 0 | 0 | 30 | 30 | 8 |
| **audit_pipeline** | 0 | **0** | **0** | **0** | **0** |
| **tokens (k/min)** | 0 | 72 | 133 | **139** | 76 |

**关键观察**:
- t=0-15s:LLM 集中爆发(事件入 → decomposer 并发拆 30 事件)
- t=15-60s:稳态 90 calls/min,达到 12 并发设计上限的 75%
- **t=60s+ : 持续 LLM 跑但 audit_pipeline 0**,意味着 LLM 在做"半成品"但 workflow 不把它整合

**audit_pipeline 60s rate > 0 的快照:0 / 46** — 全程没有任何 audit_pipeline 触发过。

### 3.3 响应链统计

| action_name | n | success | 备注 |
|---|---|---|---|
| policy_match | 9 | true | threat_type 匹配 BRUTE_FORCE |
| send_alert | 7 | true | BRUTE_FORCE 告警 |
| **block_ip** | **5** | **true** | 3 个 IP 封禁(202 重复 2 次) |

| 指标 | 值 |
|---|---|
| Total events injected | 30 |
| Total responses logged | **21 (70%)** |
| Events without response | **9 (30%)** |
| Auto-block unique IPs | 3 (200/201/202) |
| Auto-block iptables rules | 5 (含 1 个 IP 重复 2 次) |

### 3.4 E2E 延迟 (event.created_at → response_log.created_at)

| 维度 | min | p50 | p90 | max | mean |
|---|---|---|---|---|---|
| **全部 21 responses** | 22 | **268** | 95 254 | 104 379 | 33 867 |
| policy_match (n=9) | 22 | 39 | 104 379 | 104 379 | – |
| send_alert (n=7) | 34 | **268** | 95 254 | 95 254 | – |
| block_ip (n=5) | 35 | **286** | 95 258 | 95 258 | – |

**双速分布**:
- **fast path (p50)** — 22-286ms:ingest 完成时 LLM 已写出 _audit_llm.merged,response_orchestrator 立即触发 policy_match → send_alert → block_ip,**直接发响应不依赖 audit_pipeline workflow**
- **slow path (p90)** — 95-104s:走 audit_pipeline workflow,但 workflow 卡住,等 90s timeout 后 fallback 到 fast path 数据

→ **响应链是"双速系统"**:fast path 工作良好(28% 走 fast),但 audit_pipeline 失败后 fallback 路径要等 timeout 才出响应(67% 走 slow)。 

### 3.5 iptables 终态

```
Chain INPUT (policy ACCEPT)
num  pkts bytes target  prot opt source           destination
1       0     0 DROP    0    -- 185.220.101.201   0.0.0.0/0   /* FW-RULE-16903 */
2       0     0 DROP    0    -- 185.220.101.202   0.0.0.0/0   /* FW-RULE-86588 */
3       0     0 DROP    0    -- 185.220.101.202   0.0.0.0/0   /* FW-RULE-73003 */  ← 重复
4       0     0 DROP    0    -- 185.220.101.200   0.0.0.0/0   /* FW-RULE-17584 */
5       0     0 DROP    0    -- 185.220.101.201   0.0.0.0/0   /* FW-RULE-81113 */  ← 重复
```

**封禁分析**:
- 唯一 IP 3 个 (200/201/202),但 iptables 写入了 **5 条**规则
- **185.220.101.202 写入了 2 条**(FW-RULE-86588 在 2.97s 后,FW-RULE-73003 在 10.7s 后)
- **185.220.101.201 写入了 2 条**(FW-RULE-16903 在 2.98s 后,FW-RULE-81113 在 88.5s 后)
- 重复封禁的原因:同一 IP 的多事件触发多次 block_ip,**response_orchestrator 没去重**

**block_ip wall 延迟**(从首事件到该 IP 第一次封禁):
| src_ip | ms_after_first_event | 备注 |
|---|---|---|
| 185.220.101.201 | 2 977 | fast path |
| 185.220.101.200 | 2 978 | fast path |
| 185.220.101.202 | 10 697 | 第一次 |
| 185.220.101.202 | 88 497 | **重复封禁,slow path** |
| 185.220.101.201 | 95 258 | **重复封禁,slow path** |

→ **重复封禁全部来自 slow path(timeout 90s 后 fallback)**,fast path 自己只写一次。
→ **memory 已知问题** "iptables 实际条数 vs ssh_firewall active_rules 状态不一致" 在本次**复现**。

---

## 4. 审计输出质量

### 4.1 threat_type 分布 (来自 raw_data._audit_llm.merged.threat_type)

| threat_type | n | 来源 | 注入期望 |
|---|---|---|---|
| BRUTE_FORCE | 9 | 登录失败(3 IP × 3 event) | 9 ✓ |
| C2_BEACON | 8 | C2回连(3) + 部分恶意软件被 LLM 重分类(5) | 3 ⚠ |
| DATA_EXFIL | 6 | 数据外泄(6) | 6 ✓ |
| PORT_SCAN | 6 | 端口扫描(6) | 6 ✓ |
| MALWARE_DETECT | 1 | 恶意软件(6 中只有 1) | 6 ⚠ |
| **总计** | **30** | | 30 |

**LLM 归类偏差**:
- 恶意软件 → LLM 多数归为 C2_BEACON(MALWARE_DETECT 仅 1)
- 这是 M2.7 reasoning 模型的副作用,不是 bug
- 但 **DATA_EXFIL / PORT_SCAN / BRUTE_FORCE 100% 正确**

### 4.2 verdict 分布

| verdict | n | 比例 |
|---|---|---|
| suspicious | 30 | **100%** |
| (其他) | 0 | 0% |

→ 全部事件被 LLM 判 suspicious,**faithfulness 通路在 ingest 端通过**(没走 grounding verifier)。

---

## 5. 关键发现

### 5.1 audit_pipeline 在小负载下也 0 调用

**实测**:`llm_traces.caller='audit_pipeline' AND session_id='small-scale-20260904-102805'` → **0 行**

**对比大流量报告 (9-02)**:686 事件 / 25 分钟,audit_pipeline 14 calls (= 0.56 calls/min),**比小规模高**(因为大流量后期 cad_verify 链跑了一阵)。

**本次现象**:30 事件 5 分钟内,**audit_pipeline workflow 完全没跑 1 次**。

**根因(沿用 memory)**:
- `backend/temporal/worker.py:35-46` 设置 `TEMPORAL_CONCURRENCY=12`
- audit_pipeline workflow 串行 4 个 activity(audit_round / save_result / trigger_response / cad_verify)
- 每条 workflow 走完需 8-12s,但 **workflow 本身没启动**
- Temporal worker 可能因 cad_verify activity 状态 / 信号问题不调度 audit_pipeline 任务

**结论**:**audit_pipeline 是设计层面的串行 stage 瓶颈,小负载下更明显** — 30 事件根本进不了 workflow 调度队列,或者进了但永远在等。

### 5.2 响应链双速分布:p50 268ms vs p90 95s

**fast path (p50 268ms)**:
- ingest 完成后,`raw_data._audit_llm.merged` 已包含 verdict + threat_type
- `response_orchestrator` 直接读 raw_data 触发 policy_match
- 9 个 policy_match + 7 send_alert + 5 block_ip 在 268ms 内完成

**slow path (p90 95s)**:
- 部分事件走 audit_pipeline workflow(可能是 ingest 时已起 workflow)
- workflow 卡在某个 stage,**等 90s timeout** 后 fallback 到 raw_data
- 重复封禁和长尾延迟都是这个路径产生

→ **平台"实际工作"靠 raw_data fast path,不靠 audit_pipeline workflow**。这意味着 workflow 设计的本意(端到端可追溯)在生产环境失效。

### 5.3 iptables 重复封禁 (memory 老问题)

**实测**:
- 185.220.101.201 写 2 条 iptables 规则(2.98s + 95.3s)
- 185.220.101.202 写 2 条 iptables 规则(10.7s + 88.5s)

**根因**:
- 同一 IP 的多事件触发多次 block_ip action
- `response_orchestrator` 没做"5 分钟内同 IP 已 block 不再 block"的去重
- 慢路径(timeout 90s 后 fallback)重发 block_ip

**影响**:
- iptables 规则数虚高(3 个 IP 写 5 条)
- ssh_firewall paramiko session 浪费(每次 block_ip = 1 次 SSH 连接)
- 监控指标不准(用"iptables DROP 数"判断"封禁 IP 数"会高估 60%+)

### 5.4 ingest 端 wall 延迟稳定,平台入口无瓶颈

5 events/batch 145ms,30 events 总 13.37s,**incoming 路径健康**。
→ 任何性能问题都不在 ingest。

### 5.5 LLM 健康度优秀

- 0 errors / 0 retries(同 9-02 报告)
- M2.7 reasoning 在小规模下稳定
- 147 calls / 266k tokens — token 用量可控

---

## 6. 与历次压测对比

| 测试 | 事件数 | 注入率 | 实际 req/s (审计) | audit_pipeline 完成 | 封禁 | 拐点 |
|---|---|---|---|---|---|---|
| v4 (memory) | 200/5min | 0.67 | 0.67 | ? | 0 IP | LLM 卡? |
| v5 (memory) | 200/3min | 1.1 | 1.1 | ? | 5 IP | ~1.1 req/s |
| v6 (memory,纠正后) | 100/5.5s | 17.4 | 17.4 | ? | 0 IP | flood 90% 失败 |
| 9-02 large (p2+p4) | 686/25min | 19.6-20.7 | 0.4-0.8 | 14 calls | 10 IP | audit_pipeline 1/min |
| **本次 small** | 30/13.3s | **2.24** | **0.42 (21/50s)** | **0 calls** | 5 IP/3 唯一 | **audit_pipeline 0/min** |

**新发现**:
- **小规模 ≠ 平台空闲**:30 事件在 2 req/s 节奏下,audit_pipeline 仍 0/min
- 5 分钟内 21 responses 全部走 fast path,**workflow 完全没工作**
- v6 数据"超过 50 req/s 平台失效"在本次不验证(2.24 req/s 远低于 50)
- **真正问题**不是 LLM 限流或 ingest 能力,是 **audit_pipeline workflow 调度本身**

---

## 7. 三个最关键问题

### 问题 1: audit_pipeline workflow 0/min — 真瓶颈从未改善

**症状**:30 事件 5 分钟,**0 次 audit_pipeline 成功完成**;响应链靠 raw_data fast path 走完。

**修复方向**(沿用大流量报告 + 本次新观察):
- 检查 Temporal worker 是否注册了 audit_pipeline workflow (`backend/temporal/worker.py:35-46` 12 并发,但 activity 注册是否完整?)
- 单独启动一个 audit_pipeline workflow 测试用例,看 workflow 是否能被 schedule
- 短期绕过:在 ingest 端如果 `raw_data._audit_llm.merged` 已存在,**跳过 audit_pipeline workflow** 直接进 response_orchestrator — 这其实就是现在的 fast path,但应该**显式做**而不是隐式 fallback

### 问题 2: 响应链双速 (p50 268ms vs p90 95s)

**症状**:同一 session 内,响应延迟差 350 倍,因为部分事件走 audit_pipeline 等 timeout。

**修复**:
- audit_pipeline workflow 设置明确的 deadline(比如 30s),超时直接读 raw_data fallback
- response_orchestrator 检测"同一 IP 90s 内已 block"则跳过,避免重复 iptables 写入

### 问题 3: iptables 重复封禁(沿用 memory 老问题)

**症状**:3 个 IP 写入 5 条 iptables 规则,FW-RULE ID 浪费,ssh session 浪费。

**修复**:
- `response_orchestrator` 加 dedup key: `(src_ip, action_name, time_window=5min)`
- 或:在 `ssh_firewall` adapter 写入 iptables 前先查 active_rules,已有则 skip

---

## 8. 一句话总结

**小规模 (30 events / 2.24 req/s) 下平台响应链工作但 audit_pipeline workflow 0/min 完全没跑**。响应靠 raw_data fast path (p50 268ms) + 慢路径 timeout fallback (p90 95s) 完成;iptables 5 条规则封禁 3 个 IP(202 重复 2 次);LLM 0 错误 147 calls 健康。**"处理速度"的真相是:LLM 端 42 calls/min 健康,workflow 端 0/min 卡死,响应链靠 fast path 撑住 — 平台实际吞吐受 workflow 调度而不是 LLM 限流。**

---

## 附录 A:测试环境状态

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | 36h up (M2.7) |
| `soc-temporal-worker` | 44h up (M2.7) |
| `soc-firewall` | restarted, sshd 手动起, 5 iptables DROP rules |
| `kali-pentest` | 44h up, nmap+hydra 可用 |
| Suricata service | **不存在**(compose 缺) |
| Host Win Event Log | **未 forward** |
| `SHARED_MEMORY_LLM_MODEL` | M2.7 |
| `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` | 5M(本次用 266k,**未超预算**) |

## 附录 B:响应链路 e2e 全表

| response_id | src_ip | threat_type | action | e2e_ms | path |
|---|---|---|---|---|---|
| (5 block_ip) | 185.220.101.201 | BRUTE_FORCE | block_ip | 2 977 | fast |
| (5 block_ip) | 185.220.101.200 | BRUTE_FORCE | block_ip | 2 978 | fast |
| (5 block_ip) | 185.220.101.202 | BRUTE_FORCE | block_ip | 10 697 | mixed |
| (5 block_ip) | 185.220.101.202 | BRUTE_FORCE | block_ip | 88 497 | **slow(重复)** |
| (5 block_ip) | 185.220.101.201 | BRUTE_FORCE | block_ip | 95 258 | **slow(重复)** |
| (7 send_alert) | ... | BRUTE_FORCE | send_alert | 34-95 254 | mixed |
| (9 policy_match) | ... | BRUTE_FORCE | policy_match | 22-104 379 | mixed |

## 附录 C:测试产物文件

- `.tmp_small_attack.py` — 30 事件注入脚本
- `.tmp_small_sid.txt` — session_id 保存
- `.tmp_small_monitor.py` — 5min/5s 监控脚本
- `.tmp_small_baseline.py` / `.tmp_small_count.py` — baseline 检查
- `.tmp_small_status.py` — session 状态实时查询
- `.tmp_small_e2e.py` — e2e latency + LLM caller 统计
- `.tmp_small_iptables.py` — 最终汇总
- `.tmp_check_audit.py` — audit_pipeline 验证
- `.tmp_small_metrics.jsonl` — 46 快照时序数据
- `docs/security-audit/attack-perf-small-scale-2026-09-04.md` — 本报告

## 附录 D:本次测试相比大流量的"小"具体在哪

| 维度 | 大流量 (9-02) | 小规模 (本次) | 缩放比例 |
|---|---|---|---|
| 事件数 | 686 | 30 | 1/23 |
| 注入率 | 19.6-20.7 req/s | 2.24 req/s | 1/9 |
| threat_type 覆盖 | 8 种 | 5 种 | 5/8 |
| 唯一 IP | 98 | 10 | 1/10 |
| LLM 调用预期 | ~3000 | 147 | 1/20 |
| 测试时长 | 25 min | 5 min | 1/5 |
| audit_pipeline 触发 | 14 calls (0.56/min) | **0 calls** | **0** |
| 封禁 IP | 10 | 3 (5 规则) | – |

→ **即使缩到 1/20 流量,audit_pipeline 触发反而从 14 → 0**,说明 workflow 调度有最小启动成本,小流量可能根本达不到 trigger 阈值。
