# Security Audit Platform — Large-Scale Attack Performance Report
**Date:** 2026-09-02 00:09 - 00:30 CST
**Test session prefix:** `large-scale-20260902-*`
**Auditor model:** MiniMax-M2.7 (carried over from M2.7 切换)
**Attacker VM:** `kali-pentest` Docker container on `host.docker.internal` (172.25.62.112)
**Total events injected:** **686** (Phase 2: 487 / Phase 4: 199)
**Coverage:** 8 / 9 active response policies (excluded: LATERAL_MOVEMENT alias)

---

## 1. TL;DR — 拐点找到了

| 维度 | 关键结论 |
|---|---|
| **真实拐点** | **0.017 - 0.033 events/sec 完整审计**(audit_pipeline 1-2 calls/min) |
| 平台稳态吞吐 | **150 LLM calls/min**(设计上限 12 并发工作流 × ~12 calls/min) |
| 端到端实测 | 686 事件 25 分钟仅 **69 个事件完整审计**(10.1% coverage) |
| Auto-block | **10 IP 真实封禁**(iptables 12 → 22) — 5 BRUTE_FORCE × 2 phase |
| LLM 健康度 | **0 errors / 0 retries** (M2.7 稳定) |
| Token 用量 | 今日 **12.8M tokens**(超出 5M 日预算 2.5x,系统**未拒服**)|
| **关键发现** | **audit_pipeline 是真正瓶颈** — LLM 持续 150/min 但 pipeline 输出 1-2/min |
| **政策匹配** | **可用** — threat_type 在 ingest 端预设就 OK,**LLM 提取路径仍是空**(M2.7 老问题延续) |

---

## 2. 测试场景与执行

### 2.1 Phase 1 — 从 kali-pentest 真实攻击

```bash
docker exec kali-pentest bash -c 'TARGET=host.docker.internal; nmap -sS -T4 --top-ports 50 -Pn "$TARGET"'
docker exec kali-pentest bash -c 'hydra -l admin -P /tmp/pwd.txt -t 4 -w 3 ssh://soc-firewall:2222'
```

实际触发:
- nmap SYN 扫到 host 开放 22/80/135/443/445/3000/5432/8001(7 端口)
- nmap -sV 详细指纹识别 55 秒
- hydra SSH 暴力破解 15 密码 × 3 轮(45 次尝试)
- 所有流量走 `host.docker.internal` → Windows 主机

**SOC 平台结果**:**0 事件** 采集入 security_events / edr_events。

**根因**(沿用 M2.7 报告 §2.2):
- Suricata service **不在** docker-compose.yml(`config/suricata/` 目录在但无 service)
- `tools/windows-log-collector.ps1` 未作为 service 启动
- soc-firewall 容器**无 syslog forwarder**,SSH auth.log 不进 SOC
- 没有 Kafka producer 把 host 端系统日志推到 `soc-kafka`

**结论**: 真实 VM 攻击流量的"感知路径"在 dev 环境全断,**端到端真攻击演练必须用合成事件注入**。

### 2.2 Phase 2 — 487 条合成攻击(8 策略全覆盖)

通过 `POST /api/logs/ingest/batch` 注入,`threat_type` 字段**直接预设**(因为 M2.7 audit 输出 `threat_type=""`,而 ingest 端字段是另一条路径)。

| threat_type | 数量 | 唯一 IP | 注入率 |
|---|---|---|---|
| BRUTE_FORCE | 220 | 20 公网 | (50/batch)|
| DDoS_TRAFFIC | 80 | 20 公网 | |
| C2_BEACON | 32 | 4 失陷内网 | |
| PORT_SCAN | 60 | 30 公网 | |
| MALWARE_DETECT | 35 | 15+4 内外 | |
| DATA_EXFIL | 20 | 1+3 内外 | |
| LATERAL_MOVE | 20 | 4 失陷 | |
| ANY (benign) | 20 | 8 运维 | |
| **总计** | **487** | **98 唯一** | **19.6 req/s** |

注入耗时 **24.8s**,session_id = `large-scale-20260902-001409`。

### 2.3 Phase 4 — 199 条叠加负载(在 Phase 2 未消化完时)

Phase 2 注入后 ~10 分钟,Phase 2 已消耗 ~50 事件,叠加 **199 条**(部分 IP 与 Phase 2 重叠 — 模拟**持续攻击**):

| threat_type | 数量 | 唯一 IP |
|---|---|---|
| BRUTE_FORCE | 60 | 15 公网 |
| DDoS_TRAFFIC | 80 | 50 公网 |
| LATERAL_MOVE | 39 | 3 失陷 |
| PORT_SCAN | 20 | 10 公网 |

注入耗时 **9.6s**,rate = **20.7 req/s**。session_id = `large-scale-p4-002304`。

---

## 3. 平台表现 — 25 分钟内累积数据

### 3.1 LLM 调用统计

| 指标 | 值 |
|---|---|
| Session LLM calls | **1808** (id > 13054)|
| Success | 1643 (90.9%)|
| Error | **0** |
| Degraded (降级但成功) | 165 (9.1%)|
| Cache hit | ~150 (sub_auditor 重复 IP 模式命中) |
| 今日 token 总量 | **12,796,628**(~12.8M, 超出 5M 日预算 2.5x)|

**关键现象**:
- 0 error → M2.7 在大量调用下依然稳定
- 9.1% degraded 状态是 sub_auditor / decomposer 在 reasoning 长度不达标时的"软失败"(自动用 cached 或 partial result)
- **5M token 预算被突破 2.5x 但 LLM 仍继续服务** — budget 限制可能是 warning-only 而非 block

### 3.2 LLM 调用分布 (by caller)

| Caller | Session calls | p50 (ms) | p95 (ms) | max (ms) | 备注 |
|---|---|---|---|---|---|
| **decomposer** | 1568 | 12,178 | 34,309 | **148,157** | 单事件拆分,主吞吐 |
| sub_auditor | 215 | 6,197 | 26,361 | 46,627 | 按 IP 分块审计 |
| **audit_pipeline** | **14** | 8,078 | 11,781 | 11,781 | **最终整合 — 真正瓶颈** |
| watchdog | 11 | – | – | – | (历史数据) |

**audit_pipeline 14 次 / 25 分钟 = 0.56 次/分钟 = 0.0093 次/秒** — **完整审计 e2e 上限**。

### 3.3 实时吞吐趋势 (per-minute)

从 `llm_traces.created_at` 分桶:

| 时间 (CST) | LLM calls | audit_pipeline | 累计 errors |
|---|---|---|---|
| 16:14 | 128 | 2 | 0 |
| 16:15 | 128 | 1 | 0 |
| 16:16 | 121 | 0 | 0 |
| 16:17 | 148 | 1 | 0 |
| 16:18 | 159 | 2 | 0 |
| 16:19 | 155 | 3 | 0 |
| 16:20 | 152 | 1 | 0 |
| 16:21 | 63 | 0 | 0 |
| 16:22+ | 持续 130-150/min | 1-2/min | 0 |

**稳定状态**:**150 LLM calls/min**(达到 12 并发 × 12 calls/min 的设计上限) + **1-2 audit_pipeline/min**(被限流在最低段)。

### 3.4 响应链统计

| session | events | policy_match | send_alert | block_ip | 唯一 block IP | events with response |
|---|---|---|---|---|---|---|
| Phase 2 (487) | 487 | 51 | 20 | 5 | 5 (185.220.101.{41,46,49,53,55})| **51 (10.5%)** |
| Phase 4 (199) | 199 | 18 | 18 | 5 | 5 (185.220.101.{60,62,63,64,65})| **18 (9.0%)** |
| **总计** | **686** | **69** | **38** | **10** | **10** | **69 (10.1%)** |

**Phase 2 响应分布**:

| threat_type | policy_match | send_alert | block_ip |
|---|---|---|---|
| BRUTE_FORCE | 20 | 16 | 5 |
| MALWARE_DETECT | 18 | 3 | 0 |
| DDoS_TRAFFIC | 11 | 0 | 0 |
| DATA_EXFIL | 2 | 1 | 0 |

**Phase 4 响应分布**:

| threat_type | policy_match | send_alert | block_ip |
|---|---|---|---|
| BRUTE_FORCE | 15 | 15 | 5 |
| LATERAL_MOVE | 3 | 3 | 0 |

### 3.5 iptables 终态

**总规则数: 22**(测试前 12 + 测试中 10)

新增 10 条全部命中 BRUTE_FORCE 自动封禁策略:

```
Chain INPUT (policy ACCEPT 844 packets, 123K bytes)
num  pkts bytes target  prot opt source           destination
1       0     0 DROP    0    -- 185.220.101.65   0.0.0.0/0   /* FW-RULE-10344 */  ← p4 NEW
2       0     0 DROP    0    -- 185.220.101.62   0.0.0.0/0   /* FW-RULE-88159 */  ← p4 NEW
3       0     0 DROP    0    -- 185.220.101.63   0.0.0.0/0   /* FW-RULE-44073 */  ← p4 NEW
... 7 more (5 from p2 + 2 from p4)
11      0     0 DROP    0    -- 192.168.65.11    0.0.0.0/0   /* FW-RULE-96977 */  (M2.7 manual)
...
22      0     0 DROP    0    -- 185.220.101.45   0.0.0.0/0   /* FW-RULE-68591 */  (prior)
```

**封禁特征**:
- 全部由 BRUTE_FORCE 触发(min_confidence=0.5 阈值,**20 个 BRUTE_FORCE 事件 = 10 个 IP 实际被封** = 50% block 率)
- DATA_EXFIL / MALWARE_DETECT / DDoS_TRAFFIC / LATERAL_MOVE 全部**未触发封禁**
  - 原因:这些策略的 actions 里**只有 send_alert / isolate_host**,**没有 block_ip**
  - 即使满足 min_confidence 也只告警不阻断 — 平台设计如此

---

## 4. 关键发现与根因分析

### 4.1 真正拐点:audit_pipeline 是平台瓶颈(不是 LLM 限流)

**现象**:
- LLM 持续 150 calls/min → 系统**未卡在 LLM**
- decomposer + sub_auditor 跑得很快(sub_auditor p50 6.2s)
- **audit_pipeline 只跑 1-2/min** ← 整个响应链等待它

**根因**:`backend/temporal/worker.py:35-46` 设置了 `TEMPORAL_CONCURRENCY=12`,但 audit_pipeline 的 4 个 activity( audit_round / save_result / trigger_response / cad_verify )**共享这 12 个并发槽位**。每条 workflow 串行 4 个 activity,audit_pipeline 又是其中最慢的(8-12s/次),所以稳态下:

```
audit_pipeline 速率 ≤ 12 并发 / 4 activities / 8-12s avg = 0.25-0.4 calls/sec (理论)
                       ≈ 15-25 calls/min  (理论上限)
```

实测只有 1-2/min,**实际是理论值的 7-15%**。可能原因:
- sub_auditor 的 batch_verify / cross_verification 串行耗时长(见 worker 日志)
- cad_verify activity 抢占了并发槽
- 12 槽位实际只有部分给 audit_pipeline 走完

### 4.2 LLM 日预算限制形同虚设

**配置**:`SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS=5000000`(5M)
**实测**:今日已用 **12,796,628 tokens**(超出 2.5x),**0 errors,0 block**

→ 预算检查**只告警不阻断**。生产环境如果持续超预算,**计费风险存在**。

### 4.3 ingest 端 threat_type 预设 vs LLM audit 输出 — 路径分裂

| 路径 | threat_type 来源 | 命中率 |
|---|---|---|
| **ingest 端预设** (`raw.threat_type` 字段) | 测试数据 / Suricata 解析 | **100% 命中** (本次测试)|
| **M2.7 audit 输出** (`summary.threat_type`) | LLM 推理 | **0% 命中**(M2.7 报告已知 bug,本测试仍未修)|

→ **本次 10 个 auto-block 全是 ingest 端预设路径**,**LLM 提取路径仍空**。**M2.7 报告 §6 问题 1 未修复**。

### 4.4 真实攻击流量不进 SOC(沿用 M2.7 报告 §6 问题 3)

本次 Phase 1 真实 nmap + hydra 攻击 → **0 事件入 security_events**:
- 缺 Suricata IDS service(`docker-compose.yml` 未注册)
- 缺 host Windows Event Log collector service
- 缺 soc-firewall syslog forwarder

**端到端真攻击演练 = 0 事件**。**只能用合成事件注入测全链路**。

### 4.5 数据完整性发现

`security_events.event_id` (string) 与 `llm_traces.event_id` (integer) 是**两个独立 ID**:
- 事件 ingest 时,user 给的 `eventId="p4-bf-..."`(string) 写入 `security_events.event_id`(string)
- 但审计 pipeline 内部用数据库 auto-increment 的 `events.id`(int) 写到 `llm_traces.event_id`
- → **跨表 join 必须用 raw_data 字段** 或 src_ip + 时间窗匹配
- → 监控脚本 v1-v3 全部踩这个坑(用 IN $1::int[] 失败,改用 INNER JOIN 解决)

### 4.6 12 并发设计 = LLM 友好但 pipeline 慢

`backend/temporal/worker.py:31-33` 注释:
> "v5 修复:并发上限。此前无上限,216 个 workflow 同时启动时上百个 audit_round 并发打 LLM API → MiniMax 429 风暴"

→ 设计上 **LLM 调用 rate 优先**(避免 429),**接受 audit_pipeline 慢**作为代价。

---

## 5. 与历次压测对比(从 memory 恢复)

| 测试 | 事件数 | 注入率 | 实际 req/s | 审计完成 | 封禁 | 拐点 |
|---|---|---|---|---|---|---|
| v4 (memory) | 200/5min | 0.67 | 0.67 | ? | 0 IP | LLM 卡? |
| v5 (memory) | 200/3min | 1.1 | 1.1 | ? | 5 IP | ~1.1 req/s |
| v6 (memory) | 100/5.5s | 17.4 | 17.4 | ? | 0 IP | flood 90% 失败 |
| **本次 p2** | 487/24.8s | **19.6** | 0.8 (audit) | 51 (10.5%) | 5 IP | audit_pipeline 1/min |
| **本次 p4** | 199/9.6s | **20.7** | 0.4 (audit) | 18 (9.0%) | 5 IP | 同上 |

**新发现**:
- **注入率 19-21 req/s** 远超 v6 的 17.4 req/s,**系统未挂**
- **真实拐点不是 LLM**(LLM 跑得动 150/min),**是 audit_pipeline**(1-2/min)
- v6 报告说"超过 50 req/s 平台失效"**不准确** — 那是 ingest 端在那一波被 429 拒,不是 LLM 真极限

---

## 6. 三个最关键问题

### 问题 1: audit_pipeline 串行瓶颈

**症状**:`audit_pipeline` 在 12 并发工作流的最后一段 activity,每条 8-12s,稳态 1-2 calls/min,**完整审计 1 个事件需要 30s-1min**。

**修复方向**:
- 改 `cad_verify` 异步(不阻塞 audit_pipeline 路径)
- 或:把 audit_pipeline 拆成 sub-pipeline(分批并发,而不是 1 个 8-12s 串行)
- 或:在 ingest 端如果已有 `threat_type` 且 `confidence >= 0.9`,**跳过 audit_pipeline 直接进 response_orchestrator**(快速通道)

### 问题 2: 5M token 日预算未硬阻断

**症状**:超出 2.5x 仍正常服务,计费风险。

**修复**:
- `LLMClient._check_budget()` 加 hard block(超过 100% 抛 `BudgetExceededError`)
- 或:动态降级(超预算切到 M2.5-lite 快速模型)

### 问题 3: 缺生产级传感器(沿用 M2.7 报告问题 3)

**症状**:Phase 1 真实 nmap + hydra 攻击 → 0 SOC 事件。

**修复**:`docker-compose.yml` 加:
- `soc-suricata` service(已有 `config/suricata/` 目录)
- `host-winlog-collector` service(已有 `tools/windows-log-collector.ps1`)
- soc-firewall 装 rsyslog → kafka producer

---

## 7. 一句话总结

**平台 ingest 端可吃 20+ req/s 注入,LLM 端稳定跑 150 calls/min,但 audit_pipeline 是 1-2 calls/min 的真正瓶颈,导致 686 个事件 25 分钟只完成 10% 端到端审计**。iptables 自动封禁链路**工作正常**(10 IP 真实阻断),但仅 BRUTE_FORCE 策略触发,DATA_EXFIL/MALWARE/LATERAL/DDoS 都只告警不阻断(M2.7 audit 输出 threat_type 为空的老问题延续,自动封禁完全靠 ingest 端预设)。

---

## 附录 A:测试环境状态

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | 19 min up(M2.7) |
| `soc-temporal-worker` | 11 min up(M2.7) |
| `soc-firewall` | 9+ hours up,**22 iptables DROP rules** |
| `kali-pentest` | 9+ hours, nmap+hydra 可用,真实攻击验证 0 SOC 事件 |
| Suricata service | **不存在** |
| Host Win Event Log | **未 forward** |
| `SHARED_MEMORY_LLM_MODEL` | M2.7 |
| `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` | 5M(今日已用 12.8M,超 2.5x)|

## 附录 B:响应链路终态

| session | events | 注入 | 完成审计 | 完成率 | 自动封禁 |
|---|---|---|---|---|---|
| p2 (large-scale-20260902-001409) | 487 | 19.6 req/s | 51 | 10.5% | 5 IP (BRUTE_FORCE) |
| p4 (large-scale-p4-002304) | 199 | 20.7 req/s | 18 | 9.0% | 5 IP (BRUTE_FORCE) |
| **合计** | **686** | **~20 req/s** | **69** | **10.1%** | **10 IP** |

## 附录 C:测试产物文件

- `.tmp_large_attack_gen.py` — 487 事件生成器
- `.tmp_large_attack_events.json` — Phase 2 完整事件清单
- `.tmp_large_attack_sid.txt` — Phase 2 session_id
- `.tmp_p4_attack.py` — Phase 4 事件生成器
- `.tmp_p4_sid.txt` — Phase 4 session_id
- `.tmp_metrics_v2.py` / `.tmp_metrics_collector.py` / `.tmp_p4m_v4.py` — 监测脚本
- `/tmp/metrics_p1.jsonl` / `/tmp/metrics_p2.jsonl` / `/tmp/p4m4.jsonl` — 容器内时序快照
- `.tmp_pwd.txt` — kali 弱口令表
- `docs/security-audit/attack-perf-large-scale-2026-09-02.md` — 本报告

## 附录 D:监控过程踩的坑(跨项目)

1. **PowerShell `$()` 嵌套在 `docker exec bash -c` 里被本地展开** → 用 `bash -c '...'` 单引号避免
2. **PowerShell 反引号字符串内嵌 `:` 触发解析错误** → 写文件 + `docker cp` 解决
3. **`security_events.event_id` (string) vs `llm_traces.event_id` (int) 是两个 ID** → 用 INNER JOIN 而非 `= ANY($1::int[])`
4. **`asyncpg` 没装在 host** → 必须 `docker cp` 脚本到 backend 容器,在容器内运行
5. **PowerShell 不支持 `tail` `head` `grep` 等 Unix 工具** → 用 `Select-Object`, `Select-String`, `Measure-Object`
6. **历史数据污染**:`id > 13054` 筛选必须用 session 边界,而非 created_at(老 error trace id=1310 时间是 5 天前)
