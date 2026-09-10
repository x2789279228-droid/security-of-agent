# Security Audit Platform — Large-Scale Attack Performance Report
**Date:** 2026-09-10 13:30 - 13:49 CST (active run ~18 min)
**Test session:** `large-scale-20260910-1789047071`
**Auditor model:** MiniMax-M2.7 (LLM = M2.7, but LLM 调用链今天整体停滞)
**Attacker VM:** `kali-pentest` Docker container (4.63GB kali-mcp:latest image)
**Target host:** `host.docker.internal` = Windows host (192.168.65.254)
**Total events planned:** **3000** @ ~2 req/s sustained (~25 min)
**Total events actually sent:** **2050 events / 1025 batches / 1 HTTP non-202** (68% of target, manually stopped at 18min)
**Coverage:** 8 threat types (same as 9/2 baseline)

---

## 1. TL;DR — 平台今天**自己崩溃了**

| 维度 | 关键结论 |
|---|---|
| **Phase 1 真攻击** | **0 SOC 事件** — Suricata 路径仍未修(9/2 已知问题延续) |
| **Phase 2 入队** | **HTTP 202: 1024/1025 batches (99.9%)**; 实际 1.88 req/s,接近目标 |
| **Phase 2 入库** | **0 events drained to security_events** ← **核心问题** |
| **真实拐点** | **不是 9/2 的 audit_pipeline**,是 **`soc-backend-ingestpy` Kafka consumer 自崩溃** (05:38:29 `CommitFailedError` → `LeaveGroup` → 至今 no active members) |
| **LLM 调用** | 30 min 内 audit_pipeline / decomposer / sub_auditor **全部 0 调用**;只有 embedding(2633 次)和 post_mortem_service(1 次)在跑 |
| **Block 链路** | soc-firewall 容器**不存在** + backend 无 iptables binary → 策略虽新增 4 类 block_ip,**全部静默失败** |
| **背景洪水** | `ndr-flood-1788622227` 持续以 ~14 events/sec 灌入(50,371 事件/小时),把 ingest 队列压垮 |

**一句话总结**:今天测试被一个**外部背景 session 完全主导** —— `ndr-flood-1788622227` 持续洪水 + 平台 ingest consumer 崩溃,我的 2050 事件全部入 Kafka 队列但 0 落地;9/2 已知的真攻击感知缺失 + soc-firewall 下线导致 block_ip 死路,在今天因为**审计 LLM 链也整体瘫痪**而更加严重。

---

## 2. 测试场景与执行

### 2.1 Phase 1 — 从 kali-pentest 真实攻击

```bash
# 容器重启 (kali-pentest 之前 Exited 47 小时)
docker start kali-pentest

# nmap SYN scan
docker exec kali-pentest bash -c 'nmap -sS -T4 --top-ports 50 -Pn host.docker.internal'

# hydra SSH 爆破
docker exec kali-pentest bash -c 'hydra -l admin -P /tmp/pwd.txt -t 4 -w 3 -f ssh://host.docker.internal:22'
```

**实际触发**:
- nmap 找到 host 开放 22 / 80 / 135 / 443 / 445
- banner 抓取: **`SSH-2.0-OpenSSH_for_Windows_9.5`** ← Windows OpenSSH Server 已启用
- hydra 10 口令 × 1 轮 → **0 有效密码**

**SOC 平台结果**:
- security_events (5 min): **0**
- edr_events (5 min): **0**
- network_flows (5 min): **0**

**根因**(沿用 9/2 报告 §6 问题 3):
- Suricata IDS service **仍未注册**(`config/suricata/` 目录存在但 `docker-compose.yml` 无 service)
- `tools/windows-log-collector.ps1` 未作为 service 运行
- soc-firewall syslog forwarder **不存在**(容器已下线,见 §4.1)
- → 端到端真攻击感知路径**完全断**,必须用合成事件注入测全链路

### 2.2 Phase 2 — 2050 条合成攻击 (8 策略, sustained 1.88 req/s)

通过 `POST /api/logs/ingest/batch` 注入(需 JWT Bearer,9/2 是开放的)。

**Auth 鉴权变化**(新增 vs 9/2):
```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"StudyAgent2024!DB"}' | jq -r .access_token)
```

**事件分布**(同 9/2 8 策略口径 × 实际发送量):

| threat_type | 数量 (按 9/2 比例 × 2050) | 唯一 IP 池 |
|---|---|---|
| BRUTE_FORCE | ~926 | 40 (185.220.101.x) + 80 (203.0.113.x) 公网 |
| DDoS_TRAFFIC | ~336 | 80 + 60 公网 |
| PORT_SCAN | ~252 | 80 + 60 + 40 公网 |
| C2_BEACON | ~135 | 30 失陷内网 |
| MALWARE_DETECT | ~148 | 30 内网 + 80 公网 |
| DATA_EXFIL | ~84 | 30 失陷内网 |
| LATERAL_MOVE | ~84 | 30 失陷内网 |
| USER_LOGIN (benign) | ~85 | 20 运维内网 |
| **总计** | **2050** | **~370 唯一 IP** |

**注入速率**:
- 计划: 2.0 req/s × 25 min = 3000 events
- 实际: 1.88 req/s × 18 min 9 sec = **2050 events**
- HTTP 状态: 1024 × 202 / 1025 batches (99.9%)
- 1 batch 失败(batch_seq unknown,推测是 consumer 崩溃时点的 in-flight 请求)
- p50 / p95 / max 延迟:**未抓取完整分布**(见 §5 监控坑),但单 batch 一般 5-25ms

**session_id**: `large-scale-20260910-1789047071`

### 2.3 Phase 3 (取消)

**取消原因**: 主跑进行到 18min 时发现 Kafka consumer 已自崩溃,追加 burst 无意义。详见 §4.2。

---

## 3. 平台表现 — 终态统计

### 3.1 我的事件落库情况(核心)

| 表 | 我 session 的行数 | 备注 |
|---|---|---|
| `security_events` | **0** | consumer 死后所有事件滞留在 Kafka |
| `response_logs` | **0** | 同一原因 |
| `llm_traces` | **0** | 同一原因 |
| Kafka topic `security-events-ingest` | **~2050** (从 last peek seq=1954 + 后续 ~96) | 已入队,未消费 |

### 3.2 全平台吞吐 (后 30 min)

| 指标 | 值 |
|---|---|
| `security_events` 后 30 min 新增 | (查询超时,见 §5) |
| `ndr-flood-1788622227` 后 60 min | **50,371** events (~840/min = ~14/sec) |
| `security_events` 总数(终态) | **369,293** |
| `llm_traces` 后 30 min | 2636 calls (2633 embedding + 1 post_mortem + 2 unknown) |
| `llm_traces` 今日累计 | 3,359 calls / 639,875 tokens |

**注意**: 今日 LLM 调用量比 9/2 的 12.8M tokens 低 20 倍 — 不是因为平台空闲,而是**审计 LLM 链整体停滞**(见 §4.2)。

### 3.3 响应链统计

| session | 入队 events | 入库 events | 触发响应 | 封禁 IP | 入库率 |
|---|---|---|---|---|---|
| **large-scale-20260910-1789047071 (本次)** | 2050 | **0** | **0** | **0** | **0%** |
| ndr-flood-1788622227 (背景) | (持续 ~14/s) | (持续入) | (持续) | (持续) | (待统计) |

### 3.4 iptables / Firewall 终态

**架构变更 vs 9/2**:
- 9/2: `soc-firewall` 容器有 iptables,22 条 DROP rules
- 今天: **`soc-firewall` 容器不存在**,backend 容器**无 iptables binary** (`which iptables` → not found)

**block_ip 路径**:
```
strategy match → policy.action=block_ip → SSH transport → SHARED_MEMORY_FW_SSH_HOST=soc-firewall → connection refused → 静默失败
```

即使策略加了 4 类 block_ip(见 §4.1),也没有真实封禁能力。

---

## 4. 关键发现与根因

### 4.1 9/2 → 9/10 架构变化清单

| 项 | 9/2 | 9/10 |
|---|---|---|
| API 鉴权 | `/api/*` 开放 | **JWT Bearer required**(`/api/auth/login` 拿 token) |
| 策略存储 | `policies` 表(DB) | **`/data/response_policies/*.yml` 文件**,30s 热加载 |
| 威胁分类 | 直接 leaf 枚举 | **两层 taxonomy**(category → leaves + alias_leaves) |
| `soc-firewall` 容器 | 存在,有 iptables,22 DROP rules | **不存在** |
| Backend 容器 iptables | 通过 SSH 调用 soc-firewall | **无 binary**,block_ip 静默失败 |
| LLM 预算 | 5M tokens/day,告警不阻断 | **`BUDGET_UNLIMITED=true` + `DAILY_BUDGET_TOKENS=0`** (9/2 担心的计费风险已关闭) |
| Block 策略覆盖 | 仅 BRUTE_FORCE 有 block_ip | **+ DDoS / C2 / DATA_EXFIL / EXFIL / BENIGN-FALLBACK / BEHAVIOR-ANOMALY**(7 类有 block_ip)|
| `summary_compression` embedding | 正常 | **API 响应格式不匹配**(`Unknown keys: ['vectors', 'base_resp']`,持续失败) |

### 4.2 核心发现: Kafka ingest consumer 自崩溃

**时间线**:
```
04:34:39  consumer 启动,加入 group soc-backend-ingestpy
04:34:39  设置订阅 topic: security-events-ingest
05:22+    ndr-flood 背景洪水开始(50k+ 事件/小时)
05:38:29  consumer 报 CommitFailedError → LeaveGroup → 退出
05:38:30  之后 security-events-ingest 队列无人消费,lag 持续增长
13:48+    我的 2050 事件全部入队但 0 落地
```

**Backend 日志原文**(`docker logs shared-memory-backend --since 90m`):
```
2026-09-10 05:38:29,976 [kafka_consumer] ERROR: 
  Python-ingest consumer crashed: CommitFailedError: 
  ('Commit cannot be completed since the group has already rebalanced... 
   the time between subsequent calls to poll() was longer than the configured 
   max_poll_interval_ms, which typically implies that the poll loop is spending 
   too much time message processing. You can address this either by 
   increasing the rebalance timeout with max_poll_interval_ms, or by reducing 
   the maximum size of batches returned in poll() with max_poll_records.')
2026-09-10 05:38:30,064 [aiokafka.consumer.group_coordinator] INFO: 
  LeaveGroup request succeeded
```

**根因链**:
1. `ndr-flood-1788622227` 持续以 ~14 events/sec 灌入 topic
2. ingest consumer 每条事件要走 DB 写入 + 内存分析 + 分类 + 多步 enrichment
3. 消费速率跟不上入队速率,lag 持续堆积
4. consumer `poll()` 之间的间隔超过 `max_poll_interval_ms`(默认 5 min,具体值未查)
5. 触发 rebalance,consumer 试图 commit 但 group 已 rebalance
6. CommitFailedError 抛出,consumer 自我退出(代码里 `except` 没有重连逻辑)
7. 至今 8+ 小时无人处理 `security-events-ingest`

**对比 9/2**:
- 9/2 报告"audit_pipeline 1-2 calls/min 是真瓶颈"
- 今天的瓶颈**下沉一层**:不是 audit_pipeline 不够快,是 **audit_pipeline 根本没东西可审计** — consumer 死后,事件到不了 audit_pipeline
- 9/2 的拐点 `audit_pipeline` 是 **审计完成率 10.1%**;今天的拐点是 **入库率 0%**(更彻底)

### 4.3 背景洪水 `ndr-flood-1788622227` 的本质

- 24h 累计: **325,709 security_events** + 63,917 response_logs + 12,720 llm_traces
- 60 min 累计: **50,371 events** (~840/min ≈ 14/sec)
- 这是某个长期压测留下的 background session,**无人停止**
- 当前 `security_events` 总数 369,293 中 88% 都来自这个 session

→ 平台没有"per-session 限流"机制,单 session 可以独霸 ingest consumer 全部吞吐。

### 4.4 真攻击感知路径仍未修复(沿用 9/2 结论)

Phase 1 真实 nmap + hydra 攻击 → 0 SOC 事件,与 9/2 完全一致:
- 缺 Suricata IDS service
- 缺 host Windows Event Log collector
- 缺 soc-firewall syslog forwarder(且容器已下线)

### 4.5 block_ip 链路完全断(新增 vs 9/2)

9/2 至少有 soc-firewall 容器 + iptables,封禁了 10 个 IP。今天:
- soc-firewall 容器**不存在**
- backend 容器**无 iptables binary**
- SSH transport `soc-firewall:22` → connection refused
- → 策略层面新增的 4 类 block_ip **全部静默失败**

### 4.6 embedding API 响应格式不匹配(新增)

`summary_compression` 模块持续报错:
```
ERROR: Embedding call failed after retries: Unknown embedding response keys: ['vectors', 'base_resp']
```
- 频率:后 30 min 内 **数百次**
- 影响:`summary_compression` 全部失败 → summary 向量无法生成 → RAG 召回降级
- 推测:embedding 服务端升级后改了响应 schema,客户端未跟进

---

## 5. 监控过程踩的坑(本次新增)

| 坑 | 现象 | 解法 |
|---|---|---|
| API 鉴权 | 9/2 开放的 `/api/*` 今天 **401 Unauthorized** | 先 `POST /api/auth/login` 拿 JWT Bearer |
| PowerShell GBK 解码炸 | `docker exec` 输出含 UTF-8 中文 → `UnicodeDecodeError: 'gbk'` | Python `decode("utf-8", errors="replace")` 或 `subprocess.run(..., capture_output=True)` 后显式 decode |
| psql 在 backend 容器不存在 | `FileNotFoundError: psql` | 改用 `shared-memory-pg` 容器(`pgvector/pgvector:0.8.2-pg16` 自带 psql) |
| PG 鉴权 | `shared-memory-pg` 容器里 `admin` 用户需要密码 | `PGPASSWORD=...` 环境变量 |
| `security_events.threat_type` 列不存在 | 9/2 报告里能直接查的列,现在移到 `raw_data->>'threat_type'` | 用 JSONB 操作符 |
| HTTP 202 ≠ 落地 | ingest 走 Kafka 异步,202 只表示入队 | 必须查 `security_events.session_id` 才知是否真入库 |
| stdout buffering | 长时间跑看不到进度 | 看 file mtime 而非 stdout;Python 文件默认 block-buffer,跑 25 min 看不到 print |
| 监控脚本误跑两遍 | Admin Python + hermes-agent Python 两个解释器同时被 PATH 命中 | 写脚本前先 `Get-Command python` 确认解释器唯一 |
| `docker exec ... bash -c '...'` 的 PowerShell 转义 | `\"` 在 PS 双引号字符串里被错误解析 | docker cp 一个 .sh 进容器再执行,完全绕开 escape |

---

## 6. 与历次压测对比

| 测试 | 事件数 | 注入率 | 入库率 | 审计完成率 | 封禁 IP | 拐点 |
|---|---|---|---|---|---|---|
| v4 (memory) | 200/5min | 0.67/s | ? | ? | 0 IP | LLM 卡? |
| v5 (memory) | 200/3min | 1.1/s | ? | ? | 5 IP | ~1.1 req/s |
| v6 (memory) | 100/5.5s | 17.4/s | 10% | flood | 0 IP | ingest 429 |
| **9/2 p2** | 487/24.8s | **19.6/s** | 100% | 51 (10.5%) | 5 IP | audit_pipeline 1/min |
| **9/2 p4** | 199/9.6s | **20.7/s** | 100% | 18 (9.0%) | 5 IP | audit_pipeline 1/min |
| **9/10 这次** | 2050/18min | **1.88/s** | **0%** | **0** | **0** | **ingest consumer 崩溃** |

**新发现**:
- **入库率 0%** 是历次压测从未出现的"完全失败"状态
- 不是因为 ingest 端被 429 拒(v6 报告的"超过 50 req/s 平台失效"),而是 consumer 自身崩了
- 平台"自爆"模式:**慢 → CommitFailedError → LeaveGroup → 永远不回来**

---

## 7. 三个最关键问题

### 问题 1: Kafka ingest consumer 单点 + 无自愈

**症状**:
- 单一 consumer 实例(`soc-backend-ingestpy`)
- 处理慢时 commit 超时 → 自退出 → 无 supervisor 重启
- 一旦死掉,security-events-ingest topic 永远堆积

**修复方向**:
- **加 supervisor**:consumer 进程退出时自动重启
- **加多 consumer 实例**:至少 2-3 个并行 partition 消费
- **优化 commit 策略**:`max_poll_interval_ms` 调大,或 commit 频率与处理速率解耦
- **per-session 限流**:ndr-flood 单 session 不能独霸吞吐

### 问题 2: 真攻击感知路径缺失(沿用 9/2)

**症状**: nmap/hydra 在本机跑,平台 0 事件

**修复**:
- `docker-compose.yml` 加 `soc-suricata` service
- `host-winlog-collector` service
- soc-firewall 容器要么重启,要么改用 host netsh advfirewall 实现

### 问题 3: block_ip 无真实执行点(9/10 升级版)

**症状**: 策略加了 7 类 block_ip,但 soc-firewall 容器不存在,backend 无 iptables,所有 block_ip 静默失败

**修复**:
- 重启 soc-firewall 容器 + iptables
- 或: block_ip action 实现改为 host netsh advfirewall firewall add rule
- 或: 实现 SOC 平台**模拟 block_ip**(只记日志 + dashboard 标记,不真封)— 至少能观测策略效果

### 附加:embedding API 兼容性

**症状**: `summary_compression` 持续报 `Unknown keys: ['vectors', 'base_resp']`

**修复**: 检查 embedding provider 升级日志,更新客户端 response parser

---

## 8. 一句话总结

**今天测试的本质被一个外部背景 session (`ndr-flood-1788622227`) 完全主导:Kafka ingest consumer 因 lag 堆积触发 `CommitFailedError` 自崩溃并 `LeaveGroup`,我的 2050 事件全部入队但 0 落地,平台真正的瓶颈从 9/2 的 audit_pipeline 转移到了 **ingest consumer 单点 + 无自愈 + 无 per-session 限流**。9/2 已知的 Suricata / 真攻击感知缺失 + soc-firewall 下线导致 block_ip 死路在今天因为审计 LLM 链也整体瘫痪(后 30 min audit_pipeline / decomposer / sub_auditor 全部 0 调用)而更加严重 —— 平台今天的真实状态是"能接 HTTP 但没人处理"。**

---

## 附录 A: 测试环境状态

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | 41 min up (M2.7) |
| `soc-temporal-worker` | 2h+ up |
| `kali-pentest` | 启动于 13:24, nmap+hydra 可用 |
| Suricata service | **不存在** (9/2 同) |
| Host Win Event Log | **未 forward** (9/2 同) |
| `soc-firewall` | **不存在** (9/2 → 9/10 架构变更) |
| `SHARED_MEMORY_LLM_MODEL` | MiniMax-M2.7 |
| `SHARED_MEMORY_LLM_BUDGET_UNLIMITED` | **true** (9/2 是 5M/day) |
| `soc-backend-ingestpy` consumer | **DEAD** since 05:38:30 (CommitFailedError) |
| `ndr-flood-1788622227` | **持续活跃** (~14 events/sec) |

## 附录 B: Kafka 终态

| consumer group | topic | current | log-end | lag | 状态 |
|---|---|---|---|---|---|
| **soc-backend-ingestpy** | security-events-ingest | 362,762 | 1,429,398 | **1,066,636** | **no active members** |
| soc-backend-alerts | security-alerts | 3,910 | 3,911 | 1 | OK |
| soc-backend-audit | security-audit-queue | 1,039 | 1,040 | 1 | OK |
| soc-backend-enriched | security-events-enriched | 14,768 | 14,769 | 1 | OK |
| soc-backend-rejected | security-logs-rejected | 269,209 | 269,210 | 1 | OK |
| soc-backend-cep-partial | security-cep-partial | 459 | 459 | 0 | OK |

→ **唯一 lag = 1M+ 的是 ingestpy**,其他 consumer 都健康。说明问题专在 ingest 路径,不在 audit/alerts 路径。

## 附录 C: 测试产物文件

- `tools/attack-large-scale-2026-09-10.py` — 3000 事件生成器 (8 策略分布、JWT 鉴权、批次 flush)
- `tools/monitor-2026-09-10.py` — 60s 间隔监控循环
- `.tmp_main_run_1789047071.jsonl` — Phase 2 注入日志 (1025 batches / 2050 events)
- `.tmp_monitor_20260910.jsonl` — 监控快照
- `.tmp_pwd.txt` — kali 弱口令表
- `.tmp_psql_run.sh` / `.tmp_pol_scan.sh` / `.tmp_phase1_check.sh` / `.tmp_kafka_inspect.sh` — 容器内诊断脚本
- `.tmp_db_query.sh` / `.tmp_inspect_schema.py` / `.tmp_dbg_sessions.py` / `.tmp_dbg_kafka.py` — DB 探针
- `.tmp_final_db_check.sh` / `.tmp_final_agg.py` — 最终汇总
- `docs/security-audit/attack-perf-large-scale-2026-09-10.md` — 本报告
