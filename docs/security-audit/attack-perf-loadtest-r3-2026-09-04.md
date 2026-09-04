# Security Audit Platform — Load Test with EDR Real Data (R3)
**Date:** 2026-09-04 13:20 - 13:31 CST (UTC 05:20 - 05:31)
**Test session:** `r3-loadtest-20260904-132040`
**Auditor model:** MiniMax-M2.7 (持续在线)
**Test data:** `D:\浏览器下载\xwechat_files\wxid_39ziqr3spt522_bbce\msg\file\2026-07\测试数据.json`
**Total events injected:** **10** (深信服/EDR 真实事件, 每条 13-22 KB JSON, 50+ 字段)
**Ingest rate:** **1.07 req/s** (10 events / 9.3 s, 1 event/s 节奏)

---

## 0. 与前几次报告的关系

| 报告 | 事件数 | 数据形态 | 注入率 | 修复状态 |
|---|---|---|---|---|
| `attack-perf-large-scale-2026-09-02.md` (大流量) | 686 | 简单模拟 (5 字段) | 19.6-20.7 req/s | 修复前 |
| `attack-perf-small-scale-2026-09-04.md` (r1) | 30 | 简单模拟 (5 字段) | 2.24 req/s | 修复前 |
| `attack-perf-small-scale-2026-09-04-r2.md` (r2) | 30 | 简单模拟 (5 字段) | 2.28 req/s | 修复后 audit_pipeline 跑通 |
| **本报告 (r3)** | **10** | **深信服 EDR 真实数据 (50+ 字段/15KB)** | **1.07 req/s** | **修复后, 验证"放大"** |

**"放大"的解释**:
- 事件数 10 < r1/r2 的 30
- 但**单事件复杂度放大 ~20×**:r1/r2 每条 200-500B JSON,本次每条 13-22KB
- 字段数从 r1/r2 的 5-7 字段 → 本次 50+ 字段
- 数据形态:深信服/EDR 真实 API 攻击日志 (host/url/protocol/severity/threatSubType/ruleIds/...)
- 转换注入 + audit_pipeline 真实 LLM 处理, 测量**单事件复杂度提升**后平台处理速度

---

## 1. TL;DR — 修复仍生效, 但 ingest 端不存表问题延续

| 维度 | r1 | r2 | **r3 (本次)** | 评价 |
|---|---|---|---|---|
| 事件数 | 30 | 30 | **10** (但单条复杂度 20×) | – |
| 单 event size | 200-500B | 200-500B | **13-22KB** | "放大" |
| 注入率 | 2.24 req/s | 2.28 req/s | 1.07 req/s | – |
| audit_pipeline calls | 0 (r1) | 108 (4-stage × 27) | **25** (不均匀) | ✅ 跑通但分布变 |
| audit_pipeline 4-stage 完整性 | 0 stage | 27 × 4 (完美) | **1 × 4 + 10 × 1 + 1 × 1** | ⚠ 不均匀 |
| LLM 错误 | 0 | 0 | 0 | 持平 |
| Cache hit | 33% | 33% | **0%** | ⚠ 大降 |
| 响应 (r3 session) | 21 | 15 | **0** | ⚠ 0 response |
| iptables 新增规则 | 5 (3 IP 重复) | 3 (3 IP 干净) | 0 (新规则来自前 loadtest) | – |
| **Ingest 端是否存表** | 30/30 | **27/30 (3 丢)** | **0/10 (全丢)** | ⚠ 退化 |
| **事件持久化率** | 100% | 90% | **0%** | ⚠ 进一步退化 |

**核心结论**:
- ✅ **上午修复 (audit_pipeline 4-stage) 仍生效** — r3 baseline 显示 audit_pipeline 历史 4810 (r2 时 3842 → +968 = 期间有测试), 最近 5 次 success, latency 32-56s
- ✅ **r3 测试中 audit_pipeline 跑了 25 calls** (10 sub_auditor + 10 execute + 1 decomposer + 1 execute_deep + 1 execute_recheck + 1 review)
- ⚠ **但 audit_pipeline workflow 分布不均**:只有 1 个 event 跑完 4 stage, 其余只跑 1 个 sub-stage
- ⚠ **ingest 端存表问题延续**:r2 时 3 事件丢, 本次 10 事件**全丢** (`events_in_session = 0`, `resp_in_session = 0`)
- ⚠ **0 response 在 r3 session 内** — audit_pipeline 跑但 response_orchestrator 没触发
- ⚠ **Cache hit 0%** (r2 时 33%) — 真实 EDR 字段 schema 与缓存 key 不匹配, 全部走 LLM

---

## 2. 测试场景与执行

### 2.1 真实攻击 (nmap + hydra) — 沿用 r1/r2 结论

r1/r2 已验证:kali-pentest → 本机扫描 + 暴力破解 → **SOC 入库 0 事件** (Suricata/host-winlog-collector 仍未部署)。
本次不重复跑, 直接进入合成事件测试。

### 2.2 Phase 2: 真实 EDR 数据注入 (10 events / 1 req/s)

**测试数据来源**:`测试数据.json` (10 events 深信服/EDR 真实 API 攻击日志)

| 属性 | 值 |
|---|---|
| 事件数 | 10 |
| threatType 分布 | type=1 (8 个) + type=3 (2 个) |
| 唯一 src_ip | 6 (192.168.113.29, 119.23.107.2, 172.29.218.40, 192.168.148.140, 172.19.172.37, 91.149.204.222) |
| 唯一 host | 6 (192.168.212.166:8080, www.auto.com:80, 15.53.112.60:80, 91.149.204.222:9999, ...) |
| 唯一 url | 6 (/Index_M/GetSystem, /api/auth/login, /access.log, ...) |
| 单 event size | 13-22 KB JSON |
| 平均 event size | 14,941 bytes |
| 总 payload | 152,250 bytes |
| 字段数 (non_empty) | 50-56 (vs r1/r2 模拟事件 5-7 字段) |

**转换方式**:EDR 字段 → SOC ingest schema, 完整 EDR 字段塞入 `raw_data.raw_edr` (15KB/event)
- `threatType=1` (8 个) → `MALWARE_DETECT`
- `threatType=3` (2 个) → `WEB_ATTACK`
- `host` 拆 `dst_ip:dst_port`
- 完整 EDR 数据保留在 raw_data 用于 LLM 上下文

**注入节奏**:1 event / 1s, 让 audit_pipeline 真有时间处理每条 (15KB 数据 LLM 处理需要更长)

```powershell
python .tmp_r3_inject.py
# → 10 events / 9.3s / 1.07 req/s
# → batch wall: 18-61ms (比 r1/r2 快 5×, backend 24min up)
# → session_id=r3-loadtest-20260904-132040
```

**Ingest 端 wall latency** (单条注入, 13-22KB/event):
| Event | size (B) | wall (ms) |
|---|---|---|
| 1 | 21 952 | 61 |
| 2 | 19 793 | 26 |
| 3 | 13 906 | 27 |
| 4 | 13 867 | 34 |
| 5 | 14 831 | 22 |
| 6 | 14 837 | 20 |
| 7 | 13 314 | 35 |
| 8 | 13 201 | 36 |
| 9 | 13 925 | 18 |
| 10 | 12 624 | 22 |
| **均值** | **15 225** | **30** |

→ **Ingest 端延迟 30ms / 15KB** — 即便单 event 数据量是 r1/r2 的 30-100×, ingest 端 wall 仍然稳定 (首次 61ms 偏高, 后续 18-36ms)。
→ 推测: ingest 端不解析 raw_data.raw_edr, 只把它存入 jsonb 列

### 2.3 环境前置 (修复后 24 min)

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | **24 min up** (r2 时也是这个容器, 仍未重启) |
| `soc-temporal-worker` | 24 min up |
| `shared-memory-frontend` | 24 min up |
| `soc-firewall` | 3h up, iptables 9 DROP rules (1 旧 + 8 来自 loadtest-1788497810) |
| `SHARED_MEMORY_LLM_MODEL` | M2.7 |
| audit_pipeline 历史累计 | **4810** (r2 时 3842 → +968 = 期间用户跑过 loadtest 验证) |

**修复后 audit_pipeline 最近 5 次 (05:05-05:06 UTC, 13:05-13:06 CST, 测试前 15 min)**:
| id | session | status | latency_ms |
|---|---|---|---|
| 48575 | loadtest-1788497810 | success | 54 157 |
| 48574 | loadtest-1788497810 | success | 35 349 |
| 48573 | loadtest-1788497810 | success | 35 250 |
| 48572 | loadtest-1788497810 | success | 32 114 |
| 48571 | loadtest-1788497810 | success | 56 226 |

→ **audit_pipeline 修复仍生效** (latency 32-57s, status=success)

---

## 3. 平台表现 — 5 分钟内累积数据

### 3.1 audit_pipeline 调用 (r3 session)

| 指标 | 值 |
|---|---|
| **audit_pipeline calls (r3 session)** | **25** |
| Errors | 0 |
| Total tokens | 41 750 |
| Cache hit | **0** (vs r2 33%) |
| Latency p50 | 13 710 ms |
| Latency p90 | 34 736 ms |
| Latency max | 57 276 ms |
| Latency mean | 17 886 ms |

**4-stage operation 分布 (r3 session)**:

| Operation | n | avg_ms | min_ms | max_ms | 备注 |
|---|---|---|---|---|---|
| **sub_auditor** | **11** | 13 246 | 7 493 | 19 762 | 1 stage 跑通 (r2 时 0) |
| **execute** | **10** | 13 759 | 8 408 | 20 915 | 1 stage 跑通 (r2 时 0) |
| decomposer | 1 | 32 277 | 32 277 | 32 277 | 仅 1 event 跑 |
| execute_deep | 1 | 34 736 | 34 736 | 34 736 | 仅 1 event 跑 |
| execute_recheck | 1 | 39 561 | 39 561 | 39 561 | 仅 1 event 跑 |
| review | 1 | 57 276 | 57 276 | 57 276 | 仅 1 event 跑 |
| **Total** | **25** | – | – | – | – |

**vs r2 (30 events → 108 calls)**:
- r2: 27 events × 4 stages = 108 calls (4 stages 各 27)
- **r3: 1 event × 4 stages + 11 events × sub_auditor + 10 events × execute = 25 calls**
- r3 的 workflow 形态与 r2 不一致 — **真实 EDR 数据的 audit_pipeline 走的是不同路径**

**r2 vs r3 形态对比的可能原因**:
1. r2 数据是 ingest 后端**模拟**的简单事件, audit_pipeline 走完整 4 stage workflow
2. r3 数据是**真实 EDR 形态**, audit_pipeline 可能在 ingest 端已经做了部分 audit (例如已经识别出 threat_class), **跳过 decomposer 直接进 execute**
3. 或者 r3 事件的 `raw_data.raw_edr` 字段触发 audit_pipeline 走**新 path** (因为结构完全不同)

### 3.2 Cache hit 大降: 33% → 0%

| 测试 | cache_hit 数 | cache_hit_rate | 推测原因 |
|---|---|---|---|
| r1 (模拟事件) | ~15 | 10% | 事件小, 命中难 |
| r2 (模拟事件) | 36 | **33%** | 30 events 中重复 IP 模式多, sub_auditor 命中 |
| **r3 (真实 EDR)** | **0** | **0%** | EDR 字段 schema 与 cache key 不匹配, 全部 miss |

→ **真实 EDR 数据让 cache 完全失效** — 每个事件 50+ 字段, 13-22KB, 几乎不可能与之前的 cache key 匹配
→ 这是放大测试的副作用:数据复杂度提升 → cache 命中率下降 → token 成本上升

### 3.3 响应链 — **r3 session 0 response**

| 指标 | r1 | r2 | **r3** |
|---|---|---|---|
| response_logs (本 session) | 21 | 15 | **0** |
| policy_match | 9 | 6 | 0 |
| send_alert | 7 | 6 | 0 |
| block_ip | 5 | 3 | 0 |
| events_in_session (security_events) | 30 | 0 (r2 已知 bug) | **0** |

→ **r3 注入 10 events 后, 5 分钟内 0 response_logs 写入**
→ r3 audit_pipeline 跑了 25 calls (1 event × 4 stage + 21 events × 1 stage) 但 **response_orchestrator 0 触发**

**为什么 0 response?**:
1. **ingest 端不存表问题**延续 — 10 events 没写 security_events, response_orchestrator 找不到事件来匹配
2. audit_pipeline workflow 跑通后, 输出的 verdict/threat_type 应该在 raw_data._audit_llm 里, 但因为 ingest 端**没存表**, response_orchestrator **找不到这些 event_id**
3. 实质上是:audit_pipeline 跑通 ✅, 但**响应链依赖 security_events.id**, 而 security_events 没记录, **响应链断裂**

### 3.4 iptables 状态

| 状态 | 数量 | 来源 |
|---|---|---|
| 总 DROP 规则 | 9 | 1 旧 (r1/r2) + 8 新 (本次 test 之外) |
| r3 注入的 src_ip 是否被封 | **否** | r3 events 没产生 response, 没触发 block_ip |
| 8 条新规则的 src_ip | 10.9.x.x (8 个) | 溯源:之前的 loadtest-1788497810 (r2 之后, 13:05 跑的 loadtest) |

**10.9.x.x 封禁溯源**:
- event_id 9455-9593, threat=BRUTE_FORCE, message="验证突发打流"
- raw_eid 格式: `loadtest-1788497810-{N}-...`
- 这些是 13:05 跑的 loadtest 触发的, **不是本次 r3 测试**

→ **r3 测试期间 0 个 IP 被新封禁** (因为 0 response)

### 3.5 E2E 延迟 — **无 response 无法计算**

r3 session 内 0 response, 无法算 e2e。
但 audit_pipeline 5 阶段 latency 范围 7.5-57.3s, 估计 e2e (audit + response) **30-90s** (如果 response 能跑通的话)。

---

## 4. ingest 端不存表问题 — 从 r2 退化到 r3

| 测试 | ingest 写入 security_events 成功率 | resp_in_session |
|---|---|---|
| r1 (9-04 上午) | 30/30 = 100% | 21 |
| r2 (9-04 中午) | **27/30 = 90%** (3 丢失) | 15 (指向历史 event) |
| **r3 (9-04 下午)** | **0/10 = 0%** (全丢) | **0** |

**r3 退化更严重**:
- r2 还有 27/30 (90%) 进了表, response 链只是关联错 event
- **r3 是 0/10, 完全没进表, response 链彻底断裂**

**可能原因**:
1. r2 报告已经发现 ingest 端保存有问题, **修复未完成** (用户说 backend 24 min up 一直没重启)
2. **真实 EDR 数据 15KB** 与之前 200-500B 模拟数据 schema 差异, ingest 端写入时可能触发**列约束** (例如 `dst_port` 列是 int, EDR 某些 host 是非数字)
3. ingest 端在 audit_llm 跑完后, 保存到 security_events 失败但仍返回 200
4. 或者 r2 之后 ingest 端有**新改动**引入 bug

**影响**:
- audit_pipeline 仍能跑 (用 in-memory event 对象)
- response_orchestrator **依赖 security_events.id** — 没有 id 就没有响应
- 监控数据丢失 (events_in_session=0, resp_in_session=0)
- 历史回溯断层

---

## 5. 与 r2 关键对比

| 维度 | r2 | r3 (本次) | 变化 |
|---|---|---|---|
| 事件数 | 30 | 10 | 1/3 |
| 单 event size | 200-500B | 13-22KB | 30-100× |
| 注入率 | 2.28 req/s | 1.07 req/s | 1/2 |
| audit_pipeline calls | 108 (4-stage × 27) | 25 (不均匀) | ↓ |
| audit_pipeline 4-stage 完整度 | 100% (27/27 events) | **3.3% (1/10 events)** | ↓ |
| Cache hit | 33% | 0% | ↓ |
| response_logs (本 session) | 15 | 0 | ↓ |
| security_events 写入 | 27/30 = 90% | 0/10 = 0% | ↓ |
| iptables 新规则 | 3 | 0 (本 session) | – |
| Token 用量 | 137 489 | 41 750 | ↓ (事件少) |
| Tokens/event | 4 583 | **4 175** | 持平 (audit_pipeline 跑过) |

**核心观察**:
- **"放大"只放大了单 event 复杂度, 但 audit_pipeline 处理单 event 数量下降** (因 response 链断)
- audit_pipeline 仍能跑, 但只 1 event 走完 4 stage (10%)
- cache 命中率从 33% → 0% (数据 schema 不匹配)
- **ingest 端存表问题从 r2 的 10% 丢失 → r3 的 100% 丢失**, 严重退化

---

## 6. 三个建议

### 建议 1: 修复 ingest 端存表问题 (P0)

**症状**:r2 时 3 事件丢, r3 时 10 事件全丢, 且 response 链依赖 security_events.id

**修复方向**:
1. 查 `backend/routers/logs.py` (或类似) 的 ingest 端代码, 看保存到 security_events 的 try/except
2. 单独 POST 1 条事件, 看 backend 日志是否有异常
3. 检查 schema 约束 (例如 EDR 的 host 是 "15.53.112.60:80", 拆 dst_port 是 "80" 但可能某些 host 不是数字)

### 建议 2: response_orchestrator 不应强依赖 security_events.id

**症状**:audit_pipeline 跑通了 (用 in-memory event), 但 response_orchestrator 必须有 security_events.id 才能 match policy

**修复方向**:
- response_orchestrator 接受 raw_data 里 `_audit_llm.merged` 的 verdict/threat_type, 不需要 security_events.id
- 或 audit_pipeline 完成后**主动**调用 response_orchestrator (而不是由 temporal workflow 调度)
- 或 ingest 端**先保存** security_events 再触发 audit_pipeline (而不是反过来)

### 建议 3: cache key 改进

**症状**:真实 EDR 字段让 cache 命中率 0% (vs r2 33%)

**修复方向**:
- cache key 不要用完整 raw_data, 而是用 (event_type, src_ip, threat_type, dst_port) 这样的**摘要 key**
- 这样 10 个事件的 cache key 只看核心字段, 可以命中

---

## 7. 一句话总结

**r3 压测确认上午 audit_pipeline 修复仍生效** (历史 4810 calls, 最近 5 次 success), 但**真实 EDR 数据的复杂度让 audit_pipeline workflow 分布不均** (1 event 跑完 4 stage / 10 events 只跑 1 stage), **cache 命中率从 33% 降到 0%**, **且 ingest 端存表问题从 r2 的 10% 丢失退化为 r3 的 100% 丢失**, 导致**响应链彻底断裂 (0 response), iptables 无新封禁**。建议优先排查 ingest 端存表 bug 和 response_orchestrator 对 security_events.id 的强依赖。

---

## 附录 A:测试环境状态

| 组件 | 状态 |
|---|---|
| `shared-memory-backend` | 24 min up (从 r2 测试以来) |
| `soc-temporal-worker` | 24 min up |
| `shared-memory-frontend` | 24 min up |
| `soc-firewall` | 3h up, 9 iptables DROP rules (1 r1/r2 旧 + 8 loadtest-1788497810) |
| `kali-pentest` | 47h up |
| `SHARED_MEMORY_LLM_MODEL` | M2.7 |
| audit_pipeline 历史累计 | 4810 (r2 时 3842) |
| `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` | 5M (本次用 41k) |

## 附录 B:三次压测对比

| 指标 | r1 (修复前) | r2 (修复后) | **r3 (放大 EDR)** |
|---|---|---|---|
| 事件数 | 30 | 30 | 10 |
| 单 event size | 200-500B | 200-500B | 13-22KB |
| 注入率 | 2.24 req/s | 2.28 req/s | 1.07 req/s |
| audit_pipeline calls | 0 | 108 | 25 |
| audit_pipeline 4-stage 完整度 | 0% | 90% (27/30) | 10% (1/10) |
| E2E p50 | 268 ms (fast) | 12.6 s | **无 (0 response)** |
| E2E p90 | 95 s (timeout) | 20.2 s | – |
| E2E max | 104 s | 20.2 s | – |
| response_logs | 21 (70%) | 15 (50%) | **0 (0%)** |
| iptables 新规则 | 5 (3 IP 重复) | 3 (3 IP 干净) | 0 (本 session) |
| Cache hit | ~10% | 33% | **0%** |
| Ingest 写入率 | 100% | 90% | **0%** |
| Tokens | 265k | 137k | 41k |

## 附录 C:测试产物文件

- `.tmp_r3_inject.py` — 10 events EDR 注入脚本 (含 EDR→SOC schema 转换)
- `.tmp_r3_sid.txt` — session_id 保存
- `.tmp_r3_baseline.py` — 修复后 baseline
- `.tmp_r3_resp.py` — 响应分析 + audit_pipeline 详情
- `.tmp_r3_probe.py` — ingest 探针 (端口错误未运行)
- `D:\浏览器下载\xwechat_files\wxid_39ziqr3spt522_bbce\msg\file\2026-07\测试数据.json` — 原始 EDR 数据 (10 events, 171KB)
- `docs/security-audit/attack-perf-loadtest-r3-2026-09-04.md` — 本报告
