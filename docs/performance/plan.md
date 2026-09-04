# SOC 安全审计平台 — 生产级性能改造方案 v1

**日期**: 2026-09-02
**作者**: Mavis (基于 explore 任务的 evidence-first 探索)
**范围**: `D:\揭榜挂帅\shared-memory-platform` 攻击检测→响应全链路
**目标读者**: 后端工程师、平台架构师、运维 SRE

> 本方案基于 explore 报告(`docs/performance/explore-report-2026-09-02.md`, 即将归档)产出的 12 个 evidence-backed 性能瓶颈。
> 所有"数据点"均来自:
> 1. `docs/security-audit/attack-perf-large-scale-2026-09-02.md` (2026-09-02 真实压测)
> 2. `docs/security-audit/attack-perf-m27-2026-09-01.md` (2026-09-01 M2.7 切换)
> 3. `docs/security-audit/AUDIT_REPORT.md` (渗透审计 v1)
> 4. explore 报告(代码层面 file_path:line 引用)
> 5. 历史 v6 数据(已纠正:**100 IP / 95% / 17.4 req/s**)

---

## 0 · TL;DR

| 维度 | 当前(2026-09-02 实测) | 目标(P2 末) | 关键差距 |
|------|---------------------|--------------|---------|
| **audit_pipeline 吞吐** | 1-2 calls/min(理论 18/min) | ≥ 60 calls/min | 12 槽 4 activity 串行共享 / 串行 workflow |
| **端到端完成率** | 10.1% (69/686 事件 25min) | ≥ 80% P1 / ≥ 95% P2 | 阻塞在 audit_pipeline 排不上 |
| **封禁 P99 延迟** | 受 audit_pipeline 阻塞(分钟级) | ≤ 5s P0 / ≤ 2s P1 | 同上 |
| **真实攻击流量入口** | 0 事件(全部断链) | 全链路接通 | Suricata / winlog collector 未启 |
| **SSH/iptables 状态一致性** | iptables ≠ _active_rules dict | 100% 一致 | rollback 不彻底 + 内存无持久化 |
| **LLM 日预算** | 形同虚设(12.8M / 5M 0 阻断) | 硬阻断 + 告警 | 只告警不阻断 |
| **生产级 SLO** | 无 | 99.9% 可用 + P99 5s | 当前不可用 |

**核心策略**(3 条):
1. **先把串行解锁**:Temporal 12 槽 4 activity 共享 + workflow 串行 3 round → 拆并发,FastPath 跳过 audit
2. **把单点变多点**:SSH 单例单连接 → 连接池;iptables 单条 → 批处理;rate_limiter 单进程 → Redis
3. **把断的接上**:Suricata / winlog collector 启 service,真实攻击流量入 SOC,rollback 真实清 iptables

---

## 1 · 当前状态分析(evidence-backed)

### 1.1 真实性能画像(2026-09-02 25min 压测)

| 指标 | 实测 | 来源 |
|---|---|---|
| 注入事件 | 686(Phase 2: 487, Phase 4: 199) | `attack-perf-large-scale-2026-09-02.md:6` |
| 注入率 | 0.46 events/sec(20.7 req/s × 25min) | 同上:65 |
| 端到端完成 | 10.1% (69/686) | 同上:17 |
| audit_pipeline 速率 | 1-2 calls/min(理论 18/min) | 同上:21, 111, 188-200 |
| Auto-block | 10 IP 真实封禁(iptables 12 → 22) | 同上:18 |
| LLM 健康 | 0 errors / 0 retries(M2.7 稳定) | 同上:19 |
| Token 用量 | 12.8M(超 5M 预算 2.5x,0 阻断) | 同上:20, 99, 205 |
| 真实攻击流量 | 0 事件(nmap + hydra 全断) | 同上:41, m27 报告:39-49 |

### 1.2 12 个核心瓶颈(按影响排序)

#### 瓶颈 #1:`audit_pipeline` 串行瓶颈 — **真实拐点**

- **现象**:686 事件 25 分钟仅 69 完成(10.1%);理论 18 calls/min,实测 1-2/min
- **根因**:
  - `backend/temporal/worker.py:35-46` `max_concurrent_activities=12`,4 activity 共享
  - `backend/temporal/workflows.py:33-141` 串行 3 round + 3 收尾 activity
  - audit_pipeline p50 8-12s
  - 理论 12/4/10s = 0.3 calls/sec,实测仅 7-15% 理论值
- **影响**:整个响应链等待,封禁延迟分钟级

#### 瓶颈 #2:SSH 单例单连接 + 同步阻塞

- **现象**:`backend/response_engine/ssh_firewall.py:49-70` 全局单例 + 同步 `exec_command`
- **根因**:`ssh_firewall.py:216` `self._client.exec_command` 同步;`ssh_firewall.py:199-222` `_exec` 只 `asyncio.to_thread` 包装;无连接池
- **影响**:所有封禁/解封排队,burst 时退化为串行

#### 瓶颈 #3:`iptables DROP` vs `_active_rules` 状态不一致

- **现象**:iptables 真实规则(22 条 DROP)与 `_active_rules` 内存 dict 不一致
- **根因**:
  - `ssh_firewall.py:70` `_active_rules: dict` 纯内存
  - `response_registry.py:369-378` `_auto_unblock` 容器重启后丢失
  - `ssh_firewall.py:343-367` `rollback_all` 只按 comment 删,`_active_rules` 标记 revoked 不删 dict
- **影响**:容器重启后状态失真,rollback 残留

#### 瓶颈 #4:rollback_all 不彻底

- **现象**:只删带 `FW-RULE-`/`EDR-ISO-` comment 规则,其他残留不清理
- **根因**:`ssh_firewall.py:343-367` `rollback_all` 按 comment 字符串匹配
- **影响**:长期累积垃圾规则

#### 瓶颈 #5:LLM 审计链路 0% 完成(历史 v6,已修正)

- **现象**:历史 v6 报告"flood 90% 失败,iptables 0%,LLM 0%"
- **修正**:2026-09-02 实测已吃下(20.7 req/s),完成度差但非 0
- **关联**:真实拐点不是 LLM,是 audit_pipeline(见 #1)

#### 瓶颈 #6:ingest 端串行处理

- **现象**:`log_ingestion.py:980-992` `ingest_batch` 无 `asyncio.gather`
- **根因**:前置流程(异常检测/Sigma/存储/case_manager/memory_tree/sliding_window)同步顺序
- **影响**:486 events / 24.8s = 19.6 req/s 灌入(已吃下,但前置可能成为瓶颈)

#### 瓶颈 #7:Temporal Worker 12 槽位串行共享

- **现象**:4 activity 共享 12 槽
- **根因**:`worker.py:35-46` `max_concurrent_activities=12, max_concurrent_workflow_tasks=12`
- **影响**:与 #1 重叠,但更具体到 Temporal 配置

#### 瓶颈 #8:LLM 日预算限制形同虚设

- **现象**:12.8M tokens / 5M budget = 2.5x,只告警不阻断
- **根因**:`docker-compose.yml:253` `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS=5000000`,检查逻辑只告警
- **影响**:成本失控风险

#### 瓶颈 #9:真实攻击流量不进 SOC

- **现象**:Phase 1 真实 nmap+hydra → 0 事件
- **根因**:
  - Suricata `profiles=["ndr"]`(`docker-compose.yml:543-558`)默认未启
  - `tools/windows-log-collector.ps1` 未作为 service
  - soc-firewall 无 syslog forwarder
- **影响**:**dev 环境无法做真攻击演练**,所有性能数据来自合成事件

#### 瓶颈 #10:FastPath 双轨路径分裂

- **现象**:ingest 端 threat_type 100% 命中,LLM 审计输出 0% 命中
- **根因**:M2.7 audit 输出 `threat_type=""` 持续未修
- **影响**:所有 auto-block 走 ingest 端预设路径(10/10),审计路径空跑

#### 瓶颈 #11:iptables 批处理缺失

- **现象**:每条 block_ip 1 次 iptables 命令 + 1 次 SSH exec_command
- **根因**:`response_executor.py:130-213` 串行/并行在 action 级,不在 iptables 规则级
- **影响**:SSH roundtrip ≈ 10-50ms/条,burst 100 IP = 1-5s 串行

#### 瓶颈 #12:MCP Guard 工具全 mock

- **现象**:Agent 调 MCP Guard 工具封禁不生效
- **根因**:`mcp_guard/tool_registry.py` 6 工具全 mock(`AUDIT_REPORT.md:126`)
- **影响**:Agent 路径走不通,只能走 response_engine 路径

### 1.3 已有性能基础设施盘点

| 类别 | 已有 | 缺 |
|------|------|----|
| **批处理** | sub_auditor IP 分块(LLM 层) | iptables 批处理、SSH 命令批处理 |
| **缓存** | LLM 响应 cache 600s(12.5% 命中)、TTL 自动解封 Redis、Rollback Token 内存+Redis 双写、PG 事件幂等、ResponseLog Redis cache、_audit_status_cache LRU | IP 去重 cache(短时间内重复 block 同一 IP) |
| **异步** | asyncio.create_task 多处、Temporal Workflow | Celery/RQ 等持久化队列 |
| **背压** | Kafka 5 并发、Audit-LLM 20、Temporal 12、LLM Enhancer 5、HTTP 120/min、SecurityGuard 30/min、Kafka DLQ | HTTP 端 429 显式降级 |
| **熔断** | CAD circuit_breaker、Veto Gates、Faithfulness Gate | LLM 预算硬熔断、SSH/iptables 健康熔断 |
| **真实流量** | log_simulator.py(合成) | Suricata、winlog collector、soc-firewall syslog forwarder |

### 1.4 部署架构

- **服务**:19 必选 + 3 可选 profile(ndr/sandbox/intel)
- **核心**:`postgres / redis / qdrant / kafka / schema-registry / flink-jobmanager / flink-taskmanager / backend / frontend / temporal-worker / otel-collector / tempo / jaeger / temporal-postgres / temporal / temporal-ui / prometheus / grafana`
- **关键 env**:`SHARED_MEMORY_LLM_*` / `SHARED_MEMORY_RESPONSE_SSH_*` / `SHARED_MEMORY_FW_SSH_*` / `SHARED_MEMORY_KAFKA_*` / `SHARED_MEMORY_TEMPORAL_*` / `TEMPORAL_CONCURRENCY` / `SHARED_MEMORY_RATE_LIMIT_PER_MINUTE`

---

## 2 · 目标指标(生产级)

### 2.1 吞吐量目标

| 指标 | 当前 | P0 末 | P1 末 | P2 末 |
|------|------|------|------|------|
| audit_pipeline calls/min | 1-2 | 10-15 | 30-50 | ≥ 60 |
| ingest 端 events/sec | 20.7 | 30 | 80 | ≥ 150 |
| 端到端完成率 | 10.1% | 40% | 80% | ≥ 95% |
| SSH block_ip/sec | < 10 | 30 | 100 | ≥ 200 |
| iptables 规则管理/sec | < 20 | 50 | 200 | ≥ 500 |

### 2.2 延迟目标

| 指标 | 当前 | P0 末 | P1 末 | P2 末 |
|------|------|------|------|------|
| FastPath 端到端 P99(ingest → iptables) | 分钟级 | ≤ 10s | ≤ 5s | ≤ 2s |
| AuditPath 端到端 P99 | 分钟级 | ≤ 30s | ≤ 15s | ≤ 8s |
| SSH single block P99 | 100ms(单条) | 100ms | 50ms | 30ms |

### 2.3 可用性 / 一致性

| 指标 | 当前 | P0 末 | P1 末 | P2 末 |
|------|------|------|------|------|
| 平台 SLO | N/A | 99.0% | 99.5% | 99.9% |
| iptables vs _active_rules 一致 | 不一致 | 100% | 100% | 100% |
| 容器重启后状态恢复 | 丢失 | 持久化 | 持久化 | 持久化 |
| 真实攻击流量入口 | 0 | 1(Suricata 或 winlog 二选一) | 全接通 | 全接通 + 容灾 |

### 2.4 可观测性

| 指标 | 当前 | P0 末 | P1 末 | P2 末 |
|------|------|------|------|------|
| Trace 覆盖 | 部分 | 关键路径 100% | 全部 stage | 全部 stage + 业务维度 |
| 关键 SLO 仪表板 | 无 | 1 个核心 | 4 个业务 | 全 SLO/SLI 体系 |
| 告警 | 仅 LLM 错误 | 4 类 | 10 类 | 全量 + 业务异常 |
| 压测基线 | 1 份(09-02) | 3 个量级 | 5 个量级 | 混沌工程 |

### 2.5 资源上限(单 backend 实例)

| 资源 | 当前基线 | 目标上限 |
|------|----------|----------|
| CPU | < 30% | 70% @ 100 req/s |
| MEM | < 4GB | 6GB @ 100 req/s |
| SSH 活跃连接数 | 1 | 10 (P1) / 50 (P2) |
| LLM 并发槽 | 20 | 30 (P1) / 自适应 (P2) |
| Temporal activity 槽 | 12 | 50 (P0) / 100+ (P1) |

---

## 3 · P0 紧急方案(1-2 周)

> 目标:消除明显阻塞、单点、状态不一致,接通真实攻击流量入口,LLM 预算硬阻断。
> 不改架构,只调配置 + 局部修复 + 启 service。

### P0-1:调整 Temporal 并发配置

- **目标**:audit_pipeline calls/min 从 1-2 → 10-15
- **改动**:
  - `backend/temporal/worker.py:35-46` `TEMPORAL_CONCURRENCY`:12 → 30(env 覆盖,`docker-compose.yml:396` 已是 30,需 reconcile)
  - `docker-compose.yml:396` `TEMPORAL_CONCURRENCY: 30` 已覆盖,需确认 worker.py 默认值与 env 优先级
  - 临时:`docker-compose up -d temporal-worker`(不 restart)
- **风险**:中 — 触发 LLM 429 风暴(216 workflow 同启已被 429 验证)
- **缓解**:分 3 阶段提升(12→20→30),每阶段观察 LLM 错误率
- **涉及文件**:`backend/temporal/worker.py`、`docker-compose.yml`、`docs/performance/plan.md`
- **验证**:重启后跑 attack-perf-large-scale 同场景,audit_pipeline calls/min ≥ 10

### P0-2:FastPath 跳过 audit_pipeline(高置信度短路)

- **目标**:threat_type 预设 + confidence ≥ 0.9 时,直进 response_orchestrator
- **改动**:
  - `backend/log_ingestion.py:310` 现有 `_audit_pipeline` 后台任务前,加 fast-path 短路
  - `backend/log_ingestion.py:129-338` `ingest` 入口加置信度判断
  - 已有 `correlation_engine.infer_threat_type` 路径(`log_ingestion.py:121`)
- **影响**:M2.7 切回 M3 也行(LLM 提 threat_type 修复前先绕过)
- **风险**:中 — 漏掉 LLM 审计本应发现的复杂攻击
- **缓解**:fast-path 事件同步保留到 audit-queue,后台异步审计(仅写 trace + log,不阻塞响应)
- **涉及文件**:`backend/log_ingestion.py`、`backend/correlation_engine.py`、`backend/response_engine/response_orchestrator.py`
- **验证**:Phase 2 487 事件 → 端到端完成率 ≥ 40%,FastPath 事件全部 auto-block 成功

### P0-3:rollback_all 真实清理 iptables

- **目标**:`rollback_all` 把 `_active_rules` 全部清掉 + iptables 真实删
- **改动**:
  - `backend/response_engine/ssh_firewall.py:343-367` `rollback_all` 改为:
    1. 从 `_active_rules` 复制所有 rule_id
    2. 调 `iptables -D INPUT -s <ip> -j DROP -m comment --comment "FW-RULE-xxx"` 每个
    3. 成功后从 `_active_rules` 删
    4. 失败的事务回滚
  - 启用 `transport.execute` 真实删 path(现有 stub)
- **风险**:高 — 误删可能影响生产(缓解:加 dry_run mode + 二次确认)
- **涉及文件**:`backend/response_engine/ssh_firewall.py`、`backend/response_engine/response_executor.py`
- **验证**:手动 block 10 IP → rollback_all → iptables -L INPUT 确认 0 条 DROP

### P0-4:iptables 真实状态 ↔ `_active_rules` 启动时 reconcile

- **目标**:backend 启动时,读取 iptables 真实规则,rebuild `_active_rules` dict
- **改动**:
  - `backend/response_engine/ssh_firewall.py:109-127` `connect` 成功后调 `_reconcile_with_iptables`
  - `_reconcile_with_iptables`:执行 `iptables -L INPUT -n --line-numbers`,解析 comment `FW-RULE-xxx`,rebuild dict
  - `backend/response_engine/response_registry.py:369-378` `_auto_unblock` 改用 Redis SortedSet(已有 `ttl_manager.py` 模式)持久化
- **风险**:中 — reconcile 解析失败回退到"全清重建"(再 P0-3)
- **涉及文件**:`backend/response_engine/ssh_firewall.py`、`backend/response_engine/ttl_manager.py`、`backend/response_engine/response_registry.py`
- **验证**:手动塞 5 条 iptables DROP 规则(非本平台生成)→ 重启 backend → `_active_rules` 包含 5 条

### P0-5:启 Suricata service(接通真实攻击流量)

- **目标**:`docker-compose up -d suricata` 后,`nmap -sS` 攻击流量进 SOC
- **改动**:
  - `docker-compose.yml:543-558` suricata service 改 `profiles: []`(默认启)或拆出独立 compose
  - 配 `config/suricata/eve.json` output → syslog 或 Kafka producer
  - 启动验证:`docker exec soc-suricata tail -f /var/log/suricata/eve.json | grep -i "alert"`
- **风险**:中 — Suricata 配置错误可能漏报或误报
- **缓解**:先 profiles=["ndr"] 不变,新加 `docker-compose.ndr.yml` 独立 profile
- **涉及文件**:`docker-compose.yml`、`config/suricata/*.yml`(新增)、`docs/deployment.md`
- **验证**:从 kali 跑 nmap → SOC security_events 有 nmap signature 事件

### P0-6:LLM 预算硬阻断

- **目标**:日 token > 5M 时,返回 429 + 告警
- **改动**:
  - 找到 LLM 调用入口(`backend/llm_enhancer.py`、各 agent),加 `check_daily_budget`
  - 超预算时:`raise DailyBudgetExceeded`,上层捕获后转 429
  - `docker-compose.yml:253` `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` 检查逻辑改硬阻断
- **风险**:中 — 误阻断导致响应链全断
- **缓解**:分级(80% 告警 / 95% 降级 / 100% 阻断),阻断只针对非关键路径
- **涉及文件**:`backend/llm_enhancer.py`、`backend/agents/*.py`、`backend/config.py`
- **验证**:mock LLM 返回大量 token → 触发阻断 → response 429

### P0-7:LLM threat_type 修复(M2.7 老问题)

- **目标**:LLM 审计输出 `threat_type` 非空
- **改动**:
  - 读 `backend/agents/agent_*.py` 4 个 LLM 智能体,找到 threat_type 输出节点
  - 改 prompt 模板或加 post-process parser
  - M3 模型回归(已有 env `SHARED_MEMORY_LLM_MODEL=mimo-v2.5` 切回 `mimo-v2.7` 或 `mimo-v3`)
- **风险**:低 — prompt 调整风险小
- **涉及文件**:`backend/prompts/*.py`、`backend/agents/agent_reviewer.py`
- **验证**:跑 50 事件 batch → LLM 输出 threat_type 命中率 ≥ 80%

### P0-8:HTTP 429 显式降级(response/simulate 端)

- **目标**:`routers/response.py:124-161` `simulate_threat` 端点 429
- **改动**:
  - 已有 `rate_limit_per_minute=120` 中间件(全局)
  - 加端点级 rate limit(`simulate` 30/min、`execute` 60/min)
  - audit CRIT-02 修复:加 `verify_operator_token` 中间件
- **风险**:低
- **涉及文件**:`backend/routers/response.py`、`backend/security_guard/rate_limiter.py`
- **验证**:loop 100 次 simulate → 第 31 次开始 429

---

## 4 · P1 中期方案(1-2 月)

> 目标:异步化、批处理、连接池、缓存、可观测。
> 改局部架构,不重写。

### P1-1:SSH 连接池

- **目标**:SSH block_ip/sec 从 < 10 → 100
- **改动**:
  - 新增 `backend/response_engine/ssh_pool.py`:连接池(paramiko.SSHClient per-channel)
  - 池大小:`SHARED_MEMORY_SSH_POOL_SIZE` env,默认 5(P0=10, P1=20, P2=50)
  - `backend/response_engine/ssh_firewall.py` 改用 `ssh_pool.get()/release()`
- **风险**:中 — paramiko channel 复用坑(SSH channel 不是线程安全)
- **涉及文件**:`backend/response_engine/ssh_firewall.py`(新增)、`backend/response_engine/ssh_pool.py`、`backend/config.py`、`docker-compose.yml`
- **验证**:100 并发 block_ip 任务 → 完成时间 < 5s

### P1-2:iptables 批处理

- **目标**:iptables 规则管理/sec 从 < 20 → 200
- **改动**:
  - 新增 `backend/response_engine/iptables_batcher.py`:累积 N 条 / 50ms 后批量执行
  - `backend/response_engine/response_executor.py:130-213` 改用 batcher
  - 批命令:`iptables -I INPUT -s 1.1.1.1 -j DROP -m comment --comment "FW-RULE-1"; iptables -I INPUT -s 2.2.2.2 -j DROP ...`
  - 或 `iptables-save` + `iptables-restore` 整体替换(更高吞吐)
- **风险**:高 — 单条失败回滚复杂
- **涉及文件**:`backend/response_engine/iptables_batcher.py`(新增)、`backend/response_engine/response_executor.py`、`backend/response_engine/ssh_firewall.py`
- **验证**:1000 IP 批量 block → 完成时间 < 5s,错误率 < 0.1%

### P1-3:RateLimiter 升级 Redis(多进程一致)

- **目标**:`security_guard/rate_limiter.py` 单进程 → 多进程一致
- **改动**:
  - 用 Redis Lua script 实现 sliding window(原子)
  - 或用 Redis SortedSet + ZREMRANGEBYSCORE
  - `backend/security_guard/rate_limiter.py:31-33` `_global_calls` `_action_calls` 改 Redis backend
- **风险**:中 — Redis 故障 fallback 到内存(降级)
- **涉及文件**:`backend/security_guard/rate_limiter.py`、`backend/security_guard/security_guard.py`
- **验证**:启 4 个 backend 实例(不同 worker)→ 限流 30/min 仍生效

### P1-4:audit_pipeline workflow 重构(拆串行)

- **目标**:audit_pipeline calls/min 从 10-15 → 30-50
- **改动**:
  - `backend/temporal/workflows.py:33-141` 串行 3 round → 改为:
    1. round 1 + 2 并行(2 activity 并发)
    2. round 3 仅在 round 1/2 不一致时跑
    3. cad_verify 改异步(workflow return 后,后台跑)
  - 或:拆成 2 workflow(decompose + review)→ save_result 触发 2 workflow 并行
  - `backend/temporal/activities.py:23-122` `audit_round` 内 p50 8-12s 优化:
    1. sub_auditor LLM 调用并发(同 IP 多个 sub-query)
    2. 跳过中间 review round(confidence 阈值)
- **风险**:高 — workflow 重构容易破坏 determinism
- **涉及文件**:`backend/temporal/workflows.py`、`backend/temporal/activities.py`、`backend/agents/*.py`
- **验证**:686 事件 25min → 完成率 ≥ 80%

### P1-5:ingest 端 asyncio.gather 化

- **目标**:ingest events/sec 从 20 → 80
- **改动**:
  - `backend/log_ingestion.py:980-992` `ingest_batch` 改 `asyncio.gather`
  - 前置流程(异常检测/Sigma/存储/case_manager/memory_tree/sliding_window)独立 task
  - `asyncio.Semaphore(50)` 限制并发
- **风险**:中 — 共享状态需锁
- **涉及文件**:`backend/log_ingestion.py`、`backend/case_manager.py`、`backend/memory_tree.py`、`backend/sliding_window.py`(如有)
- **验证**:500 events batch 灌入 → 完成时间 < 10s

### P1-6:审计状态去重 cache(同 threat_type 短时多次)

- **目标**:避免重复 LLM 调用
- **改动**:
  - 新增 `backend/agents/audit_dedup.py`:Redis 7s TTL(SHA256(prompt) → result)
  - `backend/temporal/activities.py:23-122` `audit_round` 调用前查 cache
  - 命中率目标:30%+
- **风险**:低 — cache miss 不影响正确性
- **涉及文件**:`backend/agents/audit_dedup.py`(新增)、`backend/temporal/activities.py`
- **验证**:跑 100 重复事件 → 70+ cache hit,LLM 调用 < 30

### P1-7:可观测性 — 关键 SLO 仪表板

- **目标**:Grafana 4 个核心面板
  1. **audit_pipeline 速率** — Prometheus metric `audit_pipeline_calls_per_min`
  2. **端到端完成率** — `audit_completion_ratio`(5min 窗口)
  3. **封禁 P99 延迟** — histogram `block_ip_latency_seconds`
  4. **真实攻击流量** — `security_events_per_min` by threat_type
- **改动**:
  - `backend/metrics.py` 新增 4 个指标
  - `monitoring/grafana/soc-slo.json`(新增)
  - 各 P0/P1 改动同步埋点
- **风险**:低
- **涉及文件**:`backend/metrics.py`、`monitoring/grafana/soc-slo.json`、`docs/performance/plan.md`
- **验证**:启 Grafana → 4 个面板都有数据(从 P0 末开始的压测可见)

### P1-8:审计 trace 覆盖率 100%

- **目标**:`pipeline_tracer.py` 关键路径 100% 覆盖
- **改动**:
  - 已有 stage:`STAGES` (`pipeline_tracer.py:32-43`)
  - 新增 stage:`temporal_dispatch`、`audit_round`、`save_result`、`trigger_response`、`cad_verify`、`iptables_exec`
  - 漏点扫描:`audit_pipeline_complete` 总 stage 包裹
- **风险**:低
- **涉及文件**:`backend/observability/pipeline_tracer.py`、`backend/temporal/activities.py`
- **验证**:跑 100 事件 → 100% trace 有 audit_pipeline_complete stage

---

## 5 · P2 长期方案(2-3 月)

> 目标:分层架构、容量规划、SLO/SLI 体系、混沌工程。

### P2-1:引入独立响应引擎进程

- **目标**:backend 进程拆分为 ingest / audit / response 3 个进程
- **改动**:
  - 新增 `backend/response_engine/server.py`:独立 FastAPI app
  - `backend/response_engine/` 整体迁出 backend 进程
  - 通过 Kafka 通信(`response-commands` topic)
- **风险**:高 — 通信延迟 + 一致性
- **涉及文件**:`backend/response_engine/server.py`(新增)、`backend/main.py`、`docker-compose.yml`
- **验证**:3 进程独立压测,任一进程 OOM 不影响其他

### P2-2:异步任务队列(Celery 或 RQ)

- **目标**:替换 `asyncio.create_task` 短任务 → 持久化队列
- **改动**:
  - 新增 `backend/queue/`:Celery + Redis broker
  - 替换 `_audit_pipeline` `_fast_response` `_auto_unblock` `_poll_approval` 为 Celery task
  - 优势:持久化、重试、可观测
- **风险**:高 — Temporal vs Celery 双系统成本
- **涉及文件**:`backend/queue/`(新增)、`backend/log_ingestion.py`、`backend/response_engine/response_orchestrator.py`、`docker-compose.yml`
- **验证**:backend 进程 crash → Celery task 仍能完成

### P2-3:Flink 端扩展(实时评分 + 攻击链)

- **目标**:Flink 端预先 block 高置信度攻击,绕过 audit_pipeline
- **改动**:
  - `flink-jobs/src/.../AnomalyDetectionJob.java` 加 CEP 触发 Kafka `auto-block-commands`
  - response_engine 订阅 `auto-block-commands`,direct ssh_firewall
  - FastPath 进一步缩短
- **风险**:高 — 误报代价大
- **涉及文件**:`flink-jobs/src/.../AnomalyDetectionJob.java`、`backend/response_engine/auto_block_consumer.py`(新增)
- **验证**:Flink 端 CEP 触发 → 1s 内 iptables DROP

### P2-4:SLO/SLI 体系 + Error Budget

- **目标**:全 SLO 监控 + 告警 + 月度 Error Budget 评审
- **改动**:
  - 定义 SLO 文档:`docs/slo/slo-catalog.md`
  - Prometheus alerting rules:`monitoring/prometheus/slo-alerts.yml`
  - 月度 review checklist
- **涉及文件**:`docs/slo/slo-catalog.md`(新增)、`monitoring/prometheus/slo-alerts.yml`(新增)
- **验证**:3 个核心 SLO 有告警 + Error Budget 仪表板

### P2-5:混沌工程(Chaos Mesh / Litmus)

- **目标**:故障注入常态化
- **改动**:
  - 引入 chaos-mesh
  - 实验:`network-delay`、`pod-kill`、`redis-failover`、`llm-429-storm`
  - 跑在 staging
- **涉及文件**:`infrastructure/chaos/`(新增)、`docs/chaos/`(新增)
- **验证**:chaos 实验可见告警

---

## 6 · 风险评估

### 6.1 P0 风险

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| Temporal 30 触发 LLM 429 | 高 | 高 | 分阶段提升(12→20→30)+ 监控 LLM 错误率 |
| FastPath 漏报复杂攻击 | 中 | 中 | 后台仍跑 audit(仅 trace+log),不阻塞响应 |
| rollback_all 误删 | 中 | 高 | dry_run mode + 二次确认 + iptables comment 验证 |
| Suricata 误报/漏报 | 中 | 中 | 独立 profile 启动,小流量验证再全开 |
| LLM 预算硬阻断误伤 | 中 | 中 | 分级(80% 告警 / 95% 降级 / 100% 阻断) |

### 6.2 P1 风险

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| SSH 连接池 channel 复用 | 中 | 中 | paramiko Transport 复用,Channel per-task |
| iptables 批量失败回滚 | 高 | 高 | 单条失败 → 全 batch 事务回滚 + 告警 |
| workflow 重构破坏 determinism | 中 | 高 | 完整重放测试 + chaos 实验 |
| asyncio.gather 共享状态 | 中 | 中 | asyncio.Lock 保护 |

### 6.3 P2 风险

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 进程拆分通信延迟 | 高 | 中 | Kafka 异步 + 同步降级路径 |
| 双系统(Temporal + Celery)成本 | 中 | 中 | Celery 只接管短任务,Temporal 留 audit |
| 混沌实验触发生产事故 | 中 | 高 | 仅 staging 跑 + 实验审批流程 |

---

## 7 · 验证方案

### 7.1 P0 验证清单

| 阶段 | 验证方法 | 工具 | 通过标准 |
|------|----------|------|----------|
| P0-1 Temporal 调并发 | 跑 attack-perf-large-scale 复测 | `log_simulator.py` | audit_pipeline calls/min ≥ 10 |
| P0-2 FastPath | 487 事件 batch | 同上 | 完成率 ≥ 40%,FastPath 全 auto-block |
| P0-3 rollback_all | 手动 block 10 IP → rollback_all | `docker exec soc-firewall iptables -L` | 0 DROP 残留 |
| P0-4 iptables reconcile | 手动塞 5 条 iptables → 重启 backend | 检查 `_active_rules` | 5 条全恢复 |
| P0-5 Suricata | nmap 攻击 | `docker exec soc-suricata tail` | security_events 有 nmap signature |
| P0-6 LLM 预算 | mock 大量 token | 直接调 LLM 入口 | 阻断 + 429 |
| P0-7 threat_type | 50 事件 batch | `log_simulator.py` | threat_type 命中 ≥ 80% |
| P0-8 HTTP 429 | loop 100 次 simulate | curl | 第 31 次 429 |

### 7.2 P1 验证清单

| 阶段 | 验证方法 | 通过标准 |
|------|----------|----------|
| P1-1 SSH 池 | 100 并发 block_ip | < 5s |
| P1-2 iptables 批 | 1000 IP 批量 | < 5s, 错误率 < 0.1% |
| P1-3 RateLimiter Redis | 4 backend 实例 + 限流测试 | 30/min 仍生效 |
| P1-4 workflow 重构 | 686 事件 25min | 完成率 ≥ 80% |
| P1-5 asyncio.gather | 500 events batch | < 10s |
| P1-6 审计去重 | 100 重复事件 | 命中率 ≥ 70% |
| P1-7 SLO 仪表板 | Grafana 看 | 4 面板有数据 |
| P1-8 trace 覆盖 | 100 事件 | 100% 覆盖 audit_pipeline_complete |

### 7.3 P2 验证清单

| 阶段 | 验证方法 | 通过标准 |
|------|----------|----------|
| P2-1 进程拆分 | 独立压测 | 任一进程 OOM 不影响其他 |
| P2-2 Celery | 进程 crash 测试 | task 不丢失 |
| P2-3 Flink 端 auto-block | 注入 + 看 iptables | < 1s |
| P2-4 SLO/SLI | 告警 + 仪表板 | 3 SLO 告警 + Error Budget 可见 |
| P2-5 混沌工程 | chaos 实验 | 可见告警 + 恢复 |

### 7.4 压测基线(必做)

- 3 个数量级测试:`10 req/s`、`50 req/s`、`150 req/s`
- 每量级 ≥ 5 min 稳态
- 多维指标:iptables/LLM/资源/状态一致性
- 报告"拐点",不只报"100%/0%"

---

## 8 · 附录

### 8.1 架构图(文字版)

```
                            ┌──────────────────────────────────────┐
                            │  真实攻击源(nmap/hydra/exploit)        │
                            └─────────────┬────────────────────────┘
                                          │
              ┌───────────────────────────┼────────────────────────┐
              ▼                           ▼                        ▼
        Suricata(p0-5)            windows-log-collector         log_simulator
        soc-firewall syslog        host PowerShell              (合成事件)
              │                           │                        │
              └───────────────┬───────────┴────────────┬───────────┘
                              ▼                        ▼
                      Kafka security-logs-raw     (HTTP /ingest)
                              │
                              ▼
                      Flink LogValidationJob(校验+去重)
                              │
                              ▼
                  Kafka security-logs-validated
                              │
                              ▼
                  Flink AnomalyDetectionJob(CEP 多模式)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        security-alerts  audit-queue   events-enriched
                              │
                              ▼
                  KafkaConsumer(AUDIT_SEMAPHORE=5)
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
        FastPath(p0-2)            Temporal Workflow(p1-4)
        threat_type+conf≥0.9      4 activity 串行
        直进 response              → AuditPipelineWorkflow
        (后台仍 audit)             → save_result
                                  → trigger_response
                                  → cad_verify(async p1-4)
                  │                       │
                  └───────────┬───────────┘
                              ▼
                  ResponseOrchestrator(p0-1 Temporal 30)
                              │
                  ┌───────────┼────────────┐
                  ▼           ▼            ▼
              policy       security      approval
              engine       guard         queue
                  │
                  ▼
                  ResponseExecutor(parallel=true p1-5)
                              │
                              ▼
                  ResponseRegistry → ssh_firewall
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
        SSH 连接池(p1-1)        iptables 批处理(p1-2)
        paramiko pool            iptables-save/restore
                  │                       │
                  └───────────┬───────────┘
                              ▼
                  iptables DROP + _active_rules(p0-3/p0-4 持久化)
```

### 8.2 文件清单索引

完整文件清单见 `docs/performance/files-to-modify.md`。本附录只列阶段文件数:

| 阶段 | 新增 | 修改 | 删除 | 合计 |
|------|------|------|------|------|
| P0 | 0 | 9 | 0 | 9 |
| P1 | 3 | 11 | 0 | 14 |
| P2 | 8 | 7 | 0 | 15 |
| **合计** | **11** | **27** | **0** | **38** |

### 8.3 参考资料

- `docs/security-audit/attack-perf-large-scale-2026-09-02.md` — 2026-09-02 真实压测
- `docs/security-audit/attack-perf-m27-2026-09-01.md` — 2026-09-01 M2.7 切换
- `docs/security-audit/AUDIT_REPORT.md` — 渗透审计 v1
- explore 报告(归档) — 12 个瓶颈 evidence
- memory:历史 v6 已纠正(**100 IP / 95% / 17.4 req/s**)
- 9p bind mount + uvicorn PID 1 namespace 隔离教训(`memory`)
- docker restart vs compose up -d 改 env 教训(`memory`)
- Temporal 12 并发限制 = audit_pipeline 真实瓶颈(`memory`)

---

**v1 总结**:平台从"勉强吃下 20 req/s"到"生产级 100+ req/s",关键是**先把串行解锁**(P0 Temporal + FastPath)、**把单点变多点**(P1 SSH 池 + iptables 批 + Redis RateLimiter)、**把断的接上**(P0 Suricata + reconcile)、**最后分层**(P2 进程拆分 + Celery + 混沌)。
