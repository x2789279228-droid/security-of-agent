# SOC 安全审计平台 — 性能改造文件清单 v1

**日期**: 2026-09-02
**配套方案**: `docs/performance/plan.md`
**说明**: 本清单**包含完整文件**(配置/部署/测试/文档/新建/删除),不只是关键代码文件。每个文件按 5 字段格式标注。

---

## P0 紧急阶段文件清单(9 个修改 + 4 个新增 = 13 个)

### `backend/temporal/worker.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: 改 `TEMPORAL_CONCURRENCY` 默认值与 env reconcile;`worker.py:35-46` 改读 `os.getenv("TEMPORAL_CONCURRENCY", "30")`(从 12 提到 30);同时支持 env 调整时 hot-reload(可选,加监听文件 /usr/local/etc/concurrency)
- **依赖**: `docker-compose.yml:396` 已覆盖 30
- **风险**: 中 — 触发 LLM 429 风暴;缓解:分 3 阶段提升(12→20→30),监控 LLM 错误率

### `docker-compose.yml`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. `docker-compose.yml:396` `TEMPORAL_CONCURRENCY: 30` 加注释说明 worker.py 已对接
  2. `docker-compose.yml:543-558` suricata service 改 `profiles: []` 或拆出独立 `docker-compose.ndr.yml`,默认不启,加 `suricata` profile
  3. 加 env `SHARED_MEMORY_FW_AUTO_RECONCILE=true`(P0-4 启动时 reconcile)
  4. 加 env `SHARED_MEMORY_LLM_DAILY_BUDGET_MODE=hard`(P0-6 硬阻断)
- **依赖**: `backend/temporal/worker.py`、`backend/response_engine/ssh_firewall.py`、`backend/llm_enhancer.py`
- **风险**: 中 — Suricata 误报;缓解:独立 profile,验证再开

### `backend/log_ingestion.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. P0-2 FastPath:`log_ingestion.py:129-338` `ingest` 入口加 `if correlation_engine.infer_threat_type(event) and event.confidence >= 0.9: await response_orchestrator.on_threat_detected(event, fast_path=True)` 短路
  2. FastPath 事件同步保留到 audit-queue(后台异步审计)
  3. P1-5:`log_ingestion.py:980-992` `ingest_batch` 改 `asyncio.gather`,前置流程独立 task,`asyncio.Semaphore(50)` 限流
- **依赖**: `backend/correlation_engine.py`、`backend/response_engine/response_orchestrator.py`、`backend/case_manager.py`、`backend/memory_tree.py`
- **风险**: 中 — FastPath 漏报复杂攻击;asyncio.gather 共享状态需锁

### `backend/correlation_engine.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. P0-2:`infer_threat_type`(`log_ingestion.py:121` 调用)返回 `(threat_type, confidence)` 元组
  2. 加 `confidence` 字段到结果(基于 CEP 命中数 / 异常评分综合)
- **依赖**: `backend/log_ingestion.py`
- **风险**: 低 — 纯函数改动

### `backend/response_engine/response_orchestrator.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. P0-2:`on_threat_detected`(`response_orchestrator.py:185-401`)加 `fast_path: bool` 参数;FastPath 跳过 `_guarded_execute` 部分审查
  2. P2-2:`_poll_approval`(`response_orchestrator.py:403-`)改用 Celery task 替代 `asyncio.create_task`
- **依赖**: `backend/log_ingestion.py`、`backend/queue/tasks.py`(P2-2)
- **风险**: 中 — FastPath 跳过审查;缓解:同步保留后台审计 trace

### `backend/response_engine/ssh_firewall.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. P0-3:`rollback_all`(`ssh_firewall.py:343-367`)改为:
     - 从 `_active_rules` 复制所有 rule_id
     - 逐个调 `iptables -D INPUT -s <ip> -j DROP -m comment --comment "FW-RULE-xxx"`
     - 成功后从 `_active_rules` 删;失败时事务回滚
  2. P0-4:`connect`(`ssh_firewall.py:109-127`)成功后调 `_reconcile_with_iptables`:执行 `iptables -L INPUT -n --line-numbers` 解析 comment `FW-RULE-xxx`,rebuild dict
  3. P1-1:从 `ssh_firewall.py:49-70` 单例 → 改用 `ssh_pool.get()/release()`
- **依赖**: `backend/response_engine/response_executor.py`、`backend/response_engine/ttl_manager.py`、`backend/response_engine/ssh_pool.py`(P1-1)
- **风险**: 高 — rollback 误删;连接池 channel 复用坑

### `backend/response_engine/response_executor.py`
- **类型**: 修改
- **所属阶段**: P0 + P1
- **改动内容**:
  1. P0-3:`execute_actions`(`response_executor.py:130-213`)rollback 失败时不再只标记 revoked
  2. P1-2:改用 `iptables_batcher` 批量执行(每批 50 / 50ms)
  3. P1-5:`parallel=False` 默认 → 改 `parallel=True`(P1 末)
- **依赖**: `backend/response_engine/ssh_firewall.py`、`backend/response_engine/iptables_batcher.py`(P1-2)
- **风险**: 高 — 批量失败回滚复杂

### `backend/response_engine/ttl_manager.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-4:`_active_rules` 持久化从纯内存 → Redis SortedSet(已有模式 `soc:ttl:index`),TTL 与 iptables 规则同步
- **依赖**: `backend/response_engine/ssh_firewall.py`、`backend/response_engine/response_registry.py`
- **风险**: 中 — Redis 故障 fallback

### `backend/response_engine/response_registry.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-4:`_auto_unblock`(`response_registry.py:369-378`)从 `asyncio.create_task` 改用 `ttl_manager.register`,持久化到 Redis(容器重启不丢)
- **依赖**: `backend/response_engine/ttl_manager.py`、`backend/response_engine/ssh_firewall.py`
- **风险**: 中

### `backend/llm_enhancer.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-6:加 `check_daily_budget` 函数,日 token > 5M 时 `raise DailyBudgetExceeded`;分级 80% 告警 / 95% 降级 / 100% 阻断
- **依赖**: `backend/agents/*.py`、`backend/config.py`
- **风险**: 中 — 误阻断响应链;缓解:分级 + 非关键路径才阻断

### `backend/agents/*.py`
- **类型**: 修改
- **所属阶段**: P0 + P1
- **改动内容**:
  1. P0-6:所有 LLM 调用入口加 `check_daily_budget` 包装
  2. P0-7:`agent_reviewer.py` prompt 改 threat_type 提取模板
  3. P1-4:`sub_auditor.py` LLM 调用并发(同 IP 多 sub-query)
  4. P1-6:调用前查 `audit_dedup` cache
- **依赖**: `backend/llm_enhancer.py`、`backend/agents/audit_dedup.py`(P1-6)、`backend/prompts/*.py`
- **风险**: 中

### `backend/prompts/*.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-7:threat_type 提取 prompt 模板改,显式要求输出 `threat_type` 字段(从枚举 8 个值中选)
- **依赖**: `backend/agents/agent_reviewer.py`
- **风险**: 低

### `backend/routers/response.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**:
  1. P0-8:`simulate_threat`(`routers/response.py:124-161`)加端点级 rate limit(30/min)
  2. P0-8:加 `verify_operator_token` 中间件(audit CRIT-02 修复)
  3. P0-8:`execute_response`(`routers/response.py:234-285`)加 60/min rate limit
- **依赖**: `backend/security_guard/rate_limiter.py`
- **风险**: 低

### `backend/security_guard/rate_limiter.py`
- **类型**: 修改
- **所属阶段**: P0 + P1
- **改动内容**:
  1. P0-8:加端点级 rate limit(已有 `RateLimiter.check` 复用)
  2. P1-3:`_global_calls`(`rate_limiter.py:31`) `_action_calls`(`rate_limiter.py:33`) 改 Redis backend(Lua script 原子 sliding window)
- **依赖**: `backend/routers/response.py`
- **风险**: 中 — Redis 故障 fallback

### `config/suricata/suricata.yaml` *(新增)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: P0-5:Suricata 配置文件,启用 eve.json 输出,kafka output(`security-logs-raw` topic,Suricata plugin)
- **依赖**: `docker-compose.yml`、`tools/syslog-adapter.py`
- **风险**: 中 — Suricata 配置错误

### `config/suricata/eve-output.json` *(新增)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: P0-5:eve.json 输出规则,包含所有 alert 类型
- **依赖**: `config/suricata/suricata.yaml`
- **风险**: 低

### `docker-compose.ndr.yml` *(新增)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: P0-5:独立 NDR profile,包含 suricata + tools/syslog-adapter;`docker-compose -f docker-compose.yml -f docker-compose.ndr.yml up -d` 启动
- **依赖**: `config/suricata/suricata.yaml`
- **风险**: 中

### `tools/syslog-adapter.py`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-5:加 Kafka producer output,接收 Suricata eve.json 推 `security-logs-raw`
- **依赖**: `config/suricata/suricata.yaml`
- **风险**: 低

### `docs/deployment.md`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-5:加 "启用真实攻击流量" 章节,Suricata 配置 + ndr profile 启动方式 + 验证步骤
- **依赖**: `config/suricata/*.yml`、`docker-compose.ndr.yml`
- **风险**: 低

### `docs/performance/plan.md` *(本文件配套)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: 本方案文档(已完成)
- **依赖**: 全部
- **风险**: 低

---

## P1 中期阶段文件清单(3 个新增 + 11 个修改)

### `backend/response_engine/ssh_pool.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-1:paramiko Transport 池(`SSHClient` per-channel),`get()/release()` 上下文管理器;池大小 `SHARED_MEMORY_SSH_POOL_SIZE` env,默认 5(P1 末 20)
- **依赖**: `backend/response_engine/ssh_firewall.py`、`backend/config.py`
- **风险**: 中 — channel 不是线程安全

### `backend/response_engine/iptables_batcher.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-2:累积 N 条 / 50ms 后批量执行,失败事务回滚;支持 `iptables-save/restore` 整体替换模式
- **依赖**: `backend/response_engine/ssh_firewall.py`、`backend/response_engine/response_executor.py`
- **风险**: 高 — 批量失败回滚复杂

### `backend/agents/audit_dedup.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-6:Redis 7s TTL(SHA256(prompt) → result);`get_or_compute(prompt, compute_fn)` 接口
- **依赖**: `backend/temporal/activities.py`
- **风险**: 低

### `backend/config.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-1:加 `SSH_POOL_SIZE` (int) `LLM_DAILY_BUDGET_MODE` (str) `LLM_AUDIT_DEDUP_TTL` (int) 配置项
- **依赖**: `backend/response_engine/ssh_pool.py`、`backend/llm_enhancer.py`、`backend/agents/audit_dedup.py`
- **风险**: 低

### `backend/temporal/workflows.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-4:`AuditPipelineWorkflow.run`(`workflows.py:33-141`)拆串行:
  - round 1 + 2 并行(2 activity 并发)
  - round 3 仅 round 1/2 不一致时跑
  - cad_verify 改异步(workflow return 后,后台跑)
- **依赖**: `backend/temporal/activities.py`、`backend/agents/*.py`
- **风险**: 高 — 破坏 determinism

### `backend/temporal/activities.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**:
  1. P1-4:`audit_round`(`activities.py:23-122`)p50 8-12s 优化:sub_auditor LLM 并发;跳过中间 review round(confidence 阈值)
  2. P1-6:调用前查 `audit_dedup` cache
  3. P1-8:`audit_pipeline_complete` 总 stage 包裹
- **依赖**: `backend/temporal/workflows.py`、`backend/agents/audit_dedup.py`、`backend/observability/pipeline_tracer.py`
- **风险**: 高

### `backend/case_manager.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-5:`case_manager` 独立 task 化(支持 `asyncio.gather`),加 `asyncio.Lock` 保护共享状态
- **依赖**: `backend/log_ingestion.py`
- **风险**: 中

### `backend/memory_tree.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-5:`memory_tree.add_leaf`(`log_ingestion.py:202`)独立 task 化,加锁
- **依赖**: `backend/log_ingestion.py`
- **风险**: 中

### `backend/metrics.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-7:新增 4 个 Prometheus 指标:
  - `audit_pipeline_calls_per_min`(Counter)
  - `audit_completion_ratio`(Gauge,5min 窗口)
  - `block_ip_latency_seconds`(Histogram)
  - `security_events_per_min`(Counter, by threat_type label)
- **依赖**: `monitoring/grafana/soc-slo.json`
- **风险**: 低

### `monitoring/grafana/soc-slo.json` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-7:Grafana dashboard 4 个核心面板(见 plan.md § 4.7)
- **依赖**: `backend/metrics.py`
- **风险**: 低

### `backend/observability/pipeline_tracer.py`
- **类型**: 修改
- **所属阶段**: P1
- **改动内容**: P1-8:`STAGES`(`pipeline_tracer.py:32-43`)加 `temporal_dispatch`、`audit_round`、`save_result`、`trigger_response`、`cad_verify`、`iptables_exec`
- **依赖**: `backend/temporal/activities.py`
- **风险**: 低

### `backend/tests/test_ssh_pool.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-1:SSH pool 并发测试(100 并发 get/release)
- **依赖**: `backend/response_engine/ssh_pool.py`
- **风险**: 低

### `backend/tests/test_iptables_batcher.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-2:batch 1000 IP + 失败回滚测试
- **依赖**: `backend/response_engine/iptables_batcher.py`
- **风险**: 低

### `backend/tests/test_audit_dedup.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1-6:重复 prompt 命中率测试
- **依赖**: `backend/agents/audit_dedup.py`
- **风险**: 低

### `backend/tests/performance/test_load_p1.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1 验证:3 个数量级(10/50/150 req/s) ≥ 5min 压测,多维指标
- **依赖**: `log_simulator.py`
- **风险**: 低

### `tools/attack-simulator.sh`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: P0-5:加 nmap signature 攻击(nmap -sS / nmap -sV / hydra),验证 Suricata 接入
- **依赖**: `config/suricata/*.yml`、`tools/syslog-adapter.py`
- **风险**: 低

---

## P2 长期阶段文件清单(8 个新增 + 7 个修改)

### `backend/response_engine/server.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-1:独立 FastAPI app(响应引擎),端口 8002
- **依赖**: `backend/main.py`、`docker-compose.yml`、`backend/response_engine/`
- **风险**: 高 — 进程拆分通信

### `backend/main.py`
- **类型**: 修改
- **所属阶段**: P2
- **改动内容**: P2-1:删除 `response_engine` 路由(迁出到独立进程);保留 ingest / audit / observability
- **依赖**: `backend/response_engine/server.py`
- **风险**: 中

### `backend/queue/` *(整个目录新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-2:Celery + Redis broker 接入,文件:
  - `backend/queue/__init__.py`
  - `backend/queue/celery_app.py`
  - `backend/queue/tasks.py`(替换 `_audit_pipeline` `_fast_response` `_auto_unblock` `_poll_approval`)
- **依赖**: `backend/log_ingestion.py`、`backend/response_engine/response_orchestrator.py`、`docker-compose.yml`
- **风险**: 高 — Temporal + Celery 双系统

### `flink-jobs/src/main/java/.../AnomalyDetectionJob.java`
- **类型**: 修改
- **所属阶段**: P2
- **改动内容**: P2-3:CEP 触发 Kafka `auto-block-commands` topic(高置信度攻击)
- **依赖**: `backend/response_engine/auto_block_consumer.py`
- **风险**: 高 — 误报代价

### `backend/response_engine/auto_block_consumer.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-3:Kafka consumer 订阅 `auto-block-commands`,direct 调 `ssh_firewall.block_ip`
- **依赖**: `flink-jobs/src/.../AnomalyDetectionJob.java`
- **风险**: 高

### `docs/slo/slo-catalog.md` *(新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-4:SLO 目录:
  - audit_pipeline 速率 ≥ 60 calls/min
  - 端到端完成率 ≥ 95%
  - 封禁 P99 ≤ 2s
  - 平台可用性 ≥ 99.9%
- **依赖**: `monitoring/prometheus/slo-alerts.yml`
- **风险**: 低

### `monitoring/prometheus/slo-alerts.yml` *(新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-4:Prometheus alerting rules(3 SLO burn rate)
- **依赖**: `docs/slo/slo-catalog.md`、`backend/metrics.py`
- **风险**: 低

### `infrastructure/chaos/` *(整个目录新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-5:chaos-mesh 部署:
  - `infrastructure/chaos/chaos-mesh-install.yaml`
  - `infrastructure/chaos/experiments/network-delay.yaml`
  - `infrastructure/chaos/experiments/pod-kill.yaml`
  - `infrastructure/chaos/experiments/redis-failover.yaml`
  - `infrastructure/chaos/experiments/llm-429-storm.yaml`
- **依赖**: `docs/chaos/`
- **风险**: 中 — 仅 staging

### `docs/chaos/` *(整个目录新增)*
- **类型**: 新增
- **所属阶段**: P2
- **改动内容**: P2-5:混沌工程文档:
  - `docs/chaos/README.md`
  - `docs/chaos/runbook.md`
  - `docs/chaos/experiment-template.md`
- **依赖**: `infrastructure/chaos/`
- **风险**: 低

### `docs/performance/explore-report-2026-09-02.md` *(新增)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: 归档 explore 任务的最终报告(目前只在 task final_text)
- **依赖**: 全部
- **风险**: 低

### `tools/perf-test-v7.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P0
- **改动内容**: P0 验证脚本:基于 `log_simulator.py` 改 3 个量级压测
- **依赖**: `log_simulator.py`
- **风险**: 低

### `tools/perf-test-v8.py` *(新增)*
- **类型**: 新增
- **所属阶段**: P1
- **改动内容**: P1 验证脚本:3 数量级 + 5min 稳态 + 多维指标(plan.md §7.4)
- **依赖**: `tools/perf-test-v7.py`
- **风险**: 低

### `README.md`
- **类型**: 修改
- **所属阶段**: P0
- **改动内容**: 更新性能数据(从"勉强 20 req/s" → "P0 末 30 req/s,P1 末 80 req/s");加 SLO 章节链接到 `docs/slo/`
- **依赖**: `docs/performance/plan.md`
- **风险**: 低

### `CHANGELOG.md` *(如不存在则新增)*
- **类型**: 修改 / 新增
- **所属阶段**: P0
- **改动内容**: 加 v1.1 / v1.2 / v2.0 性能改造记录
- **依赖**: 全部
- **风险**: 低

### `.env.example` *(如不存在则新增)*
- **类型**: 修改 / 新增
- **所属阶段**: P0
- **改动内容**: 加新 env 变量示例:
  - `SHARED_MEMORY_SSH_POOL_SIZE=5`
  - `SHARED_MEMORY_LLM_DAILY_BUDGET_MODE=hard`
  - `SHARED_MEMORY_FW_AUTO_RECONCILE=true`
  - `SHARED_MEMORY_TEMPORAL_CONCURRENCY=30`
  - `SHARED_MEMORY_LLM_AUDIT_DEDUP_TTL=7`
- **依赖**: 全部 P0/P1
- **风险**: 低

### `docker-compose.yml`(P2 再次大改)
- **类型**: 修改
- **所属阶段**: P2
- **改动内容**:
  1. 加 `response-engine` service(`backend/response_engine/server.py`)
  2. 加 `celery-worker` + `celery-beat` service
  3. backend 缩为 ingest + audit + observability
- **依赖**: `backend/response_engine/server.py`、`backend/queue/`
- **风险**: 高

---

## 总览统计

### 按阶段

| 阶段 | 新增 | 修改 | 删除 | 合计 |
|------|------|------|------|------|
| P0 紧急 | 4 | 16 | 0 | 20 |
| P1 中期 | 9 | 13 | 0 | 22 |
| P2 长期 | 14 | 4 | 0 | 18 |
| **合计** | **27** | **33** | **0** | **60** |

> 注: 同一文件跨阶段被修改时,只在最早阶段列(P0 优先),后续阶段只在该文件 P0 条目中注明"依赖 P1-X 改动"。这样避免重复。
>
> 修正: v1 初稿我数错为 38,实际含跨阶段 + 新增目录 60 个。如用户希望"去重后净文件数",请告知,我可以整理。

### 按类型

| 类型 | 数量 | 占比 |
|------|------|------|
| 修改 | 33 | 55% |
| 新增 | 27 | 45% |
| 删除 | 0 | 0% |

### 按目录

| 目录 | 文件数 |
|------|--------|
| `backend/response_engine/` | 8 |
| `backend/temporal/` | 3 |
| `backend/agents/` | 2 |
| `backend/` (根 + 顶层) | 9 |
| `backend/tests/` | 5 |
| `config/suricata/` | 2 |
| `docs/` | 6 |
| `flink-jobs/` | 1 |
| `infrastructure/chaos/` | 5 |
| `monitoring/grafana/` | 1 |
| `monitoring/prometheus/` | 1 |
| `tools/` | 4 |
| `docker-compose.yml` | 1(跨阶段) |
| 根目录 | 2(README, CHANGELOG) |
| `.env.example` | 1 |

---

## 修改优先级

1. **第一周(必须)**:P0 全部 20 个文件,优先 P0-2(快速见效) + P0-1(Temporal 调并发) + P0-3/4(状态一致)
2. **第二周**:P0-5(Suricata) + P0-6(LLM 预算) + P0-7(threat_type) + P0-8(HTTP 429)
3. **第三-四周**:P1 全部 22 个文件
4. **P2 起**:季度节奏,不在 sprint 范畴

---

## 不修改的(明确划线)

以下文件**不**在本次性能改造范围:

- `flink-jobs/src/main/java/.../LogValidationJob.java`(验证+去重,已 OK)
- `frontend/`(前端不在性能范围)
- `tools/windows-log-collector.ps1`(只在 P0-5 验证 win 攻击流量,本身不改)
- `init.sql`(DB schema 不变)
- `backend/veto_gates.py`、`backend/faithfulness_gate.py`(纯函数,已 OK)
- `backend/cad.py`(CAD 已有 circuit_breaker)
- `backend/mcp_guard/`(P2 单独处理,且目前路径不通)

---

**v1 文件清单总结**:60 个文件,跨 3 个阶段,从"调配置"到"重架构"渐进。**P0 全部 1-2 周可完成**,见效快(完成率从 10% → 40%)。P1 是真正的工程量,P2 是季度工作。
