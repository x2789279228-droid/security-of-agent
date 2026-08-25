# 03 · 后端核心模块

> Backend 是一个 FastAPI 应用，但**远不止 CRUD**。
> 这一章按"职责域"把后端 25+ 子模块串成 8 个簇，每簇讲清"做什么、关键类、如何被调"。

---

## 后端目录速览

```
backend/
├── app.py                          ← FastAPI 主入口（13 个 router，~179 端点）
├── config.py                       ← 配置中心（从 .env 读取）
├── models.py                       ← SQLAlchemy ORM
├── event_store.py                  ← 事件存取（增删改查、批量）
├── kafka_consumer.py               ← 消费 3 个 topic
├── kafka_producer.py               ← 审计结果回写 Kafka
├── log_ingestion.py                ← 日志接入 + 自动审计 + 自动响应入口
├── anomaly_detector.py             ← Python 侧异常检测（HTTP 模式兜底）
├── correlation_engine.py           ← 攻击链关联（Python 侧兜底）
├── event_bus.py                    ← 实时事件总线（SSE）
│
├── agents/                         ← Audit-LLM 四层 + CAD
│   ├── base.py                     ← LLM 客户端封装
│   ├── chunker.py                  ← 上下文分块
│   ├── agent_decomposer.py         ← ① 拆解
│   ├── agent_tool_builder.py       ← ② 拼工具
│   ├── agent_executor.py           ← ③ 执行（最大）
│   ├── agent_reviewer.py           ← ④ 复核
│   ├── sub_auditor.py              ← 平行子审计
│   ├── agent_a.py / b / c / d.py   ← 4 类审计员（分析/决策/报告/归档）
│   └── agent_cad.py                ← 独立监督（调 cad.py）
│
├── cad.py                          ← 穿透验证 + 上下文审计 + 熔断器
├── grounding_verifier.py           ← 反幻觉（3 层）
│
├── response_engine/                ← 响应引擎
│   ├── response_orchestrator.py    ← 主入口
│   ├── response_policies.py        ← 8 条策略
│   ├── response_executor.py        ← 动作执行
│   ├── response_registry.py        ← 动作注册表
│   ├── response_log.py             ← 响应日志
│   ├── human_approval.py           ← 审批队列
│   ├── safe_executor.py            ← 二次安全校验
│   ├── command_whitelist.py        ← 命令白名单
│   ├── asset_whitelist.py          ← 资产白名单
│   ├── execution_modes.py          ← 执行模式分级
│   ├── post_validator.py           ← 执行后校验
│   ├── ttl_manager.py              ← 临时封禁 TTL
│   ├── ssh_firewall.py             ← 防火墙执行
│   └── transport.py                ← 跨平台传输抽象
│
├── sigma_engine/                   ← Sigma 规则引擎
│   ├── engine.py                   ← pySigma 封装
│   ├── store.py                    ← 规则 CRUD（YAML）
│   ├── mapping.py                  ← 字段映射
│   ├── backend_keywords.py         ← 关键词搜索后端
│   ├── rules/SIG-001..011.yml      ← 内置规则
│   ├── rules_community_active/     ← 灰度规则
│   └── tools/dry_run_import.py     ← 社区规则导入
│
├── rag/                            ← RAG 知识库
│   ├── retriever.py                ← 检索 + LLM 重排
│   ├── seeder.py                   ← MITRE/CAPEC 导入
│   ├── knowledge_base.py           ← 知识库管理
│   ├── chunker.py                  ← 文档分块
│   ├── context_builder.py          ← 上下文拼装
│   ├── evidence_verifier.py        ← 证据验证
│   ├── mitre_importer.py           ← MITRE ATT&CK
│   └── capec_importer.py           ← CAPEC
│
├── mcp_guard/                      ← 工具调用 4 层检查
│   ├── guard_server.py             ← 入口
│   ├── tool_registry.py            ← 白名单
│   ├── permission_manager.py       ← RBAC
│   ├── validator.py                ← Pydantic 校验
│   ├── policy_engine.py            ← 规则引擎
│   ├── call_logger.py              ← 调用审计
│   └── approval_queue.py           ← 审批
│
├── security_guard/                 ← 调用安全守卫
│   ├── security_guard.py           ← 主入口
│   ├── intent_checker.py           ← 意图审查
│   ├── sequence_guard.py           ← 序列管控
│   ├── rate_limiter.py             ← 频率限制
│   └── context_manager.py          ← 上下文感知
│
├── stabilizer/                     ← LLM 输出稳定化
│   ├── stabilizer.py               ← 编排器
│   ├── json_repair.py              ← JSON 容错
│   ├── tool_resolver.py            ← 工具名归一
│   ├── param_coercer.py            ← 参数强转
│   └── models.py                   ← 数据类
│
├── temporal/                       ← Temporal 工作流（可选启用）
│   ├── client.py
│   ├── workflows.py
│   ├── activities.py
│   └── worker.py
│
├── observability/                  ← 可观测性
│   ├── pipeline_tracer.py          ← trace_id 贯穿
│   ├── health_monitor.py           ← 健康监控
│   └── watchdog.py                 ← 看门狗
│
├── threat_intel/                   ← 威胁情报
├── traffic_capture/                ← NDR 抓包
├── traffic_baseline/               ← 流量基线
├── encrypted_traffic/              ← 加密流量分析
├── edr_fusion/                     ← EDR 融合
├── zeroday_detect/                 ← 0day 沙箱
├── phishing_guard/                 ← 反钓鱼
├── ids_connector/                  ← IDS 对接
├── session_reconstruct/            ← 会话重建
├── event_archive/                  ← 事件归档
├── data_security/                  ← 敏感字段加密
├── asset/                          ← 资产管理
├── ops_metrics/                    ← 运营指标
├── prompts/                        ← LLM 提示词（46 个 .j2）
└── routers/                        ← FastAPI 路由
    ├── auth.py
    ├── logs.py
    ├── chat.py
    ├── audit.py
    ├── response.py
    ├── ops.py           ← 运营 (38K，最大)
    ├── rag.py
    ├── kafka.py
    ├── sources.py
    ├── assets.py
    ├── capabilities.py
    ├── ndr.py
    ├── edr_intel.py
    ├── phishing.py
    └── ...
```

---

## 簇 1：入口与基础设施

### `app.py` — FastAPI 主入口

**职责**：注册所有路由、启动 Kafka 消费者、初始化全局组件、挂中间件。

**关键中间件**（按顺序）：
1. CORS（白名单 `.env`）
2. 全局认证（除 `/api/auth/login`、`/api/health`、SSE 之外的路径）
3. 限流（120 次/分钟 IP 级，基于内存 dict → 多副本需改 Redis）
4. 安全响应头（CSP / X-Frame-Options / HSTS）

**启动流程**：
```python
@asynccontextmanager
async def lifespan(app):
    # 1. 启动 Kafka 消费 (后台 task)
    # 2. 启动 watchdog
    # 3. 按开关 import NDR/EDR/Phishing/...
    yield
    # 关闭时优雅停 Kafka
```

### `config.py` — 配置中心

- 全部配置从 `.env` 读，Pydantic Settings
- 关键开关：`sigma_engine`、`qdrant_enabled`、`capture_enabled`、`edr_enabled`、`sandbox_enabled`、`phishing_enabled`
- 安全相关：JWT 过期、限流阈值、CORS 白名单

### `models.py` — ORM

SQLAlchemy 2.x 异步，对应 `init.sql`：
- SecurityEvent（事件主表）
- Memory / Conversation（记忆与对话）
- ResponseLog（响应日志）
- Case / WorkOrder（工单与案例）
- Asset（资产）

---

## 簇 2：事件接入与 Kafka

### `log_ingestion.py` — 日志接入门面

**两条入口**：
- HTTP: `POST /api/logs/ingest`（demo / 单测用）
- Kafka: `kafka_consumer._handle_enriched()`（生产）

**核心方法 `_audit_pipeline(event)`**（自动审计）：
```
1. Sigma 快速检测 → 命中则可能直接走快路径
2. 异常评分（如未在 Flink 阶段算过）
3. 写 RAG 检索（拿相似案例与 MITRE 技术）
4. 启动 Audit-LLM 4 层流水线
5. CAD 监督
6. 根据结论决定是否走响应
```

### `kafka_consumer.py` — Kafka 消费

订阅 3 个 topic（`security-events-enriched` / `security-audit-queue` / `security-alerts`），分别走 3 个 handler。

**关键修复**（2026-08-23）：`_handle_enriched` 增加对"高严重事件也排队审计"的逻辑，详见 [02 数据流]。

### `event_bus.py` — 实时事件总线

基于 asyncio.Queue + SSE，把后端事件推到前端。供 `/api/events/stream` 订阅。

### `event_store.py` — 事件存取

封装了 `get_unreviewed_anomalies()`（用 anomaly_score 独立列过滤，避免低分淹没）等查询。

---

## 簇 3：Audit-LLM 4 层 + CAD

这是后端最大、最复杂的一块，单独写一章都不过分。这里只给总览。

```
log_ingestion._audit_pipeline(event)
   │
   ├─ ① Decomposer (agent_decomposer.py:14261 字节)
   │   · 拆解事件为子问题（攻击类型/影响/紧急度）
   │   · 输出: structured_subproblems[]
   │
   ├─ ② ToolBuilder (agent_tool_builder.py:6194 字节)
   │   · 决定调哪些工具
   │   · 工具: rag.search / sigma.detect / asset.query / case.search
   │   · 输出: tool_plan[]
   │
   ├─ ③ Executor (agent_executor.py:29905 字节，最大)
   │   · 实际调用工具（经 Stabilizer + MCP Guard + SecurityGuard）
   │   · 输出: tool_results[]
   │
   ├─ ④ Reviewer (agent_reviewer.py:7929 字节)
   │   · 复盘: 是否遗漏/幻觉
   │   · 输出: final_verdict + confidence + actions
   │
   └─ Sub-Auditor (sub_auditor.py:11765 字节)
       · 平行多视角审计
       · 与主流水线结果交叉验证
```

### `agent_cad.py` — 独立监督

不在流水线内，作为外部监督者：
```python
cad.audit_pipeline(event_id, audit_llm_data)
   ├─ verifier.verify_claims(evidence_trail)  # 穿透验证
   ├─ 算 hallucination_risk / evidence_completeness
   ├─ circuit_breaker.record_audit_result()
   └─ 写 cad_reports
```

### `cad.py` — 穿透验证与熔断

```python
class Verifier:
    async def verify_claims(...) -> List[VerificationReport]:
        # 对 LLM 声明的"某 evidence 来自某源"做反向验证

class ContextAuditor:
    # 上下文级风险审计（每小时跑一次）

class CircuitBreaker:
    # 累计 hallucination_risk, 超阈值熔断
```

---

## 簇 4：响应引擎

13 个子模块协作，把"决定做什么"变成"实际去做什么"。

### 决策链

```
response_orchestrator.on_threat_detected(threat)
   ↓
1. policy_engine.match() → 8 条预置策略
   策略: 端口扫描→封禁 30min
        SSH 暴力破解→临时封禁 1h
        C2 信标→立刻封禁 24h
        数据外泄→告警+等审批
        ...
   ↓
2. 决策: needs_approval?
   ↓ 是 ↓
   human_approval.submit(actions) → 写工单
   ↓ 否 ↓
3. security_guard.inspect(action_name, threat) → allow/deny
   ↓ allow ↓
4. response_executor.execute_actions(actions)
   ├─ command_whitelist 校验命令
   ├─ asset_whitelist 校验目标
   ├─ execution_modes 决定 mode (auto/soft/dry-run)
   ├─ safe_executor 二次校验
   ├─ ssh_firewall / transport 真实执行
   ├─ post_validator 校验结果
   └─ ttl_manager 安排过期回收
   ↓
5. 写 response_logs (含 rollback_token)
```

### 关键模块速记

| 模块 | 一句话 | 关键方法 |
|------|--------|----------|
| `response_orchestrator` | 主入口 | `on_threat_detected` |
| `response_policies` | 8 条预置策略 | `match()` |
| `human_approval` | 审批工单 | `submit / decide` |
| `response_executor` | 执行 | `execute_actions` |
| `command_whitelist` | 命令白名单 | `is_allowed(cmd)` |
| `asset_whitelist` | 资产白名单 | `is_target_allowed(ip)` |
| `execution_modes` | 模式分级 | `mode_for(severity)` |
| `safe_executor` | 二次校验 | `safe_run()` |
| `ssh_firewall` | SSH 防火墙 | `block_ip / unblock` |
| `transport` | 跨平台传输 | Windows/Linux 适配 |
| `post_validator` | 执行后校验 | `validate(result)` |
| `ttl_manager` | TTL 回收 | `schedule_expiry` |
| `response_log` | 日志 | `record(action, result)` |

### 设计哲学

- **不要把"执行"和"决策"放在同一个模块**：决策可测试、可审计；执行易出错、要二次校验
- **每个动作都有 rollback_token**：出问题可按 token 反向撤销
- **command/asset 双重白名单**：白名单是兜底而非主防线（防 LLM 拼出 `"iptables; rm -rf /"`）

---

## 簇 5：Sigma 规则引擎

代码：`backend/sigma_engine/`

**设计目标**：用社区标准 Sigma 规则（YAML），避免每个项目都重写"如果…就…"

**架构**：
```
PySigmaDetector
   ├─ SigmaCollection.load_ruleset(rules_dir)
   ├─ SQLiteBackend.convert_rule(rule) → SQL 谓词
   ├─ 把每条事件插入内存 SQLite 临时表
   └─ 用 SQL 谓词求值，命中则返回
```

**两种模式**：
- `pySigma` 模式（默认）：真 Sigma 规则，可与社区 3000+ 规则互通
- `legacy` 模式：内置 11 条 Python 字典规则，pySigma 不可用时降级

**内置规则**：`backend/sigma_engine/rules/SIG-001..011.yml`，覆盖：
- 登录爆破、路径遍历、SQL 注入、Webshell、XSS、SSRF、命令注入、异常外发、可疑进程、横向移动、权限提升

**字段桥接**：平台事件字段 → Sigma 字段（FIELD_MAP in `engine.py:59`）

---

## 簇 6：RAG 知识库

代码：`backend/rag/`

**目标**：让 LLM 审计时能拿到"权威背景"（MITRE 战术、CAPEC 攻击模式、案例库）

**架构**：
```
RAG.retrieve(query)
   ├─ 1. embed(query) → 向量
   ├─ 2. Qdrant.search(vector, top_k=20)  # 默认向量库
   │     兜底: pgvector.search()
   ├─ 3. LLM 重排(rerank) → top 5
   ├─ 4. context_builder.build() → 给 LLM 的提示词
   └─ 5. evidence_verifier.verify() → 断言每条检索结果可信
```

**导入器**：
- `mitre_importer.py`：从 STIX bundle 导入 MITRE ATT&CK
- `capec_importer.py`：导入 CAPEC 攻击模式
- `seeder.py`：统一的批量导入工具（支持去重、增量）

**关键设计**：
- Qdrant 优先 + pgvector 兜底（`qdrant_enabled=True` 默认）
- Agent 记忆与 RAG 知识库**分两个 collection**（`agent_memories` vs `mitre_techniques`）
- 检索结果会做 evidence_verifier 断言，**有依据才能进入 LLM 提示词**

---

## 簇 7：自审计 5 道闸

| 闸 | 模块 | 防什么 | 触发位置 |
|----|------|--------|----------|
| **MCP Guard** | `mcp_guard/` | LLM 调幻觉工具/越权 | 每次 LLM 工具调用 |
| **Stabilizer** | `stabilizer/` | LLM 输出 JSON 烂/工具名错 | LLM 原始输出之后 |
| **SecurityGuard** | `security_guard/` | 重复调/危险意图/超频率 | 每个 action 执行前 |
| **Grounding Verifier** | `grounding_verifier.py` | LLM 证据幻觉 | LLM 返回结论时 |
| **CAD** | `agents/agent_cad.py` | 整条流水线结论不可信 | 流水线完成后 |

> 详细设计见 [05 自审计体系]。

---

## 簇 8：可观测性

| 模块 | 职责 | 端点 |
|------|------|------|
| `pipeline_tracer.py` | trace_id 贯穿，OTel span | 写入 Tempo |
| `health_monitor.py` | 各组件健康探活 | `/api/health` |
| `watchdog.py` | 关键 task 挂掉自动拉起 | 后台 |
| `event_bus.py` | SSE 实时推送 | `/api/events/stream` |

**可观测性三层**：
- 指标（Metrics）：Flink 自带 Counter/Gauge；Backend 用 Prometheus client
- 日志（Logs）：结构化 JSON，`backend/logs/`
- 链路（Traces）：OTel → Tempo

---

## 簇 9：可对接能力（默认关）

| 能力 | 子目录 | 开关 | 测试 |
|------|--------|------|------|
| NDR 流量 | `traffic_capture/` | `capture_enabled` | `tests/test_inc_ndr.py` |
| 加密流量 | `encrypted_traffic/` | (随 NDR) | 同上 |
| EDR 融合 | `edr_fusion/` | `edr_enabled` | `tests/test_inc_edr.py` |
| 威胁情报 | `threat_intel/` | `intel_enabled` | `tests/test_inc_threat_intel.py` |
| 0day 沙箱 | `zeroday_detect/` | `sandbox_enabled` | `tests/test_inc_zeroday.py` |
| 反钓鱼 | `phishing_guard/` | `llm_phishing_enabled` | `tests/test_inc_phishing.py` |
| IDS 对接 | `ids_connector/` | (随 EDR) | — |
| 资产管理 | `asset/` | 默认开 | `tests/` |
| 字段加密 | `data_security/` | 默认开 | `tests/` |
| 复盘分析 | `post_mortem_service.py` | 默认开 | — |
| 反馈闭环 | `feedback_loop.py` | 默认开 | — |

详见 `docs/advanced_capabilities.md`。

---

## 簇 10：Temporal 工作流（可选）

`backend/temporal/` 提供**长时间、可中断、可恢复**的工作流编排（用于复杂多步审计/响应）。

- 默认未启用
- 启用需在 `config.py` 配 Temporal server
- 适合"封禁→等 1 小时观察→再封禁→再观察"这种链式动作

---

## 测试组织

```
backend/tests/
├── conftest.py             ← pytest fixture
├── inc_mock_servers.py     ← mock 外部 HTTP (CAPE/MISP/TAXII)
├── inc_testcases.py        ← 共享测试数据
├── test_arch_unification.py
├── test_case_lifecycle.py
├── test_inc_*.py           ← 可对接能力的离线测试
├── test_log_normalize_http.py
├── test_observability.py
├── test_p0_ops_modules.py
├── test_prompts_integrity.py   ← 提示词模板完整性
├── test_safe_executor.py
├── test_security_audit_fixes.py
├── test_token_cost.py
├── test_trace_otel.py
├── test_vector_store_qdrant.py
└── test_llm_enhancers.py
```

最新全量通过数：**232+ passed**（含修复 Qdrant/pySigma/Prompts 后的扩展）。

---

## 上一章

> [02 数据流与事件生命周期](./02-data-flow.md)

---

## 下一章

- 想看 Flink 怎么写 Java 流处理：→ [04 Flink 流处理作业]
- 想看 5 道闸怎么用：→ [05 自审计体系]
- 想看前端怎么展示：→ [06 前端架构与页面]


---

## 动手点

1. **找一次响应执行**：
   ```bash
   # 触发一条 C2 告警
   # 查 response_logs 表
   curl http://localhost:8001/api/response/logs
   # 看 rollback_token，记下来后可尝试 rollback
   curl -X POST http://localhost:8001/api/response/rollback/<token>
   ```

2. **改一条 Sigma 规则**：
   ```bash
   # 编辑 backend/sigma_engine/rules/SIG-001.yml
   # 调高 detection 阈值
   # 触发 reload（toggle 内部会 reload）
   curl -X POST http://localhost:8001/api/ops/rules/sigma/SIG-001/toggle
   # 注入新事件验证
   ```

3. **看 LLM 调了几次工具**：
   ```bash
   # 调用审计
   curl -X POST http://localhost:8001/api/guard/call -d '{...}'
   # 看到 decision=allow/deny/require_confirmation
   ```
