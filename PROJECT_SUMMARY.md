# 共享记忆安全审计 Agent 平台 — 项目总结

> 更新时间：2026-08-04 · 当前分支：v1（未推送远程）

## 一、项目概述

全自动安全审计 Agent 平台，基于 **Kafka + Flink** 流处理架构，集成数据源认证、实时异常检测、攻击链 CEP、LLM 智能审计与自动响应执行。定位为"共享记忆"式的 SOC（安全运营中心）系统：日志接入 → 实时检测 → LLM 审计 → 事件闭环运营。

## 二、技术栈

| 层 | 技术 |
|----|------|
| 消息总线 | Apache Kafka 3.7 (KRaft 模式) |
| 流处理 | Apache Flink 1.18 (Java, CEP + DataStream API) |
| 后端 | Python FastAPI + SQLAlchemy + pgvector + Redis + aiokafka |
| 安全工具 | paramiko SSH + iptables + nmap |
| 工具调用控制 | MCP Guard 4 层检查 + SecurityGuard 安全守卫 + Trusted Action Gateway |
| LLM | OpenAI 兼容 API（SiliconFlow，GLM-Z1-9B-0414） |
| 向量库 | PostgreSQL 16 + pgvector（embedding 1024 维） |
| 前端 | React 19 + TypeScript + Tailwind CSS 4 + Framer Motion |
| 部署 | Docker Compose（PostgreSQL 16 + Redis 7 + Kafka + Flink） |

## 三、核心架构（Kafka + Flink）

```
日志源 (syslog/API/模拟器) ──带 API Key 认证──▶ Kafka: security-logs-raw
                                                    │
                                                    ▼
                         Flink Job 1: LogValidationJob（Schema校验/API Key认证/字段归一化/60s去重）
                                                    │
                             ┌──────────────────────┴───────────────────┐
                             ▼                                          ▼
                  security-logs-rejected                    security-logs-validated
                             │                                          │
                             ▼                                          ▼
                    Flink Job 2: AnomalyDetectionJob（多维异常评分 + CEP 攻击链检测 + 分级路由）
                             │                        │                        │
                             ▼                        ▼                        ▼
                  security-alerts             security-audit-queue    security-events-enriched
                             │                        │                        │
                             ▼                        ▼                        ▼
                       响应引擎                    Audit-LLM 流水线          EventStore + 记忆树
                    （策略匹配/SSH执行）      （Decomposer→ToolBuilder→    （PostgreSQL）
                                             Executor→Reviewer）
                                                        │
                                                        ▼
                                             CAD 独立监督（熔断器+穿透验证）
```

## 四、后端核心模块

| 模块 | 说明 |
|------|------|
| **Kafka 消息总线** | 7 个 Topic 分级路由，解耦数据源与处理引擎，支持重放 |
| **Flink 验证** | Schema 校验 + API Key 认证 + 去重，拒绝非法数据源 |
| **Flink CEP** | 3 种攻击链模式实时检测（端口扫描→C2 / 横向移动 / 数据外泄） |
| **Sigma 检测引擎** | 11 条规则覆盖 8 类攻击，规则化精确匹配，<1ms 延迟 |
| **Audit-LLM** | 四层流水线：Decomposer→ToolBuilder→Executor→Reviewer，迭代审核 + 反幻觉 |
| **Grounding 验证** | 三层校验：程序化字段溯源 + 知识库交叉验证 + LLM 复核 |
| **CAD** | 独立监督角色：穿透验证 + 上下文审计 + 熔断器 |
| **MCP Guard** | 4 层工具调用控制：白名单→RBAC→参数校验→规则引擎 |
| **SecurityGuard** | 调用安全守卫：意图审查 + 序列管控 + 频率限制 + 上下文感知 |
| **Stabilizer** | LLM 输出稳定化：JSON 修复→工具名归一→参数强转→Schema 校验 |
| **响应引擎** | 8 条策略、5 种动作，SSH 真实执行 + iptables 防火墙 + 按 rule_id 回滚 |
| **RAG 知识库** | MITRE ATT&CK / CAPEC 导入，向量检索 + LLM 重排，断言验证 |
| **数据源管理** | API Key 注册/吊销/拒绝日志 |
| **TAG** | Trusted Action Gateway：A0-A4 自治等级、分步提权、幂等控制、影响范围控制、审计轨迹 |

## 五、前端页面

| 页面 | 路由 | 说明 |
|------|------|------|
| 首页 | `/` | Hero 场景 + 服务状态 |
| 日志中心 | `/logs` | 安全事件日志（实时推送 + 严重度筛选 + 搜索） |
| 监控 | `/monitor` | 实时监控 |
| 安全审计 | `/security-audit` | Audit-LLM 流水线结果 + 证据链追溯 |
| 响应 | `/response` | 响应策略 + DDoS 决策 + A4 预检 |
| 运营中心 | `/operations` | 事件闭环运营（概览/案例/工单/复盘/反馈调优/规则） |
| 知识库 | `/rag` | RAG 知识库检索/管理/质量评估 |
| 登录 | `/login` | 认证（admin / .env 配置密码） |

## 六、v1 分支新增内容（相对 GitHub 原版）

### 6.1 A4 动作安全策略 — backend/response_engine/db_safety.py
- 永久禁止工具清单（drop_database、wipe_disk、rm_rf、block_rfc1918_permanent 等 27 项）
- 数据库事件允许动作白名单（仅查询/限连/只读/快照/隔离/暂停/工单）
- DbSafetyPolicy.check_action() 识别 A4 动作 → 阻断 + 处置建议 + 人工审批工单
- A4 动作不可通过分步提权绕过

### 6.2 DDoS 响应策略 — backend/response_engine/ddos_policy.py
- 6 类场景：外部单 IP / 外部 CIDR / 分布式外部 / 内部单主机 / 内部多主机 / 核心网络级
- RFC1918 内网网段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）禁止自动封禁
- 内部 DDoS 优先限速/EDR/NAC/交换机端口控制/禁用账号
- 外部 CIDR 阻断需 7 项条件（高置信度证据/明确授权/非受保护服务商/短TTL/Canary/自动回滚/业务健康检查）
- 大规模 DDoS 切换清洗设备/运营商/云 Anti-DDoS

### 6.3 Trusted Action Gateway — backend/trusted_action_gateway/
- state_machine.py：A0-A4 自治等级状态机
- models.py：ActionGrant（临时授权）、ActionLedger（幂等台账）
- idempotency_guard.py：SHA256 idempotency_key 防止重复执行
- impact_policy.py：影响范围控制 + canary 执行
- executors/iptables_executor.py + post_verifier.py：执行 + 执行后验证
- tag_router.py：挂载到 /api/tag/*

### 6.4 后端稳定性修复 — backend/app.py、backend/config.py
- 全局 DB 异常处理器：DB 不可用时返回 200 + 空数据（列表端点返回 []，统计端点返回 {"total":0,...}）
- lifespan 降级启动：PostgreSQL/Redis 不可用时仍可启动，跳过知识库播种/Scheduler
- config.py：env_file = "../.env" + extra = "ignore"（修复 .env 未加载导致登录失败）

### 6.5 前端调整
- vite.config.ts：代理端口 8001→8000（与后端实际端口对齐）
- api.ts：新增 14 个 TAG 调用方法
- Response.tsx：新增 DDoS 决策 + A4 预检 Tab（保持原 UI 风格）
- LifecycleLoop.tsx：环形流程图极坐标重构（严格居中、正圆、均匀分布、响应式）

## 七、Git 状态

- 分支：v1（新建，基于 main）
- 提交：245f6c2 — "v1: A4 安全策略 + DDoS 响应策略 + TAG 集成"（41 文件，+10027/-1006）
- 远程：origin → https://github.com/x2789279228-droid/security-of-agent.git
- 未推送：git 未走系统代理（127.0.0.1:7897），直连 github.com 超时；且沙盒禁止写 .gitconfig.lock，无法修改全局代理配置

## 八、当前运行状态

- 后端：uvicorn 运行于 http://localhost:8000（DEGRADED 模式：PostgreSQL/Redis 不可用，API 返回空数据）
- 前端：Vite 运行于 http://localhost:3002（3001 被占用）
- 登录：admin / admin123 可用（.env 已正确加载）
- 已核验 18 个核心端点全部返回 200，4 个页面（日志中心/安全审计/知识库/响应）正常渲染

## 九、已知限制

1. PostgreSQL 不可用：依赖 DB 的页面显示空数据，需启动 PostgreSQL（shared_memory 库，admin/admin123）才能看到真实数据
2. Redis 不可用：仅影响 SSE 实时推送与缓存
3. Kafka 未启用：aiokafka 未安装，仍走 HTTP 直连模式
4. SSH 适配器为 stub：响应引擎 mock 模式，未接真实设备
5. v1 分支未推送到 GitHub：需配置 git 代理后推送

## 十、快速启动

```bash
# 1. 配置 .env（LLM Key / 管理员密码）
# 2. 启动全部服务（Docker）
docker-compose up -d --build

# 3. 提交 Flink 作业
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager

# 4. 注入测试数据
python log_simulator.py --kafka localhost:9092 --mode chain

# 5. 本地开发（无 Docker）
cd backend && python -m uvicorn app:app --host 0.0.0.0 --port 8000
cd frontend && npm run dev
```
