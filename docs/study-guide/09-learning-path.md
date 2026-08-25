# 09 · 推荐学习路径

> 不同角色、不同目的，推荐的路径不一样。
> 这一章给三套路径：**理解 / 改它 / 讲它**。

---

## 路径 A：理解（4-8 小时）

目标：能在 5 分钟内向人介绍"这个项目做什么"。

```
0. 跑起来（30 min）
   - docker compose up -d --build
   - 打开前端 4 个页面
   - 注入攻击链看效果
   ↓
1. [00 项目地图] 30 min
   ↓
2. [01 架构] 1 h
   - 重点理解 5 层职责
   ↓
3. [02 数据流] 1 h
   - 重点理解 7 个 topic
   ↓
4. 看一次 [10 FAQ] 30 min
   ↓
5. 动手：
   - 注入一次攻击链，前端追到响应执行
   - 改一条 Sigma 规则看 reload
   ↓
[已读 4.5 小时] 目标：能讲清项目做什么、怎么做到的
```

---

## 路径 B：改它（3-7 天）

目标：能独立加一个模块 / 修一个 bug / 提交 PR。

```
路径 A 完成
   ↓
6. [03 后端模块] 1 天
   - 重点读 audit/response/sigma/rag/mcp_guard/security_guard 六个
   ↓
7. [04 Flink 作业] 半天
   - 重点读 LogValidationJob 与 AnomalyDetectionJob
   ↓
8. [05 自审计体系] 半天
   - 重点理解 5 道闸的协作
   ↓
9. [07 数据模型] 半天
   - 跑 SQL 查表
   ↓
10. [06 前端] 1 h
    - 改个标题、加个统计卡片
    ↓
11. 实战（2 天）：
    - 选项 1：加一条 Sigma 规则
    - 选项 2：加一个反钓鱼检测器
    - 选项 3：加一条 CEP 攻击链
    - 选项 4：写一个端到端测试
    ↓
[已读 5 天] 目标：能独立提交 PR
```

---

## 路径 C：讲它（半天，针对评委）

目标：3 分钟讲亮点 + 现场 demo + 答辩问答。

```
1. 准备 3 分钟开场（参考下面的"亮点清单"）
   ↓
2. 准备 5 分钟 demo：
   - 注入攻击链 → 看前端实时
   - 看 LLM 审计 4 层 → 看 CAD 监督
   - 看响应执行 + 真实防火墙
   - 看自审计：故意让 LLM 调危险工具被拒
   ↓
3. 准备 2 分钟结尾（架构 + 安全自审计设计哲学）
   ↓
4. 准备 5 分钟问答预案（参考下面的"易被问到"）
   ↓
5. 现场跑一遍（提前一天部署，备好降级方案）
```

### 亮点清单（按评委喜好排序）

1. **真流处理架构**（Kafka + Flink）— 区别于"单 LLM Agent"
2. **LLM 4 层 + CAD 监督**（反幻觉）— 不是"让 LLM 自己审自己"
3. **5 道安全闸**（Guard / Stabilizer / SecurityGuard / Grounding / CAD）— 平台自身安全
4. **真实执行**（iptables / netsh / paramiko）— 不是模拟
5. **审计链路可追**（trace_id 贯穿）— 不是黑盒
6. **社区标准**（Sigma / MITRE / STIX）— 不是造轮子
7. **可离线测试**（`tests/test_inc_*.py`）— 不是 PPT 项目

### 易被问到的问题预案

**Q：和传统 SIEM 区别？**
A：SIEM 强在检索与合规；本平台强在"AI 原生 + 自审计"。SIEM 不会拦 LLM 幻觉，我们有 5 道闸。

**Q：LLM 幻觉怎么办？**
A：4 层流水线（拆解→工具→执行→复核）+ CAD 独立监督（穿透验证，不信 LLM 汇报）+ Grounding 3 层校验。

**Q：响应执行错了怎么办？**
A：双重白名单（命令/资产）+ 执行后校验 + TTL 自动回收 + 按 rollback_token 一键回滚。

**Q：性能？**
A：Flink Kafka EXACTLY_ONCE，秒级延迟；Backend 异步 + 限流；Redis 缓存热数据。

**Q：怎么扩展能力？**
A：3 个开关位：`config.py` + `routers/<feature>.py` + 后台 `start()/stop()`。

**Q：和 v1.3.0 区别？**
A：v1.3.0 是 MCP 控制网关（4 层 Guard）；本平台是完整 SOC 平台，**集成**了 v1.3.0 的 Guard 作为安全中间件。
详细见 `D:\揭榜挂帅\v1.3.0_vs_platform_对比分析.md`。

**Q：成本？**
A：单机 8C16G 可跑 demo；生产 16C32G × 3 节点。LLM API 按调用计费，控频后可预估。

**Q：合规？**
A：审计 trail 全留；字段加密落库；JWT + RBAC；CORS / CSP / HSTS 头齐；详细见 `README.md` 安全加固章节。

**Q：依赖了哪些外部服务？**
A：默认全本地（PG/Redis/Kafka/Flink）。NDR/EDR/沙箱/威胁情报/反钓鱼等可对接能力需外部，按需启用。

**Q：会不会被 prompt 注入攻击？**
A：是的。所以有 5 道闸，prompt 注入只能在最坏情况下让 LLM 调一个**已注册且 RBAC 通过**的工具。真正的危险操作（删除规则、关防火墙）要么白名单拦截、要么人工审批。

---

## 路径 D：系统重塑（2-4 周，针对改造者）

目标：把它拆成可独立部署的多个服务，或反过来整合更多能力。

```
1. 路径 B 完成
   ↓
2. [04 Flink 作业] 深入读 — 准备拆分或新增作业
   ↓
3. [08 部署] 深入读 — 准备多副本 / HA 改造
   ↓
4. 看 `.github/workflows/` 与 CI 配置
   ↓
5. 实战：
   - 选项 1：拆 Backend 为 "audit-svc" + "response-svc" + "ingest-svc"
   - 选项 2：把 LLM 替换为本地的 vLLM
   - 选项 3：把 Qdrant 替换为 Milvus
   - 选项 4：加联邦学习 (federated_learn_runs 表已有)
   ↓
[已读 4 周] 目标：能独立运维 + 改造
```

---

## 三个阶段的"必读代码"

按"花 1 小时 / 收益最大"排序：

| 序号 | 文件 | 收益 |
|------|------|------|
| 1 | `backend/app.py` | 入口 + 中间件 + 路由全貌 |
| 2 | `backend/kafka_consumer.py` | Kafka 消费 3 个 topic |
| 3 | `flink-jobs/.../LogValidationJob.java` | Flink 校验逻辑 |
| 4 | `flink-jobs/.../AnomalyDetectionJob.java` | 异常评分 + CEP |
| 5 | `backend/agents/agent_executor.py` | LLM 执行层（最大） |
| 6 | `backend/response_engine/response_orchestrator.py` | 响应编排 |
| 7 | `backend/mcp_guard/guard_server.py` | 4 层 Guard |
| 8 | `backend/stabilizer/stabilizer.py` | LLM 输出稳定化 |
| 9 | `backend/agents/agent_cad.py` | 独立监督 |
| 10 | `backend/sigma_engine/engine.py` | Sigma 引擎 |

---

## 三个"必改实验"

| 实验 | 改哪里 | 验证什么 |
|------|--------|----------|
| **加一条 Sigma 规则** | `backend/sigma_engine/rules/SIG-012.yml` | reload 后注入新事件验证 |
| **加一条 CEP 模式** | 推 `CepPatternConfig` JSON 到 cep-patterns topic | 不重启 Flink 模式生效 |
| **加一个端点** | `backend/routers/<feature>.py` + `app.py` 注册 | 前端调用成功 |

---

## 三个"必查日志"

| 场景 | 查哪里 |
|------|--------|
| 平台卡了 | `docker compose logs --tail=200 backend` |
| 审计异常 | `backend/logs/audit_*.log`（含 trace_id） |
| 响应失败 | `response_logs` 表 + `backend/logs/response_*.log` |

---

## 三个"必看测试"

| 测试 | 路径 | 看到什么 |
|------|------|----------|
| Prompts 完整性 | `tests/test_prompts_integrity.py` | 5 个测试保提示词零硬编码 |
| Sigma 引擎 | `tests/test_inc_threat_intel.py` | 5 个 mock IOC 匹配 |
| Qdrant 兜底 | `tests/test_vector_store_qdrant.py` | 4 个降级路径 |

---

## 三个"常见思维陷阱"

1. **把"LLM 看到的内容"和"LLM 输出的内容"混为一谈**
   - LLM 看到：用户输入 + RAG 检索 + 历史对话
   - LLM 输出：JSON 工具调用 / 文字结论
   - 两者的"安全护栏"不一样

2. **把"自动执行"和"无审批"混为一谈**
   - 自动执行 ≠ 跳过所有检查
   - 仍然过 Guard 4 层 + SecurityGuard 4 维
   - 真正的"无审批"是 `human_approval.py` 跳过

3. **把"日志中心 analyzed=False"理解成"没处理"**
   - analyzed 字段只反映"是否被 LLM 审计"
   - 响应已执行的事件可能 analyzed=False（早期 bug，已修）
   - 看 `status` 字段更准确（responded / closed / ...）

---

## 上一章

> [08 部署、运维与调优](./08-deployment.md)

---

## 下一章

- 卡住了：→ [10 常见问题与陷阱]
- 想看数据模型：→ [07 数据模型与消息契约]
- 想回到首页：→ [README]


---

## 行动建议

- 每天 1 个动手点
- 每周 1 个实战（加规则 / 加端点 / 修 bug）
- 每月 1 次全链路 demo 演练
- 季度 1 次升级演练（拉新版本 + 滚动升级）
