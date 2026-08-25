# 02 · 数据流与事件生命周期

> 平台把"安全事件"当作一个**有生命的对象**：从诞生到归档，全程有 `trace_id` 陪伴。
> 这一章追一条事件走完全程，看它在每个环节被加了什么字段、被谁消费。

---

## 一、Kafka Topic 总览（10 个）

> 完整常量定义见 `flink-jobs/src/main/java/com/soc/util/KafkaConfig.java`

### 主链路（7 个）

| Topic | 写入者 | 读取者 | 含义 |
| :--- | :--- | :--- | :--- |
| `security-logs-raw` | syslog-adapter / log_simulator | Flink Job 1 | 原始日志，**未校验** |
| `security-logs-rejected` | Flink Job 1 | 审计归档 | 被拒绝的日志 + 拒绝原因 |
| `security-logs-validated` | Flink Job 1 | Flink Job 2 | 通过校验，**未评分** |
| `security-events-enriched` | Flink Job 2 | Backend | 富化后全量事件（含异常分） |
| `security-alerts` | Flink Job 2 | Backend | 高分 / 严重 / CEP 命中告警 |
| `security-audit-queue` | Flink Job 2 | Backend | 中分待 LLM 审计 |
| `security-audit-results` | Backend | 前端 / 归档 | LLM 审计完成结果 |

### 辅助 / 兜底（3 个）

| Topic | 用途 |
| :--- | :--- |
| `security-logs-dlq` | 死信队列：Flink 处理失败的消息（JSON 解析失败、Schema 校验失败兜底） |
| `security-cep-partial` | CEP 部分匹配（半截攻击链的中间状态） |
| `security-cep-patterns` | CEP 模式配置（Broadcast 热更新通道） |
| `security-sigma-hit` | Sigma 命中事件（SigmaThresholdAggregationJob 消费做阈值去抖） |

> 实际 Kafka 上 7 + 3 共 10 个 topic。Backend 消费 3 个主 topic（enriched / audit-queue / alerts）。

---

## 二、一条事件的一生

下面追一条 **"192.168.1.100 触发 50 次 SSH 登录失败 → 暴力破解告警"** 的全过程。

### 阶段 1 · 诞生（外部 → Kafka）

```bash
# log_simulator.py 生成攻击链
python log_simulator.py --kafka localhost:9094 --mode chain --apiKey soc-simulator-2024
```

事件载荷（简化）：

```json
{
  "eventId": "evt-uuid-001",
  "timestamp": 1724567890123,
  "eventType": "BRUTE_FORCE",
  "severity": "high",
  "srcIp": "192.168.1.100",
  "dstIp": "10.0.0.5",
  "protocol": "SSH",
  "message": "50 failed login attempts in 60s",
  "confidence": 80,
  "rawData": { "...": "..." }
}
```

→ 推送到 `security-logs-raw`，**带 API Key**。

### 阶段 2 · Flink 校验（Job 1）

代码：`flink-jobs/src/main/java/com/soc/job/LogValidationJob.java`

流水步骤：

```
1. JSON 解析            （失败 → rejected 侧输出）
2. Schema 校验          （必填字段 / severity 枚举 / confidence 范围 / IP 格式）
3. API Key 认证         （白名单：soc-syslog-2024 / soc-api-2024 / soc-simulator-2024）
4. 字段标准化          （数字 severity → 文本：70 → high；eventType 大写；时间戳校验）
5. 60s 去重            （按 srcIp + eventType + messageHash 的 ValueState + TTL）
6. 数据源信誉评分      （SourceReputationFunction：5min 滑窗打分）
7. 写入 Kafka          （EXACTLY_ONCE：走事务 + Checkpoint）
```

被拒绝的走 `security-logs-rejected`，payload 多一个字段：

```json
{
  "rejectionType": "AUTHENTICATION_FAILED",
  "rejectionReason": "API Key 不在白名单中",
  "rawMessage": "...",
  "rejectedAt": 1724567890456,
  "jobName": "LogValidationJob",
  "stage": "AUTH"
}
```

被接受的加 `trace_id` 头后写 `security-logs-validated`：

```json
{
  "...": "原事件",
  "rawData": { "_traceparent": "00-abc123-...-01" }
}
```

> **设计要点**：拒绝原因分 4 类（JSON 解析失败 / Schema 校验失败 / 认证失败 / 重复），每类都有 metric counter，方便看数据源质量。

### 阶段 3 · 异常评分（Job 2）

代码：`flink-jobs/src/main/java/com/soc/job/AnomalyDetectionJob.java`

流水步骤：

```
1. 分配事件时间水印      （forBoundedOutOfOrderness(10s) + withIdleness(2min)）
2. 异常评分 (按 srcIp KeyedProcessFunction)：
   · 频率：5min 滑窗事件数 > 20  →  +0.3
   · 严重度权重：critical=1.0, high=0.6, medium=0.3, low=0, info=-0.05
   · 时段：0-5 点                →  +0.4
   · 综合分限制在 [0, 1]
3. CEP 攻击链匹配 (3 模式)：
   · port_scan_to_c2：PORT_SCAN → BRUTE_FORCE → C2_BEACON（30min）
   · lateral_movement：SUSPICIOUS_LOGIN → FILE_ACCESS → LATERAL_MOVE（60min）
   · data_exfil：FILE_ACCESS → DATA_EXFIL（15min）
4. 智能路由（基于分数）：
   · score ≥ 0.6 或 severity ∈ {critical, high}  →  security-alerts
   · score ≥ 0.3                                  →  security-audit-queue
   · 所有事件                                     →  security-events-enriched
```

我们的暴力破解事件：

- 5min 内 50 次  →  频率 +0.3
- severity = high  →  权重 +0.6
- 时段 = 0-5 点  →  +0.4
- 综合分 = 1.0（封顶）

**路由**：`security-alerts` + `security-events-enriched`（两个都写）。

### 阶段 4 · Backend 消费（enriched + alerts）

代码：`backend/kafka_consumer.py`

```
_handle_enriched(event):
  1. 解码 → 落库 SecurityEvent 表
  2. 字段标准化入库（anomaly_score, src_ip, dst_ip, severity, event_type）
  3. 发布到 event_bus（SSE 推到前端）
  4. ★ 如果 score ≥ 0.6 或 severity ∈ {critical, high}：也调用 audit_pipeline
     （修复了早期"高严重事件不进审计"的 bug）

_handle_alert(event):
  1. 发布 alert 到 event_bus
  2. 调用 response_orchestrator.on_threat_detected()
```

> ⚠️ **历史陷阱**：早期版本高严重事件只走 alerts 不走 audit-queue，导致日志中心 80% 高危事件卡在"待审计"。修复见 `audit/02-日志中心根因排查报告.md`。

### 阶段 5 · LLM 审计（audit_pipeline）

代码：`backend/log_ingestion.py::_audit_pipeline`

流水线（4 层）：

```
AnomalyReport
   ↓
Decomposer  （agent_decomposer.py）
   · 拆解：攻击类型 / 影响面 / 紧急度
   · 输出：结构化子问题列表
   ↓
ToolBuilder  （agent_tool_builder.py）
   · 决定调哪些工具（RAG 检索 / Sigma 重检测 / 资产查询 / 案例检索）
   · 输出：工具调用计划
   ↓
Executor  （agent_executor.py）
   · 经 Stabilizer 修复 → 经 MCP Guard 4 层 → 实际调用工具
   · 输出：工具返回的证据
   ↓
Reviewer  （agent_reviewer.py）
   · 复盘：是否遗漏威胁 / 幻觉
   · 输出：最终威胁结论 + 置信度 + 建议响应
```

每层都把结果塞进 `audit_llm_data.evidence_trail`，CAD 后续审计靠这个 trail。

### 阶段 6 · CAD 独立监督

代码：`backend/agents/agent_cad.py`

```
audit_pipeline(完成) → cad.audit_pipeline(event_id, audit_llm_data)
   ↓
1. verifier.verify_claims()：
   · 对 evidence_trail 中每条 claim 做穿透验证
   · 程序化字段溯源（不是问 LLM，而是去 PG / Qdrant 查）
   ↓
2. 计算 hallucination_risk 与 evidence_completeness
   ↓
3. circuit_breaker.record_audit_result()：
   · 累计指标，超阈值则熔断（暂停 LLM 审计）
   ↓
4. 输出 CAD 报告
   · 写入 audit_trail 与 cad_reports
```

### 阶段 7 · 响应执行

代码：`backend/response_engine/response_orchestrator.py`

```
on_threat_detected(threat_info):
   ↓
1. policy_engine.match() — 匹配响应策略（8 条预置）
   ↓
2. 决策：
   · 低风险 / 封禁类  →  自动执行
   · 中风险            →  提交审批工单
   · 高风险 / 破坏性  →  拒绝
   ↓
3. SecurityGuard.inspect() — 多维审查（意图 / 序列 / 频率 / 上下文）
   ↓
4. response_executor.execute_actions()：
   · command_whitelist 校验命令
   · asset_whitelist 校验目标
   · ssh_firewall.py / transport.py 真实执行
   ↓
5. 记录 response_logs（可回滚）
```

执行示例（自动封禁 C2 IP）：

```python
actions = [
    {"action": "block_ip", "params": {"ip": "192.168.1.100", "duration": 3600}}
]
# 实际 SSH 执行：iptables -I INPUT -s 192.168.1.100 -j DROP -m comment --comment 'FW-RULE-001'
```

### 阶段 8 · 复盘与归档

```
· 告警 status 变更为 'responded'
· 自动绑定到 case（case_manager）
· Post-Mortem：post_mortem_service.py 重建事件时间线
· FeedbackLoop：把误报 / 漏报回灌到规则引擎（rule_manager）
· 30 天后归档：event_archive.py
```

---

## 三、`trace_id` 贯穿

每个事件从出生就有一个 `eventId`，Flink 给它加 `traceparent` 头，Backend 把它写入 `raw_data._traceparent`，前端在每条记录的"查看链路"按钮里看到。

```
eventId （全局唯一）
   ↓
Kafka Header：traceparent
   ↓
Flink：TraceUtil.startSpan() → OTel → Tempo
   ↓
Backend：raw_data._traceparent
   ↓
Frontend：点击"查看链路" → /api/trace/{traceparent} → Tempo
```

可在 Jaeger / Tempo UI 看到一整条调用链：日志接入 → 校验 → 富化 → 消费 → 审计 → 响应。

---

## 四、字段标准化全表

Flink 校验后事件会标准化这些字段：

| 字段 | 原始 | 标准化后 |
| :--- | :--- | :--- |
| `severity` | `70` / `high` | `high` |
| `eventType` | `port_scan` / `PortScan` | `PORT_SCAN` |
| `protocol` | `TCP` / `tcp` | `tcp` |
| `srcIp` | `192.168.1.1` | 校验 IPv4 格式 |
| `timestamp` | 缺省 / 0 | `System.currentTimeMillis()` |
| `eventId` | 缺省 | UUID |
| `traceId` | 缺省 | 等于 eventId |
| `apiKey` | 携带 | 脱敏后丢弃（写入日志） |

被修复的字段数会累加到 `fieldFixCounter` 指标。

---

## 五、被拒绝的事件去哪了

`security-logs-rejected` 这个 topic 容易被忽略，但它**非常重要**：

- 数据源出问题时，能追溯是哪个字段校验失败
- 攻击者伪造日志时，能发现异常模式
- 演示时容易"自证清白"：平台没有静默丢数据

代码：`backend/routers/kafka.py` 提供 `/api/kafka/rejections` 端点查询。

---

## 六、为什么不用 REST 同步处理

常见疑问："为什么不让后端直接 HTTP 消费日志？"

答案：3 个生产硬约束

1. **背压**：HTTP 同步调用慢就堆积，Flink 不会
2. **重放**：Flink checkpoint + Kafka offset 可以从任意点重放
3. **横向扩展**：Kafka 分区数决定 Flink 并行度上限，REST 不行

当然，平台**保留了 HTTP 入口**（`/api/logs/ingest`）用于 demo 与单点测试。

---

## 下一章

- 想看后端模块的"目录树 + 关键类"  →  [03 后端核心模块](./03-backend-modules.md)
- 想看 Flink Java 代码怎么写  →  [04 Flink 流处理作业](./04-flink-jobs.md)
- 想看 LLM 怎么"被监督"  →  [05 自审计体系](./05-self-audit.md)

---

## 动手点

1. **追一条事件**

   ```bash
   # 1. 注入
   python log_simulator.py --kafka localhost:9094 --mode chain
   # 2. 在 Kafka UI 看消息流经 7 个 topic
   # 3. 在前端"日志中心"找到这条事件
   # 4. 点开看 trace_id
   # 5. 在 Jaeger / Tempo 用 trace_id 搜
   ```

2. **看拒绝事件**

   ```bash
   # 不带 API Key 注入
   python log_simulator.py --kafka localhost:9094 --mode single --apiKey ""
   # 在 Kafka UI 看 security-logs-rejected
   # 查 API：curl http://localhost:8001/api/kafka/rejections
   ```

3. **模拟被熔断**

   - 故意在 `config.py` 把 `circuit_breaker_threshold` 调小（如 0.1）
   - 注入 3 条故意有问题的 LLM 审计
   - 观察 CAD 报告与熔断器状态变化

---

> 上一章：[01 架构总览](./01-architecture.md) · 下一章：[03 后端核心模块](./03-backend-modules.md)
