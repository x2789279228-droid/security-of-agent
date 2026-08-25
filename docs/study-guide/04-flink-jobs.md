# 04 · Flink 流处理作业

> 平台用 Apache Flink 1.19.3（Java 11）做实时流处理（实测 `flink-jobs/pom.xml` `<flink.version>1.19.3</flink.version>`，Kafka Connector 3.2.0-1.19）。本章讲清**两个核心作业**和**三个辅助作业**的代码逻辑、CEP 模式、数据契约。

---

## 一、整体拓扑

```
                     ┌──────────────────────────────┐
                     │  security-logs-raw           │
                     │  (数据源 / 适配器 / 模拟器)     │
                     └──────────────┬───────────────┘
                                    ▼
                     ╔══════════════════════════════╗
                     ║  Job 1: LogValidationJob     ║
                     ║  · 解析  · 校验  · 认证  · 去重 ║
                     ╚══════╤═══════════════╤═══════╝
                            ▼               ▼
            security-logs-validated   security-logs-rejected
                            │
                            ▼
                     ╔══════════════════════════════╗
                     ║  Job 2: AnomalyDetectionJob  ║
                     ║  · 异常评分  · CEP 攻击链     ║
                     ╚══════╤═══════════════════════╝
                            ▼
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
      security-       security-        security-events-
      alerts          audit-queue      enriched
      (高优)          (中分审计)        (全量落库)
```

辅助作业：
- `FlowAggregationJob`：把 NDR raw flow 聚合成 5min 滑窗
- `SigmaThresholdAggregationJob`：Sigma 命中做阈值聚合去抖
- `TlsFingerprintJob`：TLS JA3/JA4 指纹提取

---

## 二、Job 1：LogValidationJob

**文件**：`flink-jobs/src/main/java/com/soc/job/LogValidationJob.java`

### 流水线

```
1. KafkaSource<String> ← security-logs-raw
   .setGroupId("log-validation-job")
   .setStartingOffsets(earliest)
   .setValueOnlyDeserializer(SimpleStringSchema)

2. ProcessFunction<String, SecurityEvent>: JSON 解析
   · 失败 → REJECTED_TAG 侧输出 (rejectionType=JSON_PARSE_ERROR)

3. KeyedProcessFunction<String, SecurityEvent>: 校验+标准化+去重
   · key = srcIp (允许 unknown)
   · 4 步：
     ① Schema 校验 (必填/枚举/范围/格式)
     ② API Key 认证 (白名单)
     ③ 字段标准化 (severity 70→high, IP 校验, 时间戳校验)
     ④ 60s 滑动窗口去重 (fingerprint = srcIp+eventType+messageHash)

4. KeyedProcessFunction<String, SecurityEvent>: 数据源信誉评分
   · key = sourceId
   · 5min 滑窗按 sourceId 聚合

5. KafkaSink → security-logs-validated (EXACTLY_ONCE)
   · Header: TraceIdHeaderProvider

6. KafkaSink → security-logs-rejected (EXACTLY_ONCE)
```

### 关键代码片段

**API Key 白名单**（`LogValidationJob.java:66`）：
```java
private static final Set<String> VALID_API_KEYS = new HashSet<>(Arrays.asList(
    "soc-syslog-2024",
    "soc-api-2024",
    "soc-simulator-2024"
));
```

**Schema 校验**（增强版）：
```java
// 必填字段
if (event.getEventType() == null) return "缺少必填字段: eventType";
if (event.getSeverity() == null)  return "缺少必填字段: severity";
if (event.getMessage() == null)   return "缺少必填字段: message";

// severity 枚举（先映射再校验）
String severity = event.getSeverity().trim().toLowerCase();
if (SEVERITY_MAP.containsKey(severity)) {
    severity = SEVERITY_MAP.get(severity);
}
if (!VALID_SEVERITIES.contains(severity)) {
    return "无效的 severity 值...";
}

// confidence 范围
if (event.getConfidence() < 0 || event.getConfidence() > 100) {
    return "confidence 超出范围...";
}

// timestamp 合理性
if (event.getTimestamp() < TS_MIN || event.getTimestamp() > TS_MAX) {
    return "timestamp 不在 2020-2030 范围";
}
```

**去重**（ValueState + TTL）：
```java
ValueStateDescriptor<String> descriptor = new ValueStateDescriptor<>(
    "dedup-fingerprint", Types.STRING
);
descriptor.enableTimeToLive(
    StateTtlConfig.newBuilder(Time.seconds(60))
        .setUpdateType(OnCreateAndWrite)
        .setStateVisibility(NeverReturnExpired)
        .build()
);
```

**Flink Metrics 暴露**：
```java
group.counter("events_total");
group.counter("events_valid");
group.counter("events_schema_fail");
group.counter("events_auth_fail");
group.counter("events_duplicate");
group.gauge("valid_rate", () -> ...);  // 有效率
```

这些指标会被 Prometheus 拉取，展现在 Grafana 上。

### 设计要点

- **EXACTLY_ONCE** 通过 Kafka 事务 + Flink Checkpoint 双保证
- **失败不静默**：每类失败都有 metric + rejectionType
- **trace_id 贯穿**：每条事件加 `_traceparent` 字段，header 携带
- **可扩展**：并行度/checkpoint 配在 `flink-conf.yaml`，不在代码硬编码

---

## 三、Job 2：AnomalyDetectionJob

**文件**：`flink-jobs/src/main/java/com/soc/job/AnomalyDetectionJob.java`

### 流水线

```
1. KafkaSource<String> ← security-logs-validated

2. JSON → SecurityEvent (过滤 null)

3. 分配事件时间水印
   · forBoundedOutOfOrderness(10s)
   · withIdleness(2min)  // 防止空闲分区卡 watermark

4. KeyedProcessFunction<srcIp>: 异常评分
   · 频率: 5min 窗口事件数 > 20 → +0.3
   · 严重度: critical=1.0, high=0.6, medium=0.3, low=0, info=-0.05
   · 时段: 0-5 点 → +0.4
   · 综合分限制 [0, 1]
   · 侧输出:
     · ALERT_TAG      (score ≥ 0.6 || severity ∈ critical/high)
     · AUDIT_TAG      (0.3 ≤ score < 0.6)
     · main output    → enriched (全量)

5. CEP PatternStream: 攻击链检测
   · 3 模式 (CepPatternConfig):
     · port_scan_to_c2: PORT_SCAN → BRUTE_FORCE → C2_BEACON (30min)
     · lateral_movement: SUSPICIOUS_LOGIN → FILE_ACCESS → LATERAL_MOVE (60min)
     · data_exfil: FILE_ACCESS → DATA_EXFIL (15min)
   · 模式可热更新 (Kafka Broadcast)
   · 命中 → ATTACK_CHAIN_TAG

6. KeyedProcessFunction<srcIp>: CEP 部分匹配追踪
   · 即使没全命中，也记录"半截攻击链"作为预警
   · 例: 已经 PORT_SCAN + BRUTE_FORCE，但还没 C2_BEACON

7. Kafka Sinks
   · security-events-enriched (全量)
   · security-alerts (异常分 ALERT + CEP 命中)
   · security-audit-queue (中分事件)
```

### 异常评分代码

```java
public class AnomalyScoringFunction
        extends KeyedProcessFunction<String, SecurityEvent, String> {

    private transient ValueState<Integer> recentCount;  // 5min 窗口计数
    private transient ValueState<Long> windowStart;     // 窗口起始时间

    @Override
    public void processElement(SecurityEvent event, Context ctx, Collector<String> out) {
        // 计算 5min 窗口事件数
        long now = event.getTimestamp();
        long start = windowStart.value() == null ? now : windowStart.value();
        if (now - start > 300_000) {  // 5min
            windowStart.update(now);
            recentCount.update(0);
        }
        int count = recentCount.value() + 1;
        recentCount.update(count);

        // 频率分
        double score = 0.0;
        if (count > 20) score += 0.3;

        // 严重度分
        switch (event.getSeverity()) {
            case "critical": score += 1.0; break;
            case "high":     score += 0.6; break;
            case "medium":   score += 0.3; break;
            case "info":     score -= 0.05; break;
        }

        // 时段分 (0-5 点)
        int hour = Instant.ofEpochMilli(now).atZone(ZoneId.systemDefault()).getHour();
        if (hour >= 0 && hour < 5) score += 0.4;

        score = Math.max(0, Math.min(1, score));

        // 路由
        if (score >= 0.6 || isHighSeverity(event)) {
            ctx.output(ALERT_TAG, buildAlertJson(event, score));
        } else if (score >= 0.3) {
            ctx.output(AUDIT_TAG, buildAuditJson(event, score));
        }
        out.collect(buildEnrichedJson(event, score));
    }
}
```

### CEP 攻击链代码

```java
DataStream<String> buildCepPatterns(DataStream<SecurityEvent> events) {
    Pattern<SecurityEvent, ?> portScanToC2 = Pattern
        .<SecurityEvent>begin("scan")
        .where(new SimpleCondition<SecurityEvent>() {
            @Override public boolean filter(SecurityEvent e) {
                return "PORT_SCAN".equals(e.getEventType());
            }
        })
        .next("brute")
        .where(new SimpleCondition<SecurityEvent>() {
            @Override public boolean filter(SecurityEvent e) {
                return "BRUTE_FORCE".equals(e.getEventType());
            }
        })
        .next("c2")
        .where(new SimpleCondition<SecurityEvent>() {
            @Override public boolean filter(SecurityEvent e) {
                return "C2_BEACON".equals(e.getEventType());
            }
        })
        .within(Time.minutes(30));

    PatternStream<SecurityEvent> ps = CEP.pattern(
        events.keyBy(SecurityEvent::getSrcIp),
        portScanToC2
    );

    return ps.select((Map<String, List<SecurityEvent>> pattern) -> {
        // 构造攻击链告警
        return buildAttackChainJson("port_scan_to_c2", pattern);
    });
}
```

### CEP 模式热更新

`CepPatternConfig` 可以从 Kafka Broadcast 接收，实现不重启 Flink 改模式：

```java
public class CepPatternConfig implements Serializable {
    private String patternId;          // e.g. "port_scan_to_c2"
    private String name;               // e.g. "端口扫描→暴力破解→C2"
    private List<String> steps;        // ["PORT_SCAN","BRUTE_FORCE","C2_BEACON"]
    private int withinMinutes;         // 30
    private boolean enabled = true;
    private boolean shadowMode = false;  // 灰度：仅记录不告警
    private int version = 1;
}
```

通过 Kafka Broadcast State 推送到 Flink，触发 `PatternStream` 重建。

---

## 四、辅助作业

### SigmaThresholdAggregationJob（默认启动）
- 输入：`security-sigma-hit` topic
- 处理：对 Sigma 命中事件做阈值聚合去抖（防抖：5min 内同 IP 同规则只告警 1 次）
- 输出：聚合告警到 backend
- 这是 `submit-jobs.sh` 默认提交的**第三个作业**

### FlowAggregationJob（需 SUBMIT_NDR_JOBS=1）
- 输入：NDR raw flow (从 `traffic_capture/`)
- 处理：5min 滚动窗口聚合
- 输出：`network_flows` 聚合表
- 默认不提交，因为后端暂未消费 NDR topic（演示环境用）

### TlsFingerprintJob（需 SUBMIT_NDR_JOBS=1）
- 输入：TLS handshake 原始包
- 处理：提取 JA3 / JA3S / JA4 指纹
- 输出：`tls_sessions` 表

启用方式：
```bash
docker exec soc-flink-jobmanager bash -c "SUBMIT_NDR_JOBS=1 /opt/flink/submit-jobs.sh flink-jobmanager"
```

---

## 五、构建与提交

```bash
# 1. 构建
cd flink-jobs
mvn clean package -DskipTests

# 2. 提交到 Flink 集群
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
```

`submit-jobs.sh` 内容：
```bash
#!/bin/bash
FLINK_HOME=/opt/flink
$FLINK_HOME/bin/flink run \
  -c com.soc.job.LogValidationJob \
  $FLINK_HOME/usrlib/log-validation-job.jar &
$FLINK_HOME/bin/flink run \
  -c com.soc.job.AnomalyDetectionJob \
  $FLINK_HOME/usrlib/anomaly-detection-job.jar
wait
```

Dockerfile 多阶段构建：
```dockerfile
FROM maven:3.9 AS build
WORKDIR /build
COPY pom.xml ./
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

FROM flink:1.18-java11
COPY --from=build /build/target/*.jar $FLINK_HOME/usrlib/
COPY submit-jobs.sh $FLINK_HOME/
```

---

## 六、关键设计模式

读 Flink 代码时常见的几个"为什么这么写"：

### 1. 用侧输出（Side Output）而不是分流到多个 stream
- 一份输入，零拷贝路由到多个出口
- 比 `split` API 更灵活，类型安全

### 2. 用 ValueState + TTL 而不是 RocksDB 全量
- 单条去重不需要 RocksDB
- TTL 让过期状态自动清理
- 内存压力小

### 3. 用 BroadcastState 做模式热更新
- 一份配置推所有并行度
- 不需要重启 Flink 改 CEP

### 4. EXACTLY_ONCE 双重保障
- Kafka 事务
- Flink Checkpoint
- 两条必须同时开才有 EXACTLY_ONCE

### 5. 不在代码里硬编码并行度
- 在 `flink-conf.yaml` 统一配
- 按 Kafka 分区数弹性扩容

---

## 上一章

> [03 后端核心模块](./03-backend-modules.md)

---

## 下一章

- 想看 5 道自审计闸门：→ [05 自审计体系]
- 想看前端怎么展示：→ [06 前端架构与页面]
- 想看数据模型怎么落：→ [07 数据模型与消息契约]


---

## 动手点

1. **跑一个 CEP 模式注入**：
   ```bash
   # 用 log_simulator --mode chain 触发 3 步攻击链
   python log_simulator.py --kafka localhost:9094 --mode chain
   # 在 Flink Dashboard 看 CEP operator 的状态
   # 打开 http://localhost:3002，登录后点 completed jobs → AnomalyDetectionJob
   # 看 attackChainAlerts counter
   ```

2. **加一条 CEP 模式（不重启 Flink）**：
   ```bash
   # 1. 编辑 CepPatternConfig.json
   # 2. 推送到 cep-patterns topic (Broadcast 主题)
   # 3. 看新模式立即生效
   ```

3. **看 Flink 指标**：
   ```bash
   # Flink REST（通过 3002 反代）
   curl -u admin:password http://localhost:3002/api/v1/.../metrics
   ```
