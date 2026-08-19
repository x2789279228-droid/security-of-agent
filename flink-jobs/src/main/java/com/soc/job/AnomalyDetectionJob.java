package com.soc.job;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.AlertEvent;
import com.soc.model.SecurityEvent;
import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.SerializableTimestampAssigner;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.state.MapState;
import org.apache.flink.api.common.state.MapStateDescriptor;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.cep.CEP;
import org.apache.flink.cep.PatternSelectFunction;
import org.apache.flink.cep.PatternStream;
import org.apache.flink.cep.pattern.Pattern;
import org.apache.flink.cep.pattern.conditions.SimpleCondition;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.streaming.api.windowing.assigners.TumblingEventTimeWindows;
import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.streaming.api.functions.windowing.WindowFunction;
import org.apache.flink.util.Collector;
import org.apache.flink.util.OutputTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 异常检测作业 (Job 2)
 *
 * 功能：
 * 1. 从 security-logs-validated 消费已验证事件
 * 2. 异常评分（KeyedProcessFunction，按 srcIp 分组）：
 *    - 频率异常：5 分钟窗口内事件数 > 20 → +0.3
 *    - 严重级别权重：critical=1.0, high=0.6, medium=0.3, low=0.0, info=-0.05
 *    - 时间异常：凌晨 0-5 点 → +0.4
 *    - 综合评分限制在 [0, 1]
 * 3. CEP 攻击链检测：
 *    - port_scan_to_c2: PORT_SCAN → BRUTE_FORCE → C2_BEACON (30分钟内)
 *    - lateral_movement: SUSPICIOUS_LOGIN → FILE_ACCESS → LATERAL_MOVE (60分钟内)
 *    - data_exfil: FILE_ACCESS → DATA_EXFIL (15分钟内)
 * 4. 路由：
 *    - score >= 0.6 或 severity 为 critical/high → security-alerts
 *    - score >= 0.3 → security-audit-queue (LLM 审计)
 *    - 所有事件 → security-events-enriched
 */
public class AnomalyDetectionJob {

    private static final Logger LOG = LoggerFactory.getLogger(AnomalyDetectionJob.class);

    /** 侧输出标签：告警事件 */
    private static final OutputTag<String> ALERT_TAG =
            new OutputTag<String>("security-alerts") {};

    /** 侧输出标签：审计队列事件 */
    private static final OutputTag<String> AUDIT_TAG =
            new OutputTag<String>("audit-queue") {};

    /** 侧输出标签：CEP 攻击链告警 */
    private static final OutputTag<String> ATTACK_CHAIN_TAG =
            new OutputTag<String>("attack-chain-alerts") {};

    /** 侧输出标签：迟到事件（超过 watermark 的事件）*/
    private static final OutputTag<String> LATE_DATA_TAG =
            new OutputTag<String>("late-data") {};

    public static void main(String[] args) throws Exception {
        // 创建 Flink 执行环境
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        // 并行度/checkpoint 由 flink-conf.yaml 统一配置 (生产级), 不在代码硬编码

        // ==================== 1. 构建 Kafka Source ====================
        KafkaSource<String> kafkaSource = KafkaSource.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setTopics(KafkaConfig.TOPIC_VALIDATED_LOGS)
                .setGroupId("anomaly-detection-job")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setValueOnlyDeserializer(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                .build();

        // ==================== 2. 消费并解析事件 ====================
        DataStream<String> rawStream = env.fromSource(
                kafkaSource,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(5)),
                "Kafka-ValidatedLogs-Source"
        );

        // JSON → SecurityEvent
        SingleOutputStreamOperator<SecurityEvent> eventStream = rawStream
                .map(new JsonToEventFunction())
                .filter(event -> event != null)
                .name("JSON-Parse-Validated");

        // 分配事件时间水印（使用事件自带时间戳 + 空闲源检测）
        SingleOutputStreamOperator<SecurityEvent> timestampedStream = eventStream
                .assignTimestampsAndWatermarks(
                        WatermarkStrategy.<SecurityEvent>forBoundedOutOfOrderness(Duration.ofSeconds(10))
                                .withIdleness(Duration.ofMinutes(2))
                                .withTimestampAssigner(new SerializableTimestampAssigner<SecurityEvent>() {
                                    @Override
                                    public long extractTimestamp(SecurityEvent event, long recordTimestamp) {
                                        return event.getTimestamp();
                                    }
                                })
                );

        // ==================== 3. 异常评分（KeyedProcessFunction）====================
        SingleOutputStreamOperator<String> enrichedStream = timestampedStream
                .keyBy(SecurityEvent::getSrcIp)
                .process(new AnomalyScoringFunction())
                .name("Anomaly-Scoring");

        // ==================== 4. CEP 攻击链检测 ====================
        DataStream<String> attackChainAlerts = buildCepPatterns(timestampedStream);

        // ==================== 4.5 CEP 部分匹配追踪 ====================
        DataStream<String> partialMatches = timestampedStream
                .keyBy(SecurityEvent::getSrcIp)
                .process(new CepPartialMatchFunction())
                .name("CEP-Partial-Match-Tracker");

        // ==================== 5. 获取侧输出 ====================
        DataStream<String> alertStream = enrichedStream.getSideOutput(ALERT_TAG);
        DataStream<String> auditStream = enrichedStream.getSideOutput(AUDIT_TAG);

        // ==================== 6. 构建 Kafka Sinks ====================

        // Sink: security-events-enriched（所有富化事件）
        KafkaSink<String> enrichedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                // 值=JSON + trace_id header (全链路追踪, TraceIdHeaderProvider)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_ENRICHED_EVENTS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-ano-enr")
                .build();

        enrichedStream
                .sinkTo(enrichedSink)
                .name("Kafka-Enriched-Sink");

        // Sink: security-alerts（高优先级告警）
        KafkaSink<String> alertSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_ALERTS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-ano-ale")
                .build();

        // 合并异常评分告警和 CEP 攻击链告警
        alertStream
                .union(attackChainAlerts)
                .sinkTo(alertSink)
                .name("Kafka-Alerts-Sink");

        // Sink: security-audit-queue（LLM 审计队列）
        KafkaSink<String> auditSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_AUDIT_QUEUE)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-ano-aud")
                .build();

        auditStream
                .sinkTo(auditSink)
                .name("Kafka-AuditQueue-Sink");

        // Sink: security-cep-partial（部分匹配可视化）
        KafkaSink<String> partialSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_CEP_PARTIAL)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-ano-par")
                .build();

        partialMatches
                .sinkTo(partialSink)
                .name("Kafka-CEP-Partial-Sink");

        // ==================== 7. 启动作业 ====================
        LOG.info("启动异常检测作业: AnomalyDetectionJob");
        LOG.info("Kafka Bootstrap: {}", KafkaConfig.KAFKA_BOOTSTRAP);
        LOG.info("输入 Topic: {}", KafkaConfig.TOPIC_VALIDATED_LOGS);
        LOG.info("输出 Topics: {} / {} / {} / {}",
                KafkaConfig.TOPIC_ENRICHED_EVENTS, KafkaConfig.TOPIC_ALERTS,
                KafkaConfig.TOPIC_AUDIT_QUEUE, KafkaConfig.TOPIC_CEP_PARTIAL);

        env.execute("AnomalyDetectionJob");
    }

    // ==================== CEP 攻击链模式定义 ====================

    /**
     * 构建 CEP 攻击链检测模式
     *
     * 检测三种攻击链：
     * 1. port_scan_to_c2: 端口扫描 → 暴力破解 → C2 信标 (30分钟)
     * 2. lateral_movement: 可疑登录 → 文件访问 → 横向移动 (60分钟)
     * 3. data_exfil: 文件访问 → 数据外泄 (15分钟)
     */
    private static DataStream<String> buildCepPatterns(DataStream<SecurityEvent> eventStream) {

        // ---------- 模式 1: 端口扫描 → 暴力破解 → C2 信标 ----------
        // 攻击逻辑：攻击者先扫描开放端口，然后对发现的服务进行暴力破解，最后建立 C2 通道
        Pattern<SecurityEvent, ?> portScanToC2 = Pattern
                .<SecurityEvent>begin("port_scan")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "PORT_SCAN".equals(event.getEventType());
                    }
                })
                .next("brute_force")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "BRUTE_FORCE".equals(event.getEventType());
                    }
                })
                .next("c2_beacon")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "C2_BEACON".equals(event.getEventType());
                    }
                })
                .within(Time.minutes(30));

        // ---------- 模式 2: 可疑登录 → 文件访问 → 横向移动 ----------
        // 攻击逻辑：通过可疑方式登录后，访问敏感文件，然后向其他主机横向移动
        Pattern<SecurityEvent, ?> lateralMovement = Pattern
                .<SecurityEvent>begin("suspicious_login")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "SUSPICIOUS_LOGIN".equals(event.getEventType());
                    }
                })
                .next("file_access")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "FILE_ACCESS".equals(event.getEventType());
                    }
                })
                .next("lateral_move")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "LATERAL_MOVE".equals(event.getEventType());
                    }
                })
                .within(Time.minutes(60));

        // ---------- 模式 3: 文件访问 → 数据外泄 ----------
        // 攻击逻辑：访问敏感文件后，将数据外传到外部服务器
        Pattern<SecurityEvent, ?> dataExfil = Pattern
                .<SecurityEvent>begin("file_access_exfil")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "FILE_ACCESS".equals(event.getEventType());
                    }
                })
                .next("data_exfil")
                .where(new SimpleCondition<SecurityEvent>() {
                    @Override
                    public boolean filter(SecurityEvent event) {
                        return "DATA_EXFIL".equals(event.getEventType());
                    }
                })
                .within(Time.minutes(15));

        // ---------- 应用 CEP 模式（按 srcIp 分组）----------
        ObjectMapper mapper = new ObjectMapper();

        // 模式 1: port_scan_to_c2
        PatternStream<SecurityEvent> portScanStream = CEP.pattern(
                eventStream.keyBy(SecurityEvent::getSrcIp), portScanToC2);

        DataStream<String> portScanAlerts = portScanStream.select(
                new AttackChainAlertSelector("port_scan_to_c2",
                        "检测到攻击链: 端口扫描 → 暴力破解 → C2信标通信"));

        // 模式 2: lateral_movement
        PatternStream<SecurityEvent> lateralStream = CEP.pattern(
                eventStream.keyBy(SecurityEvent::getSrcIp), lateralMovement);

        DataStream<String> lateralAlerts = lateralStream.select(
                new AttackChainAlertSelector("lateral_movement",
                        "检测到攻击链: 可疑登录 → 文件访问 → 横向移动"));

        // 模式 3: data_exfil
        PatternStream<SecurityEvent> exfilStream = CEP.pattern(
                eventStream.keyBy(SecurityEvent::getSrcIp), dataExfil);

        DataStream<String> exfilAlerts = exfilStream.select(
                new AttackChainAlertSelector("data_exfil",
                        "检测到攻击链: 文件访问 → 数据外泄"));

        // 合并所有攻击链告警
        return portScanAlerts.union(lateralAlerts).union(exfilAlerts);
    }

    // ==================== CEP 告警生成器 ====================

    /**
     * 攻击链模式匹配后生成 AlertEvent
     */
    public static class AttackChainAlertSelector implements PatternSelectFunction<SecurityEvent, String> {

        private final String chainName;
        private final String description;
        private transient ObjectMapper mapper;

        public AttackChainAlertSelector(String chainName, String description) {
            this.chainName = chainName;
            this.description = description;
        }

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public String select(Map<String, List<SecurityEvent>> pattern) throws Exception {
            // 获取匹配到的第一个事件（起始事件）
            SecurityEvent firstEvent = null;
            for (Map.Entry<String, List<SecurityEvent>> entry : pattern.entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    firstEvent = entry.getValue().get(0);
                    break;
                }
            }

            if (firstEvent == null) {
                return null;
            }

            // 收集攻击链中所有事件类型 + 证据链
            List<String> reasons = new ArrayList<>();
            List<String> evidenceEventIds = new ArrayList<>();
            List<Map<String, Object>> evidenceChain = new ArrayList<>();
            long minTs = Long.MAX_VALUE;
            long maxTs = Long.MIN_VALUE;

            reasons.add(description);
            for (Map.Entry<String, List<SecurityEvent>> entry : pattern.entrySet()) {
                for (SecurityEvent evt : entry.getValue()) {
                    reasons.add(String.format("[%s] %s -> %s (%s)",
                            entry.getKey(), evt.getEventType(), evt.getDstIp(), evt.getMessage()));

                    // 证据链：记录每个事件的 ID 和摘要
                    if (evt.getEventId() != null) {
                        evidenceEventIds.add(evt.getEventId());
                    }
                    Map<String, Object> snapshot = new HashMap<>();
                    snapshot.put("step", entry.getKey());
                    snapshot.put("eventId", evt.getEventId());
                    snapshot.put("eventType", evt.getEventType());
                    snapshot.put("severity", evt.getSeverity());
                    snapshot.put("srcIp", evt.getSrcIp());
                    snapshot.put("dstIp", evt.getDstIp());
                    snapshot.put("message", evt.getMessage() != null ?
                            evt.getMessage().substring(0, Math.min(evt.getMessage().length(), 200)) : "");
                    snapshot.put("timestamp", evt.getTimestamp());
                    evidenceChain.add(snapshot);

                    minTs = Math.min(minTs, evt.getTimestamp());
                    maxTs = Math.max(maxTs, evt.getTimestamp());
                }
            }

            // 构建告警事件
            AlertEvent alert = new AlertEvent();
            alert.setAlertId("CHAIN-" + UUID.randomUUID().toString());
            alert.setEventType(chainName);
            alert.setSeverity("critical");
            alert.setSrcIp(firstEvent.getSrcIp());
            alert.setDstIp(firstEvent.getDstIp());
            alert.setMessage(description + " | 源IP: " + firstEvent.getSrcIp());
            alert.setAnomalyScore(1.0);
            alert.setAlertType("ATTACK_CHAIN");
            alert.setReasons(reasons);
            alert.setTimestamp(System.currentTimeMillis());
            alert.setTraceId(firstEvent.getTraceId());
            alert.setEvidenceEventIds(evidenceEventIds);
            alert.setEvidenceChain(evidenceChain);
            alert.setTimeSpanMs(maxTs > minTs ? maxTs - minTs : 0);

            LOG.warn("🚨 攻击链检测 [{}]: srcIp={}, 证据={}个事件, 跨度={}ms",
                    chainName, firstEvent.getSrcIp(),
                    evidenceEventIds.size(), alert.getTimeSpanMs());

            return getMapper().writeValueAsString(alert);
        }
    }

    // ==================== 异常评分函数（增强版）====================

    /**
     * 异常评分核心逻辑（按 srcIp 分组）— 增强版
     *
     * 评分维度（含分数分解）：
     * 1. 严重级别权重：critical=1.0, high=0.6, medium=0.3, low=0.0, info=-0.05
     * 2. 频率异常（动态基线）：超过 mean + 2σ → +0.3（冷启动期用静态阈值 20）
     * 3. 时间异常：凌晨 0-5 点 → +0.4
     * 4. 资产重要性加成：dstIp 命中高价值资产 → ×1.3（通过 Broadcast 同步）
     *
     * 增强特性：
     * - 动态基线：滑动均值/标准差，自适应每个 IP 的正常频率
     * - 冷启动保护：前 10 条事件仅建基线，不触发告警
     * - 告警风暴抑制：同 IP 5 分钟内最多 3 条告警
     * - 评分可解释：rawData 中包含各维度分数分解
     */
    public static class AnomalyScoringFunction
            extends KeyedProcessFunction<String, SecurityEvent, String> {

        private static final int COLD_START_EVENTS = 10;   // 冷启动事件数
        private static final int MAX_ALERTS_PER_WINDOW = 3; // 每 5 分钟最大告警数
        private static final double FREQ_SIGMA_FACTOR = 2.0; // 频率异常 σ 倍数

        private transient ValueState<Long> eventCountState;
        private transient MapState<Long, Long> windowCountState;

        // ── 动态基线状态 ──
        private transient ValueState<Double> freqMeanState;    // 频率均值
        private transient ValueState<Double> freqM2State;      // Welford M2（方差计算）
        private transient ValueState<Long> baselineSamples;    // 基线样本数

        // ── 告警风暴抑制 ──
        private transient ValueState<Long> alertWindowStart;   // 当前告警窗口起始
        private transient ValueState<Integer> alertCountInWindow; // 窗口内告警数

        private transient ObjectMapper mapper;

        // ── 数据质量指标 ──
        private transient org.apache.flink.metrics.Counter totalEvents;
        private transient org.apache.flink.metrics.Counter lateEvents;
        private transient org.apache.flink.metrics.Counter alertEvents;
        private transient org.apache.flink.metrics.Counter suppressedAlerts;
        private transient org.apache.flink.metrics.Counter coldStartSkips;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public void open(Configuration parameters) {
            org.apache.flink.api.common.state.StateTtlConfig stateTtl =
                    org.apache.flink.api.common.state.StateTtlConfig.newBuilder(
                                    org.apache.flink.api.common.time.Time.hours(2))
                            .setUpdateType(org.apache.flink.api.common.state.StateTtlConfig.UpdateType.OnCreateAndWrite)
                            .setStateVisibility(org.apache.flink.api.common.state.StateTtlConfig.StateVisibility.NeverReturnExpired)
                            .cleanupInRocksdbCompactFilter(1000)
                            .build();

            ValueStateDescriptor<Long> countDesc =
                    new ValueStateDescriptor<>("ip-event-count", Types.LONG);
            countDesc.enableTimeToLive(stateTtl);
            eventCountState = getRuntimeContext().getState(countDesc);

            MapStateDescriptor<Long, Long> windowDesc =
                    new MapStateDescriptor<>("window-counts", Types.LONG, Types.LONG);
            windowDesc.enableTimeToLive(stateTtl);
            windowCountState = getRuntimeContext().getMapState(windowDesc);

            // 动态基线状态
            ValueStateDescriptor<Double> meanDesc =
                    new ValueStateDescriptor<>("freq-mean", Types.DOUBLE);
            meanDesc.enableTimeToLive(stateTtl);
            freqMeanState = getRuntimeContext().getState(meanDesc);

            ValueStateDescriptor<Double> m2Desc =
                    new ValueStateDescriptor<>("freq-m2", Types.DOUBLE);
            m2Desc.enableTimeToLive(stateTtl);
            freqM2State = getRuntimeContext().getState(m2Desc);

            ValueStateDescriptor<Long> samplesDesc =
                    new ValueStateDescriptor<>("baseline-samples", Types.LONG);
            samplesDesc.enableTimeToLive(stateTtl);
            baselineSamples = getRuntimeContext().getState(samplesDesc);

            // 告警风暴抑制状态
            ValueStateDescriptor<Long> alertWinDesc =
                    new ValueStateDescriptor<>("alert-window-start", Types.LONG);
            alertWinDesc.enableTimeToLive(stateTtl);
            alertWindowStart = getRuntimeContext().getState(alertWinDesc);

            ValueStateDescriptor<Integer> alertCntDesc =
                    new ValueStateDescriptor<>("alert-count-in-window", Types.INT);
            alertCntDesc.enableTimeToLive(stateTtl);
            alertCountInWindow = getRuntimeContext().getState(alertCntDesc);

            // Metrics
            org.apache.flink.metrics.MetricGroup group =
                    getRuntimeContext().getMetricGroup().addGroup("data_quality");
            totalEvents = group.counter("scoring_total");
            lateEvents = group.counter("scoring_late");
            alertEvents = group.counter("scoring_alerts");
            suppressedAlerts = group.counter("scoring_suppressed");
            coldStartSkips = group.counter("scoring_coldstart_skip");
        }

        @Override
        public void processElement(SecurityEvent event,
                                   KeyedProcessFunction<String, SecurityEvent, String>.Context ctx,
                                   Collector<String> out) throws Exception {

            totalEvents.inc();

            // ========== 迟到数据检测 ==========
            long currentWatermark = ctx.timerService().currentWatermark();
            boolean isLate = event.getTimestamp() < currentWatermark;
            if (isLate) {
                lateEvents.inc();
                Map<String, Object> raw = event.getRawData() != null ?
                        event.getRawData() : new HashMap<>();
                raw.put("_late", true);
                raw.put("_lateMs", currentWatermark - event.getTimestamp());
                event.setRawData(raw);
            }

            List<String> anomalyReasons = new ArrayList<>();
            Map<String, Double> scoreBreakdown = new HashMap<>();

            // ========== 冷启动检查 ==========
            Long currentCount = eventCountState.value();
            if (currentCount == null) currentCount = 0L;
            currentCount++;
            eventCountState.update(currentCount);
            boolean inColdStart = currentCount <= COLD_START_EVENTS;

            // ========== 维度 1: 严重级别权重 ==========
            double severityScore = getSeverityWeight(event.getSeverity());
            scoreBreakdown.put("severity", severityScore);
            if (severityScore >= 0.6) {
                anomalyReasons.add(String.format("高严重级别: severity=%s (分数=%.2f)",
                        event.getSeverity(), severityScore));
            }

            // ========== 维度 2: 频率异常（动态基线）==========
            long windowStart = (event.getTimestamp() / 300000) * 300000;
            Long windowCount = windowCountState.get(windowStart);
            if (windowCount == null) windowCount = 0L;
            windowCount++;
            windowCountState.put(windowStart, windowCount);
            cleanExpiredWindows(windowStart);

            // 更新动态基线（Welford 在线算法）
            updateBaseline(windowCount.doubleValue());

            double frequencyScore = 0.0;
            Double mean = freqMeanState.value();
            Double m2 = freqM2State.value();
            Long samples = baselineSamples.value();

            if (samples != null && samples > COLD_START_EVENTS && mean != null && m2 != null) {
                // 动态阈值: mean + 2σ
                double stddev = Math.sqrt(m2 / samples);
                double dynamicThreshold = mean + FREQ_SIGMA_FACTOR * stddev;
                if (windowCount > dynamicThreshold) {
                    frequencyScore = 0.3;
                    anomalyReasons.add(String.format(
                            "频率异常(动态): 5分钟 %d 事件 > 阈值 %.1f (μ=%.1f, σ=%.1f)",
                            windowCount, dynamicThreshold, mean, stddev));
                }
                scoreBreakdown.put("frequency", frequencyScore);
                scoreBreakdown.put("freq_mean", mean);
                scoreBreakdown.put("freq_stddev", stddev);
                scoreBreakdown.put("freq_threshold", dynamicThreshold);
            } else {
                // 冷启动期：使用静态阈值
                if (windowCount > 20) {
                    frequencyScore = 0.3;
                    anomalyReasons.add(String.format(
                            "频率异常(静态): 5分钟 %d 事件 > 阈值 20 (冷启动期)", windowCount));
                }
                scoreBreakdown.put("frequency", frequencyScore);
            }

            // ========== 维度 3: 时间异常 ==========
            int hour = Instant.ofEpochMilli(event.getTimestamp())
                    .atZone(ZoneId.of("Asia/Shanghai"))
                    .getHour();
            double timeScore = 0.0;
            if (hour >= 0 && hour < 5) {
                timeScore = 0.4;
                anomalyReasons.add(String.format("凌晨异常活动: %d:00 (分数=%.2f)", hour, timeScore));
            }
            scoreBreakdown.put("time", timeScore);

            // ========== 综合评分 ==========
            double rawScore = severityScore + frequencyScore + timeScore;
            double anomalyScore = Math.min(1.0, Math.max(0.0, rawScore));
            scoreBreakdown.put("total", anomalyScore);

            // ========== 附加到 rawData ==========
            Map<String, Object> rawData = event.getRawData();
            if (rawData == null) rawData = new HashMap<>();
            rawData.put("_anomalyScore", anomalyScore);
            rawData.put("_anomalyReasons", anomalyReasons);
            rawData.put("_scoreBreakdown", scoreBreakdown);
            rawData.put("_coldStart", inColdStart);
            rawData.put("_eventCount", currentCount);
            rawData.put("_windowCount", windowCount);
            event.setRawData(rawData);

            String enrichedJson = getMapper().writeValueAsString(event);

            // ========== 路由逻辑（含冷启动保护 + 风暴抑制）==========
            String severity = event.getSeverity() != null ? event.getSeverity().toLowerCase() : "";
            boolean isHighSeverity = "critical".equals(severity) || "high".equals(severity);
            boolean shouldAlert = (anomalyScore >= 0.6 || isHighSeverity) && !inColdStart;

            if (inColdStart && (anomalyScore >= 0.6 || isHighSeverity)) {
                coldStartSkips.inc();
                anomalyReasons.add("冷启动保护: 基线建立中，跳过告警");
            }

            if (shouldAlert) {
                // 告警风暴抑制：同 IP 5 分钟内最多 MAX_ALERTS_PER_WINDOW 条
                if (isAlertSuppressed(event.getTimestamp())) {
                    suppressedAlerts.inc();
                    rawData.put("_alertSuppressed", true);
                } else {
                    alertEvents.inc();
                    AlertEvent alert = buildAlert(event, anomalyScore, anomalyReasons, "ANOMALY");
                    String alertJson = getMapper().writeValueAsString(alert);
                    ctx.output(ALERT_TAG, alertJson);
                }
            } else if (anomalyScore >= 0.3 && !inColdStart) {
                ctx.output(AUDIT_TAG, enrichedJson);
            }

            out.collect(enrichedJson);
        }

        /** Welford 在线算法更新基线 */
        private void updateBaseline(double value) throws Exception {
            Long n = baselineSamples.value();
            if (n == null) n = 0L;
            Double mean = freqMeanState.value();
            if (mean == null) mean = 0.0;
            Double m2 = freqM2State.value();
            if (m2 == null) m2 = 0.0;

            n++;
            double delta = value - mean;
            mean += delta / n;
            double delta2 = value - mean;
            m2 += delta * delta2;

            baselineSamples.update(n);
            freqMeanState.update(mean);
            freqM2State.update(m2);
        }

        /** 告警风暴抑制检查 */
        private boolean isAlertSuppressed(long eventTimestamp) throws Exception {
            long windowStart = (eventTimestamp / 300000) * 300000;
            Long currentWindowStart = alertWindowStart.value();
            Integer count = alertCountInWindow.value();

            if (currentWindowStart == null || currentWindowStart != windowStart) {
                alertWindowStart.update(windowStart);
                alertCountInWindow.update(1);
                return false;
            }

            if (count != null && count >= MAX_ALERTS_PER_WINDOW) {
                return true;
            }

            alertCountInWindow.update((count != null ? count : 0) + 1);
            return false;
        }

        private double getSeverityWeight(String severity) {
            if (severity == null) return 0.0;
            switch (severity.toLowerCase()) {
                case "critical": return 1.0;
                case "high": return 0.6;
                case "medium": return 0.3;
                case "low": return 0.0;
                case "info": return -0.05;
                default: return 0.0;
            }
        }

        private void cleanExpiredWindows(long currentWindowStart) throws Exception {
            long previousWindowStart = currentWindowStart - 300000;
            List<Long> toRemove = new ArrayList<>();
            for (Map.Entry<Long, Long> entry : windowCountState.entries()) {
                if (entry.getKey() < previousWindowStart) {
                    toRemove.add(entry.getKey());
                }
            }
            for (Long key : toRemove) {
                windowCountState.remove(key);
            }
        }

        private AlertEvent buildAlert(SecurityEvent event, double score,
                                      List<String> reasons, String alertType) {
            AlertEvent alert = new AlertEvent();
            alert.setAlertId("ALERT-" + UUID.randomUUID().toString());
            alert.setEventType(event.getEventType());
            alert.setSeverity(event.getSeverity());
            alert.setSrcIp(event.getSrcIp());
            alert.setDstIp(event.getDstIp());
            alert.setMessage(String.format("异常检测告警: %s | 评分=%.2f | 源IP=%s",
                    event.getEventType(), score, event.getSrcIp()));
            alert.setAnomalyScore(score);
            alert.setAlertType(alertType);
            alert.setReasons(reasons);
            alert.setTimestamp(System.currentTimeMillis());
            alert.setTraceId(event.getTraceId());
            return alert;
        }
    }

    // ==================== JSON 解析函数 ====================

    /**
     * JSON String → SecurityEvent
     * 解析失败时记录日志并返回 null
     */
    public static class JsonToEventFunction implements MapFunction<String, SecurityEvent> {
        private transient ObjectMapper mapper;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public SecurityEvent map(String value) {
            try {
                if (value == null || value.trim().isEmpty()) {
                    return null;
                }
                return getMapper().readValue(value, SecurityEvent.class);
            } catch (Exception e) {
                LOG.warn("JSON 解析失败，跳过: {}", e.getMessage());
                return null;
            }
        }
    }
}
