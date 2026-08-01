package com.soc.job;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.AlertEvent;
import com.soc.model.SecurityEvent;
import com.soc.util.KafkaConfig;
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

    public static void main(String[] args) throws Exception {
        // 创建 Flink 执行环境
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        // 演示环境：单并行度
        env.setParallelism(1);
        // 启用 Checkpoint（每 60 秒）
        env.enableCheckpointing(60000);

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

        // 分配事件时间水印（使用事件自带时间戳）
        SingleOutputStreamOperator<SecurityEvent> timestampedStream = eventStream
                .assignTimestampsAndWatermarks(
                        WatermarkStrategy.<SecurityEvent>forBoundedOutOfOrderness(Duration.ofSeconds(10))
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

        // ==================== 5. 获取侧输出 ====================
        DataStream<String> alertStream = enrichedStream.getSideOutput(ALERT_TAG);
        DataStream<String> auditStream = enrichedStream.getSideOutput(AUDIT_TAG);

        // ==================== 6. 构建 Kafka Sinks ====================

        // Sink: security-events-enriched（所有富化事件）
        KafkaSink<String> enrichedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_ENRICHED_EVENTS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .build())
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
                        .build())
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
                        .build())
                .build();

        auditStream
                .sinkTo(auditSink)
                .name("Kafka-AuditQueue-Sink");

        // ==================== 7. 启动作业 ====================
        LOG.info("启动异常检测作业: AnomalyDetectionJob");
        LOG.info("Kafka Bootstrap: {}", KafkaConfig.KAFKA_BOOTSTRAP);
        LOG.info("输入 Topic: {}", KafkaConfig.TOPIC_VALIDATED_LOGS);
        LOG.info("输出 Topics: {} / {} / {}",
                KafkaConfig.TOPIC_ENRICHED_EVENTS, KafkaConfig.TOPIC_ALERTS, KafkaConfig.TOPIC_AUDIT_QUEUE);

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

            // 收集攻击链中所有事件类型
            List<String> reasons = new ArrayList<>();
            reasons.add(description);
            for (Map.Entry<String, List<SecurityEvent>> entry : pattern.entrySet()) {
                for (SecurityEvent evt : entry.getValue()) {
                    reasons.add(String.format("[%s] %s -> %s (%s)",
                            entry.getKey(), evt.getEventType(), evt.getDstIp(), evt.getMessage()));
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
            alert.setAnomalyScore(1.0); // 攻击链确认，最高分
            alert.setAlertType("ATTACK_CHAIN");
            alert.setReasons(reasons);
            alert.setTimestamp(System.currentTimeMillis());

            LOG.warn("🚨 攻击链检测 [{}]: srcIp={}, 事件数={}",
                    chainName, firstEvent.getSrcIp(), reasons.size() - 1);

            return getMapper().writeValueAsString(alert);
        }
    }

    // ==================== 异常评分函数 ====================

    /**
     * 异常评分核心逻辑（按 srcIp 分组）
     *
     * 评分维度：
     * 1. 频率异常：5分钟窗口内同一IP事件数 > 20 → +0.3
     * 2. 严重级别权重：critical=1.0, high=0.6, medium=0.3, low=0.0, info=-0.05
     * 3. 时间异常：凌晨 0-5 点活动 → +0.4
     *
     * 综合评分 = min(1.0, max(0.0, severityWeight + frequencyBoost + timeBoost))
     */
    public static class AnomalyScoringFunction
            extends KeyedProcessFunction<String, SecurityEvent, String> {

        /** 每个 IP 的累计事件计数 */
        private transient ValueState<Long> eventCountState;

        /** 5 分钟窗口内的事件计数（窗口起始时间 → 计数）*/
        private transient MapState<Long, Long> windowCountState;

        private transient ObjectMapper mapper;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public void open(Configuration parameters) {
            eventCountState = getRuntimeContext().getState(
                    new ValueStateDescriptor<>("ip-event-count", Types.LONG));
            windowCountState = getRuntimeContext().getMapState(
                    new MapStateDescriptor<>("window-counts", Types.LONG, Types.LONG));
        }

        @Override
        public void processElement(SecurityEvent event,
                                   KeyedProcessFunction<String, SecurityEvent, String>.Context ctx,
                                   Collector<String> out) throws Exception {

            List<String> anomalyReasons = new ArrayList<>();
            double score = 0.0;

            // ========== 维度 1: 严重级别权重 ==========
            double severityWeight = getSeverityWeight(event.getSeverity());
            score += severityWeight;
            if (severityWeight >= 0.6) {
                anomalyReasons.add(String.format("高严重级别事件: severity=%s (权重=%.2f)",
                        event.getSeverity(), severityWeight));
            }

            // ========== 维度 2: 频率异常检测 ==========
            // 更新累计计数
            Long currentCount = eventCountState.value();
            if (currentCount == null) {
                currentCount = 0L;
            }
            currentCount++;
            eventCountState.update(currentCount);

            // 计算 5 分钟窗口计数
            long windowStart = (event.getTimestamp() / 300000) * 300000; // 5分钟对齐
            Long windowCount = windowCountState.get(windowStart);
            if (windowCount == null) {
                windowCount = 0L;
            }
            windowCount++;
            windowCountState.put(windowStart, windowCount);

            // 清理过期窗口（保留最近 2 个窗口）
            cleanExpiredWindows(windowStart);

            // 频率异常判定：5分钟内超过 20 个事件
            if (windowCount > 20) {
                score += 0.3;
                anomalyReasons.add(String.format("频率异常: 5分钟内 %d 个事件 (阈值=20)", windowCount));
            }

            // ========== 维度 3: 时间异常（凌晨活动）==========
            int hour = Instant.ofEpochMilli(event.getTimestamp())
                    .atZone(ZoneId.of("Asia/Shanghai"))
                    .getHour();
            if (hour >= 0 && hour < 5) {
                score += 0.4;
                anomalyReasons.add(String.format("凌晨异常活动: %d:00 (正常工作时间外)", hour));
            }

            // ========== 综合评分归一化 [0, 1] ==========
            double anomalyScore = Math.min(1.0, Math.max(0.0, score));

            // ========== 将评分附加到事件的 rawData 中 ==========
            Map<String, Object> rawData = event.getRawData();
            if (rawData == null) {
                rawData = new HashMap<>();
            }
            rawData.put("_anomalyScore", anomalyScore);
            rawData.put("_anomalyReasons", anomalyReasons);
            rawData.put("_eventCount", currentCount);
            rawData.put("_windowCount", windowCount);
            event.setRawData(rawData);

            // ========== 序列化为 JSON ==========
            String enrichedJson = getMapper().writeValueAsString(event);

            // ========== 路由逻辑 ==========
            String severity = event.getSeverity() != null ? event.getSeverity().toLowerCase() : "";
            boolean isHighSeverity = "critical".equals(severity) || "high".equals(severity);

            if (anomalyScore >= 0.6 || isHighSeverity) {
                // 高优先级 → security-alerts
                AlertEvent alert = buildAlert(event, anomalyScore, anomalyReasons, "ANOMALY");
                String alertJson = getMapper().writeValueAsString(alert);
                ctx.output(ALERT_TAG, alertJson);
            } else if (anomalyScore >= 0.3) {
                // 中等风险 → security-audit-queue（LLM 审计）
                ctx.output(AUDIT_TAG, enrichedJson);
            }

            // 所有事件都输出到 enriched 流（主流）
            out.collect(enrichedJson);
        }

        /**
         * 严重级别权重映射
         * critical=1.0, high=0.6, medium=0.3, low=0.0, info=-0.05
         */
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

        /**
         * 清理过期的窗口计数（只保留当前窗口和前一个窗口）
         */
        private void cleanExpiredWindows(long currentWindowStart) throws Exception {
            long previousWindowStart = currentWindowStart - 300000;
            // 遍历并删除比前一个窗口更早的条目
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

        /**
         * 构建告警事件
         */
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
