package com.soc.job;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.SecurityEvent;
import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.metrics.Counter;
import org.apache.flink.metrics.Gauge;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.streaming.api.functions.ProcessFunction;
import org.apache.flink.util.Collector;
import org.apache.flink.util.OutputTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 日志验证作业 (Job 1) — 增强版
 *
 * 功能：
 * 1. 从 security-logs-raw 消费原始安全日志
 * 2. JSON 解析（失败 → rejected，不再静默丢弃）
 * 3. Schema 校验：必填字段 + 类型 + 范围 + 枚举
 * 4. 字段标准化：severity 映射、eventType 大写、protocol 小写、IP 校验、时间戳校验
 * 5. 来源认证：API Key 白名单
 * 6. 去重：(srcIp + eventType + messageHash) 60 秒滑动窗口
 * 7. 数据质量指标：Flink Metrics (Counter/Gauge)
 * 8. 有效事件 → security-logs-validated
 * 9. 无效事件 → security-logs-rejected (附带拒绝原因 + 原始消息)
 */
public class LogValidationJob {

    private static final Logger LOG = LoggerFactory.getLogger(LogValidationJob.class);

    /** 侧输出标签：被拒绝的事件 */
    private static final OutputTag<String> REJECTED_TAG =
            new OutputTag<String>("rejected-logs") {};

    /** 合法 API Key 白名单 */
    private static final Set<String> VALID_API_KEYS = new HashSet<>(Arrays.asList(
            "soc-syslog-2024",
            "soc-api-2024",
            "soc-simulator-2024"
    ));

    /** 数字严重级别到文本的映射 */
    private static final Map<String, String> SEVERITY_MAP = new HashMap<>();

    /** 合法 severity 枚举 */
    private static final Set<String> VALID_SEVERITIES = new HashSet<>(
            Arrays.asList("info", "low", "medium", "high", "critical"));

    /** 合法 eventType 枚举（已知类型，未知类型允许通过但标记） */
    private static final Set<String> KNOWN_EVENT_TYPES = new HashSet<>(Arrays.asList(
            "USER_LOGIN", "FILE_ACCESS", "DNS_QUERY", "EMAIL_SENT", "VPN_CONNECT",
            "SERVICE_START", "BACKUP_COMPLETE", "CERT_RENEW",
            "PORT_SCAN", "BRUTE_FORCE", "SQL_INJECTION", "C2_BEACON",
            "DATA_EXFIL", "MALWARE_DETECT", "DDOS_TRAFFIC", "LATERAL_MOVE",
            "PRIVILEGE_ESCALATION", "XSS_ATTACK", "SUSPICIOUS_LOGIN",
            "FIREWALL_BLOCK", "CONN_REFUSED", "PROCESS_CRASH", "SYSLOG_EVENT"
    ));

    /** IPv4 正则 */
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");

    /** 时间戳合理范围：2020-01-01 ~ 2030-12-31 */
    private static final long TS_MIN = 1577836800000L;
    private static final long TS_MAX = 1924991999000L;

    static {
        SEVERITY_MAP.put("10", "info");
        SEVERITY_MAP.put("30", "low");
        SEVERITY_MAP.put("50", "medium");
        SEVERITY_MAP.put("70", "high");
        SEVERITY_MAP.put("90", "critical");
    }

    public static void main(String[] args) throws Exception {
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        // 并行度/checkpoint 由 flink-conf.yaml 统一配置 (生产级: parallelism.default /
        // execution.checkpointing.*), 不在代码硬编码, 便于按分区弹性扩容

        // ==================== 1. Kafka Source ====================
        KafkaSource<String> kafkaSource = KafkaSource.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setTopics(KafkaConfig.TOPIC_RAW_LOGS)
                .setGroupId("log-validation-job")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setValueOnlyDeserializer(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                .build();

        DataStream<String> rawStream = env.fromSource(
                kafkaSource,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(5)),
                "Kafka-RawLogs-Source"
        );

        // ==================== 2. JSON 解析（失败 → rejected 侧输出）====================
        SingleOutputStreamOperator<SecurityEvent> parsedStream = rawStream
                .process(new JsonParseProcessFunction())
                .name("JSON-Parse-With-Reject");

        DataStream<String> parseRejectedStream = parsedStream.getSideOutput(REJECTED_TAG);

        // ==================== 3. 验证 + 标准化 + 去重 ====================
        SingleOutputStreamOperator<SecurityEvent> validatedStream = parsedStream
                .keyBy(event -> event.getSrcIp() != null ? event.getSrcIp() : "unknown")
                .process(new ValidationAndDedupFunction())
                .name("Validate-Normalize-Dedup");

        DataStream<String> validationRejectedStream = validatedStream.getSideOutput(REJECTED_TAG);

        // ==================== 4. 合并所有 rejected 流 ====================
        DataStream<String> allRejectedStream = parseRejectedStream
                .union(validationRejectedStream);

        // ==================== 4.5 数据源信誉评分 ====================
        SingleOutputStreamOperator<SecurityEvent> scoredStream = validatedStream
                .keyBy(event -> event.getSourceId() != null ? event.getSourceId() : "unknown")
                .process(new SourceReputationFunction())
                .name("Source-Reputation-Scoring");

        // ==================== 5. Kafka Sink - 已验证事件 ====================
        KafkaSink<String> validatedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                // 值=JSON + trace_id header (全链路追踪, TraceIdHeaderProvider)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_VALIDATED_LOGS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                // Exactly-Once: 依赖 checkpoint, 保证重启/重放不重不漏
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-logval")
                .build();

        scoredStream
                .map(new EventToJsonFunction())
                .name("Serialize-Valid")
                .sinkTo(validatedSink)
                .name("Kafka-Validated-Sink");

        // ==================== 6. Kafka Sink - 被拒绝事件 ====================
        KafkaSink<String> rejectedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_REJECTED_LOGS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-logval-rej")
                .build();

        allRejectedStream
                .sinkTo(rejectedSink)
                .name("Kafka-Rejected-Sink");

        // ==================== 7. 启动 ====================
        LOG.info("启动日志验证作业 (增强版): LogValidationJob");
        LOG.info("Kafka Bootstrap: {}", KafkaConfig.KAFKA_BOOTSTRAP);
        LOG.info("输入 Topic: {}", KafkaConfig.TOPIC_RAW_LOGS);
        LOG.info("输出 Topic: {} / {}", KafkaConfig.TOPIC_VALIDATED_LOGS, KafkaConfig.TOPIC_REJECTED_LOGS);

        env.execute("LogValidationJob");
    }

    // ==================== JSON 解析（ProcessFunction，支持侧输出）====================

    /**
     * JSON 解析 — 解析失败不再静默丢弃，而是发送到 rejected 侧输出
     */
    public static class JsonParseProcessFunction
            extends ProcessFunction<String, SecurityEvent> {

        private transient ObjectMapper mapper;
        private transient Counter parseSuccessCounter;
        private transient Counter parseFailCounter;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public void open(Configuration parameters) {
            parseSuccessCounter = getRuntimeContext().getMetricGroup()
                    .addGroup("data_quality").counter("json_parse_success");
            parseFailCounter = getRuntimeContext().getMetricGroup()
                    .addGroup("data_quality").counter("json_parse_fail");
        }

        @Override
        public void processElement(String value, Context ctx, Collector<SecurityEvent> out) {
            try {
                if (value == null || value.trim().isEmpty()) {
                    parseFailCounter.inc();
                    emitParseRejected(ctx, value, "EMPTY_MESSAGE", "消息为空");
                    return;
                }
                SecurityEvent event = getMapper().readValue(value, SecurityEvent.class);
                if (event.getEventId() == null || event.getEventId().isEmpty()) {
                    event.setEventId(UUID.randomUUID().toString());
                }
                if (event.getTimestamp() == 0) {
                    event.setTimestamp(System.currentTimeMillis());
                }
                if (event.getTraceId() == null || event.getTraceId().isEmpty()) {
                    event.setTraceId(event.getEventId());
                }
                parseSuccessCounter.inc();
                out.collect(event);
            } catch (Exception e) {
                parseFailCounter.inc();
                emitParseRejected(ctx, value, "JSON_PARSE_ERROR",
                        "JSON 解析失败: " + e.getMessage());
            }
        }

        private void emitParseRejected(Context ctx, String rawMessage,
                                       String rejectionType, String reason) {
            try {
                Map<String, Object> rejected = new HashMap<>();
                rejected.put("rawMessage", rawMessage != null ?
                        rawMessage.substring(0, Math.min(rawMessage.length(), 2000)) : "null");
                rejected.put("rejectionType", rejectionType);
                rejected.put("rejectionReason", reason);
                rejected.put("rejectedAt", System.currentTimeMillis());
                rejected.put("jobName", "LogValidationJob");
                rejected.put("stage", "JSON_PARSE");

                ctx.output(REJECTED_TAG, getMapper().writeValueAsString(rejected));
                LOG.warn("JSON 解析失败 → rejected: {}", reason);
            } catch (Exception e) {
                LOG.error("序列化解析失败记录异常: {}", e.getMessage());
            }
        }
    }

    // ==================== 验证 + 标准化 + 去重 ====================

    /**
     * 核心验证逻辑（增强版）：
     * 1. Schema 校验 - 必填字段 + 枚举 + 范围
     * 2. 字段标准化 - severity/eventType/protocol/IP/timestamp
     * 3. 来源认证 - API Key 白名单
     * 4. 去重 - 60 秒指纹窗口
     * 5. 数据质量指标 - Flink Metrics
     */
    public static class ValidationAndDedupFunction
            extends KeyedProcessFunction<String, SecurityEvent, SecurityEvent> {

        private transient ValueState<String> dedupState;
        private transient ObjectMapper mapper;

        // ── 数据质量指标 ──
        private transient Counter totalCounter;
        private transient Counter validCounter;
        private transient Counter schemaFailCounter;
        private transient Counter authFailCounter;
        private transient Counter dupCounter;
        private transient Counter fieldFixCounter;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public void open(Configuration parameters) {
            ValueStateDescriptor<String> descriptor = new ValueStateDescriptor<>(
                    "dedup-fingerprint", Types.STRING);
            org.apache.flink.api.common.state.StateTtlConfig ttlConfig =
                    org.apache.flink.api.common.state.StateTtlConfig.newBuilder(
                                    org.apache.flink.api.common.time.Time.seconds(60))
                            .setUpdateType(org.apache.flink.api.common.state.StateTtlConfig.UpdateType.OnCreateAndWrite)
                            .setStateVisibility(org.apache.flink.api.common.state.StateTtlConfig.StateVisibility.NeverReturnExpired)
                            .build();
            descriptor.enableTimeToLive(ttlConfig);
            dedupState = getRuntimeContext().getState(descriptor);

            // 注册数据质量指标
            org.apache.flink.metrics.MetricGroup group =
                    getRuntimeContext().getMetricGroup().addGroup("data_quality");
            totalCounter = group.counter("events_total");
            validCounter = group.counter("events_valid");
            schemaFailCounter = group.counter("events_schema_fail");
            authFailCounter = group.counter("events_auth_fail");
            dupCounter = group.counter("events_duplicate");
            fieldFixCounter = group.counter("fields_normalized");

            // 有效率 Gauge
            group.gauge("valid_rate", (Gauge<Double>) () -> {
                long total = totalCounter.getCount();
                return total == 0 ? 1.0 : (double) validCounter.getCount() / total;
            });
        }

        @Override
        public void processElement(SecurityEvent event,
                                   KeyedProcessFunction<String, SecurityEvent, SecurityEvent>.Context ctx,
                                   Collector<SecurityEvent> out) {

            totalCounter.inc();

            // ========== 第一步：Schema 校验（增强）==========
            String schemaError = validateSchemaEnhanced(event);
            if (schemaError != null) {
                schemaFailCounter.inc();
                emitRejected(ctx, event, "SCHEMA_VALIDATION_FAILED", schemaError);
                return;
            }

            // ========== 第二步：来源认证 ==========
            String authError = validateApiKey(event);
            if (authError != null) {
                authFailCounter.inc();
                emitRejected(ctx, event, "AUTHENTICATION_FAILED", authError);
                return;
            }

            // ========== 第三步：字段标准化（增强）==========
            int fixes = normalizeEventEnhanced(event);
            fieldFixCounter.inc(fixes);

            // ========== 第四步：去重 ==========
            try {
                String fingerprint = computeFingerprint(event);
                String existing = dedupState.value();
                if (existing != null && existing.equals(fingerprint)) {
                    dupCounter.inc();
                    emitRejected(ctx, event, "DUPLICATE",
                            "60秒内重复事件: fingerprint=" + fingerprint);
                    return;
                }
                dedupState.update(fingerprint);
            } catch (Exception e) {
                LOG.warn("去重状态访问异常: {}", e.getMessage());
            }

            // ========== 验证通过 ==========
            validCounter.inc();
            out.collect(event);
        }

        /**
         * 增强 Schema 校验：
         * - 必填字段非空
         * - severity 枚举校验（映射后）
         * - confidence 范围 [0, 100]
         * - timestamp 合理性 [2020, 2030]
         * - srcIp/dstIp IPv4 格式（非空时）
         */
        private String validateSchemaEnhanced(SecurityEvent event) {
            // 必填字段
            if (event.getEventType() == null || event.getEventType().trim().isEmpty()) {
                return "缺少必填字段: eventType";
            }
            if (event.getSeverity() == null || event.getSeverity().trim().isEmpty()) {
                return "缺少必填字段: severity";
            }
            if (event.getMessage() == null || event.getMessage().trim().isEmpty()) {
                return "缺少必填字段: message";
            }

            // severity 枚举（先映射再校验）
            String severity = event.getSeverity().trim().toLowerCase();
            if (SEVERITY_MAP.containsKey(severity)) {
                severity = SEVERITY_MAP.get(severity);
            }
            if (!VALID_SEVERITIES.contains(severity)) {
                return "无效的 severity 值: " + event.getSeverity()
                        + " (合法: info/low/medium/high/critical 或 10/30/50/70/90)";
            }

            // confidence 范围
            if (event.getConfidence() < 0 || event.getConfidence() > 100) {
                return "confidence 超出范围 [0,100]: " + event.getConfidence();
            }

            // timestamp 合理性
            long ts = event.getTimestamp();
            if (ts < TS_MIN || ts > TS_MAX) {
                return "时间戳超出合理范围 [2020,2030]: " + ts
                        + " (" + Instant.ofEpochMilli(ts) + ")";
            }

            // IP 格式校验（非空时）
            if (event.getSrcIp() != null && !event.getSrcIp().isEmpty()
                    && !isValidIpv4(event.getSrcIp())) {
                return "无效的 srcIp 格式: " + event.getSrcIp();
            }
            if (event.getDstIp() != null && !event.getDstIp().isEmpty()
                    && !isValidIpv4(event.getDstIp())) {
                return "无效的 dstIp 格式: " + event.getDstIp();
            }

            return null;
        }

        private boolean isValidIpv4(String ip) {
            return IPV4_PATTERN.matcher(ip.trim()).matches();
        }

        private String validateApiKey(SecurityEvent event) {
            String apiKey = event.getApiKey();
            if (apiKey == null || apiKey.trim().isEmpty()) {
                return "缺少 API Key，无法验证来源";
            }
            if (!VALID_API_KEYS.contains(apiKey.trim())) {
                return "无效的 API Key: " + apiKey + "，不在授权白名单中";
            }
            return null;
        }

        /**
         * 增强字段标准化：
         * - severity: 数字→文本 + 小写
         * - eventType: 大写 + trim
         * - protocol: 小写 + trim
         * - message: 截断 500 字符
         * - srcIp/dstIp: trim
         * - timestamp: 秒→毫秒自动修正
         *
         * @return 修正的字段数量
         */
        private int normalizeEventEnhanced(SecurityEvent event) {
            int fixes = 0;

            // severity 规范化
            String severity = event.getSeverity().trim().toLowerCase();
            if (SEVERITY_MAP.containsKey(severity)) {
                event.setSeverity(SEVERITY_MAP.get(severity));
                fixes++;
            } else if (!severity.equals(event.getSeverity())) {
                event.setSeverity(severity);
                fixes++;
            }

            // eventType 大写
            if (event.getEventType() != null) {
                String normalized = event.getEventType().trim().toUpperCase();
                if (!normalized.equals(event.getEventType())) {
                    event.setEventType(normalized);
                    fixes++;
                }
            }

            // protocol 小写
            if (event.getProtocol() != null && !event.getProtocol().isEmpty()) {
                String normalized = event.getProtocol().trim().toLowerCase();
                if (!normalized.equals(event.getProtocol())) {
                    event.setProtocol(normalized);
                    fixes++;
                }
            }

            // message 截断
            if (event.getMessage() != null && event.getMessage().length() > 500) {
                event.setMessage(event.getMessage().substring(0, 500));
                fixes++;
            }

            // IP trim
            if (event.getSrcIp() != null) {
                String trimmed = event.getSrcIp().trim();
                if (!trimmed.equals(event.getSrcIp())) {
                    event.setSrcIp(trimmed);
                    fixes++;
                }
            }
            if (event.getDstIp() != null) {
                String trimmed = event.getDstIp().trim();
                if (!trimmed.equals(event.getDstIp())) {
                    event.setDstIp(trimmed);
                    fixes++;
                }
            }

            // timestamp 秒→毫秒修正（如果值看起来是秒级）
            long ts = event.getTimestamp();
            if (ts > 0 && ts < 10000000000L) {
                event.setTimestamp(ts * 1000);
                fixes++;
            }

            return fixes;
        }

        private String computeFingerprint(SecurityEvent event) {
            String srcIp = event.getSrcIp() != null ? event.getSrcIp() : "";
            String eventType = event.getEventType() != null ? event.getEventType() : "";
            String message = event.getMessage() != null ? event.getMessage() : "";
            return srcIp + "|" + eventType + "|" + md5(message);
        }

        private String md5(String input) {
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            } catch (Exception e) {
                return String.valueOf(input.hashCode());
            }
        }

        private void emitRejected(KeyedProcessFunction<String, SecurityEvent, SecurityEvent>.Context ctx,
                                  SecurityEvent event, String rejectionType, String reason) {
            try {
                Map<String, Object> rejected = new HashMap<>();
                rejected.put("originalEvent", event);
                rejected.put("rejectionType", rejectionType);
                rejected.put("rejectionReason", reason);
                rejected.put("rejectedAt", System.currentTimeMillis());
                rejected.put("jobName", "LogValidationJob");
                rejected.put("stage", "VALIDATION");

                String json = getMapper().writeValueAsString(rejected);
                ctx.output(REJECTED_TAG, json);

                LOG.debug("事件被拒绝 [{}]: {} - {}", rejectionType, event.getEventType(), reason);
            } catch (Exception e) {
                LOG.error("序列化被拒绝事件失败: {}", e.getMessage());
            }
        }
    }

    // ==================== 事件序列化 ====================

    public static class EventToJsonFunction implements MapFunction<SecurityEvent, String> {
        private transient ObjectMapper mapper;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public String map(SecurityEvent event) throws Exception {
            return getMapper().writeValueAsString(event);
        }
    }
}
