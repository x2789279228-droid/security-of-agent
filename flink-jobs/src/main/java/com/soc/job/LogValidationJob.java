package com.soc.job;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.SecurityEvent;
import com.soc.util.KafkaConfig;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;
import org.apache.flink.util.OutputTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * 日志验证作业 (Job 1)
 *
 * 功能：
 * 1. 从 security-logs-raw 消费原始安全日志
 * 2. Schema 校验：检查必填字段 (eventType, severity, message)
 * 3. 来源认证：验证 apiKey 是否在白名单中
 * 4. 字段规范化：severity 映射、message 截断
 * 5. 去重：基于 (srcIp + eventType + messageHash) 的 60 秒滑动去重
 * 6. 有效事件 → security-logs-validated
 * 7. 无效事件 → security-logs-rejected (附带拒绝原因)
 */
public class LogValidationJob {

    private static final Logger LOG = LoggerFactory.getLogger(LogValidationJob.class);

    /** 侧输出标签：被拒绝的事件 */
    private static final OutputTag<String> REJECTED_TAG =
            new OutputTag<String>("rejected-logs") {};

    /** 合法 API Key 白名单 - 来源认证 */
    private static final Set<String> VALID_API_KEYS = new HashSet<>(Arrays.asList(
            "soc-syslog-2024",
            "soc-api-2024",
            "soc-simulator-2024"
    ));

    /** 数字严重级别到文本的映射 */
    private static final Map<String, String> SEVERITY_MAP = new HashMap<>();

    static {
        SEVERITY_MAP.put("10", "info");
        SEVERITY_MAP.put("30", "low");
        SEVERITY_MAP.put("50", "medium");
        SEVERITY_MAP.put("70", "high");
        SEVERITY_MAP.put("90", "critical");
    }

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
                .setTopics(KafkaConfig.TOPIC_RAW_LOGS)
                .setGroupId("log-validation-job")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setValueOnlyDeserializer(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                .build();

        // ==================== 2. 消费并解析 JSON ====================
        DataStream<String> rawStream = env.fromSource(
                kafkaSource,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(5)),
                "Kafka-RawLogs-Source"
        );

        // JSON 解析：String → SecurityEvent（解析失败则跳过）
        SingleOutputStreamOperator<SecurityEvent> parsedStream = rawStream
                .map(new JsonParseFunction())
                .filter(event -> event != null)
                .name("JSON-Parse");

        // ==================== 3. 验证 + 去重（Keyed ProcessFunction）====================
        // 按 srcIp 分组，用于去重状态管理
        SingleOutputStreamOperator<SecurityEvent> validatedStream = parsedStream
                .keyBy(event -> event.getSrcIp() != null ? event.getSrcIp() : "unknown")
                .process(new ValidationAndDedupFunction())
                .name("Validate-And-Dedup");

        // ==================== 4. 获取侧输出（被拒绝的事件）====================
        DataStream<String> rejectedStream = validatedStream.getSideOutput(REJECTED_TAG);

        // ==================== 5. 构建 Kafka Sink - 已验证事件 ====================
        KafkaSink<String> validatedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_VALIDATED_LOGS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .build())
                .build();

        // 有效事件序列化为 JSON 后写入 validated topic
        validatedStream
                .map(new EventToJsonFunction())
                .name("Serialize-Valid")
                .sinkTo(validatedSink)
                .name("Kafka-Validated-Sink");

        // ==================== 6. 构建 Kafka Sink - 被拒绝事件 ====================
        KafkaSink<String> rejectedSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.KAFKA_BOOTSTRAP)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_REJECTED_LOGS)
                        .setValueSerializationSchema(new org.apache.flink.api.common.serialization.SimpleStringSchema())
                        .build())
                .build();

        rejectedStream
                .sinkTo(rejectedSink)
                .name("Kafka-Rejected-Sink");

        // ==================== 7. 启动作业 ====================
        LOG.info("启动日志验证作业: LogValidationJob");
        LOG.info("Kafka Bootstrap: {}", KafkaConfig.KAFKA_BOOTSTRAP);
        LOG.info("输入 Topic: {}", KafkaConfig.TOPIC_RAW_LOGS);
        LOG.info("输出 Topic: {} / {}", KafkaConfig.TOPIC_VALIDATED_LOGS, KafkaConfig.TOPIC_REJECTED_LOGS);

        env.execute("LogValidationJob");
    }

    // ==================== JSON 解析函数 ====================

    /**
     * 将原始 JSON 字符串解析为 SecurityEvent
     * 解析失败时记录日志并返回 null（后续 filter 过滤）
     */
    public static class JsonParseFunction implements MapFunction<String, SecurityEvent> {
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
                SecurityEvent event = getMapper().readValue(value, SecurityEvent.class);
                // 如果没有 eventId，自动生成
                if (event.getEventId() == null || event.getEventId().isEmpty()) {
                    event.setEventId(UUID.randomUUID().toString());
                }
                // 如果没有时间戳，使用当前时间
                if (event.getTimestamp() == 0) {
                    event.setTimestamp(System.currentTimeMillis());
                }
                return event;
            } catch (Exception e) {
                LOG.warn("JSON 解析失败，跳过该消息: {}", e.getMessage());
                return null;
            }
        }
    }

    // ==================== 验证 + 去重处理函数 ====================

    /**
     * 核心验证逻辑：
     * 1. Schema 校验 - 必填字段检查
     * 2. 来源认证 - API Key 白名单验证
     * 3. 字段规范化 - severity 映射、message 截断
     * 4. 去重 - 60 秒内相同 (srcIp+eventType+messageHash) 的事件只保留第一条
     */
    public static class ValidationAndDedupFunction
            extends KeyedProcessFunction<String, SecurityEvent, SecurityEvent> {

        /** 去重状态：存储事件指纹，60 秒 TTL */
        private transient ValueState<String> dedupState;

        private transient ObjectMapper mapper;

        private ObjectMapper getMapper() {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper;
        }

        @Override
        public void open(Configuration parameters) {
            // 配置去重状态，TTL 60 秒
            ValueStateDescriptor<String> descriptor = new ValueStateDescriptor<>(
                    "dedup-fingerprint", Types.STRING);
            // 注意：Flink 1.18 中 TTL 通过 StateTtlConfig 配置
            org.apache.flink.api.common.state.StateTtlConfig ttlConfig =
                    org.apache.flink.api.common.state.StateTtlConfig.newBuilder(
                                    org.apache.flink.api.common.time.Time.seconds(60))
                            .setUpdateType(org.apache.flink.api.common.state.StateTtlConfig.UpdateType.OnCreateAndWrite)
                            .setStateVisibility(org.apache.flink.api.common.state.StateTtlConfig.StateVisibility.NeverReturnExpired)
                            .build();
            descriptor.enableTimeToLive(ttlConfig);
            dedupState = getRuntimeContext().getState(descriptor);
        }

        @Override
        public void processElement(SecurityEvent event,
                                   KeyedProcessFunction<String, SecurityEvent, SecurityEvent>.Context ctx,
                                   Collector<SecurityEvent> out) {

            // ========== 第一步：Schema 校验 ==========
            String schemaError = validateSchema(event);
            if (schemaError != null) {
                emitRejected(ctx, event, "SCHEMA_VALIDATION_FAILED", schemaError);
                return;
            }

            // ========== 第二步：来源认证 ==========
            String authError = validateApiKey(event);
            if (authError != null) {
                emitRejected(ctx, event, "AUTHENTICATION_FAILED", authError);
                return;
            }

            // ========== 第三步：字段规范化 ==========
            normalizeEvent(event);

            // ========== 第四步：去重检查 ==========
            try {
                String fingerprint = computeFingerprint(event);
                String existing = dedupState.value();
                if (existing != null && existing.equals(fingerprint)) {
                    // 60 秒内重复事件，丢弃
                    emitRejected(ctx, event, "DUPLICATE",
                            "60秒内重复事件: fingerprint=" + fingerprint);
                    return;
                }
                // 更新去重状态
                dedupState.update(fingerprint);
            } catch (Exception e) {
                LOG.warn("去重状态访问异常: {}", e.getMessage());
                // 状态异常不影响主流程，继续处理
            }

            // ========== 验证通过，输出有效事件 ==========
            out.collect(event);
        }

        /**
         * Schema 校验：检查必填字段
         */
        private String validateSchema(SecurityEvent event) {
            if (event.getEventType() == null || event.getEventType().trim().isEmpty()) {
                return "缺少必填字段: eventType";
            }
            if (event.getSeverity() == null || event.getSeverity().trim().isEmpty()) {
                return "缺少必填字段: severity";
            }
            if (event.getMessage() == null || event.getMessage().trim().isEmpty()) {
                return "缺少必填字段: message";
            }
            return null;
        }

        /**
         * 来源认证：验证 API Key 是否在白名单中
         */
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
         * 字段规范化：
         * - severity 转小写
         * - 数字 severity 映射为文本
         * - message 截断到 500 字符
         */
        private void normalizeEvent(SecurityEvent event) {
            // severity 规范化
            String severity = event.getSeverity().trim().toLowerCase();
            // 检查是否为数字级别，进行映射
            if (SEVERITY_MAP.containsKey(severity)) {
                severity = SEVERITY_MAP.get(severity);
            }
            event.setSeverity(severity);

            // message 截断（防止超长日志）
            String message = event.getMessage();
            if (message != null && message.length() > 500) {
                event.setMessage(message.substring(0, 500));
            }

            // eventType 转大写（统一格式）
            if (event.getEventType() != null) {
                event.setEventType(event.getEventType().trim().toUpperCase());
            }
        }

        /**
         * 计算事件指纹：srcIp + eventType + MD5(message)
         * 用于 60 秒窗口内去重
         */
        private String computeFingerprint(SecurityEvent event) {
            String srcIp = event.getSrcIp() != null ? event.getSrcIp() : "";
            String eventType = event.getEventType() != null ? event.getEventType() : "";
            String message = event.getMessage() != null ? event.getMessage() : "";

            String raw = srcIp + "|" + eventType + "|" + md5(message);
            return raw;
        }

        /**
         * MD5 哈希（用于 message 去重指纹）
         */
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
                // MD5 不可用时退化为 hashCode
                return String.valueOf(input.hashCode());
            }
        }

        /**
         * 输出被拒绝的事件到侧输出流
         * 格式：JSON { originalEvent, rejectionReason, rejectionType, timestamp }
         */
        private void emitRejected(KeyedProcessFunction<String, SecurityEvent, SecurityEvent>.Context ctx,
                                  SecurityEvent event, String rejectionType, String reason) {
            try {
                Map<String, Object> rejected = new HashMap<>();
                rejected.put("originalEvent", event);
                rejected.put("rejectionType", rejectionType);
                rejected.put("rejectionReason", reason);
                rejected.put("rejectedAt", System.currentTimeMillis());
                rejected.put("jobName", "LogValidationJob");

                String json = getMapper().writeValueAsString(rejected);
                ctx.output(REJECTED_TAG, json);

                LOG.debug("事件被拒绝 [{}]: {} - {}", rejectionType, event.getEventType(), reason);
            } catch (Exception e) {
                LOG.error("序列化被拒绝事件失败: {}", e.getMessage());
            }
        }
    }

    // ==================== 事件序列化函数 ====================

    /**
     * SecurityEvent → JSON String
     */
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
