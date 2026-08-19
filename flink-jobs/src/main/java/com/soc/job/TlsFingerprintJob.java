package com.soc.job;

import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.api.common.state.MapStateDescriptor;
import org.apache.flink.api.common.typeinfo.BasicTypeInfo;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.BroadcastStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.co.BroadcastProcessFunction;
import org.apache.flink.util.Collector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * Flink Job 4: TLS 指纹实时计算与恶意匹配
 *
 * 从 ndr-tls-sessions Topic 消费 TLS 会话元数据（JSON），
 * 实时计算 JA3 指纹（MD5），并与广播的已知恶意指纹库匹配。
 *
 * 处理逻辑:
 *   1. 解析 TLS 会话 JSON（含 ja3_fields 原始字段）
 *   2. 计算 JA3 哈希: MD5(version,ciphers,extensions,curves,point_formats)
 *   3. 广播恶意指纹库（从 security-cep-patterns Topic 动态更新）
 *   4. 命中恶意指纹 → 生成告警 → security-alerts
 *   5. 所有记录附加 ja3_hash → ndr-tls-enriched
 */
public class TlsFingerprintJob {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // 广播状态描述符: 恶意 JA3 指纹集合
    private static final MapStateDescriptor<String, Set<String>> MALICIOUS_JA3_STATE =
            new MapStateDescriptor<>(
                    "malicious-ja3",
                    BasicTypeInfo.STRING_TYPE_INFO,
                    new org.apache.flink.api.common.typeinfo.TypeHint<Set<String>>() {}.getTypeInfo()
            );

    public static void main(String[] args) throws Exception {
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        // checkpoint 由 flink-conf.yaml 统一配置 (生产级)

        String bootstrap = KafkaConfig.getBootstrapServers();

        // Source 1: TLS 会话流
        KafkaSource<String> tlsSource = KafkaSource.<String>builder()
                .setBootstrapServers(bootstrap)
                .setTopics("ndr-tls-sessions")
                .setGroupId("flink-tls-fingerprint")
                .setStartingOffsets(OffsetsInitializer.latest())
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        DataStream<String> tlsStream = env.fromSource(
                tlsSource,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(5)),
                "TLS Sessions Source"
        );

        // Source 2: 恶意指纹更新流（复用 cep-patterns Topic 做配置下发）
        KafkaSource<String> patternSource = KafkaSource.<String>builder()
                .setBootstrapServers(bootstrap)
                .setTopics("security-cep-patterns")
                .setGroupId("flink-tls-fingerprint-patterns")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        BroadcastStream<String> patternStream = env.fromSource(
                patternSource,
                WatermarkStrategy.noWatermarks(),
                "JA3 Pattern Updates"
        ).broadcast(MALICIOUS_JA3_STATE);

        // 连接 TLS 流与广播指纹库，执行匹配
        DataStream<String> enriched = tlsStream
                .connect(patternStream)
                .process(new TlsFingerprintFunction());

        // Sink 1: ndr-tls-enriched（所有记录，附加 ja3_hash）
        KafkaSink<String> enrichedSink = KafkaSink.<String>builder()
                .setBootstrapServers(bootstrap)
                .setRecordSerializer(
                        KafkaRecordSerializationSchema.builder()
                                .setTopic("ndr-tls-enriched")
                                .setValueSerializationSchema(new SimpleStringSchema())
                                .setHeaderProvider(new TraceIdHeaderProvider())
                                .build()
                )
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-tls")
                .build();

        enriched.sinkTo(enrichedSink);

        // Sink 2: security-alerts（命中恶意指纹的告警）
        // 通过侧输出流实现（在 TlsFingerprintFunction 中通过 OutputTag）
        // 简化实现: 告警直接写入 enriched 流，由后端 kafka_consumer 根据 alert 字段路由
        // 生产环境应使用 OutputTag 分流

        env.execute("TLS Fingerprint Job");
    }

    /**
     * TLS 指纹计算 + 恶意匹配
     */
    public static class TlsFingerprintFunction
            extends BroadcastProcessFunction<String, String, String> {

        // 内存中的恶意 JA3 集合（由广播流更新）
        private final Set<String> maliciousJa3Set = new HashSet<>();

        @Override
        public void processBroadcastElement(String pattern, Context ctx, Collector<String> out) throws Exception {
            // 解析指纹更新消息: {"type":"ja3_update","hashes":["abc123","def456"]}
            try {
                JsonNode node = MAPPER.readTree(pattern);
                if (node.has("type") && "ja3_update".equals(node.get("type").asText())) {
                    JsonNode hashes = node.get("hashes");
                    if (hashes != null && hashes.isArray()) {
                        maliciousJa3Set.clear();
                        for (JsonNode h : hashes) {
                            maliciousJa3Set.add(h.asText().toLowerCase());
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            // 同步到广播状态（供故障恢复）
            ctx.getBroadcastState(MALICIOUS_JA3_STATE).put("malicious_set", new HashSet<>(maliciousJa3Set));
        }

        @Override
        public void processElement(String record, ReadOnlyContext ctx, Collector<String> out) throws Exception {
            try {
                JsonNode node = MAPPER.readTree(record);
                ObjectNode result = (ObjectNode) node.deepCopy();

                // 计算 JA3（如果尚未计算）
                String ja3Hash = "";
                if (node.has("ja3_hash") && !node.get("ja3_hash").asText().isEmpty()) {
                    ja3Hash = node.get("ja3_hash").asText().toLowerCase();
                } else if (node.has("ja3_fields")) {
                    ja3Hash = computeJa3(node.get("ja3_fields"));
                    result.put("ja3_hash", ja3Hash);
                }

                // 恶意匹配
                boolean isMalicious = !ja3Hash.isEmpty() && maliciousJa3Set.contains(ja3Hash);
                result.put("ja3_malicious_match", isMalicious);

                if (isMalicious) {
                    result.put("alert", true);
                    result.put("alert_type", "MALICIOUS_JA3");
                    result.put("alert_message", "TLS 客户端指纹命中已知恶意 JA3: " + ja3Hash);
                }

                out.collect(MAPPER.writeValueAsString(result));
            } catch (Exception ignored) {
                // 解析失败直接透传
                out.collect(record);
            }
        }

        /**
         * 计算 JA3 指纹: MD5(version,ciphers,extensions,curves,point_formats)
         */
        private String computeJa3(JsonNode fields) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append(fields.has("version") ? fields.get("version").asInt() : 771);
                sb.append(",");

                // ciphers
                if (fields.has("ciphers") && fields.get("ciphers").isArray()) {
                    StringBuilder cs = new StringBuilder();
                    for (JsonNode c : fields.get("ciphers")) {
                        int val = c.asInt();
                        if (!isGrease(val)) {
                            if (cs.length() > 0) cs.append("-");
                            cs.append(val);
                        }
                    }
                    sb.append(cs);
                }
                sb.append(",");

                // extensions
                if (fields.has("extensions") && fields.get("extensions").isArray()) {
                    StringBuilder ext = new StringBuilder();
                    for (JsonNode e : fields.get("extensions")) {
                        int val = e.asInt();
                        if (!isGrease(val)) {
                            if (ext.length() > 0) ext.append("-");
                            ext.append(val);
                        }
                    }
                    sb.append(ext);
                }
                sb.append(",");

                // curves (supported_groups)
                if (fields.has("supported_groups") && fields.get("supported_groups").isArray()) {
                    StringBuilder curves = new StringBuilder();
                    for (JsonNode g : fields.get("supported_groups")) {
                        int val = g.asInt();
                        if (!isGrease(val)) {
                            if (curves.length() > 0) curves.append("-");
                            curves.append(val);
                        }
                    }
                    sb.append(curves);
                }
                sb.append(",");
                sb.append("0"); // point_formats: uncompressed

                // MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digest = md.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : digest) {
                    hex.append(String.format("%02x", b));
                }
                return hex.toString();
            } catch (Exception e) {
                return "";
            }
        }

        private boolean isGrease(int value) {
            return (value & 0x0F0F) == 0x0A0A;
        }
    }
}
