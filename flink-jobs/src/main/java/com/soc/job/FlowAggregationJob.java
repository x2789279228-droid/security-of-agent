package com.soc.job;

import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.api.java.functions.KeySelector;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.windowing.assigners.TumblingEventTimeWindows;
import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.streaming.api.functions.windowing.WindowFunction;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.util.Collector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Duration;

/**
 * Flink Job 3: 网络流聚合
 *
 * 从 ndr-flows Topic 消费原始流记录（JSON），
 * 按 src_ip 分组，5 分钟滚动窗口聚合统计，
 * 输出聚合结果到 ndr-flows-aggregated Topic。
 *
 * 聚合指标:
 *   - total_bytes_out: 窗口内总流出字节
 *   - total_bytes_in: 窗口内总流入字节
 *   - flow_count: 窗口内流数量
 *   - unique_dst_ips: 唯一目标 IP 数
 *   - unique_dst_ports: 唯一目标端口数
 *   - top_protocol: 最频繁的应用协议
 */
public class FlowAggregationJob {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        // checkpoint 由 flink-conf.yaml 统一配置 (生产级)

        String bootstrap = KafkaConfig.getBootstrapServers();

        // Source: ndr-flows
        KafkaSource<String> source = KafkaSource.<String>builder()
                .setBootstrapServers(bootstrap)
                .setTopics("ndr-flows")
                .setGroupId("flink-flow-aggregation")
                .setStartingOffsets(OffsetsInitializer.latest())
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        DataStream<String> flowStream = env.fromSource(
                source,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(10)),
                "NDR Flows Source"
        );

        // 按 src_ip 分组 → 5 分钟滚动窗口 → 聚合
        DataStream<String> aggregated = flowStream
                .keyBy((KeySelector<String, String>) value -> {
                    try {
                        JsonNode node = MAPPER.readTree(value);
                        return node.has("src_ip") ? node.get("src_ip").asText() : "unknown";
                    } catch (Exception e) {
                        return "unknown";
                    }
                })
                .window(TumblingEventTimeWindows.of(Time.minutes(5)))
                .apply(new FlowWindowAggregator());

        // Sink: ndr-flows-aggregated
        KafkaSink<String> sink = KafkaSink.<String>builder()
                .setBootstrapServers(bootstrap)
                .setRecordSerializer(
                        KafkaRecordSerializationSchema.builder()
                                .setTopic("ndr-flows-aggregated")
                                .setValueSerializationSchema(new SimpleStringSchema())
                                .setHeaderProvider(new TraceIdHeaderProvider())
                                .build()
                )
                .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE)
                .setTransactionalIdPrefix("soc-flow")
                .build();

        aggregated.sinkTo(sink);

        env.execute("Flow Aggregation Job");
    }

    /**
     * 窗口聚合函数: 将同一 src_ip 在 5 分钟内的所有流聚合为一条统计记录
     */
    public static class FlowWindowAggregator implements WindowFunction<String, String, String, TimeWindow> {

        @Override
        public void apply(String srcIp, TimeWindow window, Iterable<String> input, Collector<String> out) {
            long totalBytesOut = 0;
            long totalBytesIn = 0;
            int flowCount = 0;
            java.util.Set<String> dstIps = new java.util.HashSet<>();
            java.util.Set<Integer> dstPorts = new java.util.HashSet<>();
            java.util.Map<String, Integer> protocolCounts = new java.util.HashMap<>();

            for (String record : input) {
                try {
                    JsonNode node = MAPPER.readTree(record);
                    flowCount++;
                    totalBytesOut += node.has("bytes_out") ? node.get("bytes_out").asLong() : 0;
                    totalBytesIn += node.has("bytes_in") ? node.get("bytes_in").asLong() : 0;

                    if (node.has("dst_ip")) dstIps.add(node.get("dst_ip").asText());
                    if (node.has("dst_port")) dstPorts.add(node.get("dst_port").asInt());

                    String proto = node.has("app_protocol") && !node.get("app_protocol").asText().isEmpty()
                            ? node.get("app_protocol").asText()
                            : (node.has("protocol") ? node.get("protocol").asText() : "OTHER");
                    protocolCounts.merge(proto, 1, Integer::sum);
                } catch (Exception ignored) {
                }
            }

            if (flowCount == 0) return;

            // 找最频繁协议
            String topProtocol = protocolCounts.entrySet().stream()
                    .max(java.util.Map.Entry.comparingByValue())
                    .map(java.util.Map.Entry::getKey)
                    .orElse("OTHER");

            // 构建输出 JSON
            try {
                ObjectNode result = MAPPER.createObjectNode();
                result.put("src_ip", srcIp);
                result.put("window_start", window.getStart());
                result.put("window_end", window.getEnd());
                result.put("flow_count", flowCount);
                result.put("total_bytes_out", totalBytesOut);
                result.put("total_bytes_in", totalBytesIn);
                result.put("unique_dst_ips", dstIps.size());
                result.put("unique_dst_ports", dstPorts.size());
                result.put("top_protocol", topProtocol);

                // 异常标记: 单窗口内连接过多唯一目标（扫描特征）
                if (dstIps.size() > 20 || dstPorts.size() > 15) {
                    result.put("anomaly_flag", "scan_behavior");
                } else if (totalBytesOut > 100 * 1024 * 1024) {
                    result.put("anomaly_flag", "large_exfil");
                }

                out.collect(MAPPER.writeValueAsString(result));
            } catch (Exception ignored) {
            }
        }
    }
}
