package com.soc.job;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.SerializableTimestampAssigner;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.windowing.ProcessWindowFunction;
import org.apache.flink.streaming.api.windowing.assigners.SlidingProcessingTimeWindows;
import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

/**
 * SigmaThresholdAggregationJob — Sigma 聚合阈值窗口
 *
 * 消费 backend 发布的 sigma 聚合候选(security-sigma-hit, 见 backend sigma_engine 命中带
 * x-soc-aggregation 的规则如 SIG-001/007 时发布)。
 * 按 srcIp + ruleId key 做 5m 滑动窗口计数, 单窗计数超过规则 threshold 则生成聚合告警
 * 写回 security-alerts, 供平台消费。pySigma 只做单事件匹配, 阈值统计由本 job 分布式完成。
 */
public class SigmaThresholdAggregationJob {

    private static final Logger LOG = LoggerFactory.getLogger(SigmaThresholdAggregationJob.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** sigma-hit 事件 POJO(与 backend 发布字段一致)。 */
    public static class SigmaHit implements java.io.Serializable {
        public String srcIp;
        public String ruleId;
        public int threshold;
        public long timestamp;
        public static SigmaHit fromString(String s) {
            try {
                JsonNode n = MAPPER.readTree(s);
                SigmaHit h = new SigmaHit();
                JsonNode si = n.get("src_ip");
                h.srcIp = si != null ? si.asText("") : "";
                JsonNode ri = n.get("rule_id");
                h.ruleId = ri != null ? ri.asText("") : "";
                JsonNode th = n.get("threshold");
                h.threshold = th != null ? th.asInt(0) : 0;
                JsonNode ts = n.get("timestamp");
                h.timestamp = ts != null ? ts.asLong(0L) : System.currentTimeMillis();
                return h;
            } catch (Exception e) {
                LOG.warn("SigmaHit parse fail: {}", e.getMessage());
                return null;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();

        KafkaSource<String> source = KafkaSource.<String>builder()
                .setBootstrapServers(KafkaConfig.getBootstrapServers())
                .setTopics(KafkaConfig.TOPIC_SIGMA_HIT)
                .setGroupId("sigma-threshold-agg-job")
                .setStartingOffsets(OffsetsInitializer.earliest())
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        // source(字符串) → 解析为 SigmaHit
        DataStream<SigmaHit> hits = env.fromSource(
                source,
                org.apache.flink.api.common.eventtime.WatermarkStrategy.noWatermarks(),
                "SigmaHit-Source"
        ).map(SigmaHit::fromString)
                .filter(h -> h != null && h.srcIp != null && !h.srcIp.isEmpty());

        // 5m 窗口 / 1m 滑动(处理时间), 按 srcIp+ruleId 聚合计数, 超阈值输出告警
        DataStream<String> alerts = hits
                .keyBy(h -> h.srcIp + "#" + h.ruleId)
                .window(SlidingProcessingTimeWindows.of(Time.minutes(5), Time.minutes(1)))
                .process(new ThresholdWindowFunction())
                .name("Sigma-Threshold-Aggregation");

        KafkaSink<String> alertSink = KafkaSink.<String>builder()
                .setBootstrapServers(KafkaConfig.getBootstrapServers())
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(KafkaConfig.TOPIC_ALERTS)
                        .setValueSerializationSchema(new SimpleStringSchema())
                        .setHeaderProvider(new TraceIdHeaderProvider())
                        .build())
                .setDeliveryGuarantee(DeliveryGuarantee.AT_LEAST_ONCE)
                .setTransactionalIdPrefix("soc-sig-agg")
                .build();

        alerts.sinkTo(alertSink).name("Kafka-SigmaAgg-Alerts-Sink");

        env.execute("SigmaThresholdAggregationJob");
    }

    /** 窗口内计数超过阈值则输出聚合告警 JSON。 */
    public static class ThresholdWindowFunction
            extends ProcessWindowFunction<SigmaHit, String, String, TimeWindow> {
        @Override
        public void process(String key, Context ctx, Iterable<SigmaHit> elems, Collector<String> out) {
            int count = 0;
            int threshold = 0;
            String srcIp = ""; String ruleId = "";
            for (SigmaHit h : elems) {
                count++;
                srcIp = h.srcIp;
                ruleId = h.ruleId;
                threshold = Math.max(threshold, h.threshold);
            }
            if (count > 0 && count >= threshold) {
                try {
                    java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
                    m.put("source", "sigma_aggregation");
                    m.put("rule_id", ruleId);
                    m.put("src_ip", srcIp);
                    m.put("count", count);
                    m.put("threshold", threshold);
                    m.put("window_start", ctx.window().getStart());
                    m.put("window_end", ctx.window().getEnd());
                    m.put("severity", "high");
                    m.put("type", "SIGMA_AGGREGATE");
                    String json = MAPPER.writeValueAsString(m);
                    LOG.info("Sigma aggregate hit {} count={} threshold={}", key, count, threshold);
                    out.collect(json);
                } catch (Exception e) {
                    LOG.warn("alert serialization failed: {}", e.getMessage());
                }
            }
        }
    }
}
