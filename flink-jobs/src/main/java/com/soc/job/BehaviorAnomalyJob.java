package com.soc.job;

import com.soc.util.KafkaConfig;
import com.soc.util.TraceIdHeaderProvider;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.functions.RichMapFunction;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.node.ObjectNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 行为基线异常作业 (L4)
 *
 * 从 ndr-flows-aggregated 消费 5 分钟窗口聚合指标，按 src_ip 维护 Welford 动态基线。
 * 触发条件（冷启动保护后）:
 *   - zscore(flow_count) ≥ 3
 *   - unique_dst_ports ≥ 50（绝对扫描特征，冷启动期也允许）
 *   - bytes_out ≥ μ + 3σ
 *
 * 输出 security-behavior-alerts，threat_type 固定为 BEHAVIOR_ANOMALY，
 * 不依赖厂商 threat_type 字段。
 */
public class BehaviorAnomalyJob {

    private static final Logger LOG = LoggerFactory.getLogger(BehaviorAnomalyJob.class);

    public static final int COLD_START_WINDOWS = 10;
    public static final int MAX_ALERTS_PER_WINDOW = 3;
    public static final double ZSCORE_THRESHOLD = 3.0;
    public static final int ABSOLUTE_DST_PORTS = 50;
    public static final long ALERT_WINDOW_MS = 5 * 60 * 1000L;

    public static void main(String[] args) throws Exception {
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        String bootstrap = KafkaConfig.getBootstrapServers();

        KafkaSource<String> source = KafkaSource.<String>builder()
                .setBootstrapServers(bootstrap)
                .setTopics(KafkaConfig.TOPIC_FLOWS_AGGREGATED)
                .setGroupId("flink-behavior-anomaly")
                .setStartingOffsets(OffsetsInitializer.latest())
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        DataStream<String> aggregated = env.fromSource(
                source,
                WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(30))
                        .withIdleness(Duration.ofMinutes(2)),
                "NDR-Flows-Aggregated-Source"
        );

        DataStream<String> alerts = aggregated
                .map(new ParseAggMap())
                .filter(m -> m != null && m.srcIp != null && !m.srcIp.isEmpty() && !"unknown".equals(m.srcIp))
                .keyBy(m -> m.srcIp)
                .process(new BehaviorBaselineFunction())
                .name("Behavior-Baseline");

        KafkaSink<String> sink = KafkaSink.<String>builder()
                .setBootstrapServers(bootstrap)
                .setRecordSerializer(
                        KafkaRecordSerializationSchema.builder()
                                .setTopic(KafkaConfig.TOPIC_BEHAVIOR_ALERTS)
                                .setValueSerializationSchema(new SimpleStringSchema())
                                .setHeaderProvider(new TraceIdHeaderProvider())
                                .build()
                )
                .setDeliveryGuarantee(DeliveryGuarantee.AT_LEAST_ONCE)
                .setTransactionalIdPrefix("soc-behavior")
                .build();

        alerts.sinkTo(sink).name("Behavior-Alerts-Sink");
        env.execute("BehaviorAnomalyJob");
    }

    /** 聚合窗口指标（可单测）。 */
    public static class AggMetrics {
        public String srcIp = "";
        public long windowStart;
        public long windowEnd;
        public long flowCount;
        public long bytesOut;
        public int uniqueDstIps;
        public int uniqueDstPorts;
        public String anomalyFlag = "";
    }

    /**
     * 纯函数评分：返回 reasons；空列表表示不告警。
     * 供单元测试与 ProcessFunction 共用。
     */
    public static List<String> evaluate(
            long flowCount,
            long bytesOut,
            int uniqueDstPorts,
            int uniqueDstIps,
            double flowMean,
            double flowM2,
            long flowSamples,
            double bytesMean,
            double bytesM2,
            long bytesSamples,
            int coldStartWindows
    ) {
        List<String> reasons = new ArrayList<>();

        // 绝对扫描特征：冷启动也允许（防止全新攻击 IP 永远学不到基线）
        if (uniqueDstPorts >= ABSOLUTE_DST_PORTS) {
            reasons.add(String.format("unique_dst_ports=%d>=%d", uniqueDstPorts, ABSOLUTE_DST_PORTS));
        }
        if (uniqueDstIps >= 40) {
            reasons.add(String.format("unique_dst_ips=%d>=40", uniqueDstIps));
        }

        boolean warmed = flowSamples >= coldStartWindows && bytesSamples >= coldStartWindows;
        if (warmed) {
            double flowStd = Math.sqrt(flowM2 / Math.max(1, flowSamples));
            if (flowStd > 0) {
                double z = (flowCount - flowMean) / flowStd;
                if (z >= ZSCORE_THRESHOLD) {
                    reasons.add(String.format("flow_count z=%.2f (n=%d μ=%.1f σ=%.1f)",
                            z, flowCount, flowMean, flowStd));
                }
            }
            double bytesStd = Math.sqrt(bytesM2 / Math.max(1, bytesSamples));
            if (bytesStd > 0 && bytesOut >= bytesMean + ZSCORE_THRESHOLD * bytesStd) {
                reasons.add(String.format("bytes_out=%d >= μ+3σ (μ=%.0f σ=%.0f)",
                        bytesOut, bytesMean, bytesStd));
            }
        } else {
            // 冷启动静态兜底：极端窗口仍告警
            if (flowCount >= 200) {
                reasons.add(String.format("flow_count=%d>=200 (cold-start static)", flowCount));
            }
            if (bytesOut >= 200L * 1024 * 1024) {
                reasons.add(String.format("bytes_out=%d>=200MB (cold-start static)", bytesOut));
            }
        }
        return reasons;
    }

    public static double scoreFromReasons(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) return 0.0;
        // 每条原因 +0.25，封顶 1.0；绝对端口扫描至少 0.7
        double s = Math.min(1.0, 0.25 * reasons.size());
        for (String r : reasons) {
            if (r.startsWith("unique_dst_ports=")) {
                s = Math.max(s, 0.75);
            }
            if (r.contains("bytes_out=")) {
                s = Math.max(s, 0.7);
            }
        }
        return Math.min(1.0, s);
    }

    public static String inferCategory(List<String> reasons) {
        if (reasons == null) return "SCAN";
        for (String r : reasons) {
            if (r.contains("bytes_out")) return "EXFIL";
            if (r.contains("dst_ports") || r.contains("dst_ips") || r.contains("flow_count")) {
                return "SCAN";
            }
        }
        return "AVAILABILITY";
    }

    // ── Welford helpers ──
    public static class Welford {
        public long n;
        public double mean;
        public double m2;

        public void update(double x) {
            n++;
            double delta = x - mean;
            mean += delta / n;
            double delta2 = x - mean;
            m2 += delta * delta2;
        }
    }

    private static class ParseAggMap extends RichMapFunction<String, AggMetrics> {
        private transient ObjectMapper mapper;

        @Override
        public void open(Configuration parameters) {
            mapper = new ObjectMapper();
        }

        @Override
        public AggMetrics map(String value) {
            try {
                JsonNode n = mapper.readTree(value);
                AggMetrics m = new AggMetrics();
                m.srcIp = n.has("src_ip") ? n.get("src_ip").asText() : "";
                m.windowStart = n.has("window_start") ? n.get("window_start").asLong() : 0L;
                m.windowEnd = n.has("window_end") ? n.get("window_end").asLong() : 0L;
                m.flowCount = n.has("flow_count") ? n.get("flow_count").asLong() : 0L;
                m.bytesOut = n.has("total_bytes_out") ? n.get("total_bytes_out").asLong() : 0L;
                m.uniqueDstIps = n.has("unique_dst_ips") ? n.get("unique_dst_ips").asInt() : 0;
                m.uniqueDstPorts = n.has("unique_dst_ports") ? n.get("unique_dst_ports").asInt() : 0;
                m.anomalyFlag = n.has("anomaly_flag") ? n.get("anomaly_flag").asText("") : "";
                return m;
            } catch (Exception e) {
                return null;
            }
        }
    }

    public static class BehaviorBaselineFunction
            extends KeyedProcessFunction<String, AggMetrics, String> {

        private transient ValueState<Double> flowMean;
        private transient ValueState<Double> flowM2;
        private transient ValueState<Long> flowSamples;
        private transient ValueState<Double> bytesMean;
        private transient ValueState<Double> bytesM2;
        private transient ValueState<Long> bytesSamples;
        private transient ValueState<Long> alertWindowStart;
        private transient ValueState<Integer> alertsInWindow;
        private transient ObjectMapper mapper;

        @Override
        public void open(Configuration parameters) {
            org.apache.flink.api.common.state.StateTtlConfig ttl =
                    org.apache.flink.api.common.state.StateTtlConfig.newBuilder(
                                    org.apache.flink.api.common.time.Time.hours(24))
                            .setUpdateType(org.apache.flink.api.common.state.StateTtlConfig.UpdateType.OnCreateAndWrite)
                            .setStateVisibility(org.apache.flink.api.common.state.StateTtlConfig.StateVisibility.NeverReturnExpired)
                            .build();

            ValueStateDescriptor<Double> fm = new ValueStateDescriptor<>("flow-mean", Types.DOUBLE);
            fm.enableTimeToLive(ttl);
            flowMean = getRuntimeContext().getState(fm);
            ValueStateDescriptor<Double> f2 = new ValueStateDescriptor<>("flow-m2", Types.DOUBLE);
            f2.enableTimeToLive(ttl);
            flowM2 = getRuntimeContext().getState(f2);
            ValueStateDescriptor<Long> fs = new ValueStateDescriptor<>("flow-samples", Types.LONG);
            fs.enableTimeToLive(ttl);
            flowSamples = getRuntimeContext().getState(fs);

            ValueStateDescriptor<Double> bm = new ValueStateDescriptor<>("bytes-mean", Types.DOUBLE);
            bm.enableTimeToLive(ttl);
            bytesMean = getRuntimeContext().getState(bm);
            ValueStateDescriptor<Double> b2 = new ValueStateDescriptor<>("bytes-m2", Types.DOUBLE);
            b2.enableTimeToLive(ttl);
            bytesM2 = getRuntimeContext().getState(b2);
            ValueStateDescriptor<Long> bs = new ValueStateDescriptor<>("bytes-samples", Types.LONG);
            bs.enableTimeToLive(ttl);
            bytesSamples = getRuntimeContext().getState(bs);

            ValueStateDescriptor<Long> aw = new ValueStateDescriptor<>("alert-win-start", Types.LONG);
            aw.enableTimeToLive(ttl);
            alertWindowStart = getRuntimeContext().getState(aw);
            ValueStateDescriptor<Integer> ac = new ValueStateDescriptor<>("alert-count", Types.INT);
            ac.enableTimeToLive(ttl);
            alertsInWindow = getRuntimeContext().getState(ac);

            mapper = new ObjectMapper();
        }

        private void updateWelford(
                ValueState<Double> meanState,
                ValueState<Double> m2State,
                ValueState<Long> nState,
                double x
        ) throws Exception {
            long n = nState.value() == null ? 0L : nState.value();
            double mean = meanState.value() == null ? 0.0 : meanState.value();
            double m2 = m2State.value() == null ? 0.0 : m2State.value();
            n++;
            double delta = x - mean;
            mean += delta / n;
            double delta2 = x - mean;
            m2 += delta * delta2;
            nState.update(n);
            meanState.update(mean);
            m2State.update(m2);
        }

        @Override
        public void processElement(AggMetrics m, Context ctx, Collector<String> out) throws Exception {
            long flowN = flowSamples.value() == null ? 0L : flowSamples.value();
            double fMean = flowMean.value() == null ? 0.0 : flowMean.value();
            double fM2 = flowM2.value() == null ? 0.0 : flowM2.value();
            long bytesN = bytesSamples.value() == null ? 0L : bytesSamples.value();
            double bMean = bytesMean.value() == null ? 0.0 : bytesMean.value();
            double bM2 = bytesM2.value() == null ? 0.0 : bytesM2.value();

            List<String> reasons = evaluate(
                    m.flowCount, m.bytesOut, m.uniqueDstPorts, m.uniqueDstIps,
                    fMean, fM2, flowN, bMean, bM2, bytesN, COLD_START_WINDOWS
            );

            // 先评估再更新基线，避免本窗口污染自身阈值
            updateWelford(flowMean, flowM2, flowSamples, (double) m.flowCount);
            updateWelford(bytesMean, bytesM2, bytesSamples, (double) m.bytesOut);

            if (reasons.isEmpty()) {
                return;
            }

            // 告警风暴抑制
            long now = m.windowEnd > 0 ? m.windowEnd : System.currentTimeMillis();
            Long winStart = alertWindowStart.value();
            Integer count = alertsInWindow.value();
            if (winStart == null || now - winStart > ALERT_WINDOW_MS) {
                winStart = now;
                count = 0;
                alertWindowStart.update(winStart);
            }
            if (count == null) count = 0;
            if (count >= MAX_ALERTS_PER_WINDOW) {
                LOG.debug("Suppress behavior alert for {} (storm)", m.srcIp);
                return;
            }
            alertsInWindow.update(count + 1);

            double score = scoreFromReasons(reasons);
            String category = inferCategory(reasons);
            String severity = score >= 0.85 ? "critical" : "high";

            ObjectNode alert = mapper.createObjectNode();
            alert.put("alertType", "BEHAVIOR_ANOMALY");
            alert.put("threat_type", "BEHAVIOR_ANOMALY");
            alert.put("eventType", "BEHAVIOR_ANOMALY");
            alert.put("category", category);
            alert.put("srcIp", m.srcIp);
            alert.put("src_ip", m.srcIp);
            alert.put("severity", severity);
            alert.put("anomalyScore", score);
            alert.put("confidence", score);
            alert.put("response_source", "flink_baseline");
            alert.put("allow_blocking", true);
            alert.put("message", "Flink behavior baseline anomaly: " + String.join("; ", reasons));
            alert.put("window_start", m.windowStart);
            alert.put("window_end", m.windowEnd);
            alert.put("flow_count", m.flowCount);
            alert.put("unique_dst_ports", m.uniqueDstPorts);
            alert.put("unique_dst_ips", m.uniqueDstIps);
            alert.put("total_bytes_out", m.bytesOut);
            alert.put("alert_id", UUID.randomUUID().toString());
            ArrayNode arr = alert.putArray("reasons");
            for (String r : reasons) {
                arr.add(r);
            }

            String json = mapper.writeValueAsString(alert);
            LOG.warn("BEHAVIOR_ANOMALY src={} score={} reasons={}", m.srcIp, score, reasons);
            out.collect(json);
        }
    }
}
