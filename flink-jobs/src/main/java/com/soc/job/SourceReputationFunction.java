package com.soc.job;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.SecurityEvent;
import org.apache.flink.api.common.state.MapState;
import org.apache.flink.api.common.state.MapStateDescriptor;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * 数据源信誉评分函数
 *
 * 按 sourceId 分组，实时统计每个数据源的历史质量指标，
 * 计算信誉分 (0.0 ~ 1.0) 并附加到事件的 rawData 中。
 *
 * 评分维度：
 * 1. 有效率 (validRate): 通过验证的事件占比 — 权重 0.4
 * 2. 时间准确性 (timeAccuracy): 时间戳在合理范围内的占比 — 权重 0.2
 * 3. 字段完整度 (completeness): 可选字段非空的占比 — 权重 0.2
 * 4. 异常频率 (anomalyRate): 高严重级别事件占比（越低越好）— 权重 0.2
 *
 * 信誉等级：
 * - trusted    (>= 0.8): 高信任源，可跳过部分校验
 * - standard   (>= 0.5): 标准源，正常处理
 * - probation  (< 0.5): 观察期，加强校验
 *
 * 状态 TTL: 24 小时（自动清理不活跃源）
 */
public class SourceReputationFunction
        extends KeyedProcessFunction<String, SecurityEvent, SecurityEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(SourceReputationFunction.class);

    /** 时间戳合理范围 */
    private static final long TS_MIN = 1577836800000L;
    private static final long TS_MAX = 1924991999000L;

    // ── 状态 ──
    private transient ValueState<Long> totalCount;
    private transient ValueState<Long> validCount;
    private transient ValueState<Long> timeValidCount;
    private transient ValueState<Long> fieldCompleteCount;
    private transient ValueState<Long> highSeverityCount;

    private transient ObjectMapper mapper;

    private ObjectMapper getMapper() {
        if (mapper == null) {
            mapper = new ObjectMapper();
        }
        return mapper;
    }

    @Override
    public void open(Configuration parameters) {
        org.apache.flink.api.common.state.StateTtlConfig ttlConfig =
                org.apache.flink.api.common.state.StateTtlConfig.newBuilder(
                                org.apache.flink.api.common.time.Time.hours(24))
                        .setUpdateType(org.apache.flink.api.common.state.StateTtlConfig.UpdateType.OnCreateAndWrite)
                        .setStateVisibility(org.apache.flink.api.common.state.StateTtlConfig.StateVisibility.NeverReturnExpired)
                        .build();

        ValueStateDescriptor<Long> totalDesc = new ValueStateDescriptor<>("src-total", Types.LONG);
        totalDesc.enableTimeToLive(ttlConfig);
        totalCount = getRuntimeContext().getState(totalDesc);

        ValueStateDescriptor<Long> validDesc = new ValueStateDescriptor<>("src-valid", Types.LONG);
        validDesc.enableTimeToLive(ttlConfig);
        validCount = getRuntimeContext().getState(validDesc);

        ValueStateDescriptor<Long> timeDesc = new ValueStateDescriptor<>("src-time-valid", Types.LONG);
        timeDesc.enableTimeToLive(ttlConfig);
        timeValidCount = getRuntimeContext().getState(timeDesc);

        ValueStateDescriptor<Long> fieldDesc = new ValueStateDescriptor<>("src-field-complete", Types.LONG);
        fieldDesc.enableTimeToLive(ttlConfig);
        fieldCompleteCount = getRuntimeContext().getState(fieldDesc);

        ValueStateDescriptor<Long> highDesc = new ValueStateDescriptor<>("src-high-sev", Types.LONG);
        highDesc.enableTimeToLive(ttlConfig);
        highSeverityCount = getRuntimeContext().getState(highDesc);
    }

    @Override
    public void processElement(SecurityEvent event,
                               KeyedProcessFunction<String, SecurityEvent, SecurityEvent>.Context ctx,
                               Collector<SecurityEvent> out) throws Exception {

        // 更新统计
        long total = getOrZero(totalCount) + 1;
        long valid = getOrZero(validCount) + 1; // 到达此函数的事件已通过验证
        long timeValid = getOrZero(timeValidCount) + (isTimeValid(event) ? 1 : 0);
        long fieldComplete = getOrZero(fieldCompleteCount) + (isFieldComplete(event) ? 1 : 0);
        long highSev = getOrZero(highSeverityCount) + (isHighSeverity(event) ? 1 : 0);

        totalCount.update(total);
        validCount.update(valid);
        timeValidCount.update(timeValid);
        fieldCompleteCount.update(fieldComplete);
        highSeverityCount.update(highSev);

        // 计算信誉分
        double reputationScore = computeReputation(total, valid, timeValid, fieldComplete, highSev);
        String reputationLevel = getReputationLevel(reputationScore);

        // 附加到 rawData
        Map<String, Object> rawData = event.getRawData() != null ?
                event.getRawData() : new HashMap<>();
        rawData.put("_sourceReputation", Math.round(reputationScore * 1000.0) / 1000.0);
        rawData.put("_reputationLevel", reputationLevel);
        rawData.put("_sourceTotalEvents", total);
        event.setRawData(rawData);

        out.collect(event);
    }

    /**
     * 信誉分计算
     * validRate * 0.4 + timeAccuracy * 0.2 + completeness * 0.2 + (1 - anomalyRate) * 0.2
     */
    private double computeReputation(long total, long valid, long timeValid,
                                     long fieldComplete, long highSev) {
        if (total == 0) return 1.0;

        double validRate = (double) valid / total;
        double timeAccuracy = (double) timeValid / total;
        double completeness = (double) fieldComplete / total;
        double anomalyRate = (double) highSev / total;

        return validRate * 0.4
                + timeAccuracy * 0.2
                + completeness * 0.2
                + (1.0 - anomalyRate) * 0.2;
    }

    private String getReputationLevel(double score) {
        if (score >= 0.8) return "trusted";
        if (score >= 0.5) return "standard";
        return "probation";
    }

    private boolean isTimeValid(SecurityEvent event) {
        long ts = event.getTimestamp();
        return ts >= TS_MIN && ts <= TS_MAX;
    }

    private boolean isFieldComplete(SecurityEvent event) {
        return event.getSrcIp() != null && !event.getSrcIp().isEmpty()
                && event.getDstIp() != null && !event.getDstIp().isEmpty()
                && event.getProtocol() != null && !event.getProtocol().isEmpty();
    }

    private boolean isHighSeverity(SecurityEvent event) {
        String sev = event.getSeverity();
        return "critical".equalsIgnoreCase(sev) || "high".equalsIgnoreCase(sev);
    }

    private long getOrZero(ValueState<Long> state) throws Exception {
        Long val = state.value();
        return val != null ? val : 0L;
    }
}
