package com.soc.job;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import com.soc.model.SecurityEvent;
import org.apache.flink.api.common.state.MapState;
import org.apache.flink.api.common.state.MapStateDescriptor;
import org.apache.flink.api.common.state.StateTtlConfig;
import org.apache.flink.api.common.time.Time;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CEP 部分匹配追踪器
 *
 * 按 srcIp 分组，追踪每种攻击链模式的当前匹配进度。
 * 每当事件推进了某个模式的进度，就输出当前部分匹配状态。
 *
 * 输出格式 (JSON):
 * {
 *   "patternName": "port_scan_to_c2",
 *   "srcIp": "45.33.32.156",
 *   "matchedSteps": ["PORT_SCAN"],
 *   "pendingSteps": ["BRUTE_FORCE", "C2_BEACON"],
 *   "progress": 0.33,
 *   "firstEventAt": 1722600000000,
 *   "lastEventAt": 1722600060000,
 *   "status": "in_progress" | "completed" | "expired"
 * }
 *
 * 状态 TTL: 与最长攻击链窗口一致 (60 分钟 + 余量 = 90 分钟)
 */
public class CepPartialMatchFunction
        extends KeyedProcessFunction<String, SecurityEvent, String> {

    private static final Logger LOG = LoggerFactory.getLogger(CepPartialMatchFunction.class);

    /** 攻击链模式定义：名称 → 有序步骤列表 */
    private static final Map<String, List<String>> PATTERNS = new HashMap<>();

    static {
        PATTERNS.put("port_scan_to_c2", List.of("PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"));
        PATTERNS.put("lateral_movement", List.of("SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE"));
        PATTERNS.put("data_exfil", List.of("FILE_ACCESS", "DATA_EXFIL"));
    }

    /** 每个模式的当前匹配步骤索引 (patternName → 下一步索引) */
    private transient MapState<String, Integer> progressState;

    /** 每个模式的起始事件时间 (patternName → firstEventAt) */
    private transient MapState<String, Long> startTimeState;

    private transient ObjectMapper mapper;

    private ObjectMapper getMapper() {
        if (mapper == null) {
            mapper = new ObjectMapper();
        }
        return mapper;
    }

    @Override
    public void open(Configuration parameters) {
        StateTtlConfig ttlConfig = StateTtlConfig.newBuilder(Time.minutes(90))
                .setUpdateType(StateTtlConfig.UpdateType.OnCreateAndWrite)
                .setStateVisibility(StateTtlConfig.StateVisibility.NeverReturnExpired)
                .build();

        MapStateDescriptor<String, Integer> progressDesc =
                new MapStateDescriptor<>("cep-progress", Types.STRING, Types.INT);
        progressDesc.enableTimeToLive(ttlConfig);
        progressState = getRuntimeContext().getMapState(progressDesc);

        MapStateDescriptor<String, Long> startDesc =
                new MapStateDescriptor<>("cep-start-time", Types.STRING, Types.LONG);
        startDesc.enableTimeToLive(ttlConfig);
        startTimeState = getRuntimeContext().getMapState(startDesc);
    }

    @Override
    public void processElement(SecurityEvent event,
                               KeyedProcessFunction<String, SecurityEvent, String>.Context ctx,
                               Collector<String> out) throws Exception {

        String eventType = event.getEventType();
        if (eventType == null) return;

        for (Map.Entry<String, List<String>> entry : PATTERNS.entrySet()) {
            String patternName = entry.getKey();
            List<String> steps = entry.getValue();

            Integer currentIdx = progressState.get(patternName);
            if (currentIdx == null) currentIdx = 0;

            // 检查当前事件是否匹配下一步
            if (currentIdx < steps.size() && eventType.equals(steps.get(currentIdx))) {
                int newIdx = currentIdx + 1;

                // 记录起始时间
                if (currentIdx == 0) {
                    startTimeState.put(patternName, event.getTimestamp());
                }

                boolean completed = newIdx >= steps.size();
                String status = completed ? "completed" : "in_progress";

                // 更新状态
                if (completed) {
                    progressState.remove(patternName);
                    startTimeState.remove(patternName);
                } else {
                    progressState.put(patternName, newIdx);
                }

                // 构建部分匹配输出
                Long firstAt = startTimeState.get(patternName);
                Map<String, Object> partial = new HashMap<>();
                partial.put("patternName", patternName);
                partial.put("srcIp", event.getSrcIp());
                partial.put("matchedSteps", steps.subList(0, newIdx));
                partial.put("pendingSteps", completed ?
                        List.of() : steps.subList(newIdx, steps.size()));
                partial.put("progress", Math.round((double) newIdx / steps.size() * 100.0) / 100.0);
                partial.put("firstEventAt", firstAt != null ? firstAt : event.getTimestamp());
                partial.put("lastEventAt", event.getTimestamp());
                partial.put("lastEventType", eventType);
                partial.put("lastEventId", event.getEventId());
                partial.put("status", status);
                partial.put("traceId", event.getTraceId());

                out.collect(getMapper().writeValueAsString(partial));

                if (completed) {
                    LOG.info("[CEP-Partial] {} COMPLETED for srcIp={}", patternName, event.getSrcIp());
                }
            }
        }
    }
}
