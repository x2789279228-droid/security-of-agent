package com.soc.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.connector.kafka.sink.HeaderProvider;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;

import java.nio.charset.StandardCharsets;

/**
 * 为 Kafka 消息写入 trace_id header — 全链路追踪关键一环。
 *
 * 配合 KafkaRecordSerializationSchema.builder().setHeaderProvider(...) 使用:
 * 值序列化保持 JSON (SimpleStringSchema), 同时把 traceId 写入 header,
 * 使下游 (Python kafka_consumer 等) 能按统一约定从 header 提取 trace_id,
 * 贯穿 Flink→Python→PG/LLM 全链路。
 */
public class TraceIdHeaderProvider implements HeaderProvider<String> {

    private transient ObjectMapper mapper;

    @Override
    public Headers getHeaders(String element) {
        RecordHeaders headers = new RecordHeaders();
        String traceId = "";
        try {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            JsonNode node = mapper.readTree(element);
            if (node != null && node.hasNonNull("traceId")) {
                traceId = node.get("traceId").asText();
            }
            if (traceId.isEmpty() && node != null && node.hasNonNull("trace_id")) {
                traceId = node.get("trace_id").asText();
            }
        } catch (Exception ignored) {
            // 解析失败不影响主流程, header 留空
        }
        headers.add("trace_id", traceId.getBytes(StandardCharsets.UTF_8));
        return headers;
    }
}