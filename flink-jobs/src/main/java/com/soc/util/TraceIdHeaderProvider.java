package com.soc.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.connector.kafka.sink.HeaderProvider;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * 为 Kafka 消息写入标准 W3C trace 头 — 全链路追踪关键一环。
 *
 * 配合 KafkaRecordSerializationSchema.builder().setHeaderProvider(...) 使用:
 * 值序列化保持 JSON (SimpleStringSchema), 同时写入:
 *   - traceparent: W3C 标准格式 (00-traceid-spanid-flags), 供 OTel/Tempo 体系消费
 *   - trace_id:    旧版兼容头 (traceid 原文)
 * 使下游 (Python kafka_consumer 等) 能按统一约定提取 trace, 贯穿 Flink→Python→PG/LLM。
 */
public class TraceIdHeaderProvider implements HeaderProvider<String> {

    private transient ObjectMapper mapper;

    @Override
    public Headers getHeaders(String element) {
        RecordHeaders headers = new RecordHeaders();
        // 优先使用事件内已携带的标准 traceparent (Flink span 下发), 否则由 traceId 派生
        String traceparent = extractTraceparent(element);
        String traceId = "";
        if (traceparent.isEmpty()) {
            traceId = extractTraceId(element);
            traceparent = buildTraceparent(traceId);
        } else {
            traceId = traceparent.split("-")[1];
        }
        headers.add("trace_id", traceId.getBytes(StandardCharsets.UTF_8));
        headers.add("traceparent", traceparent.getBytes(StandardCharsets.UTF_8));
        return headers;
    }

    /** 从事件 JSON 提取上游 traceparent (rawData._traceparent 或顶层 traceparent) */
    private String extractTraceparent(String element) {
        try {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            JsonNode node = mapper.readTree(element);
            if (node == null) {
                return "";
            }
            if (node.hasNonNull("traceparent")) {
                return node.get("traceparent").asText();
            }
            if (node.hasNonNull("rawData") && node.get("rawData").hasNonNull("_traceparent")) {
                return node.get("rawData").get("_traceparent").asText();
            }
        } catch (Exception ignored) {
            // 解析失败不影响主流程
        }
        return "";
    }

    /** 从事件 JSON 提取 traceId (优先 traceId, 回退 trace_id) */
    private String extractTraceId(String element) {
        try {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            JsonNode node = mapper.readTree(element);
            if (node != null && node.hasNonNull("traceId")) {
                return node.get("traceId").asText();
            }
            if (node != null && node.hasNonNull("trace_id")) {
                return node.get("trace_id").asText();
            }
        } catch (Exception ignored) {
            // 解析失败不影响主流程
        }
        return "";
    }

    /** 由 traceId (可能带横线 UUID) 构造标准 W3C traceparent */
    private String buildTraceparent(String traceId) {
        String traceIdHex = normalizeTraceIdHex(traceId);
        String spanId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        return "00-" + traceIdHex + "-" + spanId + "-01";
    }

    /** 规整为 32 hex; 非法输入用 MD5 确定性补齐 */
    private String normalizeTraceIdHex(String traceId) {
        String cleaned = (traceId == null ? "" : traceId).replace("-", "").toLowerCase();
        if (cleaned.matches("^[0-9a-f]{32}$")) {
            return cleaned;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(
                    (traceId == null ? "" : traceId).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
    }
}