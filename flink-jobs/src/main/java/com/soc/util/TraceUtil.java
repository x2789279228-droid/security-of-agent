package com.soc.util;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 每事件 OpenTelemetry 标准 span 工具 (Flink 作业内)。
 *
 * 与 W3C traceparent 打通: 从事件 traceId/上游 _traceparent 重建父上下文,
 * 创建 span 后把新 traceparent (含本 span-id) 附回事件, 使下游 (Python)
 * 成为本 span 的子节点 → 形成 源→LogValidation→AnomalyDetection→Python 完整 trace 树。
 *
 * OTLP 导出端点: OTEL_EXPORTER_OTLP_ENDPOINT 或默认 otel-collector:4317。
 */
public final class TraceUtil {

    private static final String ENDPOINT = System.getenv().getOrDefault(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317");

    private static volatile Tracer TRACER = null;

    private TraceUtil() {}

    public static Tracer tracer() {
        if (TRACER == null) {
            synchronized (TraceUtil.class) {
                if (TRACER == null) {
                    Resource resource = Resource.getDefault().toBuilder()
                            .put(AttributeKey.stringKey("service.name"), "soc-flink")
                            .put(AttributeKey.stringKey("service.version"), "1.0.0")
                            .build();
                    OtlpGrpcSpanExporter exporter = OtlpGrpcSpanExporter.builder()
                            .setEndpoint(ENDPOINT)
                            .build();
                    SdkTracerProvider provider = SdkTracerProvider.builder()
                            .setResource(resource)
                            .addSpanProcessor(BatchSpanProcessor.builder(exporter).build())
                            .build();
                    OpenTelemetrySdk sdk = OpenTelemetrySdk.builder()
                            .setTracerProvider(provider)
                            .build();
                    TRACER = sdk.getTracer("soc-flink", "1.0.0");
                }
            }
        }
        return TRACER;
    }

    // ── W3C traceparent 工具 ──

    /** 规整为 32 hex; 非法输入用 MD5 确定性补齐 */
    public static String normalizeTraceIdHex(String traceId) {
        String cleaned = (traceId == null ? "" : traceId).replace("-", "").toLowerCase();
        if (cleaned.matches("^[0-9a-f]{32}$")) {
            return cleaned;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(
                    (traceId == null ? "" : traceId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
    }

    /** 由 traceId 构造根 traceparent (span-id 随机, sampled) */
    public static String makeRootTraceparent(String traceId) {
        String spanId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        return "00-" + normalizeTraceIdHex(traceId) + "-" + spanId + "-01";
    }

    /** 由已结束的 span 提取其 traceparent (供下游继承) */
    public static String traceparentOf(Span span) {
        SpanContext sc = span.getSpanContext();
        if (sc != null && sc.isValid()) {
            return "00-" + sc.getTraceId() + "-" + sc.getSpanId() + "-01";
        }
        return "";
    }

    private static final TextMapGetter<Map<String, String>> GETTER = new TextMapGetter<Map<String, String>>() {
        @Override
        public Iterable<String> keys(Map<String, String> carrier) {
            return carrier.keySet();
        }

        @Override
        public String get(Map<String, String> carrier, String key) {
            return carrier == null ? null : carrier.get(key);
        }
    };

    /** 从 traceparent 字符串提取父上下文 (非法/空 → 当前上下文) */
    public static Context extractContext(String traceparent) {
        if (traceparent == null || traceparent.isEmpty()) {
            return Context.current();
        }
        Map<String, String> carrier = new HashMap<>();
        carrier.put("traceparent", traceparent);
        try {
            return W3CTraceContextPropagator.getInstance().extract(Context.current(), carrier, GETTER);
        } catch (Exception e) {
            return Context.current();
        }
    }

    // ── span 创建 ──

    /** 创建每事件 span: 父级来自上游 traceparent, 附加业务属性 */
    public static Span startSpan(String name, String parentTraceparent, Map<String, String> attributes) {
        Span span = tracer().spanBuilder(name)
                .setParent(extractContext(parentTraceparent))
                .setAttribute("soc.importance", "normal")
                .startSpan();
        if (attributes != null) {
            for (Map.Entry<String, String> e : attributes.entrySet()) {
                span.setAttribute(e.getKey(), e.getValue());
            }
        }
        return span;
    }

    /** 便捷: 由事件 traceId 派生父 traceparent (无显式上游时) */
    public static String parentFromTraceId(String traceId) {
        return makeRootTraceparent(traceId);
    }
}
