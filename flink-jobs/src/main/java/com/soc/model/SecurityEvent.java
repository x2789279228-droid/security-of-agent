package com.soc.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * 安全事件模型
 * 表示一条经过验证的安全日志事件
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 事件唯一标识 */
    @JsonProperty("eventId")
    private String eventId;

    /** 日志来源标识 */
    @JsonProperty("sourceId")
    private String sourceId;

    /** API 密钥 - 用于来源认证 */
    @JsonProperty("apiKey")
    private String apiKey;

    /** 事件类型 (如 PORT_SCAN, BRUTE_FORCE, C2_BEACON 等) */
    @JsonProperty("eventType")
    private String eventType;

    /** 严重级别 (info, low, medium, high, critical) */
    @JsonProperty("severity")
    private String severity;

    /** 源 IP 地址 */
    @JsonProperty("srcIp")
    private String srcIp;

    /** 目标 IP 地址 */
    @JsonProperty("dstIp")
    private String dstIp;

    /** 协议类型 */
    @JsonProperty("protocol")
    private String protocol;

    /** 事件描述信息 */
    @JsonProperty("message")
    private String message;

    /** 置信度 (0.0 - 1.0) */
    @JsonProperty("confidence")
    private double confidence;

    /** 原始数据 - 保留完整的原始日志字段 */
    @JsonProperty("rawData")
    private Map<String, Object> rawData;

    /** 事件时间戳 (毫秒) */
    @JsonProperty("timestamp")
    private long timestamp;

    /** 默认构造函数 - Jackson 反序列化需要 */
    public SecurityEvent() {
        this.rawData = new HashMap<>();
    }

    /** 全参数构造函数 */
    public SecurityEvent(String eventId, String sourceId, String apiKey, String eventType,
                         String severity, String srcIp, String dstIp, String protocol,
                         String message, double confidence, Map<String, Object> rawData,
                         long timestamp) {
        this.eventId = eventId;
        this.sourceId = sourceId;
        this.apiKey = apiKey;
        this.eventType = eventType;
        this.severity = severity;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.protocol = protocol;
        this.message = message;
        this.confidence = confidence;
        this.rawData = rawData != null ? rawData : new HashMap<>();
        this.timestamp = timestamp;
    }

    // ==================== Getters & Setters ====================

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getSourceId() {
        return sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    public Map<String, Object> getRawData() {
        return rawData;
    }

    public void setRawData(Map<String, Object> rawData) {
        this.rawData = rawData;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "eventId='" + eventId + '\'' +
                ", sourceId='" + sourceId + '\'' +
                ", eventType='" + eventType + '\'' +
                ", severity='" + severity + '\'' +
                ", srcIp='" + srcIp + '\'' +
                ", dstIp='" + dstIp + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
