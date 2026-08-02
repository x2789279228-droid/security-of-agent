package com.soc.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 安全告警事件模型
 * 表示一条需要安全运营人员关注的高优先级告警
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AlertEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 告警唯一标识 */
    @JsonProperty("alertId")
    private String alertId;

    /** 事件类型 */
    @JsonProperty("eventType")
    private String eventType;

    /** 严重级别 */
    @JsonProperty("severity")
    private String severity;

    /** 源 IP 地址 */
    @JsonProperty("srcIp")
    private String srcIp;

    /** 目标 IP 地址 */
    @JsonProperty("dstIp")
    private String dstIp;

    /** 告警描述信息 */
    @JsonProperty("message")
    private String message;

    /** 异常评分 (0.0 - 1.0) */
    @JsonProperty("anomalyScore")
    private double anomalyScore;

    /** 告警类型: ANOMALY(异常检测), ATTACK_CHAIN(攻击链), THRESHOLD(阈值触发) */
    @JsonProperty("alertType")
    private String alertType;

    /** 告警触发原因列表 */
    @JsonProperty("reasons")
    private List<String> reasons;

    /** 告警时间戳 (毫秒) */
    @JsonProperty("timestamp")
    private long timestamp;

    /** 全链路追踪 ID */
    @JsonProperty("traceId")
    private String traceId;

    /** 证据链：攻击链中所有原始事件的 eventId 列表 */
    @JsonProperty("evidenceEventIds")
    private List<String> evidenceEventIds;

    /** 证据链：攻击链中所有事件的摘要快照 */
    @JsonProperty("evidenceChain")
    private List<Map<String, Object>> evidenceChain;

    /** 攻击链时间跨度（毫秒）*/
    @JsonProperty("timeSpanMs")
    private long timeSpanMs;

    /** 默认构造函数 */
    public AlertEvent() {
        this.reasons = new ArrayList<>();
        this.evidenceEventIds = new ArrayList<>();
        this.evidenceChain = new ArrayList<>();
    }

    // ==================== Getters & Setters ====================

    public String getAlertId() {
        return alertId;
    }

    public void setAlertId(String alertId) {
        this.alertId = alertId;
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

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public double getAnomalyScore() {
        return anomalyScore;
    }

    public void setAnomalyScore(double anomalyScore) {
        this.anomalyScore = anomalyScore;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public void setReasons(List<String> reasons) {
        this.reasons = reasons;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public List<String> getEvidenceEventIds() {
        return evidenceEventIds;
    }

    public void setEvidenceEventIds(List<String> evidenceEventIds) {
        this.evidenceEventIds = evidenceEventIds;
    }

    public List<Map<String, Object>> getEvidenceChain() {
        return evidenceChain;
    }

    public void setEvidenceChain(List<Map<String, Object>> evidenceChain) {
        this.evidenceChain = evidenceChain;
    }

    public long getTimeSpanMs() {
        return timeSpanMs;
    }

    public void setTimeSpanMs(long timeSpanMs) {
        this.timeSpanMs = timeSpanMs;
    }

    @Override
    public String toString() {
        return "AlertEvent{" +
                "alertId='" + alertId + '\'' +
                ", eventType='" + eventType + '\'' +
                ", severity='" + severity + '\'' +
                ", srcIp='" + srcIp + '\'' +
                ", anomalyScore=" + anomalyScore +
                ", alertType='" + alertType + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
