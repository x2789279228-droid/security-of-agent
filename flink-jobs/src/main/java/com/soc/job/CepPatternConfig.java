package com.soc.job;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

/**
 * CEP 攻击链模式配置（可通过 Kafka Broadcast 热更新）
 *
 * JSON 格式示例:
 * {
 *   "patternId": "port_scan_to_c2",
 *   "name": "端口扫描→暴力破解→C2",
 *   "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
 *   "withinMinutes": 30,
 *   "enabled": true,
 *   "shadowMode": false,
 *   "version": 1
 * }
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CepPatternConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    @JsonProperty("patternId")
    private String patternId;

    @JsonProperty("name")
    private String name;

    @JsonProperty("steps")
    private List<String> steps;

    @JsonProperty("withinMinutes")
    private int withinMinutes;

    @JsonProperty("enabled")
    private boolean enabled = true;

    /** 灰度模式：仅记录不告警 */
    @JsonProperty("shadowMode")
    private boolean shadowMode = false;

    @JsonProperty("version")
    private int version = 1;

    public CepPatternConfig() {}

    public CepPatternConfig(String patternId, String name, List<String> steps,
                            int withinMinutes, boolean enabled, boolean shadowMode, int version) {
        this.patternId = patternId;
        this.name = name;
        this.steps = steps;
        this.withinMinutes = withinMinutes;
        this.enabled = enabled;
        this.shadowMode = shadowMode;
        this.version = version;
    }

    // Getters & Setters
    public String getPatternId() { return patternId; }
    public void setPatternId(String patternId) { this.patternId = patternId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public List<String> getSteps() { return steps; }
    public void setSteps(List<String> steps) { this.steps = steps; }
    public int getWithinMinutes() { return withinMinutes; }
    public void setWithinMinutes(int withinMinutes) { this.withinMinutes = withinMinutes; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isShadowMode() { return shadowMode; }
    public void setShadowMode(boolean shadowMode) { this.shadowMode = shadowMode; }
    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    @Override
    public String toString() {
        return "CepPatternConfig{id='" + patternId + "', steps=" + steps +
                ", enabled=" + enabled + ", shadow=" + shadowMode + ", v=" + version + '}';
    }
}
