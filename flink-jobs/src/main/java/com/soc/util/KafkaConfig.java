package com.soc.util;

import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;

/**
 * Kafka 配置工具类
 * 集中管理所有 Kafka Topic 名称和连接配置
 */
public class KafkaConfig {

    // ==================== Kafka Topic 定义 ====================

    /** 原始安全日志 - 所有来源的日志统一入口 */
    public static final String TOPIC_RAW_LOGS = "security-logs-raw";

    /** 已验证日志 - 经过 Schema 校验和来源认证 */
    public static final String TOPIC_VALIDATED_LOGS = "security-logs-validated";

    /** 被拒绝日志 - 校验失败或认证不通过的日志 */
    public static final String TOPIC_REJECTED_LOGS = "security-logs-rejected";

    /** 已富化事件 - 附带异常评分的事件 */
    public static final String TOPIC_ENRICHED_EVENTS = "security-events-enriched";

    /** 安全告警 - 高优先级告警 */
    public static final String TOPIC_ALERTS = "security-alerts";

    /** 审计队列 - 等待 LLM 审计的事件 */
    public static final String TOPIC_AUDIT_QUEUE = "security-audit-queue";

    /** 死信队列 - 处理失败的消息 */
    public static final String TOPIC_DLQ = "security-logs-dlq";

    /** CEP 部分匹配 - 攻击链中间状态（可视化用）*/
    public static final String TOPIC_CEP_PARTIAL = "security-cep-partial";

    /** CEP 模式配置 - Broadcast 热更新通道 */
    public static final String TOPIC_CEP_PATTERNS = "security-cep-patterns";

    /** Sigma 聚合候选 - pySigma 单事件命中带聚合聚合规则(如 SIG-001/007)的事件; Flink 阈值窗口消费 */
    public static final String TOPIC_SIGMA_HIT = "security-sigma-hit";

    // ==================== Kafka 连接配置 ====================

    /** Kafka Bootstrap 服务器地址，支持环境变量覆盖 */
    public static final String KAFKA_BOOTSTRAP;

    static {
        String env = System.getenv("KAFKA_BOOTSTRAP");
        KAFKA_BOOTSTRAP = (env != null && !env.isEmpty()) ? env : "localhost:9092";
    }

    /**
     * 获取 Kafka Bootstrap 服务器地址
     *
     * @return bootstrap servers 字符串
     */
    public static String getBootstrapServers() {
        return KAFKA_BOOTSTRAP;
    }

    /**
     * 获取 Kafka 消费者配置
     *
     * @param groupId 消费者组 ID
     * @return 消费者 Properties
     */
    public static Properties getConsumerProperties(String groupId) {
        Properties props = new Properties();
        props.setProperty("bootstrap.servers", KAFKA_BOOTSTRAP);
        props.setProperty("group.id", groupId);
        props.setProperty("key.deserializer", StringDeserializer.class.getName());
        props.setProperty("value.deserializer", StringDeserializer.class.getName());
        // 从最早的消息开始消费（演示环境）
        props.setProperty("auto.offset.reset", "earliest");
        return props;
    }

    /**
     * 获取 Kafka 生产者配置
     *
     * @return 生产者 Properties
     */
    public static Properties getProducerProperties() {
        Properties props = new Properties();
        props.setProperty("bootstrap.servers", KAFKA_BOOTSTRAP);
        props.setProperty("key.serializer", StringSerializer.class.getName());
        props.setProperty("value.serializer", StringSerializer.class.getName());
        return props;
    }

    private KafkaConfig() {
        // 工具类，禁止实例化
    }
}
