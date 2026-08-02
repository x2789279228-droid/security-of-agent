#!/bin/bash
# Kafka Topic 差异化保留策略初始化
# 在 Kafka 启动后执行: bash tools/init-kafka-topics.sh [bootstrap-server]
# 默认: localhost:9092

BOOTSTRAP="${1:-localhost:9092}"
KAFKA_CONFIGS="kafka-configs --bootstrap-server $BOOTSTRAP"
KAFKA_TOPICS="kafka-topics --bootstrap-server $BOOTSTRAP"

echo "=== Kafka Topic 初始化 (bootstrap=$BOOTSTRAP) ==="

# 等待 Kafka 就绪
until $KAFKA_TOPICS --list >/dev/null 2>&1; do
  echo "等待 Kafka 就绪..."
  sleep 3
done

# ── 创建 Topic（如不存在）并设置差异化保留策略 ──

# 原始日志: 保留 3 天（数据量大，快速过期）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-raw --partitions 3 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-logs-raw \
  --add-config retention.ms=259200000,retention.bytes=536870912,cleanup.policy=delete

# 已验证日志: 保留 5 天
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-validated --partitions 3 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-logs-validated \
  --add-config retention.ms=432000000,retention.bytes=536870912,cleanup.policy=delete

# 被拒绝日志: 保留 14 天（审计需要，量小）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-rejected --partitions 1 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-logs-rejected \
  --add-config retention.ms=1209600000,cleanup.policy=delete

# 富化事件: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-events-enriched --partitions 3 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-events-enriched \
  --add-config retention.ms=604800000,retention.bytes=1073741824,cleanup.policy=delete

# 告警: 保留 30 天（关键安全数据，长期保留）
$KAFKA_TOPICS --create --if-not-exists --topic security-alerts --partitions 1 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-alerts \
  --add-config retention.ms=2592000000,cleanup.policy=delete

# 审计队列: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-audit-queue --partitions 2 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-audit-queue \
  --add-config retention.ms=604800000,cleanup.policy=delete

# 审计结果: 保留 30 天（合规要求）
$KAFKA_TOPICS --create --if-not-exists --topic security-audit-results --partitions 2 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-audit-results \
  --add-config retention.ms=2592000000,cleanup.policy=delete

# 死信队列: 保留 30 天（故障排查需要）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-dlq --partitions 1 --replication-factor 1
$KAFKA_CONFIGS --alter --topic security-logs-dlq \
  --add-config retention.ms=2592000000,cleanup.policy=delete

echo ""
echo "=== Topic 保留策略 ==="
echo "  security-logs-raw:          3 天  (512MB)"
echo "  security-logs-validated:    5 天  (512MB)"
echo "  security-logs-rejected:    14 天"
echo "  security-events-enriched:   7 天  (1GB)"
echo "  security-alerts:           30 天"
echo "  security-audit-queue:       7 天"
echo "  security-audit-results:    30 天"
echo "  security-logs-dlq:         30 天"
echo ""
echo "=== 完成 ==="
