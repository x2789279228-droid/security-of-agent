#!/bin/bash
# ── Kafka SCRAM 日志源账号创建脚本 (一次性) ──
# 在运行中的 Broker 上创建/更新 SCRAM-SHA-512 账号, 供外部日志源经
# SASL_SSL(9093) 推送使用。凭证存储在 Broker 内部(__scram 主题)。
#
# 用法:
#   bash tools/create-kafka-users.sh <用户名> <密码>
#   或从环境变量: KAFKA_LOG_SOURCE_USER / KAFKA_LOG_SOURCE_PASSWORD
#
# 前置: docker compose up -d kafka (Broker healthy)

set -e

KAFKA_USER="${1:-${KAFKA_LOG_SOURCE_USER:?用法: create-kafka-users.sh <用户名> <密码> 或设置 KAFKA_LOG_SOURCE_USER/PASSWORD}}"
KAFKA_PASS="${2:-${KAFKA_LOG_SOURCE_PASSWORD:?缺少密码参数}}"

echo "=== 创建/更新 Kafka SCRAM 账号: ${KAFKA_USER} ==="
docker compose exec kafka kafka-configs \
    --bootstrap-server localhost:9092 \
    --alter \
    --entity-type users \
    --entity-name "${KAFKA_USER}" \
    --add-config "SCRAM-SHA-512=[iterations=8192,password=${KAFKA_PASS}]"

echo "✅ 账号 ${KAFKA_USER} 就绪"
echo ""
echo "外部日志源连接方式:"
echo "  Bootstrap : <本机IP>:9093"
echo "  协议      : SASL_SSL / SCRAM-SHA-512"
echo "  CA 证书   : certs/kafka/ca-cert.pem (分发给日志源机器)"
