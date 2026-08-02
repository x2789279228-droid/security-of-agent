#!/bin/bash
# Kafka TLS 证书生成脚本（自签名，竞赛/开发环境用）
# 生成 CA + Broker 证书 + 客户端证书
# 用法: bash tools/gen-kafka-certs.sh

set -e

CERT_DIR="$(dirname "$0")/../certs/kafka"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS=365
PASSWORD="soc-kafka-2024"

echo "=== 1. 生成 CA 密钥和证书 ==="
openssl req -new -x509 -keyout ca-key.pem -out ca-cert.pem -days $DAYS -nodes \
  -subj "/CN=SOC-Kafka-CA/O=SharedMemory/C=CN"

echo "=== 2. 生成 Broker 密钥和证书 ==="
openssl req -new -newkey rsa:2048 -keyout broker-key.pem -out broker-csr.pem -nodes \
  -subj "/CN=kafka/O=SharedMemory/C=CN" \
  -addext "subjectAltName=DNS:kafka,DNS:localhost,IP:127.0.0.1"

openssl x509 -req -in broker-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out broker-cert.pem -days $DAYS \
  -extfile <(echo "subjectAltName=DNS:kafka,DNS:localhost,IP:127.0.0.1")

echo "=== 3. 生成客户端密钥和证书 ==="
openssl req -new -newkey rsa:2048 -keyout client-key.pem -out client-csr.pem -nodes \
  -subj "/CN=soc-client/O=SharedMemory/C=CN"

openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days $DAYS

echo "=== 4. 创建 PKCS12 密钥库（Java/Flink 用）==="
openssl pkcs12 -export -in broker-cert.pem -inkey broker-key.pem \
  -chain -CAfile ca-cert.pem -name broker \
  -out broker-keystore.p12 -password pass:$PASSWORD

openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem \
  -chain -CAfile ca-cert.pem -name client \
  -out client-keystore.p12 -password pass:$PASSWORD

echo "=== 5. 创建信任库 ==="
keytool -import -trustcacerts -alias ca -file ca-cert.pem \
  -keystore truststore.jks -storepass $PASSWORD -noprompt 2>/dev/null || \
  echo "(keytool not found, skipping JKS truststore — PEM files are sufficient)"

# 清理 CSR
rm -f broker-csr.pem client-csr.pem

echo ""
echo "=== 证书生成完成 ==="
echo "目录: $CERT_DIR"
ls -la *.pem *.p12 2>/dev/null
echo ""
echo "配置说明:"
echo "  Broker 证书: broker-cert.pem + broker-key.pem"
echo "  CA 证书:     ca-cert.pem"
echo "  客户端证书:  client-cert.pem + client-key.pem"
echo "  PKCS12:      broker-keystore.p12 / client-keystore.p12 (密码: $PASSWORD)"
