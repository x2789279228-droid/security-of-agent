#!/bin/bash
# Kafka TLS 证书生成脚本（自签名，竞赛/开发环境用）
# 生成 CA + Broker 证书 + 客户端证书
# 用法: bash tools/gen-kafka-certs.sh

set -e

CERT_DIR="$(dirname "$0")/../certs/kafka"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS=365
# 密钥库密码: 优先取 .env 的 KAFKA_SSL_PASSWORD (README 部署检查清单要求设置)
PASSWORD="${KAFKA_SSL_PASSWORD:-soc-kafka-2024}"

# 公网主机(IP 或域名, 来自 .env 的 KAFKA_PUBLIC_HOST), 外部日志源经 SASL_SSL 连接时校验用
SAN="DNS:kafka,DNS:localhost,IP:127.0.0.1"
if [ -n "${KAFKA_PUBLIC_HOST:-}" ]; then
  if echo "$KAFKA_PUBLIC_HOST" | grep -qE '^[0-9.]+$'; then
    SAN="$SAN,IP:$KAFKA_PUBLIC_HOST"
  else
    SAN="$SAN,DNS:$KAFKA_PUBLIC_HOST"
  fi
  echo "附加 SAN: $KAFKA_PUBLIC_HOST"
fi

echo "=== 1. 生成 CA 密钥和证书 ==="
openssl req -new -x509 -keyout ca-key.pem -out ca-cert.pem -days $DAYS -nodes \
  -subj "/CN=SOC-Kafka-CA/O=SharedMemory/C=CN"

echo "=== 2. 生成 Broker 密钥和证书 ==="
openssl req -new -newkey rsa:2048 -keyout broker-key.pem -out broker-csr.pem -nodes \
  -subj "/CN=kafka/O=SharedMemory/C=CN" \
  -addext "subjectAltName=$SAN"

# 用当前目录相对文件代替 <(...) 进程替换 (Git Bash/Windows 下 /dev/fd 不可用,
# 相对路径亦避免 MSYS 路径转换干扰原生 openssl)
EXT_FILE="san-ext.cnf"
echo "subjectAltName=$SAN" > "$EXT_FILE"
openssl x509 -req -in broker-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out broker-cert.pem -days $DAYS \
  -extfile "$EXT_FILE"
rm -f "$EXT_FILE"

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

echo "=== 4b. CA 信任库 (PKCS12) + cp-kafka 凭据文件 ==="
# cp-kafka 镜像要求 SSL 文件按 KAFKA_SSL_*_FILENAME + 凭据文件约定提供
printf '%s' "$PASSWORD" > broker-keystore-creds
printf '%s' "$PASSWORD" > broker-key-creds
printf '%s' "$PASSWORD" > truststore-creds

echo "=== 5. 创建信任库 ==="
# 注意: openssl pkcs12 -nokeys 生成的文件 Java 读不出条目, 必须用 keytool 导入
rm -f ca-truststore.p12
if command -v keytool >/dev/null 2>&1; then
  keytool -importcert -trustcacerts -alias ca -file ca-cert.pem \
    -keystore ca-truststore.p12 -storetype PKCS12 -storepass "$PASSWORD" -noprompt
elif command -v docker >/dev/null 2>&1; then
  echo "(本机无 keytool, 借用 Docker JDK 镜像生成)"
  # Windows/Git Bash 下转换为盘符路径, 兼容 MSYS_NO_PATHCONV
  WIN_CERT_DIR="$CERT_DIR"
  command -v cygpath >/dev/null 2>&1 && WIN_CERT_DIR="$(cygpath -w "$CERT_DIR")"
  docker run --rm -v "$WIN_CERT_DIR":/certs -w /certs maven:3.9-eclipse-temurin-11 \
    keytool -importcert -trustcacerts -alias ca -file ca-cert.pem \
    -keystore ca-truststore.p12 -storetype PKCS12 -storepass "$PASSWORD" -noprompt
else
  echo "错误: 需要 keytool 或 docker 来生成 ca-truststore.p12" >&2
  exit 1
fi

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
