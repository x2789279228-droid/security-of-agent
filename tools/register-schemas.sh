#!/bin/bash
# Schema Registry 注册脚本
# 将 Avro Schema 注册到 Confluent Schema Registry
# 用法: bash tools/register-schemas.sh [registry-url]
# 默认: http://localhost:8085

REGISTRY="${1:-http://localhost:8085}"
SCHEMA_DIR="$(dirname "$0")/../flink-jobs/schemas"

echo "=== Schema Registry 注册 (registry=$REGISTRY) ==="

# 等待 Schema Registry 就绪
until curl -s "$REGISTRY/subjects" >/dev/null 2>&1; do
  echo "等待 Schema Registry 就绪..."
  sleep 3
done

# 注册 SecurityEvent Schema
echo "注册 SecurityEvent Schema..."
curl -s -X POST "$REGISTRY/subjects/security-event-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d "{\"schema\": $(cat "$SCHEMA_DIR/security-event.avsc" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
  && echo " ✅ SecurityEvent" || echo " ❌ SecurityEvent"

# 注册 AlertEvent Schema
echo "注册 AlertEvent Schema..."
curl -s -X POST "$REGISTRY/subjects/alert-event-value/versions" \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d "{\"schema\": $(cat "$SCHEMA_DIR/alert-event.avsc" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
  && echo " ✅ AlertEvent" || echo " ❌ AlertEvent"

echo ""
echo "=== 已注册 Subjects ==="
curl -s "$REGISTRY/subjects" | python3 -m json.tool 2>/dev/null || curl -s "$REGISTRY/subjects"
echo ""
echo "=== 完成 ==="
