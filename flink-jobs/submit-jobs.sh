#!/bin/bash
# ── Flink 作业提交脚本 ──
# 等待 JobManager 就绪后提交两个 Flink 作业
# 用法: ./submit-jobs.sh [jobmanager-host]

JM_HOST="${1:-localhost}"
JM_PORT=8081
JAR_PATH="/opt/flink/lib/flink-jobs-1.0.0.jar"

echo "=== SOC 安全审计 Flink 作业提交 ==="
echo "JobManager: http://${JM_HOST}:${JM_PORT}"

# 等待 JobManager 就绪
echo "等待 JobManager 启动..."
for i in $(seq 1 60); do
    if curl -s "http://${JM_HOST}:${JM_PORT}/overview" > /dev/null 2>&1; then
        echo "JobManager 已就绪"
        break
    fi
    sleep 2
done

# 提交 Job 1: 日志验证与分级
echo ""
echo ">>> 提交 Job 1: LogValidationJob (日志验证与分级)"
/opt/flink/bin/flink run \
    -m "${JM_HOST}:${JM_PORT}" \
    -c com.soc.job.LogValidationJob \
    -p 1 \
    "$JAR_PATH" \
    && echo "✅ LogValidationJob 提交成功" \
    || echo "❌ LogValidationJob 提交失败"

sleep 3

# 提交 Job 2: 异常检测与攻击链 CEP
echo ""
echo ">>> 提交 Job 2: AnomalyDetectionJob (异常检测 + CEP 攻击链)"
/opt/flink/bin/flink run \
    -m "${JM_HOST}:${JM_PORT}" \
    -c com.soc.job.AnomalyDetectionJob \
    -p 1 \
    "$JAR_PATH" \
    && echo "✅ AnomalyDetectionJob 提交成功" \
    || echo "❌ AnomalyDetectionJob 提交失败"

echo ""
echo "=== 作业提交完成 ==="
echo "Flink Dashboard: http://${JM_HOST}:${JM_PORT}"
echo "Kafka UI:        http://localhost:8080"
