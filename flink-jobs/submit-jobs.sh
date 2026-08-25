#!/bin/bash
# ── Flink 作业提交脚本 ──
# 等待 JobManager 就绪后提交两个 Flink 作业
# 用法: ./submit-jobs.sh [jobmanager-host]

JM_HOST="${1:-localhost}"
JM_PORT=8081
JAR_PATH="/opt/flink/lib/flink-jobs-1.0.0.jar"
# 并行度: 默认取 flink-conf.yaml 的 parallelism.default (生产级配置),
# 可用 FLINK_PARALLELISM 覆盖; 不再硬编码 -p 1
PARALLELISM_ARGS=()
if [ -n "${FLINK_PARALLELISM:-}" ]; then
  PARALLELISM_ARGS=(-p "${FLINK_PARALLELISM}")
fi

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
    "${PARALLELISM_ARGS[@]}" \
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
    "${PARALLELISM_ARGS[@]}" \
    "$JAR_PATH" \
    && echo "✅ AnomalyDetectionJob 提交成功" \
    || echo "❌ AnomalyDetectionJob 提交失败"

sleep 3

# 提交 Job 3: SigmaThresholdAggregationJob (Sigma 聚合阈值窗口 - 阈值类规则分布统计)
echo ""
echo ">>> 提交 Job 3: SigmaThresholdAggregationJob (Sigma 聚合阈值窗口)"
/opt/flink/bin/flink run \
    -m "${JM_HOST}:${JM_PORT}" \
    -d \
    -c com.soc.job.SigmaThresholdAggregationJob \
    "${PARALLELISM_ARGS[@]}" \
    "$JAR_PATH" \
    && echo "✅ SigmaThresholdAggregationJob 提交成功" \
    || echo "❌ SigmaThresholdAggregationJob 提交失败"

# ── NDR 扩展作业 (可选) ──
# 默认不提交: 其输出 topic (ndr-flows-aggregated / ndr-tls-enriched)
# 后端暂未消费, 仅在启用 NDR 流量采集演示时需要。
# 启用方式: SUBMIT_NDR_JOBS=1 ./submit-jobs.sh
if [ "${SUBMIT_NDR_JOBS:-0}" = "1" ]; then
    echo ""
    echo ">>> 提交 Job 3: FlowAggregationJob (网络流聚合)"
    /opt/flink/bin/flink run \
        -m "${JM_HOST}:${JM_PORT}" \
        -c com.soc.job.FlowAggregationJob \
        "${PARALLELISM_ARGS[@]}" \
        "$JAR_PATH" \
        && echo "✅ FlowAggregationJob 提交成功" \
        || echo "❌ FlowAggregationJob 提交失败"

    sleep 3

    echo ""
    echo ">>> 提交 Job 4: TlsFingerprintJob (TLS 指纹识别)"
    /opt/flink/bin/flink run \
        -m "${JM_HOST}:${JM_PORT}" \
        -c com.soc.job.TlsFingerprintJob \
        "${PARALLELISM_ARGS[@]}" \
        "$JAR_PATH" \
        && echo "✅ TlsFingerprintJob 提交成功" \
        || echo "❌ TlsFingerprintJob 提交失败"
else
    echo ""
    echo "(跳过 NDR 作业: FlowAggregationJob / TlsFingerprintJob, SUBMIT_NDR_JOBS=1 可启用)"
fi

echo ""
echo "=== 作业提交完成 ==="
echo "Flink Dashboard: http://${JM_HOST}:${JM_PORT}"
echo "Kafka UI:        http://localhost:8080"
