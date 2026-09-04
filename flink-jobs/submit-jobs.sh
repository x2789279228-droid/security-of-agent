#!/bin/bash
# ── Flink 作业提交脚本 (幂等版) ──
# 等待 JobManager 就绪后提交核心 Flink 作业。
# 幂等: 提交每作业前经 JM REST 的 /jobs/overview 检查, 若同 job 名已有任一活跃
#       (CREATED/SCHEDULED/DEPLOYING/RUNNING/RESTARTING/RECONCILING) 实例则跳过,
#       避免守护重复执行时产生双实例; 手动反复调用同样安全。
# 用法: ./submit-jobs.sh [jobmanager-host] [jm-port]
# 依赖: curl + jq (未内部处理缺失, 见脚本头注释; GPU 无关)

JM_HOST="${1:-localhost}"
JM_PORT="${2:-8081}"
JAR_PATH="/opt/flink/lib/flink-jobs-1.0.0.jar"
# 并行度: 默认取 flink-conf.yaml 的 parallelism.default (生产级配置),
# 可用 FLINK_PARALLELISM 覆盖; 不再硬编码 -p 1
PARALLELISM_ARGS=()
if [ -n "${FLINK_PARALLELISM:-}" ]; then
  PARALLELISM_ARGS=(-p "${FLINK_PARALLELISM}")
fi

ACTIVE_STATES='("CREATED|SCHEDULED|DEPLOYING|RUNNING|RESTARTING|RECONCILING")'
# 幂等探测: 若存在同名活跃 job 则返回 0(已在运行),否则返回 1
job_is_active() {
    local job_basename="$1"
    curl -sf "http://${JM_HOST}:${JM_PORT}/jobs/overview" \
        | jq -e --arg n "${job_basename}" \
            '[.jobs[] | select(.name == $n and (.state | test("^(CREATED|SCHEDULED|DEPLOYING|RUNNING|RESTARTING|RECONCILING)$")))] | length > 0' \
        > /dev/null 2>&1
}

# 提交单个作业 (幂等)
submit_job() {
    local main_class="$1"
    local job_basename="${main_class##*.}"

    if job_is_active "${job_basename}"; then
        echo "  ↺ ${job_basename} 已在运行, 跳过提交"
        return 0
    fi

    echo "  >>> 提交 ${main_class}"
    if /opt/flink/bin/flink run \
        -d \
        -m "${JM_HOST}:${JM_PORT}" \
        -c "${main_class}" \
        "${PARALLELISM_ARGS[@]}" \
        "${JAR_PATH}"; then
        echo "  ✅ ${job_basename} 提交成功"
        sleep 2
        return 0
    else
        echo "  ❌ ${main_class} 提交失败 (将由守护/下次调用重试)"
        return 1
    fi
}

# ── 提交前确保 JM 就绪 ──
echo "=== SOC 安全审计 Flink 作业提交 (幂等自动) ==="
echo "JobManager: http://${JM_HOST}:${JM_PORT}"
echo "等待 JobManager 启动..."
jm_ready=0
for i in $(seq 1 60); do
    if curl -sf "http://${JM_HOST}:${JM_PORT}/overview" > /dev/null 2>&1; then
        echo "JobManager 已就绪"
        jm_ready=1
        break
    fi
    sleep 2
done
if [ "${jm_ready}" != "1" ]; then
    echo "❌ JobManager 在超时时间内未就绪, 中止提交 (退出码 2)" >&2
    exit 2
fi

# 该脚本内部以单个大 main 类命名约束: job 名 == execute() 参数 == 全限定类名末段。
echo ""
echo "提交核心作业..."
for mc in com.soc.job.LogValidationJob com.soc.job.AnomalyDetectionJob com.soc.job.SigmaThresholdAggregationJob; do
    submit_job "${mc}"
    sleep 1
done

# ── NDR 扩展作业 (可选) ──
# 默认不提交: 其输出 topic (ndr-flows-aggregated / ndr-tls-enriched)
# 后端暂未消费, 仅在启用 NDR 流量采集演示时需要。
# 启用方式: SUBMIT_NDR_JOBS=1 ./submit-jobs.sh
if [ "${SUBMIT_NDR_JOBS:-0}" = "1" ]; then
    echo ""
    echo "提交 NDR 扩展作业..."
    for mc in com.soc.job.FlowAggregationJob com.soc.job.TlsFingerprintJob com.soc.job.BehaviorAnomalyJob; do
        submit_job "${mc}"
        sleep 1
    done
else
    echo ""
    echo "(跳过 NDR 作业: FlowAggregationJob / TlsFingerprintJob / BehaviorAnomalyJob, SUBMIT_NDR_JOBS=1 可启用)"
fi

echo ""
echo "=== 作业提交完成 ==="
echo "Flink Dashboard: http://${JM_HOST}:${JM_PORT}"
echo "Kafka UI:        http://localhost:8080"
