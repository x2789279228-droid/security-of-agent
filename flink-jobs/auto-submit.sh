#!/bin/bash
# ── Flink 作业守护提交器 (Job 启动自动化 / 故障自动重提) ──
# 常驻循环, 每 POLL_SECONDS 检查一次:
#   1) 等 JobManager REST 就绪;
#   2) 集群总槽位 ≥ ${AUTO_SUBMIT_MIN_SLOTS} (默认 15, 即 3×TaskManager×5 全注册);
#      不足则等待(此时提交必因槽位不足失败/错位);
#   3) 调用幂等的 submit-jobs.sh 提交核心作业(shell 脚本内逐作业探测同名活跃即跳过)。
# 效果:
#   · docker compose up 后无需任何手动命令即自动提交全部核心作业 → 解决"启动未自动化"
#   · JobManager / TaskManager 崩溃重启、作业最终失败或被 cancel 后, 槽位恢复即自动重新提交
# 依赖: curl + jq (Dockerfile 已安装); 调用同目录 submit-jobs.sh (内置到 /opt/flink)
# 用法: 作为 flink-job-submitter 容器 CMD; 亦可手动执行 ./auto-submit.sh [host] [port]
# 配置(环境变量):
#   POLL_SECONDS              轮询间隔(默认 30)
#   AUTO_SUBMIT_MIN_SLOTS     触发提交所需最小总槽(默认 15)
#   JM_READY_TIMEOUT_SEC      首启等待 JM 就绪上限; 超时退出交 restart:always 拉回(默认 900)

set -u

JM_HOST="${1:-${JM_HOST:-flink-jobmanager}}"
JM_PORT="${2:-${JM_PORT:-8081}}"
POLL_SECONDS="${POLL_SECONDS:-30}"
AUTO_SUBMIT_MIN_SLOTS="${AUTO_SUBMIT_MIN_SLOTS:-15}"
JM_READY_TIMEOUT_SEC="${JM_READY_TIMEOUT_SEC:-900}"

BASE="http://${JM_HOST}:${JM_PORT}"
# CORE_JOBS: 与 submit-jobs.sh 保持一致(仅用于"是否已有人提过"的判断, 实际提交幂等由该脚本承担)
CORE_JOBS='("LogValidationJob"|"AnomalyDetectionJob"|"SigmaThresholdAggregationJob")'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBMIT_SCRIPT="${SUBMIT_SCRIPT:-${SCRIPT_DIR}/submit-jobs.sh}"

log() { echo "[auto-submit] $(date '+%F %T') $*"; }

# 0=JM 已就绪; 1=超时不可达
wait_jm_ready() {
    local waited=0
    while [ "${waited}" -lt "${JM_READY_TIMEOUT_SEC}" ]; do
        curl -sf "${BASE}/overview" > /dev/null 2>&1 && return 0
        log "等待 JobManager 就绪 (${waited}s / ${JM_READY_TIMEOUT_SEC}s)..."
        sleep 10
        waited=$((waited + 10))
    done
    return 1
}

overview_ready() {
    curl -sf "${BASE}/overview" > /dev/null 2>&1
}

# 槽位与核心作业状态: 返回码
#   0 = 待提交(槽位够, 且当前无任何核心作业存活)
#   1 = 已全部存活(无需提交)
#   2 = 槽位不足(继续等)
#   3 = JM 不可达(REST 探测失败)
cls_ready() {
    if ! overview_ready; then return 3; fi
    local overview
    overview="$(curl -sf "${BASE}/overview")" || return 3
    # 总槽位是否达到阈值 (含连字符字段须用 .["..."] 形式)
    if ! echo "${overview}" | jq -e --argjson m "${AUTO_SUBMIT_MIN_SLOTS}" '.["slots-total"] >= $m' > /dev/null 2>&1; then
        return 2
    fi
    # 是否有任一核心作业存活(更细粒度幂等交给 submit-jobs.sh)
    if curl -sf "${BASE}/jobs/overview" | jq -e --arg pat "${CORE_JOBS}" \
        '[.jobs[] | select(.name | test($pat) ) | select(.state | test("^(CREATED|SCHEDULED|DEPLOYING|RUNNING|RESTARTING|RECONCILING)$"))] | length > 0' > /dev/null 2>&1; then
        return 1
    fi
    return 0
}

log "守护启动 host=${JM_HOST}:${JM_PORT} min_slots=${AUTO_SUBMIT_MIN_SLOTS} poll=${POLL_SECONDS}s"

if ! wait_jm_ready; then
    log "JobManager 首次启动超时 (${JM_READY_TIMEOUT_SEC}s), 退出交 restart 策略重试"
    exit 1
fi
log "JobManager 已就绪"

while :; do
    cls_ready
    rc=$?
    case "${rc}" in
        0)
            log "集群槽位 ≥ ${AUTO_SUBMIT_MIN_SLOTS} 且核心作业缺失 → 触发幂等提交 (${SUBMIT_SCRIPT})"
            "${SUBMIT_SCRIPT}" "${JM_HOST}" "${JM_PORT}"
            log "提交轮回结束 (状态码 $?)"
            ;;
        1)
            log "核心作业均已在运行 → 本轮回无需动作"
            ;;
        2)
            log "总槽位仍未达 ${AUTO_SUBMIT_MIN_SLOTS}, 等待... (watchdog 保持, 槽位补齐即自动提交)"
            ;;
        3)
            log "JobManager 暂不可达, 等待其恢复(恢复后由本守护自动重交/补交)..."
            ;;
    esac
    sleep "${POLL_SECONDS}"
done
