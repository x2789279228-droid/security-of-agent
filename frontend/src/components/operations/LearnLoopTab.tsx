import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { EmptyState } from './badges'
import type { LearningRun, LearningAction } from '../../types/operations'
import { LEARN_STATUS_TONE, STATUS_TONE } from '../../lib/operationsTokens'

const MECHANISMS: { key: string; label: string }[] = [
  { key: 'baseline', label: '基线' },
  { key: 'reputation', label: '信誉' },
  { key: 'feedback', label: '反馈' },
  { key: 'degrade', label: '降级' },
  { key: 'tune', label: '调优' },
  { key: 'postmortem', label: '复盘' },
  { key: 'case', label: '案例' },
]

const ACTION_TYPE_LABELS: Record<string, string> = {
  draft_post_mortem: '补复盘草稿',
  shadow_rule: '规则降级 shadow',
  decay_baseline_entity: '基线衰减',
  update_reputation_prior: '信誉先验更新',
  persist_tuning_suggestion: '调优建议记账',
  open_review_work_order: '复盘跟进工单',
  apply_sigma_change: '修改 Sigma 规则',
  adjust_anomaly_threshold: '阈值调整',
  label_cluster: '聚类人工打标',
  propose_sequence_signature: '序列签名提议',
}

const STATUS_META = LEARN_STATUS_TONE

const FILTERS: { value: string; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'proposed', label: '待复核' },
  { value: 'auto_applied', label: '自动应用' },
  { value: 'applied', label: '已应用' },
  { value: 'dismissed', label: '已驳回' },
]

function harvestCount(v: unknown): number {
  if (typeof v === 'number') return v
  if (v && typeof v === 'object') {
    const count = (v as Record<string, unknown>).count
    if (typeof count === 'number') return count
  }
  return 0
}

function statusMeta(status: string) {
  return STATUS_META[status] ?? { label: status, color: STATUS_TONE.neutral }
}

function payloadSnippet(payload: Record<string, unknown> | undefined): string {
  if (!payload || Object.keys(payload).length === 0) return '—'
  try {
    const s = JSON.stringify(payload)
    return s.length > 64 ? `${s.slice(0, 64)}…` : s
  } catch {
    return '—'
  }
}

export function LearnLoopTab() {
  const [run, setRun] = useState<LearningRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [busyId, setBusyId] = useState<number | null>(null)
  const [running, setRunning] = useState(false)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.opsLearnLoopLatest().catch(() => null)
      setRun(r && r.id ? (r as LearningRun) : null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const triggerRun = async () => {
    setRunning(true); setMsg('')
    try {
      await api.opsLearnLoopTrigger()
      setMsg('本轮学习闭环已完成')
      await load()
    } catch (e: any) { setMsg(e.message) }
    finally { setRunning(false) }
  }

  const act = async (action: LearningAction, kind: 'apply' | 'dismiss' | 'rollback') => {
    setBusyId(action.id); setMsg('')
    try {
      const fn = kind === 'apply' ? api.opsLearnLoopApply
        : kind === 'dismiss' ? api.opsLearnLoopDismiss
        : api.opsLearnLoopRollback
      await fn(action.id)
      await load()
    } catch (e: any) { setMsg(e.message) }
    finally { setBusyId(null) }
  }

  const actions = run?.actions ?? []
  const filtered = filter === 'all' ? actions : actions.filter((a) => a.status === filter)

  const modelSummary = (run?.model_summary ?? {}) as Record<string, any>
  const clusters = (modelSummary.clusters ?? {}) as Record<string, any>
  const partialErrors: string[] = Array.isArray(modelSummary.partial_errors)
    ? modelSummary.partial_errors
    : []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-xs text-ink-faint">
          收割 → 统计/聚类/序列 → 提议动作 → 白名单自动应用 → 人工复核
        </p>
        <button
          onClick={triggerRun}
          disabled={running}
          className="px-3 py-1.5 text-xs font-medium text-on-accent rounded-lg hover:opacity-90 disabled:opacity-50"
          style={{ backgroundImage: AI_GRADIENT }}
        >
          {running ? '运行中…' : '立即跑一轮'}
        </button>
      </div>

      {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{msg}</p>}

      {loading ? (
        <EmptyState icon="⏳" title="加载学习闭环中…" />
      ) : !run ? (
        <EmptyState
          icon="🔁"
          title="暂无学习闭环运行"
          hint="点击右上「立即跑一轮」启动收割 → 提议 → 自动应用"
        />
      ) : (
        <>
          <div className="rounded-xl bg-card/80 border border-line p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <span
                className="inline-flex items-center rounded-lg px-2 py-0.5 text-[10px] font-semibold whitespace-nowrap"
                style={{
                  color: run.status === 'completed' ? STATUS_TONE.success : STATUS_TONE.pending,
                  background: (run.status === 'completed' ? STATUS_TONE.success : STATUS_TONE.pending) + '1f',
                  boxShadow: `inset 0 0 0 1px ${(run.status === 'completed' ? STATUS_TONE.success : STATUS_TONE.pending) + '4d'}`,
                }}
              >
                {run.status === 'completed' ? '已完成' : run.status}
              </span>
              <span className="text-[11px] text-ink-faint">
                #{run.id} · 触发: {run.trigger === 'manual' ? '手动' : run.trigger === 'daily' ? '每日' : run.trigger}
              </span>
              <span className="text-[11px] text-ink-faint tabular-nums">
                窗口 {run.window_start.slice(0, 16).replace('T', ' ')} → {run.window_end.slice(0, 16).replace('T', ' ')}
              </span>
              <span className="text-[11px] text-ink-faint tabular-nums ml-auto">
                提议 {run.actions_proposed} · 自动应用 {run.actions_auto_applied} · 失败 {run.actions_failed}
              </span>
            </div>

            <div className="grid grid-cols-7 gap-2">
              {MECHANISMS.map((m) => (
                <div key={m.key} className="text-center bg-mist/60 rounded-lg px-2 py-3 border border-line/60">
                  <p className="text-xl font-extrabold tracking-tight tabular-nums text-ink">
                    {harvestCount(run.harvest?.[m.key])}
                  </p>
                  <p className="text-[10px] text-ink-faint mt-0.5">{m.label}</p>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2 mt-3">
              {typeof clusters.count === 'number' && clusters.count > 0 && (
                <span className="px-2 py-1 text-[10px] font-medium text-ink-soft bg-mist rounded-md border border-line/60">
                  FP/漏报聚类 {clusters.count} 个
                </span>
              )}
              {run.error && (
                <span className="px-2 py-1 text-[10px] font-medium text-alert bg-alert/10 rounded-md border border-alert/30" title={run.error}>
                  局部失败 {run.error.length > 60 ? `${run.error.slice(0, 60)}…` : run.error}
                </span>
              )}
              {partialErrors.slice(0, 3).map((e, i) => (
                <span key={i} className="px-2 py-1 text-[10px] font-medium text-warn bg-warn/10 rounded-md border border-warn/30">
                  {String(e).slice(0, 50)}
                </span>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {FILTERS.map((f) => (
              <button
                key={f.value}
                onClick={() => setFilter(f.value)}
                className={`px-3 py-1 text-xs rounded-full transition-all ${
                  filter === f.value
                    ? 'bg-accent text-on-accent font-medium'
                    : 'bg-mist text-ink-soft hover:bg-line border border-line/60'
                }`}
              >
                {f.label}
                {f.value !== 'all' && (
                  <span className="ml-1 tabular-nums opacity-70">
                    {actions.filter((a) => a.status === f.value).length}
                  </span>
                )}
              </button>
            ))}
          </div>

          {filtered.length === 0 ? (
            <EmptyState icon="🗂" title="该状态下暂无动作" hint="等待下一轮学习闭环产出" />
          ) : (
            <div className="rounded-xl bg-card/80 border border-line overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wide text-ink-faint text-left bg-mist/60 border-b border-line">
                    <th className="px-4 py-3 font-medium">动作</th>
                    <th className="px-4 py-3 font-medium">机制</th>
                    <th className="px-4 py-3 font-medium">目标</th>
                    <th className="px-4 py-3 font-medium">状态</th>
                    <th className="px-4 py-3 font-medium">置信度</th>
                    <th className="px-4 py-3 font-medium">Payload</th>
                    <th className="px-4 py-3 font-medium text-right">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((a, i) => {
                    const meta = statusMeta(a.status)
                    const busy = busyId === a.id
                    const canApply = a.status === 'proposed'
                    const canRollback = a.status === 'auto_applied' || a.status === 'applied'
                    return (
                      <motion.tr
                        key={a.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...spring.ui, delay: Math.min(i, 10) * 0.02 }}
                        className="border-t border-line hover:bg-mist/40 transition-colors"
                      >
                        <td className="px-4 py-2.5 font-medium text-ink">
                          {ACTION_TYPE_LABELS[a.action_type] ?? a.action_type}
                          <span className="block text-[10px] font-mono text-ink-faint">{a.action_type}</span>
                        </td>
                        <td className="px-4 py-2.5 text-ink-soft">{a.mechanism || '—'}</td>
                        <td className="px-4 py-2.5 text-ink-soft font-mono max-w-[160px] truncate">
                          {a.target_type}:{a.target_id || '—'}
                        </td>
                        <td className="px-4 py-2.5">
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold whitespace-nowrap"
                            style={{ color: meta.color, background: `${meta.color}1a` }}
                          >
                            {meta.label}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 tabular-nums text-ink-soft">
                          {Math.round((a.confidence ?? 0) * 100)}%
                        </td>
                        <td className="px-4 py-2.5 text-[10px] font-mono text-ink-faint max-w-[220px] truncate" title={payloadSnippet(a.payload)}>
                          {payloadSnippet(a.payload)}
                        </td>
                        <td className="px-4 py-2.5 text-right whitespace-nowrap">
                          {busy ? (
                            <span className="text-[10px] text-ink-faint">处理中…</span>
                          ) : (
                            <>
                              {canApply && (
                                <>
                                  <button
                                    onClick={() => act(a, 'apply')}
                                    className="px-2 py-1 text-[10px] font-medium text-on-accent rounded hover:opacity-90 mr-1"
                                    style={{ backgroundImage: AI_GRADIENT }}
                                  >
                                    应用
                                  </button>
                                  <button
                                    onClick={() => act(a, 'dismiss')}
                                    className="px-2 py-1 text-[10px] font-medium text-ink-soft bg-mist rounded hover:bg-line border border-line/60"
                                  >
                                    驳回
                                  </button>
                                </>
                              )}
                              {canRollback && (
                                <button
                                  onClick={() => act(a, 'rollback')}
                                  className="px-2 py-1 text-[10px] font-medium text-ink-soft bg-mist rounded hover:bg-line border border-line/60"
                                >
                                  回滚
                                </button>
                              )}
                              {!canApply && !canRollback && <span className="text-[10px] text-ink-faint">—</span>}
                            </>
                          )}
                        </td>
                      </motion.tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <div className="rounded-xl bg-card/80 border border-line p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <p className="text-[11px] font-semibold text-ink-faint uppercase tracking-wide mb-3">自动应用白名单</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {[
            { t: '补复盘草稿', d: '已关闭案例缺失复盘 → 自动生成草稿' },
            { t: '规则降级 shadow', d: '高误报规则 → 仅告警不响应' },
            { t: '基线衰减', d: '误报 IP 基线减半（不可回滚）' },
            { t: '信誉先验更新', d: 'TP/FP 反馈 → 有界信誉微调' },
            { t: '调优建议记账', d: '调优建议持久化到学习动作' },
            { t: '复盘跟进工单', d: '复盘待办 → 自动开 review 工单' },
          ].map((x) => (
            <div key={x.t} className="bg-mist/60 rounded-lg px-3 py-2.5 border border-line/60">
              <p className="text-xs font-medium text-ink">{x.t}</p>
              <p className="text-[10px] text-ink-faint mt-0.5">{x.d}</p>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-ink-faint mt-3">
          LLM 结论永不自动写回规则 — apply_sigma_change 须人工确认后应用
        </p>
      </div>
    </div>
  )
}
