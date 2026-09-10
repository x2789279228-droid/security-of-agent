import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT, AI_GRADIENT_STOPS } from '../../lib/constants'
import { GradientNumber, EmptyState, SeverityChip } from './badges'
import type { FpStats, TuningSuggestion } from '../../types/operations'

const FEEDBACK_TYPES = [
  { value: 'false_positive', label: '误报（检测错了）' },
  { value: 'true_positive', label: '确认威胁（检测对了）' },
  { value: 'missed_threat', label: '漏报（没检测到）' },
  { value: 'rule_suggestion', label: '规则建议' },
]

export function FeedbackTab() {
  const [stats, setStats] = useState<FpStats | null>(null)
  const [suggestions, setSuggestions] = useState<TuningSuggestion[]>([])
  const [loading, setLoading] = useState(true)

  // 表单
  const [eventId, setEventId] = useState('')
  const [feedbackType, setFeedbackType] = useState('false_positive')
  const [ruleId, setRuleId] = useState('')
  const [reason, setReason] = useState('')
  const [suggestion, setSuggestion] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [s, g] = await Promise.all([
        api.opsFeedbackStats('', 30).catch(() => null),
        api.opsFeedbackSuggestions().catch(() => []),
      ])
      setStats(s)
      setSuggestions(Array.isArray(g) ? g : [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const submit = async () => {
    if (!reason) { setMsg('请填写原因/说明'); return }
    setSubmitting(true); setMsg('')
    try {
      await api.opsSubmitFeedback({
        event_id: eventId ? Number(eventId) : undefined,
        feedback_type: feedbackType,
        operator_conclusion: feedbackType,
        reason,
        rule_id: ruleId,
        rule_suggestion: suggestion,
        submitted_by: 'admin',
      })
      setMsg('反馈已提交，感谢！')
      setEventId(''); setReason(''); setSuggestion('')
      await load()
    } catch (e: any) { setMsg(e.message) }
    finally { setSubmitting(false) }
  }

  const ruleEntries = stats ? Object.entries(stats.by_rule).sort((a, b) => b[1].fp_rate - a[1].fp_rate) : []
  const fpPct = stats ? Math.round(stats.overall_fp_rate * 100) : 0

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
      {/* 左：提交反馈 */}
      <div>
        <h3 className="text-sm font-semibold text-ink tracking-tight mb-4">提交反馈</h3>
        <div className="bg-card/80 border border-line rounded-xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>事件 ID（可选）</FieldLabel>
              <input
                value={eventId}
                onChange={(e) => setEventId(e.target.value)}
                placeholder="如 42"
                className="w-full px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-card/80"
              />
            </div>
            <div>
              <FieldLabel>关联规则（可选）</FieldLabel>
              <input
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                placeholder="如 SIG-001"
                className="w-full px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-card/80 font-mono"
              />
            </div>
          </div>

          <div>
            <FieldLabel>反馈类型</FieldLabel>
            <div className="grid grid-cols-2 gap-2">
              {FEEDBACK_TYPES.map((t) => (
                <button
                  key={t.value}
                  onClick={() => setFeedbackType(t.value)}
                  className={`px-3 py-2 text-xs rounded-lg border text-left transition-all ${
                    feedbackType === t.value
                      ? 'border-accent bg-accent/[0.07] text-accent font-medium'
                      : 'border-line text-ink-soft hover:bg-mist/40'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <FieldLabel>原因 / 说明 *</FieldLabel>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="为什么这样判断？"
              rows={3}
              className="w-full px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-card/80 resize-none"
            />
          </div>

          {feedbackType === 'rule_suggestion' && (
            <div>
              <FieldLabel>规则调整建议</FieldLabel>
              <textarea
                value={suggestion}
                onChange={(e) => setSuggestion(e.target.value)}
                placeholder="建议如何调整规则？"
                rows={2}
                className="w-full px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-card/80 resize-none"
              />
            </div>
          )}

          <button
            onClick={submit}
            disabled={submitting}
            className="w-full py-2.5 text-xs font-medium text-on-accent rounded-lg hover:opacity-90 disabled:opacity-50"
            style={{ backgroundImage: AI_GRADIENT }}
          >
            {submitting ? '提交中…' : '提交反馈'}
          </button>
          {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{msg}</p>}
        </div>

        {/* 调优建议 */}
        <h3 className="text-sm font-semibold text-ink tracking-tight mt-8 mb-4">调优建议（{suggestions.length}）</h3>
        {suggestions.length === 0 ? (
          <EmptyState icon="💡" title="暂无调优建议" hint="积累反馈后，系统会自动分析并给出规则优化建议" />
        ) : (
          <div className="space-y-2.5">
            {suggestions.map((s, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring.ui, delay: i * 0.05 }}
                className="bg-card/80 border border-line rounded-xl px-5 py-4 shadow-[0_1px_3px_rgba(0,0,0,0.04)]"
              >
                <div className="flex items-center gap-2 mb-2">
                  <SeverityChip severity={s.severity} />
                  {s.rule_id && <span className="text-[11px] font-mono text-ink-faint">{s.rule_id}</span>}
                  {s.fp_rate !== undefined && (
                    <span className="text-[11px] font-semibold text-[#C23A32]">误报率 {Math.round(s.fp_rate * 100)}%</span>
                  )}
                </div>
                <p className="text-xs text-ink leading-relaxed">{s.suggestion}</p>
                {s.actions && s.actions.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {s.actions.map((a) => (
                      <span key={a} className="px-2 py-1 text-[10px] font-medium text-ink-soft bg-mist rounded-md">{a}</span>
                    ))}
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        )}
      </div>

      {/* 右：误报统计 */}
      <div>
        <h3 className="text-sm font-semibold text-ink tracking-tight mb-4">误报统计（近 30 天）</h3>
        {loading ? (
          <EmptyState icon="⏳" title="加载中…" />
        ) : (
          <div className="space-y-4">
            {/* 总体指标 */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-card/80 border border-line rounded-xl px-5 py-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <p className="text-[11px] font-medium text-ink-faint mb-2">整体误报率</p>
                <GradientNumber value={fpPct} suffix="%" />
              </div>
              <div className="bg-card/80 border border-line rounded-xl px-5 py-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <p className="text-[11px] font-medium text-ink-faint mb-2">反馈总数</p>
                <GradientNumber value={stats?.total_feedback ?? 0} />
              </div>
            </div>

            {/* 分类计数 */}
            <div className="bg-card/80 border border-line rounded-xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <div className="grid grid-cols-4 gap-3 text-center">
                <CountStat label="误报" value={stats?.false_positive ?? 0} color="#C23A32" />
                <CountStat label="确认" value={stats?.true_positive ?? 0} color="#3E7A64" />
                <CountStat label="漏报" value={stats?.missed_threat ?? 0} color="#C08A3A" />
                <CountStat label="建议" value={stats?.rule_suggestion ?? 0} color="#4A7A88" />
              </div>
            </div>

            {/* 按规则 FP 率 */}
            <div className="bg-card/80 border border-line rounded-xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <p className="text-[11px] font-semibold text-ink-faint uppercase tracking-wide mb-4">按规则误报率</p>
              {ruleEntries.length === 0 ? (
                <p className="text-xs text-ink-faint py-4 text-center">暂无按规则的反馈数据</p>
              ) : (
                <div className="space-y-3.5">
                  {ruleEntries.map(([rid, r], i) => (
                    <div key={rid}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono text-ink">{rid}</span>
                        <span className="text-[11px] text-ink-soft tabular-nums">
                          {Math.round(r.fp_rate * 100)}% <span className="text-ink-faint">({r.false_positive}/{r.total})</span>
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-black/[0.05] overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${Math.max(r.fp_rate * 100, 2)}%` }}
                          transition={{ ...spring.gentle, delay: i * 0.06 }}
                          className="h-full rounded-full"
                          style={{ backgroundImage: `linear-gradient(90deg, ${AI_GRADIENT_STOPS[0]}, ${AI_GRADIENT_STOPS[3]})` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] font-medium text-ink-faint mb-1.5">{children}</p>
}

function CountStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <p className="text-2xl font-extrabold tracking-tight tabular-nums" style={{ color }}>{value}</p>
      <p className="text-[10px] text-ink-faint mt-0.5">{label}</p>
    </div>
  )
}
