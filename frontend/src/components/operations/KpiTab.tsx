import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT, AI_GRADIENT_STOPS } from '../../lib/constants'
import { GradientNumber, EmptyState } from './badges'

interface KpiPoint { date: string; metric_value: number; dimensions?: Record<string, string> }
type KpiSeries = KpiPoint[]

interface Dashboard {
  mttd: KpiSeries
  mttr: KpiSeries
  case_count: KpiSeries
  case_cycle_hours: KpiSeries
  sla_breach_rate: KpiSeries
  fp_rate: KpiSeries
  feedback_count: KpiSeries
  order_count: KpiSeries
  case_count_priority?: Record<string, KpiSeries>
  mttr_priority?: Record<string, KpiSeries>
  sla_breach_rate_priority?: Record<string, KpiSeries>
}

interface SlaInfo {
  rate: { hours: number; total: number; breached: number; rate: number; by_priority: Record<string, { total: number; breached: number; rate: number }> }
  recent: { order_number: string; priority: string; recorded_at: string; case_id?: number }[]
}

export function KpiTab() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [sla, setSla] = useState<SlaInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [period, setPeriod] = useState(30)
  const [snapMsg, setSnapMsg] = useState('')
  const [snapshotting, setSnapshotting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [d, s] = await Promise.all([
        api.opsKpiDashboard(period).catch(() => null),
        api.opsSla(24).catch(() => null),
      ])
      setDashboard(d as any)
      setSla(s as any)
    } finally {
      setLoading(false)
    }
  }, [period])

  useEffect(() => { load() }, [load])

  const triggerSnapshot = async () => {
    setSnapshotting(true); setSnapMsg('')
    try {
      const r = await api.opsKpiSnapshot('daily', '')
      setSnapMsg(`快照成功：${r.metrics_written ?? 0} 条指标`)
      await load()
    } catch (e: any) { setSnapMsg(e.message) }
    finally { setSnapshotting(false) }
  }

  // 最新值取
  const last = (s?: KpiSeries) => (s && s.length ? s[s.length - 1].metric_value : 0)

  // 指标卡数据
  const cards = [
    { key: 'mttr', label: 'MTTR（小时）', value: last(dashboard?.mttr), color: '#FF9F0A', series: dashboard?.mttr ?? [] },
    { key: 'mttd', label: 'MTTD（小时）', value: last(dashboard?.mttd), color: '#0A84FF', series: dashboard?.mttd ?? [] },
    { key: 'case_count', label: '案例数', value: last(dashboard?.case_count), color: '#5E5CE6', series: dashboard?.case_count ?? [] },
    { key: 'fp_rate', label: '误报率', value: last(dashboard?.fp_rate), color: '#BF5AF2', series: dashboard?.fp_rate ?? [], pct: true },
    { key: 'sla_breach_rate', label: 'SLA 违约率', value: last(dashboard?.sla_breach_rate), color: '#FF375F', series: dashboard?.sla_breach_rate ?? [], pct: true },
    { key: 'order_count', label: '工单数', value: last(dashboard?.order_count), color: '#34c759', series: dashboard?.order_count ?? [] },
  ]

  return (
    <div className="space-y-6">
      {/* 顶部：周期选择 + 触发快照 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs text-ink-faint">聚合周期</span>
          {[7, 14, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setPeriod(d)}
              className={`px-3 py-1 text-xs rounded-full transition-all ${
                period === d
                  ? 'bg-accent text-white font-medium'
                  : 'bg-black/[0.04] text-ink-soft hover:bg-black/[0.07]'
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
        <button
          onClick={triggerSnapshot}
          disabled={snapshotting}
          className="px-3 py-1.5 text-xs font-medium text-white rounded-lg hover:opacity-90 disabled:opacity-50"
          style={{ backgroundImage: AI_GRADIENT }}
        >
          {snapshotting ? '生成中…' : '手动触发日快照'}
        </button>
      </div>

      {snapMsg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{snapMsg}</p>}

      {/* 指标卡阵列 */}
      {loading ? (
        <EmptyState icon="⏳" title="加载 KPI 中…" />
      ) : !dashboard ? (
        <EmptyState icon="📊" title="暂无 KPI 数据" hint='点击右上"手动触发日快照"生成历史聚合' />
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {cards.map((c) => (
              <div key={c.key} className="bg-white border border-line rounded-none px-4 py-4 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <div className="flex items-center gap-1.5 mb-2">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: c.color }} />
                  <span className="text-[11px] font-medium text-ink-faint">{c.label}</span>
                </div>
                <GradientNumber
                  value={c.pct ? Math.round((c.value ?? 0) * 100) : (c.value ?? 0).toFixed(1)}
                  suffix={c.pct ? '%' : ''}
                />
                {/* mini sparkline 用最近 7 个点的横向 bar */}
                <div className="mt-3 flex items-end gap-0.5 h-6">
                  {(c.series || []).slice(-14).map((p, i) => {
                    const v = c.pct ? p.metric_value * 100 : p.metric_value
                    const maxV = c.pct
                      ? 100
                      : Math.max(...(c.series || []).map((x) => x.metric_value), 1)
                    const h = Math.max(2, Math.min(100, (v / maxV) * 100))
                    return (
                      <motion.div
                        key={i}
                        initial={{ height: 0 }}
                        animate={{ height: `${h}%` }}
                        transition={{ ...spring.ui, delay: i * 0.02 }}
                        className="flex-1 rounded-sm"
                        style={{ background: c.color, opacity: 0.4 + (i / 14) * 0.6 }}
                      />
                    )
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* 案例数优先级切分 */}
          {dashboard.case_count_priority && (
            <div className="bg-white border border-line rounded-none p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <h3 className="text-[13px] font-semibold text-ink mb-4">按优先级的案例数（{period} 天）</h3>
              <div className="space-y-3">
                {(['critical', 'high', 'medium', 'low'] as const).map((prio) => {
                  const s = dashboard.case_count_priority![prio] || []
                  const total = s.reduce((sum, p) => sum + p.metric_value, 0)
                  const color = prio === 'critical' ? '#FF375F' : prio === 'high' ? '#FF9F0A' : prio === 'medium' ? '#0A84FF' : '#86868b'
                  return (
                    <div key={prio}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-ink">{prio}</span>
                        <span className="text-[11px] text-ink-soft tabular-nums">{total} 件</span>
                      </div>
                      <div className="h-2 rounded-full bg-black/[0.05] overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${Math.min(100, total * 5)}%` }}
                          transition={{ ...spring.gentle, delay: 0.1 }}
                          className="h-full rounded-full"
                          style={{ background: `linear-gradient(90deg, ${color}, ${AI_GRADIENT_STOPS[3]})` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* SLA breach 实时率 + 最近 breach */}
          {sla && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-white border border-line rounded-none p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <h3 className="text-[13px] font-semibold text-ink mb-3">SLA 违约率（近 24h）</h3>
                <GradientNumber value={Math.round(sla.rate.rate * 100)} suffix="%" />
                <p className="text-[11px] text-ink-faint mt-2">
                  共 {sla.rate.total} 单 · 超时 {sla.rate.breached} 单
                </p>
                <div className="mt-4 grid grid-cols-4 gap-2 text-center">
                  {Object.entries(sla.rate.by_priority).map(([prio, info]) => (
                    <div key={prio}>
                      <p className="text-sm font-bold tabular-nums" style={{
                        color: info.rate > 0.2 ? '#FF375F' : info.rate > 0.1 ? '#FF9F0A' : '#34c759',
                      }}>
                        {Math.round(info.rate * 100)}%
                      </p>
                      <p className="text-[10px] text-ink-faint mt-0.5">{prio}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white border border-line rounded-none p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
                <h3 className="text-[13px] font-semibold text-ink mb-3">最近 SLA 超时（{sla.recent.length}）</h3>
                {sla.recent.length === 0 ? (
                  <p className="text-xs text-ink-faint py-4 text-center">最近 24h 无超时</p>
                ) : (
                  <div className="space-y-1.5 max-h-80 overflow-y-auto">
                    {sla.recent.slice(0, 10).map((r, i) => (
                      <div key={i} className="flex items-center justify-between text-[11px] border-b border-line last:border-0 py-1.5">
                        <span className="font-mono text-ink">{r.order_number}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                          style={{
                            color: r.priority === 'critical' ? '#FF375F' : r.priority === 'high' ? '#FF9F0A' : '#86868b',
                            background: 'rgba(255,55,95,0.08)',
                          }}
                        >
                          {r.priority}
                        </span>
                        <span className="text-ink-faint tabular-nums">
                          {new Date(r.recorded_at).toLocaleString('zh-CN', { hour12: false })}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}