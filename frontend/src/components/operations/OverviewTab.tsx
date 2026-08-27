import { useState, useEffect, useRef, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { LifecycleLoop } from './LifecycleLoop'
import { GradientNumber, EmptyState } from './badges'
import type { SecurityCase, WorkOrder, FpStats } from '../../types/operations'

interface ActivityItem {
  id: string
  type: string
  text: string
  severity?: string
  time: number
}

export function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const [cases, setCases] = useState<SecurityCase[]>([])
  const [orders, setOrders] = useState<WorkOrder[]>([])
  const [fpStats, setFpStats] = useState<FpStats | null>(null)
  const [activity, setActivity] = useState<ActivityItem[]>([])
  const [loaded, setLoaded] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const load = useCallback(async () => {
    try {
      const [c, o, f] = await Promise.all([
        api.opsCases({ limit: '200' }).catch(() => []),
        api.opsWorkOrders({ limit: '200' }).catch(() => []),
        api.opsFeedbackStats('', 30).catch(() => null),
      ])
      setCases(Array.isArray(c) ? c : [])
      setOrders(Array.isArray(o) ? o : [])
      setFpStats(f)
    } finally {
      setLoaded(true)
    }
  }, [])

  useEffect(() => {
    load()
    // SSE 实时活动
    const es = api.eventsStream()
    esRef.current = es
    const push = (item: Omit<ActivityItem, 'id' | 'time'>) =>
      setActivity((prev) => [
        { ...item, id: `${Date.now()}-${Math.random()}`, time: Date.now() },
        ...prev,
      ].slice(0, 12))

    const onHealth = (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data)
        if (d.type === 'alert') push({ type: 'health', text: `流水线告警 [${d.stage}]: ${(d.reasons || []).join('; ')}`, severity: 'critical' })
        else if (d.type === 'diagnostic') push({ type: 'diagnostic', text: `自动诊断: ${d.root_cause}`, severity: d.severity })
        else if (d.type === 'sla_breach') push({ type: 'sla', text: `工单 ${d.order_number} SLA 超时`, severity: 'high' })
        else if (d.type === 'tuning_suggestions') push({ type: 'tuning', text: `生成 ${d.count} 条规则调优建议` })
      } catch { /* noop */ }
    }
    const onAudit = (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data)
        if (d.threat_detected) push({ type: 'threat', text: `事件 #${d.event_id} 确认威胁 [${d.threat_type}]`, severity: d.severity })
      } catch { /* noop */ }
    }
    es.addEventListener('pipeline_health', onHealth)
    es.addEventListener('audit_complete', onAudit)
    return () => {
      es.removeEventListener('pipeline_health', onHealth)
      es.removeEventListener('audit_complete', onAudit)
      es.close()
      esRef.current = null
    }
  }, [load])

  // 指标计算
  const activeCases = cases.filter((c) => !['closed', 'false_positive'].includes(c.status))
  const openCases = cases.filter((c) => c.status === 'open')
  const now = Date.now()
  const slaBreached = cases.filter((c) => (c.sla_breached || (c.sla_deadline && new Date(c.sla_deadline).getTime() < now)) && !['closed', 'false_positive'].includes(c.status))
  const activeOrders = orders.filter((o) => ['pending', 'assigned', 'in_progress'].includes(o.status))
  const pendingApprovals = orders.filter((o) => o.order_type === 'approval' && o.approval_status === 'pending')
  const fpRate = fpStats ? Math.round(fpStats.overall_fp_rate * 100) : 0

  // 闭环各阶段计数
  const loopCounts: Record<string, number> = {
    alert: cases.reduce((s, c) => s + c.event_count, 0),
    event: cases.reduce((s, c) => s + c.event_count, 0),
    case: cases.length,
    order: orders.length,
    approval: pendingApprovals.length,
    disposition: cases.filter((c) => c.status === 'responding').length,
    postmortem: cases.filter((c) => c.status === 'closed').length,
    feedback: fpStats?.total_feedback ?? 0,
    tuning: 0,
  }

  const metrics = [
    { label: '待处理案例', value: openCases.length, color: '#0A84FF', tab: 'cases' },
    { label: 'SLA 超时', value: slaBreached.length, color: '#FF375F', tab: 'cases' },
    { label: '误报率', value: fpRate, suffix: '%', color: '#BF5AF2', tab: 'feedback' },
    { label: '活跃工单', value: activeOrders.length, color: '#FF9F0A', tab: 'orders' },
    { label: '待审批', value: pendingApprovals.length, color: '#5E5CE6', tab: 'orders' },
  ]

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_340px] gap-8">
      {/* 左：闭环环 + 指标 */}
      <div>
        <LifecycleLoop
          counts={loopCounts}
          activeCases={activeCases.length}
          onNodeClick={(key) => {
            const map: Record<string, string> = {
              alert: 'cases', event: 'cases', case: 'cases',
              order: 'orders', approval: 'orders', disposition: 'cases',
              postmortem: 'postmortems', feedback: 'feedback', tuning: 'rules',
            }
            onNavigate(map[key] ?? 'cases')
          }}
        />

        {/* 指标卡 */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-8">
          {metrics.map((m, i) => (
            <motion.button
              key={m.label}
              onClick={() => onNavigate(m.tab)}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ ...spring.gentle, delay: 0.1 + i * 0.06 }}
              whileHover={{ y: -4 }}
              className="bg-white border border-line rounded-none px-4 py-4 text-left shadow-[0_1px_4px_rgba(0,0,0,0.04)] hover:shadow-[0_8px_24px_rgba(0,0,0,0.08)] transition-shadow cursor-pointer"
            >
              <div className="flex items-center gap-1.5 mb-2">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: m.color }} />
                <span className="text-[11px] font-medium text-ink-faint">{m.label}</span>
              </div>
              <GradientNumber value={m.value} suffix={m.suffix ?? ''} />
            </motion.button>
          ))}
        </div>
      </div>

      {/* 右：实时活动流 */}
      <div className="bg-white border border-line rounded-none p-5 shadow-[0_1px_4px_rgba(0,0,0,0.04)] self-start xl:sticky xl:top-16">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-ink tracking-tight">实时活动</h3>
          <span className="flex items-center gap-1.5 text-[10px] text-ink-faint">
            <motion.span
              className="w-1.5 h-1.5 rounded-full bg-ok"
              animate={{ scale: [1, 1.4, 1], opacity: [1, 0.4, 1] }}
              transition={{ duration: 1.6, repeat: Infinity }}
            />
            监听中
          </span>
        </div>

        {activity.length === 0 ? (
          <EmptyState icon="📡" title="等待事件流入" hint="注入日志或触发威胁后将实时显示" />
        ) : (
          <div className="relative space-y-0">
            {/* 渐变竖线 */}
            <div
              className="absolute left-[5px] top-2 bottom-2 w-px"
              style={{ background: 'linear-gradient(180deg, #0A84FF, #BF5AF2, #FF9F0A)', opacity: 0.3 }}
            />
            {activity.map((item) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, x: 16 }}
                animate={{ opacity: 1, x: 0 }}
                transition={spring.ui}
                className="relative pl-6 pb-4 last:pb-0"
              >
                <span
                  className="absolute left-0 top-1 w-[11px] h-[11px] rounded-full border-2 border-white shadow"
                  style={{ background: item.severity === 'critical' ? '#FF375F' : item.severity === 'high' ? '#FF9F0A' : '#0A84FF' }}
                />
                <p className="text-xs text-ink leading-relaxed">{item.text}</p>
                <p className="text-[10px] text-ink-faint mt-0.5 tabular-nums">
                  {new Date(item.time).toLocaleTimeString('zh-CN', { hour12: false })}
                </p>
              </motion.div>
            ))}
          </div>
        )}

        {loaded && (
          <button
            onClick={load}
            className="mt-4 w-full py-2 text-[11px] font-medium text-ink-soft bg-black/[0.04] rounded-lg hover:bg-black/[0.07] transition-colors"
          >
            刷新指标
          </button>
        )}
      </div>
    </div>
  )
}
