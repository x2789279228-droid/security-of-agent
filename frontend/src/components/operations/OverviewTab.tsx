import { useState, useEffect, useMemo, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { LifecycleLoop } from './LifecycleLoop'
import { GradientNumber, EmptyState } from './badges'
import {
  useEventStreamLifecycle,
  useEventStreamStore,
  severityOf,
} from '../../lib/eventStream'
import type { SecurityCase, WorkOrder, FpStats } from '../../types/operations'

interface ActivityItem {
  id: string
  type: string
  text: string
  severity?: string
  time: number
}

// 实时活动关注的业务事件类型 — 覆盖接入/告警/审计/响应/管道全链路，
// 经共享 SSE 单例(useEventStreamLifecycle)获得服务端回放与断线重连
const ACTIVITY_TYPES = new Set([
  'security_event', 'alert', 'audit_complete', 'response_action', 'pipeline_health',
])

function describeActivity(e: { type: string; data: any }): { text: string; severity?: string } {
  const d = e.data ?? {}
  switch (e.type) {
    case 'security_event':
      return {
        text: `事件接入 [${d.event_type || '未知'}] ${d.src_ip || ''}`,
        severity: String(d.severity ?? ''),
      }
    case 'alert':
      return {
        text: `告警 ⚠ ${d.alert_type || ''} · ${d.src_ip || ''}`,
        severity: String(d.severity ?? 'high'),
      }
    case 'audit_complete':
      return d.threat_detected
        ? { text: `事件 #${d.event_id} 审计确认威胁 [${d.threat_type}]`, severity: String(d.severity ?? 'high') }
        : { text: `事件 #${d.event_id} 审计完成 — 判定安全` }
    case 'response_action':
      return {
        text: `响应处置 ${d.threat_type || ''} · ${d.status || 'triggered'}`,
        severity: 'high',
      }
    case 'pipeline_health':
      if (d.type === 'diagnostic') return { text: `自动诊断: ${d.root_cause || d.trigger || ''}`, severity: d.severity }
      if (d.type === 'sla_breach') return { text: `工单 ${d.order_number} SLA 超时`, severity: 'high' }
      return { text: `管道告警 [${d.stage}]: ${(d.reasons || []).join('; ')}`, severity: d.severity ?? 'medium' }
    default:
      return { text: e.type }
  }
}

export function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const [cases, setCases] = useState<SecurityCase[]>([])
  const [orders, setOrders] = useState<WorkOrder[]>([])
  const [fpStats, setFpStats] = useState<FpStats | null>(null)
  const [loaded, setLoaded] = useState(false)

  // 实时活动: 复用平台共享 SSE 单例（带 token/断点续传/看门狗重连），
  // 从事件缓冲派生活动流 — 连接死时状态指示如实显示，不再是假"监听中"
  useEventStreamLifecycle()
  const streamStatus = useEventStreamStore((s) => s.status)
  const attempts = useEventStreamStore((s) => s.attempts)
  const buffer = useEventStreamStore((s) => s.buffer)

  const activity = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = []
    for (const e of buffer) {
      if (e.kind !== 'event' || !ACTIVITY_TYPES.has(e.type)) continue
      const { text, severity } = describeActivity(e)
      items.push({
        id: `evt-${e.id}`,
        type: e.type,
        text,
        severity: severity ?? severityOf(e.type, e.data),
        time: e.ts,
      })
      if (items.length >= 12) break
    }
    return items
  }, [buffer])

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
  }, [load])

  // 指标计算
  const activeCases = cases.filter((c) => !['closed', 'false_positive'].includes(c.status))
  const openCases = cases.filter((c) => c.status === 'open')
  // SLA 门槛取页面挂载时刻: 避免渲染期 Date.now() 造成的纯度问题, 重挂即刷新
  const [now] = useState(() => Date.now())
  const slaTerminal = ['closed', 'false_positive', 'resolved']
  const slaBreached = cases.filter((c) => (c.sla_breached || (c.sla_deadline && new Date(c.sla_deadline).getTime() < now)) && !slaTerminal.includes(c.status))
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
            {streamStatus === 'online' ? (
              <>
                <motion.span
                  className="w-1.5 h-1.5 rounded-full bg-ok"
                  animate={{ scale: [1, 1.4, 1], opacity: [1, 0.4, 1] }}
                  transition={{ duration: 1.6, repeat: Infinity }}
                />
                监听中
              </>
            ) : (
              <>
                <span className={`w-1.5 h-1.5 rounded-full ${streamStatus === 'connecting' || streamStatus === 'reconnecting' ? 'bg-nong' : 'bg-dan'}`} />
                {streamStatus === 'connecting' ? '连接中…'
                  : streamStatus === 'reconnecting' ? `重连中 (第 ${attempts} 次)`
                  : streamStatus === 'offline' ? '连接断开'
                  : '未连接'}
              </>
            )}
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
