import { useState, useEffect, useMemo, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { LifecycleLoop } from './LifecycleLoop'
import { EmptyState } from './badges'
import {
  useEventStreamLifecycle,
  useEventStreamStore,
  severityOf,
} from '../../lib/eventStream'
import type { SecurityCase, WorkOrder, FpStats, LearningRun } from '../../types/operations'
import {
  SEVERITY_TONE,
  ACTIVITY_LINE_GRADIENT,
} from '../../lib/operationsTokens'
import { KpiStat, type KpiTone } from '../ui/KpiStat'

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
  const [learnRun, setLearnRun] = useState<LearningRun | null>(null)
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
      const [c, o, f, lr] = await Promise.all([
        api.opsCases({ limit: '200' }).catch(() => []),
        api.opsWorkOrders({ limit: '200' }).catch(() => []),
        api.opsFeedbackStats('', 30).catch(() => null),
        api.opsLearnLoopLatest().catch(() => null),
      ])
      setCases(Array.isArray(c) ? c : [])
      setOrders(Array.isArray(o) ? o : [])
      setFpStats(f)
      setLearnRun(lr && lr.id ? (lr as LearningRun) : null)
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
    learn: learnRun?.actions_auto_applied ?? 0,
  }

  const metrics: { label: string; value: number; suffix?: string; tone: KpiTone; tab: string }[] = [
    { label: '待处理案例', value: openCases.length, tone: 'signal', tab: 'cases' },
    { label: 'SLA 超时', value: slaBreached.length, tone: slaBreached.length > 0 ? 'alert' : 'neutral', tab: 'cases' },
    { label: '误报率', value: fpRate, suffix: '%', tone: 'signal', tab: 'feedback' },
    { label: '活跃工单', value: activeOrders.length, tone: 'warn', tab: 'orders' },
    { label: '待审批', value: pendingApprovals.length, tone: 'accent', tab: 'orders' },
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
              learn: 'learn',
            }
            onNavigate(map[key] ?? 'cases')
          }}
        />

        {/* 指标卡 */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-6 mt-8 border-t border-line pt-6">
          {metrics.map((m, i) => (
            <motion.button
              key={m.label}
              onClick={() => onNavigate(m.tab)}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ ...spring.gentle, delay: 0.1 + i * 0.06 }}
              whileHover={{ y: -2 }}
              whileTap={{ y: -1 }}
              className="text-left cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-[#0e1a26]"
            >
              <KpiStat
                label={m.label}
                value={m.suffix ? `${m.value}${m.suffix}` : m.value}
                tone={m.tone}
                size="sm"
                className="hover:border-accent/35 transition-colors"
              />
            </motion.button>
          ))}
        </div>
      </div>

      {/* 右：实时活动流 */}
      <div className="border border-line bg-paper self-start xl:sticky xl:top-[6.25rem]">
        <div className="flex items-center justify-between border-b border-line px-6 py-4">
          <h3 className="font-serif text-[16px] font-bold text-ink tracking-tight">实时活动</h3>
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
                <span className={`w-1.5 h-1.5 rounded-full ${streamStatus === 'connecting' || streamStatus === 'reconnecting' ? 'bg-warn' : 'bg-alert'}`} />
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
          <div className="relative px-6 py-4 space-y-0">
            {/* 渐变竖线 */}
            <div
              className="absolute left-[18px] top-6 bottom-4 w-px"
              style={{ background: ACTIVITY_LINE_GRADIENT, opacity: 0.3 }}
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
                  className="absolute left-[14px] top-1 w-[9px] h-[9px] rounded-full border-2 border-paper"
                  style={{ background: SEVERITY_TONE[item.severity as keyof typeof SEVERITY_TONE] ?? SEVERITY_TONE.medium }}
                />
                <p className="text-[13px] text-ink leading-relaxed">{item.text}</p>
                <p className="text-[10px] text-ink-faint mt-0.5 tabular-nums font-mono tracking-[0.05em]">
                  {new Date(item.time).toLocaleTimeString('zh-CN', { hour12: false })}
                </p>
              </motion.div>
            ))}
          </div>
        )}

        {loaded && (
          <div className="border-t border-line px-6 py-3">
            <button
              onClick={load}
              className="w-full py-1.5 text-[11px] font-mono tracking-[0.18em] uppercase text-ink-soft hover:text-ink"
            >
              刷新指标
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
