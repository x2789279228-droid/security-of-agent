import { motion } from 'framer-motion'
import { AI_GRADIENT } from '../../lib/constants'
import type { CaseStatus, CasePriority, OrderType } from '../../types/operations'

/** 案例状态 → 展示配置 */
const CASE_STATUS_META: Record<CaseStatus, { label: string; color: string; bg: string }> = {
  open: { label: '待处理', color: '#0A84FF', bg: 'rgba(10,132,255,0.10)' },
  investigating: { label: '调查中', color: '#5E5CE6', bg: 'rgba(94,92,230,0.10)' },
  pending_approval: { label: '待审批', color: '#BF5AF2', bg: 'rgba(191,90,242,0.10)' },
  responding: { label: '处置中', color: '#FF9F0A', bg: 'rgba(255,159,10,0.12)' },
  resolved: { label: '已解决', color: '#34c759', bg: 'rgba(52,199,89,0.10)' },
  closed: { label: '已关闭', color: '#86868b', bg: 'rgba(134,134,139,0.10)' },
  false_positive: { label: '误报', color: '#86868b', bg: 'rgba(134,134,139,0.12)' },
}

/** 严重度 → 颜色 */
const SEVERITY_META: Record<string, { color: string; bg: string }> = {
  critical: { color: '#FF375F', bg: 'rgba(255,55,95,0.10)' },
  high: { color: '#FF9F0A', bg: 'rgba(255,159,10,0.12)' },
  medium: { color: '#0A84FF', bg: 'rgba(10,132,255,0.10)' },
  low: { color: '#6e6e73', bg: 'rgba(110,110,115,0.08)' },
  info: { color: '#86868b', bg: 'rgba(134,134,139,0.08)' },
}

const PRIORITY_META: Record<CasePriority, { label: string; color: string }> = {
  critical: { label: 'P0 紧急', color: '#FF375F' },
  high: { label: 'P1 高', color: '#FF9F0A' },
  medium: { label: 'P2 中', color: '#0A84FF' },
  low: { label: 'P3 低', color: '#86868b' },
}

export function StatusBadge({ status }: { status: CaseStatus }) {
  const meta = CASE_STATUS_META[status] ?? CASE_STATUS_META.open
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium whitespace-nowrap"
      style={{ color: meta.color, background: meta.bg }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: meta.color }} />
      {meta.label}
    </span>
  )
}

export function SeverityChip({ severity }: { severity: string }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap"
      style={{ color: meta.color, background: meta.bg }}
    >
      {severity}
    </span>
  )
}

export function PriorityChip({ priority }: { priority: CasePriority }) {
  const meta = PRIORITY_META[priority] ?? PRIORITY_META.medium
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold whitespace-nowrap border"
      style={{ color: meta.color, borderColor: `${meta.color}40`, background: `${meta.color}0d` }}
    >
      {meta.label}
    </span>
  )
}

/** 渐变大数字 — 指标卡核心视觉 */
export function GradientNumber({ value, suffix = '' }: { value: string | number; suffix?: string }) {
  return (
    <span
      className="text-4xl font-extrabold tracking-tight tabular-nums bg-clip-text text-transparent"
      style={{ backgroundImage: AI_GRADIENT }}
    >
      {value}
      {suffix && <span className="text-lg font-bold">{suffix}</span>}
    </span>
  )
}

const ORDER_TYPE_META: Record<OrderType, { label: string; icon: string; color: string }> = {
  disposition: { label: '处置', color: '#0A84FF', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  approval: { label: '审批', color: '#BF5AF2', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  review: { label: '复盘', color: '#FF9F0A', icon: 'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z' },
  rollback: { label: '回滚', color: '#FF375F', icon: 'M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6' },
}

export function OrderTypeIcon({ type, size = 16 }: { type: OrderType; size?: number }) {
  const meta = ORDER_TYPE_META[type] ?? ORDER_TYPE_META.disposition
  return (
    <span
      className="inline-flex items-center justify-center rounded-lg shrink-0"
      style={{ width: size + 12, height: size + 12, background: `${meta.color}14` }}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke={meta.color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: size, height: size }}>
        <path d={meta.icon} />
      </svg>
    </span>
  )
}

export function orderTypeLabel(type: OrderType): string {
  return ORDER_TYPE_META[type]?.label ?? type
}

/** SLA 倒计时徽章 — 超时红色脉冲 */
export function SlaBadge({ deadline, breached }: { deadline: string | null; breached?: boolean }) {
  if (!deadline) return null
  const remaining = new Date(deadline).getTime() - Date.now()
  const isOverdue = breached || remaining < 0
  const hours = Math.floor(Math.abs(remaining) / 3600000)
  const mins = Math.floor((Math.abs(remaining) % 3600000) / 60000)
  const text = isOverdue ? `超时 ${hours}h${mins}m` : `剩 ${hours}h${mins}m`

  return (
    <motion.span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-semibold whitespace-nowrap"
      style={{
        color: isOverdue ? '#FF375F' : '#FF9F0A',
        background: isOverdue ? 'rgba(255,55,95,0.10)' : 'rgba(255,159,10,0.12)',
      }}
      animate={isOverdue ? { opacity: [1, 0.5, 1] } : {}}
      transition={isOverdue ? { duration: 1.4, repeat: Infinity } : {}}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3 h-3">
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" strokeLinecap="round" />
      </svg>
      {text}
    </motion.span>
  )
}

/** 空状态占位 */
export function EmptyState({ icon = '📭', title, hint }: { icon?: string; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="text-4xl mb-3 opacity-60">{icon}</div>
      <p className="text-sm font-medium text-ink-soft">{title}</p>
      {hint && <p className="text-xs text-ink-faint mt-1">{hint}</p>}
    </div>
  )
}
