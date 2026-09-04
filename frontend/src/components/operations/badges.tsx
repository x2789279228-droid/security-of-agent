import { motion } from 'framer-motion'
import type { CaseStatus, CasePriority, OrderType } from '../../types/operations'

const GRAY = {
  ink: '#111111',
  nong: '#555555',
  hui: '#888888',
  dan: '#c8c8c8',
  qing: '#e8e8e8',
  mist: '#f2f2f2',
  white: '#ffffff',
}

const CASE_STATUS_META: Record<CaseStatus, { label: string; color: string; bg: string }> = {
  open: { label: '待处理', color: GRAY.white, bg: GRAY.ink },
  investigating: { label: '调查中', color: GRAY.white, bg: GRAY.nong },
  pending_approval: { label: '待审批', color: GRAY.ink, bg: GRAY.dan },
  responding: { label: '处置中', color: GRAY.ink, bg: GRAY.qing },
  resolved: { label: '已解决', color: GRAY.ink, bg: GRAY.mist },
  closed: { label: '已关闭', color: GRAY.hui, bg: GRAY.mist },
  false_positive: { label: '误报', color: GRAY.hui, bg: GRAY.qing },
}

const SEVERITY_META: Record<string, { color: string; bg: string }> = {
  critical: { color: GRAY.white, bg: GRAY.ink },
  high: { color: GRAY.white, bg: GRAY.nong },
  medium: { color: GRAY.ink, bg: GRAY.dan },
  low: { color: GRAY.ink, bg: GRAY.qing },
  info: { color: GRAY.hui, bg: GRAY.mist },
}

const PRIORITY_META: Record<CasePriority, { label: string; color: string }> = {
  critical: { label: 'P0 紧急', color: GRAY.ink },
  high: { label: 'P1 高', color: GRAY.nong },
  medium: { label: 'P2 中', color: GRAY.hui },
  low: { label: 'P3 低', color: GRAY.dan },
}

export function StatusBadge({ status }: { status: CaseStatus }) {
  const meta = CASE_STATUS_META[status] ?? CASE_STATUS_META.open
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-none text-[11px] font-medium whitespace-nowrap"
      style={{ color: meta.color, background: meta.bg }}
    >
      {meta.label}
    </span>
  )
}

export function SeverityChip({ severity }: { severity: string }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-none text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap"
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
      className="inline-flex items-center px-2 py-0.5 rounded-none text-[10px] font-semibold whitespace-nowrap border border-ink"
      style={{ color: meta.color }}
    >
      {meta.label}
    </span>
  )
}

export function GradientNumber({ value, suffix = '' }: { value: string | number; suffix?: string }) {
  return (
    <span className="text-4xl font-black tracking-tight tabular-nums text-ink">
      {value}
      {suffix && <span className="text-lg font-bold">{suffix}</span>}
    </span>
  )
}

const ORDER_TYPE_META: Record<OrderType, { label: string; icon: string }> = {
  disposition: { label: '处置', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  approval: { label: '审批', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  review: { label: '复盘', icon: 'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z' },
  rollback: { label: '回滚', icon: 'M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6' },
}

export function OrderTypeIcon({ type, size = 16 }: { type: OrderType; size?: number }) {
  const meta = ORDER_TYPE_META[type] ?? ORDER_TYPE_META.disposition
  return (
    <span
      className="inline-flex items-center justify-center rounded-none shrink-0 border border-ink"
      style={{ width: size + 12, height: size + 12 }}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="#111" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: size, height: size }}>
        <path d={meta.icon} />
      </svg>
    </span>
  )
}

export function orderTypeLabel(type: OrderType): string {
  return ORDER_TYPE_META[type]?.label ?? type
}

export function SlaBadge({ deadline, breached }: { deadline: string | null; breached?: boolean }) {
  if (!deadline) return null
  const remaining = new Date(deadline).getTime() - Date.now()
  const isOverdue = breached || remaining < 0
  const hours = Math.floor(Math.abs(remaining) / 3600000)
  const mins = Math.floor((Math.abs(remaining) % 3600000) / 60000)
  const text = isOverdue ? `超时 ${hours}h${mins}m` : `剩 ${hours}h${mins}m`

  return (
    <motion.span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-none text-[10px] font-semibold whitespace-nowrap border border-ink"
      style={{
        color: isOverdue ? '#fff' : '#111',
        background: isOverdue ? '#111' : 'transparent',
      }}
      animate={isOverdue ? { opacity: [1, 0.55, 1] } : {}}
      transition={isOverdue ? { duration: 1.4, repeat: Infinity } : {}}
    >
      {text}
    </motion.span>
  )
}

export function EmptyState({ title, hint }: { icon?: string; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center border border-line">
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint && <p className="text-xs text-ink-faint mt-1 font-light">{hint}</p>}
    </div>
  )
}
