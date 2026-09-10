import type { ReactNode } from 'react'

export type ChipTone = 'neutral' | 'accent' | 'ok' | 'warn' | 'alert' | 'signal'

const TONE: Record<ChipTone, { bg: string; text: string; border: string }> = {
  neutral: {
    bg: 'var(--color-mist)',
    text: 'var(--color-ink-soft)',
    border: 'var(--color-line)',
  },
  accent: {
    bg: 'rgba(58,101,112,0.08)',
    text: 'var(--color-accent)',
    border: 'rgba(58,101,112,0.20)',
  },
  ok: {
    bg: 'var(--color-mint)',
    text: 'var(--color-ok)',
    border: 'rgba(62,122,100,0.25)',
  },
  warn: {
    bg: 'rgba(192,138,58,0.10)',
    text: 'var(--color-warn)',
    border: 'rgba(192,138,58,0.25)',
  },
  alert: {
    bg: 'rgba(194,58,50,0.08)',
    text: 'var(--color-alert)',
    border: 'rgba(194,58,50,0.25)',
  },
  signal: {
    bg: 'rgba(74,122,136,0.08)',
    text: 'var(--color-signal)',
    border: 'rgba(74,122,136,0.20)',
  },
}

/**
 * 小标签：状态/分类用，比 button 轻、比 tag 重。
 * - tone 决定浅色背景 + 边框
 * - size sm/md 影响内边距和字号
 */
export function Chip({
  children,
  tone = 'neutral',
  size = 'sm',
  className = '',
  style,
}: {
  children: ReactNode
  tone?: ChipTone
  size?: 'sm' | 'md'
  className?: string
  style?: React.CSSProperties
}) {
  const t = TONE[tone]
  const sizes = size === 'sm' ? 'h-6 px-2 text-[11px]' : 'h-7 px-2.5 text-[12px]'
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-pill border whitespace-nowrap font-medium tabular-nums ${sizes} ${className}`}
      style={{
        background: t.bg,
        color: t.text,
        borderColor: t.border,
        borderRadius: 'var(--radius-pill)',
        ...style,
      }}
    >
      {children}
    </span>
  )
}
