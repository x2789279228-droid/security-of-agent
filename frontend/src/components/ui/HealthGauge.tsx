const TONE: Record<string, { stroke: string; track: string; text: string }> = {
  ok: { stroke: '#3E7A64', track: 'rgba(62,122,100,0.15)', text: '#3E7A64' },
  warn: { stroke: '#C08A3A', track: 'rgba(192,138,58,0.16)', text: '#C08A3A' },
  error: { stroke: '#C23A32', track: 'rgba(194,58,50,0.16)', text: '#C23A32' },
  alert: { stroke: '#C23A32', track: 'rgba(194,58,50,0.16)', text: '#C23A32' },
}

/**
 * 健康环：环图 + 可选中心数字 / 副标。
 * - 默认纯环图（不破坏现有调用）
 * - value/label 都传才显示文字层
 */
export function HealthGauge({
  health,
  size = 44,
  value,
  label,
  className = '',
}: {
  health: 'ok' | 'warn' | 'error' | string
  size?: number
  /** 中心数字（百分比 0-100 或绝对值） */
  value?: number | string
  /** 数字下方副标，如"已用 / 总量" */
  label?: string
  className?: string
}) {
  const t = TONE[health] ?? TONE.error
  const r = 16
  const c = 2 * Math.PI * r
  const filled = health === 'ok' ? 1 : health === 'warn' ? 0.62 : 0.28
  const hasText = value !== undefined || label !== undefined
  const fontSize = size >= 64 ? 14 : 11
  const labelSize = size >= 64 ? 9 : 8

  return (
    <span
      className={`relative inline-flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 44 44"
        className="-rotate-90"
        aria-hidden
        style={{ position: hasText ? 'absolute' : 'static', inset: 0 }}
      >
        <circle cx="22" cy="22" r={r} fill="none" stroke={t.track} strokeWidth="4" />
        <circle
          cx="22"
          cy="22"
          r={r}
          fill="none"
          stroke={t.stroke}
          strokeWidth="4"
          strokeDasharray={`${c * filled} ${c}`}
          strokeLinecap="round"
        />
      </svg>
      {hasText && (
        <span
          className="relative inline-flex flex-col items-center justify-center tabular-nums leading-none"
          style={{ color: t.text }}
        >
          {value !== undefined && (
            <span style={{ fontSize, fontWeight: 700, fontFamily: 'var(--font-num)' }}>
              {value}
            </span>
          )}
          {label && (
            <span
              style={{ fontSize: labelSize, marginTop: 2, color: 'var(--color-ink-faint)' }}
            >
              {label}
            </span>
          )}
        </span>
      )}
    </span>
  )
}
