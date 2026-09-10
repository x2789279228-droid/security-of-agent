import { BRAND_COLORS } from '../../lib/brand'

const TONE_STROKE: Record<string, string> = {
  ok: BRAND_COLORS.ok,
  warn: BRAND_COLORS.warn,
  alert: BRAND_COLORS.alert,
  hero: BRAND_COLORS.alert,
  signal: BRAND_COLORS.signal,
  accent: BRAND_COLORS.accent,
  neutral: BRAND_COLORS.accent,
}

export function Sparkline({
  data,
  tone = 'neutral',
  width = 96,
  height = 28,
  className = '',
}: {
  data: number[]
  tone?: keyof typeof TONE_STROKE | string
  width?: number
  height?: number
  className?: string
}) {
  const stroke = TONE_STROKE[tone] ?? TONE_STROKE.neutral
  if (!data.length) {
    return <svg width={width} height={height} className={className} aria-hidden />
  }
  const min = Math.min(...data)
  const max = Math.max(...data)
  const span = max - min || 1
  const step = data.length === 1 ? 0 : (width - 2) / (data.length - 1)
  const pts = data
    .map((v, i) => {
      const x = 1 + i * step
      const y = height - 2 - ((v - min) / span) * (height - 4)
      return `${x},${y}`
    })
    .join(' ')
  const last = data[data.length - 1]
  const lastX = 1 + (data.length - 1) * step
  const lastY = height - 2 - ((last - min) / span) * (height - 4)

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className={className} aria-hidden>
      <polyline
        points={pts}
        fill="none"
        stroke={stroke}
        strokeWidth="1.6"
        strokeLinejoin="round"
        strokeLinecap="round"
        opacity="0.9"
      />
      <circle cx={lastX} cy={lastY} r="2.1" fill={stroke} />
    </svg>
  )
}
