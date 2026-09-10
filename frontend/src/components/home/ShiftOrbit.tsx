import { useEffect, useState } from 'react'

/**
 * ShiftOrbit · 调班别控件
 *
 * 一个圆形仪表：12 时辰 / 五更，标注当前所在班次。
 * 中心嵌入小型 BrandCrest。
 *
 * 用 SVG，不用动画库（保持 60fps）。
 */
const SHIFTS = [
  { earthly: '子', label: '三更', h: 0 },
  { earthly: '丑', label: '四更', h: 2 },
  { earthly: '寅', label: '五更', h: 4 },
  { earthly: '卯', label: '平旦', h: 6 },
  { earthly: '辰', label: '食时', h: 8 },
  { earthly: '巳', label: '隅中', h: 10 },
  { earthly: '午', label: '日中', h: 12 },
  { earthly: '未', label: '日昳', h: 14 },
  { earthly: '申', label: '晡时', h: 16 },
  { earthly: '酉', label: '日入', h: 18 },
  { earthly: '戌', label: '一更', h: 20 },
  { earthly: '亥', label: '二更', h: 22 },
]

export function ShiftOrbit({ size = 160, hour = new Date().getHours() }: { size?: number; hour?: number }) {
  const [now, setNow] = useState(hour)
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date().getHours()), 60_000)
    return () => window.clearInterval(id)
  }, [])

  const cx = size / 2
  const cy = size / 2
  const r = size / 2 - 12

  // 找出当前最接近的班次
  let current = SHIFTS[0]
  for (const s of SHIFTS) {
    if (now >= s.h) current = s
  }
  if (now < 1) current = SHIFTS[0]

  return (
    <div className="inline-flex flex-col items-center">
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-label="调班">
        {/* 外环 */}
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(201,165,116,0.35)" strokeWidth={1} />
        {/* 内圈 */}
        <circle cx={cx} cy={cy} r={r * 0.62} fill="none" stroke="rgba(201,165,116,0.18)" strokeWidth={0.6} />
        {/* 12 刻度 */}
        {Array.from({ length: 12 }, (_, i) => {
          const a = (i / 12) * Math.PI * 2 - Math.PI / 2
          const x1 = cx + Math.cos(a) * r * 0.88
          const y1 = cy + Math.sin(a) * r * 0.88
          const x2 = cx + Math.cos(a) * r
          const y2 = cy + Math.sin(a) * r
          return (
            <line
              key={i}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="rgba(201,165,116,0.5)" strokeWidth={0.6}
            />
          )
        })}
        {/* 12 时辰字符 */}
        {SHIFTS.map((s, i) => {
          const a = (i / 12) * Math.PI * 2 - Math.PI / 2
          const x = cx + Math.cos(a) * r * 0.78
          const y = cy + Math.sin(a) * r * 0.78
          const isCurrent = s.earthly === current.earthly
          return (
            <text
              key={i}
              x={x} y={y}
              textAnchor="middle"
              dominantBaseline="central"
              fontSize={isCurrent ? 14 : 10}
              fill={isCurrent ? 'rgba(201,165,116,1)' : 'rgba(201,165,116,0.55)'}
              fontFamily="Noto Serif SC, serif"
              fontWeight={isCurrent ? 900 : 600}
              letterSpacing="-0.04em"
            >
              {s.earthly}
            </text>
          )
        })}
        {/* 当前指示 —— 一道金弧从中心出发 */}
        {(() => {
          const idx = SHIFTS.indexOf(current)
          const a = (idx / 12) * Math.PI * 2 - Math.PI / 2
          const x = cx + Math.cos(a) * r * 0.55
          const y = cy + Math.sin(a) * r * 0.55
          return (
            <g>
              <line x1={cx} y1={cy} x2={x} y2={y} stroke="rgba(201,165,116,0.85)" strokeWidth={0.8} />
              <circle cx={x} cy={y} r={2.5} fill="rgba(201,165,116,1)" />
            </g>
          )
        })()}
        {/* 中央守字符号 */}
        <text
          x={cx}
          y={cy + 1}
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={size * 0.16}
          fill="rgba(241,232,214,0.95)"
          fontFamily="Noto Serif SC, serif"
          fontWeight={900}
          letterSpacing="-0.04em"
        >
          守
        </text>
      </svg>
      <div className="mt-3 flex items-baseline gap-2 font-mono text-[10px] tracking-[0.26em] uppercase text-[rgba(201,165,116,0.6)]">
        <span>{current.earthly}</span>
        <span className="opacity-60">·</span>
        <span>{current.label}</span>
      </div>
    </div>
  )
}