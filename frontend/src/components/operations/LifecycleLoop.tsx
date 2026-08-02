import { motion } from 'framer-motion'
import { AI_GRADIENT_STOPS } from '../../lib/constants'

export interface LoopStage {
  key: string
  label: string
  count: number
  icon: string
}

/** 闭环 9 阶段（顺序即流转方向） */
export const LOOP_STAGES: Omit<LoopStage, 'count'>[] = [
  { key: 'alert', label: '告警', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
  { key: 'event', label: '事件', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' },
  { key: 'case', label: '案例', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
  { key: 'order', label: '工单', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4' },
  { key: 'approval', label: '审批', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  { key: 'disposition', label: '处置', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { key: 'postmortem', label: '复盘', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
  { key: 'feedback', label: '误报反馈', icon: 'M3 21v-4a4 4 0 014-4h10M3 21V5a2 2 0 012-2h14a2 2 0 012 2v10a2 2 0 01-2 2H7l-4 4zM15 8l-2 2 2 2' },
  { key: 'tuning', label: '规则优化', icon: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4' },
]

const SIZE = 460
const CENTER = SIZE / 2
const RADIUS = 168
const NODE_R = 34

function polar(angleDeg: number, r: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180
  return { x: CENTER + r * Math.cos(rad), y: CENTER + r * Math.sin(rad) }
}

export function LifecycleLoop({
  counts,
  activeCases,
  onNodeClick,
}: {
  counts: Record<string, number>
  activeCases: number
  onNodeClick?: (key: string) => void
}) {
  const step = 360 / LOOP_STAGES.length
  // 闭环路径（圆）
  const ringPath = `M ${CENTER} ${CENTER - RADIUS} A ${RADIUS} ${RADIUS} 0 1 1 ${CENTER - 0.01} ${CENTER - RADIUS}`

  return (
    <div className="relative mx-auto" style={{ width: SIZE, height: SIZE }}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="absolute inset-0 w-full h-full">
        <defs>
          <linearGradient id="loopGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            {AI_GRADIENT_STOPS.map((c, i) => (
              <stop key={i} offset={`${(i / (AI_GRADIENT_STOPS.length - 1)) * 100}%`} stopColor={c} />
            ))}
          </linearGradient>
          <filter id="loopGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* 底环 */}
        <circle cx={CENTER} cy={CENTER} r={RADIUS} fill="none" stroke="rgba(0,0,0,0.06)" strokeWidth={2} />

        {/* 渐变流动环 */}
        <path
          d={ringPath}
          fill="none"
          stroke="url(#loopGrad)"
          strokeWidth={3}
          strokeLinecap="round"
          strokeDasharray="14 12"
          filter="url(#loopGlow)"
          opacity={0.85}
        >
          <animate attributeName="stroke-dashoffset" from="0" to="-260" dur="9s" repeatCount="indefinite" />
        </path>

        {/* 沿环流动的光点 */}
        {[0, 1, 2].map((i) => (
          <circle key={i} r={4} fill={AI_GRADIENT_STOPS[i % AI_GRADIENT_STOPS.length]} filter="url(#loopGlow)">
            <animateMotion dur="12s" repeatCount="indefinite" begin={`${i * 4}s`} path={ringPath} />
          </circle>
        ))}
      </svg>

      {/* 中心指标 */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 200, damping: 18 }}
          className="flex flex-col items-center"
        >
          <span
            className="text-6xl font-extrabold tracking-tight tabular-nums bg-clip-text text-transparent leading-none"
            style={{ backgroundImage: `linear-gradient(135deg, ${AI_GRADIENT_STOPS[0]}, ${AI_GRADIENT_STOPS[2]}, ${AI_GRADIENT_STOPS[3]})` }}
          >
            {activeCases}
          </span>
          <span className="text-[11px] font-medium text-ink-faint mt-2 tracking-wide">活跃案例</span>
          <span className="flex items-center gap-1.5 mt-1.5 text-[10px] text-ink-faint">
            <motion.span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: '#34c759' }}
              animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
              transition={{ duration: 1.8, repeat: Infinity }}
            />
            闭环运转中
          </span>
        </motion.div>
      </div>

      {/* 阶段节点 */}
      {LOOP_STAGES.map((stage, i) => {
        const angle = i * step
        const { x, y } = polar(angle, RADIUS)
        const count = counts[stage.key] ?? 0
        const color = AI_GRADIENT_STOPS[i % AI_GRADIENT_STOPS.length]
        return (
          <motion.button
            key={stage.key}
            onClick={() => onNodeClick?.(stage.key)}
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 260, damping: 20, delay: i * 0.05 }}
            whileHover={{ scale: 1.12 }}
            whileTap={{ scale: 0.95 }}
            className="absolute flex flex-col items-center gap-1 group"
            style={{ left: x, top: y, transform: 'translate(-50%, -50%)' }}
          >
            <span
              className="relative flex items-center justify-center rounded-2xl bg-white border shadow-[0_2px_12px_rgba(0,0,0,0.06)] transition-shadow group-hover:shadow-[0_4px_20px_rgba(0,0,0,0.12)]"
              style={{ width: NODE_R * 2, height: NODE_R * 2, borderColor: `${color}30` }}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                <path d={stage.icon} />
              </svg>
              {count > 0 && (
                <span
                  className="absolute -top-1.5 -right-1.5 min-w-[18px] h-[18px] px-1 flex items-center justify-center rounded-full text-[10px] font-bold text-white tabular-nums"
                  style={{ background: color }}
                >
                  {count > 99 ? '99+' : count}
                </span>
              )}
            </span>
            <span className="text-[11px] font-medium text-ink-soft group-hover:text-ink transition-colors whitespace-nowrap">
              {stage.label}
            </span>
          </motion.button>
        )
      })}
    </div>
  )
}
