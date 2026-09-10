import { useEffect, useMemo, useState } from 'react'
import { useReducedMotion } from 'framer-motion'

/**
 * ShiftConsole · 机要控制台
 *
 * Hero 右侧唯一的「实时」面板。放弃 3D 旋转节点网，
 * 改用纯文字与数字的密度制造「精密仪表」感。
 *
 * 设计要点：
 * - 深室底（vault）+ 暮金描边，不与主舞台争夺视觉权重
 * - 一个主数字（事件总量）+ 三个辅助数字（巡/守/押）
 * - 自带灯柱扫光动画；reduce-motion 时仅保留底层呼吸
 */
export function ShiftConsole({
  ingested,
  pending,
  audited,
  memories,
  attackCount,
  shiftLabel,
  clock,
  perHour,
  responseMs,
}: {
  ingested: number
  pending: number
  audited: number
  memories: number
  attackCount: number
  shiftLabel: string
  clock: string
  perHour: number
  responseMs: number
}) {
  const reduce = useReducedMotion()
  const [pulse, setPulse] = useState(0)

  useEffect(() => {
    if (reduce) return
    const id = window.setInterval(() => setPulse((p) => p + 1), 1200)
    return () => window.clearInterval(id)
  }, [reduce])

  const progress = ingested > 0 ? Math.min(100, Math.round((audited / ingested) * 100)) : 0
  const threat = attackCount > 0

  return (
    <div className="console relative w-full">
      <div className="lamp-sweep" aria-hidden />

      {/* 顶部 meta */}
      <div className="relative flex items-center justify-between border-b border-[rgba(201,165,116,0.15)] px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[rgba(201,165,116,0.55)]">
            SHIFT CONSOLE
          </span>
          <span className="font-mono text-[10px] tracking-[0.2em] text-[rgba(201,165,116,0.4)]">
            CH · 01
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`relative inline-flex h-1.5 w-1.5 ${threat ? '' : 'opacity-50'}`}
            aria-hidden
          >
            <span
              className={`absolute inset-0 rounded-full ${
                threat ? 'bg-[#b03a30] animate-ping' : 'bg-[#3e7a64]'
              } opacity-60`}
            />
            <span
              className={`relative inline-block h-1.5 w-1.5 rounded-full ${
                threat ? 'bg-[#b03a30]' : 'bg-[#3e7a64]'
              }`}
            />
          </span>
          <span
            className={`font-mono text-[10px] tracking-[0.22em] uppercase ${
              threat ? 'text-[#c8695e]' : 'text-[#7c9d8e]'
            }`}
          >
            {threat ? 'THREAT' : 'NOMINAL'}
          </span>
        </div>
      </div>

      {/* 主数字 */}
      <div className="relative px-6 pt-6 pb-5">
        <p className="console-meta">事件接入 · INGESTED</p>
        <div className="mt-3 flex items-end gap-3">
          <span className="console-num tabular-nums">
            {ingested.toLocaleString()}
          </span>
          <span className="console-unit pb-2">EVENTS</span>
        </div>
        <div className="mt-4 h-px w-full bg-[rgba(201,165,116,0.15)]" />
        <div className="mt-4 flex items-center justify-between font-mono text-[11px] text-[rgba(216,222,224,0.55)] tabular-nums">
          <span>{progress}% 已审计</span>
          <span>{clock}</span>
        </div>
        {/* 进度条 */}
        <div className="mt-2 h-[2px] w-full bg-[rgba(201,165,116,0.08)]">
          <div
            className="h-full bg-[#c9a574] transition-[width] duration-700"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* 示波器轨迹：4 频正弦叠加，phase 推进 */}
        <Oscilloscope threat={threat} />
      </div>

      {/* 三个小读数 */}
      <div className="relative grid grid-cols-3 border-t border-[rgba(201,165,116,0.12)]">
        <Cell label="待处理 · PEND" value={pending} tone={pending > 0 ? 'alert' : 'dim'} />
        <Cell
          label="已审 · AUDIT"
          value={audited}
          tone="dim"
          border
        />
        <Cell label="记忆 · MEM" value={memories} tone="dim" />
      </div>

      {/* 派生读数：密度补足 */}
      <div className="relative grid grid-cols-2 border-t border-[rgba(201,165,116,0.12)]">
        <Cell
          label="小时均值 · AVG/HR"
          value={perHour}
          tone="accent"
          border
          unit=" ev"
        />
        <Cell
          label="响应中位 · MED"
          value={responseMs}
          tone="accent"
          unit=" ms"
        />
      </div>

      {/* 底栏：班次 */}
      <div className="relative flex items-center justify-between border-t border-[rgba(201,165,116,0.12)] px-6 py-3">
        <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[rgba(201,165,116,0.45)]">
          SHIFT
        </span>
        <span className="font-serif text-[15px] font-bold text-[#f1e8d6] tracking-tight">
          {shiftLabel}
        </span>
        <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[rgba(201,165,116,0.45)] tabular-nums">
          {String(pulse).padStart(3, '0')}
        </span>
      </div>
    </div>
  )
}

function Cell({
  label,
  value,
  tone,
  border = false,
  unit,
}: {
  label: string
  value: number
  tone: 'dim' | 'alert' | 'accent'
  border?: boolean
  unit?: string
}) {
  const color =
    tone === 'alert'
      ? 'text-[#d0665b]'
      : tone === 'accent'
        ? 'text-[#7ba9b5]'
        : 'text-[rgba(241,232,214,0.65)]'
  return (
    <div
      className={`px-6 py-4 ${border ? 'border-x border-[rgba(201,165,116,0.12)]' : ''}`}
    >
      <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-[rgba(201,165,116,0.45)]">
        {label}
      </p>
      <p className={`mt-1 font-serif text-[28px] font-black tabular-nums leading-none ${color}`}>
        {value.toLocaleString()}
        {unit && (
          <span className="font-mono text-[11px] tracking-[0.16em] text-[rgba(201,165,116,0.5)] ml-1.5">
            {unit}
          </span>
        )}
      </p>
    </div>
  )
}

/**
 * OScilloscope · 实时波形
 *
 * 4 频正弦 + 2 频余弦叠加，模拟"实时遥测"读数。
 * threat=true 时叠加朱砂高频尖刺。
 */
function Oscilloscope({ threat }: { threat: boolean }) {
  const reduce = useReducedMotion()
  const [t, setT] = useState(0)

  useEffect(() => {
    if (reduce) return
    let raf = 0
    const start = performance.now()
    const tick = () => {
      setT((performance.now() - start) / 1000)
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [reduce])

  const path = useMemo(() => {
    const w = 600
    const h = 36
    const cy = h / 2
    const pts: string[] = []
    for (let x = 0; x <= w; x += 2) {
      const phase = (x / w) * Math.PI * 4 + t * 1.4
      const y =
        cy +
        Math.sin(phase) * 6 +
        Math.sin(phase * 2.3 + t * 0.8) * 4 +
        Math.cos(phase * 0.6 - t * 0.5) * 3 -
        Math.sin(phase * 4.1 + t * 1.1) * 2
      pts.push(`${x},${y.toFixed(2)}`)
    }
    return 'M ' + pts.join(' L ')
  }, [t])

  const spikePath = useMemo(() => {
    if (!threat) return ''
    const w = 600
    const pts: string[] = []
    const spikePos = (Math.sin(t * 1.7) * 0.5 + 0.5) * w
    for (let x = 0; x <= w; x += 2) {
      const d = Math.abs(x - spikePos)
      const spike = Math.max(0, 14 - d * 0.5) * Math.sin(t * 4)
      pts.push(`${x},${18 + spike.toFixed(2)}`)
    }
    return 'M ' + pts.join(' L ')
  }, [t, threat])

  return (
    <div className="mt-4">
      <div className="flex items-center justify-between font-mono text-[9px] tracking-[0.26em] uppercase text-[rgba(201,165,116,0.4)]">
        <span>Oscilloscope · 实时波形</span>
        <span>CH · 04</span>
      </div>
      <svg
        viewBox="0 0 600 36"
        className="mt-1.5 block w-full"
        preserveAspectRatio="none"
        aria-hidden
      >
        {/* 中线 */}
        <line
          x1={0} y1={18} x2={600} y2={18}
          stroke="rgba(201,165,116,0.12)" strokeWidth={0.5} strokeDasharray="2 4"
        />
        {/* 网格刻度 */}
        {Array.from({ length: 6 }, (_, i) => (
          <line
            key={i}
            x1={i * 100} y1={4} x2={i * 100} y2={32}
            stroke="rgba(201,165,116,0.08)" strokeWidth={0.5}
          />
        ))}
        {/* 威胁尖刺（朱砂） */}
        {threat && (
          <path
            d={spikePath}
            fill="none"
            stroke="rgba(208, 102, 91, 0.55)"
            strokeWidth={0.8}
          />
        )}
        {/* 主波形 */}
        <path
          d={path}
          fill="none"
          stroke="rgba(201, 165, 116, 0.65)"
          strokeWidth={1}
          strokeLinecap="round"
        />
        {/* 末端光点 */}
        <circle
          cx={600} cy={18 + Math.sin(t * 5) * 4}
          r={1.5}
          fill="rgba(201, 165, 116, 0.95)"
        />
      </svg>
    </div>
  )
}