/**
 * 多 Agent 审查接力条 — Monitor 过程展示主画面
 *
 * Decomposer → Tool Builder → Executor → Reviewer → CAD → Response
 * 节点展示进行中/完成计数；业务阶段事件到达时数据包沿接力线飞行。
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import {
  AGENT_RELAY_STAGES,
  STAGE_LABELS,
  deriveRelays,
} from '../../lib/agentPipeline'
import { useEventStreamStore } from '../../lib/eventStream'
import RateHistogram from './RateHistogram'

// 节点三态：进行中=松绿柔光；有错误=朱砂；空闲=暗淡卡片（0.1s 可辨）
const NODE_TONE = {
  running: 'border-ok/70 bg-ok/[0.07] shadow-[0_0_14px_rgba(62,122,100,0.14)]',
  error: 'border-alert/70 bg-alert/[0.08] shadow-[0_0_14px_rgba(194,58,50,0.14)]',
  idle: 'border-line bg-mist/40 opacity-75',
} as const

function Node({
  label,
  running,
  completed,
  errors,
  flashKey = 0,
  active,
}: {
  label: string
  running: number
  completed: number
  errors: number
  flashKey?: number
  active?: boolean
}) {
  const tone: keyof typeof NODE_TONE =
    running > 0 || active ? 'running' : errors > 0 ? 'error' : 'idle'
  return (
    <div
      className={`relative z-10 flex min-w-[78px] flex-col items-center gap-0.5 rounded-lg border px-2.5 py-2 transition-colors ${NODE_TONE[tone]}`}
    >
      <span className={`whitespace-nowrap text-[10px] tracking-wide ${tone === 'idle' ? 'text-ink-faint' : 'text-ink-soft'}`}>{label}</span>
      <span className={`font-mono text-[15px] font-semibold tabular-nums ${tone === 'error' ? 'text-alert' : running > 0 || tone === 'running' ? 'text-accent' : 'text-ink-soft'}`}>
        {running > 0 ? (
          <span>{running}</span>
        ) : (
          completed
        )}
      </span>
      <span className="whitespace-nowrap text-[10px] text-ink-faint">
        {running > 0 ? '进行中' : errors > 0 ? `完成 · 错${errors}` : '本会话完成'}
      </span>
      {flashKey > 0 && (
        <motion.span
          key={flashKey}
          initial={{ opacity: 0.35 }}
          animate={{ opacity: 0 }}
          transition={{ duration: 0.7 }}
          className="pointer-events-none absolute inset-0 rounded-lg bg-accent/25"
        />
      )}
    </div>
  )
}

export default function AgentRelayStrip() {
  const buffer = useEventStreamStore((s) => s.buffer)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)

  const { nodeStats, active } = useMemo(() => deriveRelays(buffer), [buffer])

  const [packet, setPacket] = useState<number | null>(null)
  const [packetError, setPacketError] = useState(false)
  const [pulseStage, setPulseStage] = useState<string>('')
  const [flashMap, setFlashMap] = useState<Record<string, number>>({})
  const lastRunRef = useRef(0)

  // 最近一条 agent_stage 驱动飞行与节点脉冲
  useEffect(() => {
    if (!arrivalTick) return
    const now = Date.now()
    if (now - lastRunRef.current < 300) return
    lastRunRef.current = now

    const top = buffer.find((e) => e.kind === 'event' && e.type === 'agent_stage')
    const stage = top ? String(top.data?.stage || '') : ''
    setPacketError(top ? String(top.data?.status || '') === 'error' : false)
    if (stage && (AGENT_RELAY_STAGES as readonly string[]).includes(stage)) {
      setPulseStage(stage)
      setFlashMap((m) => ({ ...m, [stage]: (m[stage] ?? 0) + 1 }))
    }
    setPacket(arrivalTick)
  }, [arrivalTick, buffer])

  const activeStageSet = useMemo(() => {
    const set = new Set<string>()
    for (const r of active) {
      if (r.currentStage) set.add(r.currentStage)
    }
    return set
  }, [active])

  return (
    <div className="flex flex-col gap-5 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="relative min-w-0 flex-1">
        <div className="mb-2 flex items-center justify-between gap-2">
          <p className="text-[11px] text-ink-faint">
            多 Agent 审查接力 · 分解 → 工具 → 执行 → 复核 → CAD → 响应
          </p>
          <span className="font-mono text-[11px] text-ink-faint tabular-nums">
            进行中 {active.length}
          </span>
        </div>

        <div className="absolute left-[39px] right-[39px] top-[calc(50%+8px)] h-px bg-line" />

        {packet !== null && (
          <motion.span
            key={packet}
            className={`absolute z-20 h-2 w-2 rounded-full ${
              packetError
                ? 'bg-alert shadow-[0_0_8px_rgba(194,58,50,0.35)]'
                : 'bg-ok shadow-[0_0_8px_rgba(62,122,100,0.35)]'
            }`}
            style={{ marginLeft: -4, top: 'calc(50% + 8px)' }}
            initial={{ left: '5%', opacity: 0 }}
            animate={{ left: '95%', opacity: [0, 1, 1, 0.85] }}
            transition={{ duration: 0.9, ease: 'linear' }}
            onAnimationComplete={() => setPacket(null)}
          />
        )}

        <div className="relative flex items-start justify-between gap-1.5 overflow-x-auto pb-1">
          {AGENT_RELAY_STAGES.map((stage) => {
            const stats = nodeStats[stage] ?? { running: 0, completed: 0, errors: 0 }
            return (
              <Node
                key={stage}
                label={STAGE_LABELS[stage] ?? stage}
                running={stats.running}
                completed={stats.completed}
                errors={stats.errors}
                flashKey={flashMap[stage] ?? 0}
                active={activeStageSet.has(stage) || pulseStage === stage}
              />
            )
          })}
        </div>
      </div>

      <RateHistogram />
    </div>
  )
}
