/**
 * 进行中的 Agent 接力卡片 — 按 event_id 展示当前经手人与 6 格进度
 */
import { useEffect, useMemo, useState } from 'react'
import {
  AGENT_RELAY_STAGES,
  STAGE_LABELS,
  deriveRelays,
  runningLabel,
  type RelayState,
  type StageCellStatus,
} from '../../lib/agentPipeline'
import { useEventStreamStore } from '../../lib/eventStream'

const cellClass: Record<StageCellStatus, string> = {
  idle: 'bg-line',
  running: 'bg-ink animate-pulse',
  success: 'bg-nong',
  error: 'bg-hui',
  timeout: 'bg-hui',
}

function emptyStages(): Record<string, StageCellStatus> {
  const m: Record<string, StageCellStatus> = {}
  for (const s of AGENT_RELAY_STAGES) m[s] = 'idle'
  return m
}

/** 将 /observability/active-pipelines 载荷转为 RelayState */
export function relayFromHydration(p: any): RelayState {
  const stages = emptyStages()
  for (const s of p.completed_stages || []) {
    if (s in stages) stages[s] = 'success'
  }
  const cur = String(p.current_stage || '')
  if (cur in stages) stages[cur] = 'running'
  const startedAt = typeof p.started_at === 'number'
    ? Math.round(p.started_at * 1000)
    : Date.now()
  return {
    eventId: Number(p.event_id) || 0,
    sessionId: String(p.session_id || ''),
    traceId: String(p.trace_id || ''),
    currentStage: cur,
    stages,
    startedAt,
    updatedAt: Date.now(),
    lastError: '',
    done: false,
  }
}

function Card({ relay, now }: { relay: RelayState; now: number }) {
  return (
    <div className="min-w-[220px] flex-1 border border-line bg-white px-3 py-2.5">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-[12px] font-semibold text-ink">
          #{relay.eventId}
        </span>
        <span className="text-[11px] text-ink-faint tabular-nums">
          {runningLabel(relay.startedAt, now)}
        </span>
      </div>
      <p className="mt-0.5 truncate text-[12px] text-ink-soft">
        当前：
        <span className="font-semibold text-ink">
          {STAGE_LABELS[relay.currentStage] ?? relay.currentStage}
        </span>
        {relay.lastError && (
          <span className="ml-1 text-alert">· {relay.lastError.slice(0, 40)}</span>
        )}
      </p>
      <div className="mt-2 flex gap-1">
        {AGENT_RELAY_STAGES.map((s) => (
          <div
            key={s}
            title={`${STAGE_LABELS[s]} · ${relay.stages[s]}`}
            className={`h-1.5 flex-1 rounded-sm ${cellClass[relay.stages[s] ?? 'idle']}`}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[9px] text-ink-faint">
        <span>分解</span>
        <span>响应</span>
      </div>
    </div>
  )
}

export default function ActiveRelayCards({
  hydrated = [],
}: {
  hydrated?: any[]
}) {
  const buffer = useEventStreamStore((s) => s.buffer)
  const { active: fromStream } = useMemo(() => deriveRelays(buffer), [buffer])

  const active = useMemo(() => {
    if (fromStream.length > 0) return fromStream
    return (hydrated || [])
      .map(relayFromHydration)
      .filter((r) => r.eventId > 0)
  }, [fromStream, hydrated])

  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (active.length === 0) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [active.length])

  if (active.length === 0) return null

  return (
    <div className="mb-5">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold text-ink">进行中的审查接力</h3>
        <span className="font-mono text-[11px] text-ink-faint">{active.length} 条</span>
      </div>
      <div className="flex gap-2 overflow-x-auto pb-1">
        {active.slice(0, 8).map((r) => (
          <Card key={r.eventId} relay={r} now={now} />
        ))}
      </div>
    </div>
  )
}
