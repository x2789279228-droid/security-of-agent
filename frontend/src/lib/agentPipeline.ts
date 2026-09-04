/**
 * Audit-LLM 多 Agent 审查接力 — 阶段常量与从事件缓冲派生进行中状态
 *
 * 主路径: Decomposer → Tool Builder → Executor → Reviewer → CAD → Response
 */
import type { StreamEvent } from './eventStream'

export const AGENT_RELAY_STAGES = [
  'decomposer',
  'tool_builder',
  'executor',
  'reviewer',
  'cad_verify',
  'response',
] as const

export type AgentRelayStage = (typeof AGENT_RELAY_STAGES)[number]

export const STAGE_LABELS: Record<string, string> = {
  ingest: '接入',
  anomaly_detect: '异常检测',
  sigma_detect: 'Sigma 规则',
  store: '存储',
  decomposer: '分解者',
  tool_builder: '工具构建',
  executor: '执行者',
  reviewer: '复核者',
  cad_verify: 'CAD 监督',
  response: '响应引擎',
  pipeline_complete: '流水线完成',
}

export const STAGE_COLORS: Record<string, string> = {
  decomposer: '#ff9f0a',
  tool_builder: '#ff375f',
  executor: '#ff2d55',
  reviewer: '#5856d6',
  cad_verify: '#30b0c7',
  response: '#34c759',
}

export type StageCellStatus = 'idle' | 'running' | 'success' | 'error' | 'timeout'

export interface RelayState {
  eventId: number
  sessionId: string
  traceId: string
  currentStage: string
  stages: Record<string, StageCellStatus>
  startedAt: number
  updatedAt: number
  lastError: string
  done: boolean
}

function emptyStages(): Record<string, StageCellStatus> {
  const m: Record<string, StageCellStatus> = {}
  for (const s of AGENT_RELAY_STAGES) m[s] = 'idle'
  return m
}

function isRelayStage(stage: string): stage is AgentRelayStage {
  return (AGENT_RELAY_STAGES as readonly string[]).includes(stage)
}

/** 从事件缓冲派生按 event_id 聚合的接力状态（新事件在前，遍历时用旧→新覆盖） */
export function deriveRelays(buffer: StreamEvent[]): {
  active: RelayState[]
  nodeStats: Record<string, { running: number; completed: number; errors: number }>
} {
  const map = new Map<number, RelayState>()
  const nodeStats: Record<string, { running: number; completed: number; errors: number }> = {}
  for (const s of AGENT_RELAY_STAGES) {
    nodeStats[s] = { running: 0, completed: 0, errors: 0 }
  }

  // buffer 新在前：从尾部（旧）向头（新）应用，保证最终态正确
  for (let i = buffer.length - 1; i >= 0; i--) {
    const evt = buffer[i]
    if (evt.kind !== 'event') continue
    const d = evt.data ?? {}

    if (evt.type === 'agent_stage') {
      const eventId = Number(d.event_id) || 0
      if (!eventId) continue
      const stage = String(d.stage || '')
      if (!isRelayStage(stage)) continue

      let relay = map.get(eventId)
      if (!relay) {
        relay = {
          eventId,
          sessionId: String(d.session_id || ''),
          traceId: String(d.trace_id || ''),
          currentStage: stage,
          stages: emptyStages(),
          startedAt: evt.ts,
          updatedAt: evt.ts,
          lastError: '',
          done: false,
        }
        map.set(eventId, relay)
      }

      if (d.session_id) relay.sessionId = String(d.session_id)
      if (d.trace_id) relay.traceId = String(d.trace_id)
      relay.updatedAt = evt.ts

      if (d.phase === 'start') {
        relay.stages[stage] = 'running'
        relay.currentStage = stage
        relay.done = false
      } else if (d.phase === 'end') {
        const st = String(d.status || 'success') as StageCellStatus
        relay.stages[stage] =
          st === 'error' || st === 'timeout' ? st : 'success'
        if (st === 'error' || st === 'timeout') {
          relay.lastError = String(d.error || st)
        }
        // 若还有更后阶段未开始，当前指针仍停在本阶段；否则标为已过
        relay.currentStage = stage
      }
      continue
    }

    if (evt.type === 'audit_complete') {
      const eventId = Number(d.event_id) || 0
      if (!eventId) continue
      let relay = map.get(eventId)
      if (!relay) {
        relay = {
          eventId,
          sessionId: String(d.session_id || ''),
          traceId: String(d.trace_id || ''),
          currentStage: 'reviewer',
          stages: emptyStages(),
          startedAt: evt.ts,
          updatedAt: evt.ts,
          lastError: '',
          done: false,
        }
        map.set(eventId, relay)
      }
      for (const s of ['decomposer', 'tool_builder', 'executor', 'reviewer'] as const) {
        if (relay.stages[s] === 'idle' || relay.stages[s] === 'running') {
          relay.stages[s] = 'success'
        }
      }
      relay.updatedAt = evt.ts
      continue
    }

    if (evt.type === 'response_action') {
      const eventId = Number(d.event_id) || 0
      if (!eventId) continue
      let relay = map.get(eventId)
      if (!relay) {
        relay = {
          eventId,
          sessionId: String(d.session_id || ''),
          traceId: String(d.trace_id || ''),
          currentStage: 'response',
          stages: emptyStages(),
          startedAt: evt.ts,
          updatedAt: evt.ts,
          lastError: '',
          done: false,
        }
        map.set(eventId, relay)
      }
      if (relay.stages.response === 'idle' || relay.stages.response === 'running') {
        relay.stages.response = 'success'
      }
      relay.currentStage = 'response'
      relay.updatedAt = evt.ts
      relay.done = true
    }
  }

  // 收尾：CAD + response 都完成后标 done；仅有 running 的为 active
  const active: RelayState[] = []
  for (const relay of map.values()) {
    const hasRunning = AGENT_RELAY_STAGES.some((s) => relay.stages[s] === 'running')
    const allTerminal = AGENT_RELAY_STAGES.every(
      (s) => relay.stages[s] !== 'running',
    )
    // 若 reviewer+cad 已结束且无 running，视为本轮接力结束（response 可能未触发）
    if (!hasRunning && allTerminal) {
      const touched = AGENT_RELAY_STAGES.some((s) => relay.stages[s] !== 'idle')
      if (touched && relay.stages.cad_verify !== 'idle' && relay.stages.cad_verify !== 'running') {
        relay.done = true
      }
      if (touched && relay.stages.reviewer === 'success' && relay.stages.cad_verify === 'idle') {
        // 等待 CAD 或未跑 CAD — 仍可能进行中，但无 active span 时不算 active
      }
    }
    if (hasRunning) {
      relay.done = false
      active.push(relay)
    }

    for (const s of AGENT_RELAY_STAGES) {
      const st = relay.stages[s]
      if (st === 'running') nodeStats[s].running += 1
      if (st === 'success') nodeStats[s].completed += 1
      if (st === 'error' || st === 'timeout') nodeStats[s].errors += 1
    }
  }

  active.sort((a, b) => b.updatedAt - a.updatedAt)
  return { active, nodeStats }
}

export function fmtMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms)}ms`
}

export function runningLabel(startedAt: number, now = Date.now()): string {
  const sec = Math.max(0, (now - startedAt) / 1000)
  if (sec < 60) return `${sec.toFixed(0)}s`
  return `${Math.floor(sec / 60)}m${Math.floor(sec % 60)}s`
}
