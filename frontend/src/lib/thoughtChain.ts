/**
 * 监控页思维链 — 从 SSE agent_thought / REST 组装 DAG 节点
 */
import type { StreamEvent } from './eventStream'
import { AGENT_RELAY_STAGES } from './agentPipeline.ts'

export const THOUGHT_KINDS = [
  'signal', 'plan', 'tool_map', 'tool', 'rag', 'claim', 'discard', 'hop',
  'verdict', 'gate', 'review', 'cad', 'response',
] as const

export type ThoughtKind = (typeof THOUGHT_KINDS)[number]
export type ThoughtStatus = 'running' | 'success' | 'error' | 'discarded' | 'abstain' | 'blocked'

export interface ThoughtStep {
  step_id: string
  event_id: number
  session_id?: string
  trace_id?: string
  round?: number
  stage: string
  kind: ThoughtKind | string
  title: string
  summary: string
  status: ThoughtStatus | string
  confidence?: number | null
  parent_ids?: string[]
  evidence_ids?: number[]
  evidence_quotes?: string[]
  metrics?: Record<string, unknown>
  tool_name?: string
  tool_ok?: boolean | null
  signature_score?: number | null
  signature_reasons?: string[]
  chunk_id?: string
  rag_score?: number | null
  source?: string
  ts?: number
}

export interface ThoughtEdge {
  from: string
  to: string
  rel: 'derived' | 'evidences' | 'vetoed' | string
}

export interface ThoughtChainPayload {
  event_id: number
  status: string
  nodes: ThoughtStep[]
  edges: ThoughtEdge[]
  grounding: { score?: number | null; cited_event_ids: number[] }
  source: 'live' | 'persisted' | 'projected' | 'empty' | string
}

export const KIND_LABELS: Record<string, string> = {
  signal: '检测信号',
  plan: '审核计划',
  tool_map: '工具映射',
  tool: '工具调用',
  rag: '知识片段',
  claim: '威胁断言',
  discard: '丢弃断言',
  hop: '推理跳数',
  verdict: '汇总结论',
  gate: '确认闸门',
  review: '复核裁决',
  cad: 'CAD 监督',
  response: '响应',
}

const STAGE_OF_KIND: Record<string, string> = {
  signal: 'ingest',
  plan: 'decomposer',
  tool_map: 'tool_builder',
  tool: 'tool_builder',
  rag: 'tool_builder',
  claim: 'executor',
  discard: 'executor',
  hop: 'executor',
  verdict: 'executor',
  gate: 'executor',
  review: 'reviewer',
  cad: 'cad_verify',
  response: 'response',
}

/** 监控 DAG 列：接入信号 + 6 段接力 */
export const THOUGHT_COLUMNS = ['ingest', ...AGENT_RELAY_STAGES] as const
export type ThoughtColumn = (typeof THOUGHT_COLUMNS)[number]

export const COLUMN_LABELS: Record<string, string> = {
  ingest: '信号',
  decomposer: '分解',
  tool_builder: '工具',
  executor: '执行',
  reviewer: '复核',
  cad_verify: 'CAD',
  response: '响应',
}

export function columnOf(step: ThoughtStep): ThoughtColumn {
  const stage = step.stage || STAGE_OF_KIND[step.kind] || 'executor'
  if ((THOUGHT_COLUMNS as readonly string[]).includes(stage)) return stage as ThoughtColumn
  if (stage === 'ingest') return 'ingest'
  return 'executor'
}

export function mergeSteps(groups: ThoughtStep[][]): ThoughtStep[] {
  const map = new Map<string, ThoughtStep>()
  for (const group of groups) {
    for (const s of group) {
      if (!s?.step_id) continue
      map.set(s.step_id, s)
    }
  }
  return [...map.values()]
}

/** 从 SSE 缓冲抽出某事件的思维步骤（旧→新覆盖） */
export function stepsFromBuffer(buffer: StreamEvent[], eventId: number): ThoughtStep[] {
  const acc: ThoughtStep[] = []
  for (let i = buffer.length - 1; i >= 0; i--) {
    const evt = buffer[i]
    if (evt.kind !== 'event' || evt.type !== 'agent_thought') continue
    const d = evt.data ?? {}
    if (Number(d.event_id) !== eventId) continue
    if (Array.isArray(d.steps)) {
      for (const s of d.steps) {
        if (s && typeof s === 'object') acc.push(s as ThoughtStep)
      }
    } else if (d.step_id || d.kind) {
      acc.push(d as ThoughtStep)
    }
  }
  return mergeSteps([acc])
}

export function groupByColumn(nodes: ThoughtStep[]): Record<ThoughtColumn, ThoughtStep[]> {
  const grouped = {} as Record<ThoughtColumn, ThoughtStep[]>
  for (const col of THOUGHT_COLUMNS) grouped[col] = []
  for (const n of nodes) {
    grouped[columnOf(n)].push(n)
  }
  return grouped
}

/** 与后端 thought_events.build_edges 对齐，供 live SSE（只有 nodes）补边。 */
export function buildEdges(nodes: ThoughtStep[]): ThoughtEdge[] {
  const known = new Set(nodes.map((n) => n.step_id).filter(Boolean))
  const edges: ThoughtEdge[] = []
  const seen = new Set<string>()
  const push = (from: string, to: string, rel: string) => {
    const key = `${from}|${to}|${rel}`
    if (seen.has(key) || !from || !to) return
    seen.add(key)
    edges.push({ from, to, rel })
  }
  for (const n of nodes) {
    for (const pid of n.parent_ids || []) {
      if (!known.has(pid)) continue
      const rel = n.kind === 'discard' ? 'vetoed' : n.kind === 'rag' ? 'retrieved' : 'derived'
      push(pid, n.step_id, rel)
    }
    if (n.kind === 'claim') {
      for (const eid of n.evidence_ids || []) {
        push(n.step_id, `evidence:${eid}`, 'evidences')
      }
    }
  }
  return edges
}

export function ancestorIds(nodes: ThoughtStep[], startId?: string | null): Set<string> {
  const out = new Set<string>()
  if (!startId) return out
  const byId = new Map(nodes.map((n) => [n.step_id, n]))
  const stack = [startId]
  while (stack.length) {
    const id = stack.pop() as string
    if (out.has(id)) continue
    out.add(id)
    const node = byId.get(id)
    for (const pid of node?.parent_ids || []) {
      if (!out.has(pid)) stack.push(pid)
    }
  }
  return out
}

export function edgeWeight(edge: ThoughtEdge, byId: Map<string, ThoughtStep>): number {
  const to = byId.get(edge.to)
  const from = byId.get(edge.from)
  const w =
    Number(to?.metrics?.weight) ||
    Number(to?.rag_score) ||
    Number(to?.confidence) ||
    Number(from?.rag_score) ||
    Number(from?.confidence) ||
    0.35
  return Math.max(0.15, Math.min(1, w))
}

export interface AttentionItem {
  key: string
  kind: 'event' | 'rag'
  label: string
  weight: number
  eventId?: number
  step?: ThoughtStep
}

/** 选中节点祖先路径上的 RAG / 事件引用，按权重排序。 */
export function attentionItems(nodes: ThoughtStep[], selectedId?: string | null): AttentionItem[] {
  const path = ancestorIds(nodes, selectedId)
  const focus = path.size ? nodes.filter((n) => path.has(n.step_id)) : nodes
  const items: AttentionItem[] = []
  const ev = new Map<number, number>()
  for (const n of focus) {
    if (n.kind === 'rag') {
      items.push({
        key: n.step_id,
        kind: 'rag',
        label: n.title,
        weight: Number(n.rag_score ?? n.metrics?.weight) || 0.4,
        step: n,
      })
    }
    for (const id of n.evidence_ids || []) {
      const k = Number(id)
      if (!k) continue
      ev.set(k, (ev.get(k) ?? 0) + 1)
    }
  }
  const max = Math.max(1, ...ev.values())
  for (const [id, count] of ev) {
    items.push({
      key: `e${id}`,
      kind: 'event',
      label: `#${id}`,
      weight: count / max,
      eventId: id,
    })
  }
  return items.sort((a, b) => b.weight - a.weight)
}

export function citedEventCounts(nodes: ThoughtStep[]): { id: number; count: number }[] {
  const map = new Map<number, number>()
  for (const n of nodes) {
    for (const id of n.evidence_ids || []) {
      const k = Number(id)
      if (!k) continue
      map.set(k, (map.get(k) ?? 0) + 1)
    }
  }
  return [...map.entries()]
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count)
}

export function eventIdOf(evt: StreamEvent): number {
  if (evt.kind !== 'event') return 0
  return Number(evt.data?.event_id) || 0
}

export function isThoughtSelectable(evt: StreamEvent): boolean {
  if (evt.kind !== 'event') return false
  return (
    (evt.type === 'agent_stage' ||
      evt.type === 'audit_complete' ||
      evt.type === 'agent_thought' ||
      evt.type === 'response_action') &&
    eventIdOf(evt) > 0
  )
}

const THOUGHT_PICK_ORDER = ['audit_complete', 'agent_thought', 'response_action', 'agent_stage'] as const

/** SSE 缓冲里最新一条可打开思维链的 event_id（缓冲新在前） */
export function pickThoughtEventId(buffer: StreamEvent[]): number {
  for (const type of THOUGHT_PICK_ORDER) {
    const hit = buffer.find((e) => e.kind === 'event' && e.type === type && eventIdOf(e) > 0)
    if (hit) return eventIdOf(hit)
  }
  return 0
}

export function isSelfPlayEventType(type: string): boolean {
  return type === 'selfplay_round' || type === 'selfplay_match'
}

/** 给 EventRow 的一句摘要 */
export function thoughtBrief(data: Record<string, unknown>): string {
  const count = Number(data.thought_count) || (Array.isArray(data.steps) ? data.steps.length : 0)
  const title = String(data.title || '')
  const kind = String(data.kind || '')
  const label = KIND_LABELS[kind] || kind
  const parts = [label || '思维步骤']
  if (count > 1) parts.push(`${count} 步`)
  if (title) parts.push(title)
  return parts.filter(Boolean).join(' · ')
}

export function fmtConf(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(Number(v))) return ''
  return Number(v).toFixed(2)
}
