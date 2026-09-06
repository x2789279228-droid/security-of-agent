/**
 * 增强事件行 — severity 分级 / 全类型摘要 / 来源与 trace_id / 展开原始 JSON
 *
 * 性能改造：
 * - 列表由 react-window 虚拟化，仅可视区 ~30 行参与 mount/重渲染
 * - framer-motion 的 layout FLIP 动画是 500 行全量 mount 时的最大渲染开销，已移除
 * - Inner 经 memo：evt/expanded/onToggle 均为稳定引用，高频到达时命中率高
 */
import { memo, useState, type CSSProperties } from 'react'
import type { RowComponentProps } from 'react-window'
import {
  EVENT_META,
  SEVERITY_META,
  metaOf,
  severityOf,
  type StreamEvent,
} from '../../lib/eventStream'
import { STAGE_LABELS, fmtMs } from '../../lib/agentPipeline'
import { isSelfPlayEventType, isThoughtSelectable, thoughtBrief } from '../../lib/thoughtChain'

// 传给 List.rowProps 的数据（index/style 由 react-window 注入，不在此列）
export interface EventRowData {
  events: StreamEvent[]
  expandedIds: Set<number>
  onToggle: (id: number) => void
  selectedEventId?: number | null
  onSelectEvent?: (eventId: number) => void
}

type EventRowProps = RowComponentProps<EventRowData>

// 各类型摘要里优先展示的字段顺序（其余类型走通用摘要）
const PREFERRED_KEYS = [
  'threat_type', 'event_type', 'event', 'alert_type',
  'verdict', 'classification', 'label', 'stage', 'trigger', 'type',
  'src_ip', 'confidence', 'anomaly_score',
  'tool_name', 'score', 'caller',
]

function briefOf(data: any): string {
  if (!data || typeof data !== 'object') return String(data ?? '')
  const parts: string[] = []
  for (const key of PREFERRED_KEYS) {
    const v = data[key]
    if (parts.length >= 4) break
    if (v === undefined || v === null || v === '') continue
    if (typeof v === 'object') continue
    parts.push(String(v))
  }
  if (!parts.length) {
    try { return JSON.stringify(data).slice(0, 90) } catch { return '' }
  }
  return parts.join(' · ')
}

function TraceId({ traceId }: { traceId: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        navigator.clipboard?.writeText(traceId).then(
          () => { setCopied(true); setTimeout(() => setCopied(false), 1200) },
          () => {},
        )
      }}
      title={`trace_id ${traceId}（点击复制）`}
      className="font-mono text-[11px] text-ink-faint underline decoration-dan underline-offset-2 hover:text-ink"
    >
      {copied ? '已复制' : `trace ${traceId.slice(0, 8)}…`}
    </button>
  )
}

function Summary({ evt }: { evt: StreamEvent }) {
  const d = evt.data ?? {}
  switch (evt.type) {
    case 'security_event':
      return (
        <span className="text-ink-soft">
          <span className="font-mono font-medium text-ink">{d.event_type}</span>
          {' · '}{d.src_ip}
          {(Number(d.anomaly_score) || 0) >= 0.6 && (
            <span className="ml-1.5 font-semibold text-alert">⚠ 异常 {Number(d.anomaly_score).toFixed(2)}</span>
          )}
        </span>
      )
    case 'alert':
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-ink">⚠ {d.alert_type}</span>
          {' · '}<span className="font-mono">{d.event_type}</span>{' · '}{d.src_ip}
          {' · '}得分 {Number(d.anomaly_score ?? 0).toFixed(2)}
          {Array.isArray(d.reasons) && d.reasons.length > 0 && (
            <span className="text-ink-faint"> — {d.reasons.slice(0, 2).join('；')}{d.reasons.length > 2 ? ' 等' : ''}</span>
          )}
        </span>
      )
    case 'agent_thought':
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-ink">{thoughtBrief(d)}</span>
          {typeof d.event_id === 'number' && (
            <span className="font-mono text-ink-faint"> · #{d.event_id}</span>
          )}
        </span>
      )
    case 'agent_stage': {
      const label = d.agent_label || STAGE_LABELS[String(d.stage)] || d.stage
      const phase = d.phase === 'start' ? '接手' : '完成'
      const st = String(d.status || '')
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-ink">{label}</span>
          {' · '}{phase}
          {st && st !== 'running' && (
            <span className={st === 'success' ? ' text-ink-faint' : ' font-semibold text-alert'}>
              {' · '}{st}
            </span>
          )}
          {typeof d.event_id === 'number' && (
            <span className="font-mono text-ink-faint"> · #{d.event_id}</span>
          )}
          {typeof d.latency_ms === 'number' && d.latency_ms > 0 && (
            <span className="text-ink-faint"> · {fmtMs(d.latency_ms)}</span>
          )}
          {d.error && <span className="text-alert"> — {String(d.error).slice(0, 60)}</span>}
        </span>
      )
    }
    case 'audit_complete':
      return (
        <span className="text-ink-soft">
          #{d.event_id} <span className="font-mono">{d.event_type}</span> —{' '}
          {d.threat_detected ? (
            <span className="font-semibold text-ink">威胁确认（置信度 {Number(d.confidence ?? 0).toFixed(2)}）</span>
          ) : (
            <span className="font-semibold text-ink-faint">安全</span>
          )}
          {' · '}{d.rounds} 轮 · {d.duration_s}s
        </span>
      )
    case 'response_action':
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-alert">响应触发</span>{' '}
          <span className="font-mono">{d.threat_type}</span> — {d.src_ip}
          {d.status && <span className="text-ink-faint"> · {d.status}</span>}
        </span>
      )
    case 'tool_anomaly':
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-ink">工具偏离</span>
          {' · '}<span className="font-mono">{d.tool_name}</span>
          {d.caller && <span className="text-ink-faint"> · {d.caller}</span>}
          {' · '}得分 {Number(d.score ?? 0).toFixed(2)}
          {Array.isArray(d.reasons) && d.reasons[0] && (
            <span className="text-ink-faint"> — {String(d.reasons[0]).slice(0, 80)}</span>
          )}
        </span>
      )
    case 'pipeline_health': {
      if (d.type === 'diagnostic') {
        return (
          <span className="text-ink-soft">
            <span className="font-semibold text-ink">管道诊断（{SEVERITY_META[String(d.severity)]?.label ?? d.severity}）</span>
            {' — '}{d.trigger}
            {d.root_cause && <span className="text-ink-faint"> · 根因 {String(d.root_cause).slice(0, 60)}</span>}
          </span>
        )
      }
      return (
        <span className="text-ink-soft">
          <span className="font-semibold text-ink">阶段告警：{d.stage}</span>
          {Array.isArray(d.reasons) && <span className="text-ink-faint"> — {d.reasons.slice(0, 2).join('；')}</span>}
        </span>
      )
    }
    default:
      return <span className="text-ink-soft">{briefOf(d)}</span>
  }
}

const Inner = memo(function Inner({
  evt,
  expanded,
  onToggle,
  selected,
  onSelectEvent,
}: {
  evt: StreamEvent
  expanded: boolean
  onToggle: (id: number) => void
  selected?: boolean
  onSelectEvent?: (eventId: number) => void
}) {
  if (evt.kind !== 'event') {
    const isGap = evt.kind === 'gap'
    return (
      <div className="flex h-full items-center gap-3 bg-surface px-5 py-2">
        <span className="h-px flex-1 border-t border-dashed border-dan" />
        <span className="whitespace-nowrap text-[11px] text-ink-faint">
          {isGap ? '⋯ 断线窗口部分事件已超出服务端缓存，无法补齐' : '⟲ 检测到服务端重启，事件序号重新计数'}
        </span>
        <span className="h-px flex-1 border-t border-dashed border-dan" />
      </div>
    )
  }

  const meta = metaOf(evt.type)
  const sevKey = severityOf(evt.type, evt.data)
  const sev = SEVERITY_META[sevKey]
  const d = evt.data ?? {}
  const timeStr = new Date(evt.ts).toLocaleTimeString('zh-CN', { hour12: false })

  const eid = Number(d.event_id) || 0
  return (
    <div
      onClick={() => {
        onToggle(evt.id)
        if (eid && onSelectEvent) onSelectEvent(eid)
      }}
      className={`flex h-full cursor-pointer select-none flex-col justify-center border-b border-line transition-colors ${
        selected ? 'bg-mist' : expanded ? 'bg-surface' : 'hover:bg-surface/60'
      }`}
    >
      <div className="flex items-stretch">
        {/* severity 分级竖线 */}
        <span className={`${sev.bar} shrink-0 self-stretch`} />

        <div className="flex min-w-0 flex-1 items-center gap-3 py-2.5 pl-3 pr-4">
          <span className={`shrink-0 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${meta?.badge ?? 'border border-dashed border-dan text-hui'}`}>
            {meta?.label ?? evt.type}
          </span>

          <div className="min-w-0 flex-1">
            {/* 摘要行 */}
            <div className="truncate text-[13px]">
              <Summary evt={evt} />
            </div>
            {/* 元信息行 */}
            <div className="mt-0.5 flex items-center gap-2 overflow-hidden whitespace-nowrap text-[11px] text-ink-faint">
              <span
                className={`rounded-sm px-1 py-px ${sev.chip.includes('border') ? sev.chip : `${sev.chip} text-[10px]`}`}
              >
                {sev.label}
              </span>
              {(d.agent_label || d.stage) && evt.type !== 'agent_stage' && (
                <span className="border border-line px-1">
                  {d.agent_label || STAGE_LABELS[String(d.stage)] || d.stage}
                </span>
              )}
              {d.source && <span className="border border-line px-1">{d.source}</span>}
              {typeof d.trace_id === 'string' && d.trace_id && <TraceId traceId={d.trace_id} />}
              {isThoughtSelectable(evt) && (
                <span className="border border-line px-1">思维链</span>
              )}
              {isSelfPlayEventType(evt.type) && (
                <span className="border border-dashed border-dan px-1">自博弈回合，无 Audit-LLM 思维链</span>
              )}
              {evt.replay && <span title="该事件经断线续传回放补发" className="rounded-full border border-dan px-1">回放</span>}
            </div>
          </div>

          <span className="shrink-0 font-mono text-xs tabular-nums text-ink-faint" title={new Date(evt.ts).toLocaleString('zh-CN', { hour12: false })}>
            {timeStr}
          </span>
          <span className={`shrink-0 text-[10px] text-dan transition-transform ${expanded ? 'rotate-180' : ''}`}>▾</span>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-line bg-surface px-5 py-3">
          <p className="mb-1.5 flex items-center justify-between text-[11px] text-ink-faint">
            <span>
              seq {evt.seq || '—'} · {EVENT_META[evt.type]?.label ?? evt.type} · 服务端时间 {new Date(evt.ts).toLocaleString('zh-CN', { hour12: false })}
            </span>
            <span>原始载荷 ↓</span>
          </p>
          <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all bg-white p-3 font-mono text-[11px] leading-relaxed text-ink-soft">
            {JSON.stringify(d, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
})

/** react-window 行组件：外壳应用定位 style，内层 memo 化 */
export default function EventRow({
  index, events, expandedIds, onToggle, selectedEventId, onSelectEvent, style, ariaAttributes,
}: EventRowProps) {
  const evt = events[index]
  if (!evt) return null
  const eid = evt.kind === 'event' ? Number(evt.data?.event_id) || 0 : 0
  return (
    <div style={style as CSSProperties} {...ariaAttributes}>
      <Inner
        evt={evt}
        expanded={expandedIds.has(evt.id)}
        onToggle={onToggle}
        selected={!!eid && eid === selectedEventId}
        onSelectEvent={onSelectEvent}
      />
    </div>
  )
}
