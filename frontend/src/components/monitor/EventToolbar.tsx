/**
 * 过滤工具栏 — 类型 chips（实时计数）/ Agent 阶段 / 严重度 / 关键字搜索
 */
import {
  EVENT_META,
  SEVERITY_META,
  TYPE_KEYS,
} from '../../lib/eventStream'
import { AGENT_RELAY_STAGES, STAGE_LABELS } from '../../lib/agentPipeline'

const chipBase =
  'flex items-center gap-1 rounded-lg border px-2 py-1 text-[12px] transition-colors whitespace-nowrap'

function TypeChip({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean
  label: string
  count?: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`${chipBase} ${
        active
          ? 'border-accent/60 bg-accent/15 text-accent shadow-[0_2px_10px_rgba(58,101,112,0.14)]'
          : 'border-line bg-card/70 text-ink-soft hover:border-accent/50 hover:text-accent'
      }`}
    >
      {label}
      {count !== undefined && (
        <span className={`font-mono text-[11px] tabular-nums ${active ? 'text-accent/70' : 'text-ink-faint'}`}>
          {count}
        </span>
      )}
    </button>
  )
}

export interface Filters {
  type: string        // 'all' | EVENT_META key
  severity: string    // 'all' | SEVERITY_META key
  stage: string       // 'all' | AGENT_RELAY_STAGES key
  query: string
}

export default function EventToolbar({
  filters,
  onChange,
  typeCounts,
}: {
  filters: Filters
  onChange: (next: Filters) => void
  typeCounts: Record<string, number>
}) {
  const total = Object.values(typeCounts).reduce((a, b) => a + b, 0)

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line px-5 py-3">
      {/* 类型 */}
      <div className="flex flex-wrap items-center gap-1.5">
        <TypeChip active={filters.type === 'all'} label="全部" count={total} onClick={() => onChange({ ...filters, type: 'all' })} />
        {TYPE_KEYS.map((key) => (
          <TypeChip
            key={key}
            active={filters.type === key}
            label={EVENT_META[key].label}
            count={typeCounts[key] ?? 0}
            onClick={() => onChange({ ...filters, type: key })}
          />
        ))}
      </div>

      <div className="ml-auto flex flex-wrap items-center gap-3">
        {/* Agent 阶段 */}
        <select
          value={filters.stage}
          onChange={(e) => onChange({ ...filters, stage: e.target.value })}
          className="rounded-lg border border-line bg-card/70 px-2 py-1 text-[12px] text-ink transition-colors focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
          title="按 Agent 阶段筛选"
        >
          <option value="all">全部阶段</option>
          {AGENT_RELAY_STAGES.map((s) => (
            <option key={s} value={s}>{STAGE_LABELS[s]}</option>
          ))}
        </select>

        {/* 严重度 */}
        <div className="flex items-center gap-1.5">
          {[
            ['all', '全部'],
            ...Object.entries(SEVERITY_META)
              .sort((a, b) => b[1].rank - a[1].rank)
              .map(([k, m]) => [k, m.label] as const),
          ].map(([key, label]) => (
            <button
              key={key}
              onClick={() => onChange({ ...filters, severity: key as string })}
              className={`rounded-md px-1.5 py-0.5 text-[11px] transition-colors ${
                filters.severity === key
                  ? 'border border-warn/50 bg-warn/15 font-semibold text-warn'
                  : 'border border-transparent text-ink-faint hover:text-accent'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* 搜索 */}
        <input
          value={filters.query}
          onChange={(e) => onChange({ ...filters, query: e.target.value })}
          placeholder="搜索 src_ip / event_type / trace_id / Agent…"
          className="w-52 rounded-lg border border-line bg-card/70 px-2.5 py-1 text-[12px] text-ink placeholder:text-ink-faint transition-colors focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
        />
      </div>
    </div>
  )
}
