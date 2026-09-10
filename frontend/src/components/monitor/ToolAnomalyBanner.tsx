import { useEventStreamStore } from '../../lib/eventStream'

export default function ToolAnomalyBanner() {
  const latest = useEventStreamStore((s) => {
    for (let i = s.buffer.length - 1; i >= 0; i--) {
      const evt = s.buffer[i]
      if (evt.kind === 'event' && evt.type === 'tool_anomaly') return evt
    }
    return null
  })
  if (!latest) return null
  const d = latest.data ?? {}
  const reasons = Array.isArray(d.reasons) ? d.reasons : []
  return (
    <div className="mb-4 rounded-xl border border-alert/50 bg-alert/[0.06] px-4 py-3 shadow-[0_2px_14px_rgba(194,58,50,0.12)]">
      <p className="flex items-center gap-2 text-[12px] font-semibold text-alert">
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inset-0 animate-ping rounded-full bg-alert opacity-60" />
          <span className="relative h-1.5 w-1.5 rounded-full bg-alert" />
        </span>
        工具偏离 · <span className="font-mono">{d.tool_name || 'tool'}</span>
        {d.caller ? ` · ${d.caller}` : ''}
        {' · '}得分 {Number(d.score ?? 0).toFixed(2)}
      </p>
      {reasons[0] && (
        <p className="mt-1 pl-3.5 text-[11px] font-mono text-ink-soft">{String(reasons[0])}</p>
      )}
    </div>
  )
}
