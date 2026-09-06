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
    <div className="mb-4 border border-ink bg-white px-4 py-3">
      <p className="text-[12px] font-semibold text-ink">
        工具偏离 · <span className="font-mono">{d.tool_name || 'tool'}</span>
        {d.caller ? ` · ${d.caller}` : ''}
        {' · '}得分 {Number(d.score ?? 0).toFixed(2)}
      </p>
      {reasons[0] && (
        <p className="mt-1 text-[11px] font-mono text-ink-soft">{String(reasons[0])}</p>
      )}
    </div>
  )
}
