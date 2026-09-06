import { KIND_LABELS, fmtConf, type ThoughtStep } from '../../lib/thoughtChain'

const statusDot: Record<string, string> = {
  running: 'bg-ink animate-pulse',
  success: 'bg-nong',
  error: 'bg-hui',
  discarded: 'bg-dan',
  abstain: 'border border-ink bg-white',
  blocked: 'bg-hui',
}

const cardTone: Record<string, string> = {
  running: 'border-ink bg-mist',
  success: 'border-line bg-white',
  error: 'border-hui bg-white',
  discarded: 'border-dashed border-dan bg-white',
  abstain: 'border-dashed border-ink bg-white',
  blocked: 'border-hui bg-mist',
}

export default function ThoughtNode({
  step,
  selected,
  dimmed,
  onSelect,
}: {
  step: ThoughtStep
  selected?: boolean
  dimmed?: boolean
  onSelect?: (step: ThoughtStep) => void
}) {
  const st = String(step.status || 'success')
  const conf = fmtConf(step.confidence ?? step.rag_score)
  const cites = (step.evidence_ids || []).length
  return (
    <button
      type="button"
      onClick={() => onSelect?.(step)}
      className={`w-full text-left border px-2 py-1.5 transition-colors ${
        cardTone[st] ?? cardTone.success
      } ${selected ? 'ring-1 ring-ink' : 'hover:border-ink'} ${dimmed ? 'opacity-40' : ''}`}
    >
      <div className="flex items-center gap-1.5 min-w-0">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${statusDot[st] ?? statusDot.success}`} />
        <span className="truncate text-[11px] font-semibold text-ink">{step.title}</span>
      </div>
      <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-ink-faint">
        <span>{KIND_LABELS[step.kind] ?? step.kind}</span>
        {conf && <span className="tabular-nums">{conf}</span>}
        {cites > 0 && <span>证×{cites}</span>}
      </div>
    </button>
  )
}
