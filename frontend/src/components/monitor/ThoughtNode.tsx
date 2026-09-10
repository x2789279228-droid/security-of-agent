import { KIND_LABELS, fmtConf, type ThoughtStep } from '../../lib/thoughtChain'

// 状态音色：运行=磷光脉冲；成功=磷光；错误/阻断=朱砂；弃权=信号蓝虚线；丢弃=暗虚线
const statusDot: Record<string, string> = {
  running: 'bg-accent animate-pulse',
  success: 'bg-accent/80',
  error: 'bg-alert',
  discarded: 'bg-dan',
  abstain: 'border border-signal bg-transparent',
  blocked: 'bg-alert',
}

const cardTone: Record<string, string> = {
  running: 'border-accent/60 bg-accent/[0.06]',
  success: 'border-line bg-card',
  error: 'border-alert/50 bg-alert/[0.07]',
  discarded: 'border-dashed border-dan bg-card/60',
  abstain: 'border-dashed border-signal/60 bg-card/60',
  blocked: 'border-alert/60 bg-alert/[0.09]',
}

const titleTone: Record<string, string> = {
  error: 'text-alert',
  blocked: 'text-alert',
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
      className={`w-full rounded-lg text-left border px-2 py-1.5 transition-colors ${
        cardTone[st] ?? cardTone.success
      } ${selected ? 'ring-1 ring-accent shadow-[0_2px_12px_rgba(58,101,112,0.16)]' : 'hover:border-accent/50'} ${dimmed ? 'opacity-40' : ''}`}
    >
      <div className="flex items-center gap-1.5 min-w-0">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${statusDot[st] ?? statusDot.success}`} />
        <span className={`truncate text-[11px] font-semibold ${titleTone[st] ?? 'text-ink'}`}>{step.title}</span>
      </div>
      <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-ink-faint">
        <span>{KIND_LABELS[step.kind] ?? step.kind}</span>
        {conf && <span className="tabular-nums">{conf}</span>}
        {cites > 0 && <span>证×{cites}</span>}
      </div>
    </button>
  )
}
