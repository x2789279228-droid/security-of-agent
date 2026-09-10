import { attentionItems, type ThoughtStep } from '../../lib/thoughtChain'

export default function EvidenceHeatLinks({
  nodes,
  selectedId,
  onJumpEvent,
  onSelectStep,
}: {
  nodes: ThoughtStep[]
  selectedId?: string | null
  onJumpEvent?: (eventId: number) => void
  onSelectStep?: (step: ThoughtStep) => void
}) {
  const items = attentionItems(nodes, selectedId).slice(0, 10)
  if (!items.length) return null
  return (
    <div className="border-t border-line px-4 py-2">
      <p className="mb-1.5 text-[10px] tracking-wide text-ink-faint">
        证据注意力（检索分 / grounding / 引用次数）
        {selectedId ? ' · 当前结论的祖先路径' : ''}
      </p>
      <p className="mb-1.5 text-[10px] text-ink-faint">非模型内部 token 注意力</p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((it) => {
          const w = Math.max(28, Math.round(it.weight * 88))
          return (
            <button
              key={it.key}
              type="button"
              title={it.kind === 'rag' ? it.label : `事件 ${it.label}`}
              onClick={() => {
                if (it.kind === 'event' && it.eventId && onJumpEvent) onJumpEvent(it.eventId)
                if (it.kind === 'rag' && it.step && onSelectStep) onSelectStep(it.step)
              }}
              className="inline-flex items-center gap-1 rounded-md border border-line bg-card px-1.5 py-0.5 font-mono text-[10px] text-ink-soft transition-colors hover:border-accent/50 hover:text-accent"
            >
              <span
                className="inline-block h-1.5 rounded-full bg-accent"
                style={{ width: w, opacity: 0.25 + it.weight * 0.75 }}
              />
              {it.kind === 'rag' ? it.label.slice(0, 18) : it.label}
              {it.kind === 'rag' && it.weight ? (
                <span className="tabular-nums">{it.weight.toFixed(2)}</span>
              ) : null}
            </button>
          )
        })}
      </div>
    </div>
  )
}
