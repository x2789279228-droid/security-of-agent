import { useEffect, useMemo, useState } from 'react'
import { api } from '../../lib/api'
import { useEventStreamStore } from '../../lib/eventStream'
import {
  KIND_LABELS,
  ancestorIds,
  buildEdges,
  fmtConf,
  mergeSteps,
  stepsFromBuffer,
  type ThoughtChainPayload,
  type ThoughtStep,
} from '../../lib/thoughtChain'
import EvidenceHeatLinks from './EvidenceHeatLinks'
import ThoughtDag from './ThoughtDag'

function Detail({ step }: { step: ThoughtStep }) {
  const conf = fmtConf(step.confidence ?? step.rag_score)
  return (
        <div className="w-full shrink-0 border-l border-line bg-surface p-3 md:w-64">
          <p className="text-[10px] tracking-wide text-ink-faint">
            {KIND_LABELS[step.kind] ?? step.kind} · {step.stage}
          </p>
          <p className="mt-1 text-[13px] font-semibold text-ink">{step.title}</p>
          {conf && <p className="mt-0.5 font-mono text-[11px] text-accent/80">置信度 {conf}</p>}
          {step.summary && (
            <p className="mt-2 text-[12px] leading-relaxed text-ink-soft">{step.summary}</p>
          )}
          {(step.evidence_quotes || []).length > 0 && (
            <div className="mt-2 space-y-1">
              {(step.evidence_quotes || []).map((q, i) => (
                <p key={i} className="rounded-md border border-line bg-mist px-2 py-1 font-mono text-[10px] text-ink-faint">
                  “{q}”
                </p>
              ))}
            </div>
          )}
      {step.tool_name && (
        <p className="mt-2 font-mono text-[10px] text-ink-faint">
          工具 {step.tool_name}
          {step.tool_ok === false ? ' · 失败' : ''}
          {step.signature_score != null ? ` · 签名 ${Number(step.signature_score).toFixed(2)}` : ''}
        </p>
      )}
      {step.kind === 'rag' && (
        <p className="mt-2 font-mono text-[10px] text-ink-faint">
          chunk {step.chunk_id || '—'}
          {step.rag_score != null ? ` · score ${Number(step.rag_score).toFixed(2)}` : ''}
          {step.source ? ` · ${step.source}` : ''}
        </p>
      )}
      {step.trace_id && (
        <p className="mt-2 font-mono text-[10px] text-ink-faint">trace {step.trace_id.slice(0, 16)}</p>
      )}
      {(step.evidence_ids || []).length > 0 && (
        <p className="mt-2 font-mono text-[10px] text-ink-faint">
          引用事件 {(step.evidence_ids || []).map((id) => `#${id}`).join(' ')}
        </p>
      )}
      {step.status === 'discarded' && (
        <p className="mt-2 text-[11px] text-alert">该断言被闸门丢弃，不进入结论。</p>
      )}
      {step.status === 'blocked' && (
        <p className="mt-2 text-[11px] text-alert">自动响应被阻断。</p>
      )}
      {step.status === 'abstain' && (
        <p className="mt-2 text-[11px] text-ink-soft">证据不足，本步弃权。</p>
      )}
    </div>
  )
}

export default function ThoughtChainPanel({
  eventId,
  onClose,
  onJumpEvent,
  idleHint,
}: {
  eventId: number | null
  onClose?: () => void
  onJumpEvent?: (eventId: number) => void
  idleHint?: string
}) {
  const buffer = useEventStreamStore((s) => s.buffer)
  const [payload, setPayload] = useState<ThoughtChainPayload | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<ThoughtStep | null>(null)

  const live = useMemo(
    () => (eventId ? stepsFromBuffer(buffer, eventId) : []),
    [buffer, eventId],
  )

  useEffect(() => {
    if (!eventId || !onClose) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [eventId, onClose])

  useEffect(() => {
    setPayload(null)
    setSelected(null)
    setError('')
    if (!eventId) return
    let cancelled = false
    setLoading(true)
    api.thoughtChain(eventId)
      .then((d) => {
        if (!cancelled) setPayload(d)
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message || '加载失败')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [eventId])

  const nodes = useMemo(
    () => mergeSteps([payload?.nodes ?? [], live]),
    [payload, live],
  )
  const edges = useMemo(() => {
    const liveEdges = buildEdges(nodes)
    if (!payload?.edges?.length) return liveEdges
    const seen = new Set(liveEdges.map((e) => `${e.from}|${e.to}|${e.rel}`))
    const extra = payload.edges.filter((e) => !seen.has(`${e.from}|${e.to}|${e.rel}`))
    return [...liveEdges, ...extra]
  }, [nodes, payload])
  const pathIds = useMemo(
    () => ancestorIds(nodes, selected?.step_id),
    [nodes, selected],
  )

  if (!eventId) {
    return (
      <div className="mb-5 rounded-xl border border-dashed border-line bg-card/50 px-5 py-3 text-[12px] text-ink-faint">
        {idleHint || '当前没有可展示的 Audit-LLM 思维链。请注入一条安全事件，或在本页跑演示审查。'}
      </div>
    )
  }

  const source = payload?.source || (live.length ? 'live' : '')
  const gScore = payload?.grounding?.score

  return (
    <div className="mb-5 rounded-xl border border-line bg-card/70 backdrop-blur-sm overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2">
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold text-ink">
            思维链
            <span className="ml-2 font-mono text-[12px] font-normal text-accent/80">#{eventId}</span>
          </h3>
          <p className="text-[10px] text-ink-faint">
            {source === 'projected' ? '由历史审计投影' : source === 'persisted' ? '落库回放' : '实时'}
            {typeof gScore === 'number' && (
              <span className="ml-2 tabular-nums">grounding {Number(gScore).toFixed(2)}</span>
            )}
            {payload?.status && <span className="ml-2">{payload.status}</span>}
          </p>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-line px-2 py-0.5 text-[11px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
          >
            关闭
          </button>
        )}
      </div>

      {error && !nodes.length && (
        <p className="px-4 py-6 text-center text-[12px] text-alert">{error}</p>
      )}
      {loading && !nodes.length && (
        <p className="px-4 py-6 text-center text-[12px] text-ink-faint">加载思维链…</p>
      )}
      {!loading && !error && !nodes.length && (
        <p className="px-4 py-6 text-center text-[12px] text-ink-faint">
          该事件尚无结构化推理步骤（流水线开始后将逐步出现）
        </p>
      )}

      {nodes.length > 0 && (
        <div className="flex flex-col md:flex-row">
          <div className="min-w-0 flex-1">
            <ThoughtDag
              nodes={nodes}
              edges={edges}
              selectedId={selected?.step_id}
              pathIds={pathIds}
              onSelect={setSelected}
            />
            <EvidenceHeatLinks
              nodes={nodes}
              selectedId={selected?.step_id}
              onJumpEvent={onJumpEvent}
              onSelectStep={setSelected}
            />
            <p className="border-t border-line px-4 py-1.5 text-[10px] text-ink-faint">
              可解释性支撑 OWASP LLM09 误导信息（grounding / 丢弃断言）与 LLM06 过度代理（响应阻断）。
            </p>
          </div>
          {selected && <Detail step={selected} />}
        </div>
      )}
    </div>
  )
}
