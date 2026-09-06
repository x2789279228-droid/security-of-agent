import { useLayoutEffect, useRef, useState } from 'react'
import {
  COLUMN_LABELS,
  THOUGHT_COLUMNS,
  edgeWeight,
  groupByColumn,
  type ThoughtEdge,
  type ThoughtStep,
} from '../../lib/thoughtChain'
import ThoughtNode from './ThoughtNode'

type Pt = { x: number; y: number }

export default function ThoughtDag({
  nodes,
  edges = [],
  selectedId,
  pathIds,
  onSelect,
}: {
  nodes: ThoughtStep[]
  edges?: ThoughtEdge[]
  selectedId?: string
  pathIds?: Set<string>
  onSelect?: (step: ThoughtStep) => void
}) {
  const grouped = groupByColumn(nodes)
  const wrapRef = useRef<HTMLDivElement>(null)
  const [pts, setPts] = useState<Record<string, Pt>>({})
  const [box, setBox] = useState({ w: 0, h: 0 })

  useLayoutEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const measure = () => {
      const root = el.getBoundingClientRect()
      const next: Record<string, Pt> = {}
      el.querySelectorAll<HTMLElement>('[data-step-id]').forEach((node) => {
        const id = node.getAttribute('data-step-id')
        if (!id) return
        const r = node.getBoundingClientRect()
        next[id] = {
          x: r.left - root.left + r.width / 2,
          y: r.top - root.top + r.height / 2,
        }
      })
      setPts(next)
      setBox({ w: el.scrollWidth, h: el.scrollHeight })
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [nodes, selectedId])

  const byId = new Map(nodes.map((n) => [n.step_id, n]))
  const drawable = edges.filter((e) => pts[e.from] && pts[e.to])

  return (
    <div ref={wrapRef} className="relative overflow-x-auto px-3 py-3">
      {box.w > 0 && (
        <svg
          className="pointer-events-none absolute left-0 top-0"
          width={box.w}
          height={box.h}
          aria-hidden
        >
          {drawable.map((e) => {
            const a = pts[e.from]
            const b = pts[e.to]
            const onPath =
              !pathIds || pathIds.size === 0
                ? false
                : pathIds.has(e.from) && pathIds.has(e.to)
            const w = edgeWeight(e, byId)
            const stroke =
              e.rel === 'vetoed' ? '#8a5a44' : e.rel === 'retrieved' || e.rel === 'evidences' ? '#7a7a72' : '#1a1a18'
            return (
              <line
                key={`${e.from}-${e.to}-${e.rel}`}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={stroke}
                strokeWidth={onPath ? 1.8 : 0.7 + w}
                strokeOpacity={onPath ? 0.9 : selectedId ? 0.18 : 0.35}
                strokeDasharray={e.rel === 'vetoed' ? '4 3' : e.rel === 'evidences' ? '2 3' : undefined}
              />
            )
          })}
        </svg>
      )}
      <div className="relative z-[1] grid min-w-[720px] grid-cols-7 gap-2">
        {THOUGHT_COLUMNS.map((col) => {
          const colNodes = grouped[col] ?? []
          return (
            <div key={col} className="min-w-0">
              <p className="mb-1.5 truncate text-center text-[10px] tracking-wide text-ink-faint">
                {COLUMN_LABELS[col] ?? col}
                {colNodes.length > 0 && (
                  <span className="ml-1 font-mono tabular-nums">{colNodes.length}</span>
                )}
              </p>
              <div className="flex flex-col gap-1.5">
                {colNodes.length === 0 ? (
                  <div className="h-8 border border-dashed border-line" />
                ) : (
                  colNodes.map((n) => (
                    <div key={n.step_id} data-step-id={n.step_id}>
                      <ThoughtNode
                        step={n}
                        selected={selectedId === n.step_id}
                        dimmed={!!pathIds && pathIds.size > 0 && !pathIds.has(n.step_id)}
                        onSelect={onSelect}
                      />
                    </div>
                  ))
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
