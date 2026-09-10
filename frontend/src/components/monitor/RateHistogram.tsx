/**
 * 速率直方图 — 最近 60 秒事件到达量（12 × 5 秒分桶），recharts BarChart
 * 暮青柱 + 纸面 tooltip；最新一桶命中时提亮。
 */
import { useEffect, useState } from 'react'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { BRAND_COLORS } from '../../lib/brand'
import { getArrivalTimes } from '../../lib/eventStream'

const BUCKETS = 12
const BUCKET_MS = 5_000

type TipPayload = { payload?: { count?: number; from?: number; to?: number } }

function PaperTooltip({ active, payload }: { active?: boolean; payload?: TipPayload[] }) {
  if (!active || !payload?.length) return null
  const d = payload[0]?.payload
  if (!d) return null
  return (
    <div className="rounded-lg border border-line bg-card px-2.5 py-1.5 font-mono text-[11px] text-ink shadow-[0_8px_24px_rgba(28,40,56,0.14)]">
      <span className="text-accent tabular-nums">{d.count ?? 0}</span> 条
      <span className="ml-1.5 text-ink-faint tabular-nums">
        {d.from}s ~ {d.to}s
      </span>
    </div>
  )
}

export default function RateHistogram() {
  const [bars, setBars] = useState<number[]>(() => new Array(BUCKETS).fill(0))
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const sample = () => {
      const t = Date.now()
      const counts = new Array(BUCKETS).fill(0)
      for (const ts of getArrivalTimes()) {
        const age = t - ts
        if (age < 0 || age >= BUCKETS * BUCKET_MS) continue
        const idx = BUCKETS - 1 - Math.floor(age / BUCKET_MS) // 最右为最新
        counts[idx] += 1
      }
      setBars(counts)
      setNow(t)
    }
    sample()
    const timer = setInterval(sample, 1000)
    return () => clearInterval(timer)
  }, [])

  const max = Math.max(1, ...bars)
  const last30 = bars.slice(BUCKETS / 2).reduce((a, b) => a + b, 0)
  const data = bars.map((count, i) => {
    const from = -(BUCKETS - i) * BUCKET_MS / 1000
    return { i, count, from, to: from + BUCKET_MS / 1000 }
  })

  return (
    <div className="shrink-0 md:w-52">
      <div className="mb-1.5 flex items-baseline justify-between">
        <span className="text-[11px] tracking-wide text-ink-faint">到达速率 · 60s</span>
        <span className="font-mono text-[12px] font-semibold text-accent tabular-nums">{last30}/30s</span>
      </div>
      <div
        className="h-10"
        title={`最近30秒 ${last30} 条（截至 ${new Date(now).toLocaleTimeString('zh-CN', { hour12: false })}）`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }} barCategoryGap="12%">
            <Bar dataKey="count" radius={[2, 2, 0, 0]} isAnimationActive={false}>
              {data.map((d) => (
                <Cell
                  key={d.i}
                  fill={
                    d.i === BUCKETS - 1 && d.count > 0
                      ? BRAND_COLORS.accent
                      : d.count > 0
                        ? 'rgba(58,101,112,0.45)'
                        : 'rgba(58,101,112,0.18)'
                  }
                />
              ))}
            </Bar>
            <Tooltip
              cursor={{ fill: 'rgba(58,101,112,0.08)' }}
              content={<PaperTooltip />}
              wrapperStyle={{ zIndex: 30, outline: 'none' }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-ink-faint">
        <span>-60s</span>
        <span>现在</span>
      </div>
      <p className="sr-only">最大桶 {max} 条</p>
    </div>
  )
}
