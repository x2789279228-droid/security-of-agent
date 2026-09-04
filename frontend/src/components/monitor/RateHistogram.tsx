/**
 * 速率直方图 — 最近 60 秒事件到达量（12 × 5 秒分桶），手绘 div 实现，无图表库依赖
 */
import { useEffect, useState } from 'react'
import { getArrivalTimes } from '../../lib/eventStream'

const BUCKETS = 12
const BUCKET_MS = 5_000

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

  return (
    <div className="shrink-0 md:w-52">
      <div className="mb-1.5 flex items-baseline justify-between">
        <span className="text-[11px] tracking-wide text-ink-faint">到达速率 · 60s</span>
        <span className="font-mono text-[12px] font-semibold text-ink tabular-nums">{last30}/30s</span>
      </div>
      <div className="flex h-10 items-end gap-[3px]" title={`最近30秒 ${last30} 条（截至 ${new Date(now).toLocaleTimeString('zh-CN', { hour12: false })}）`}>
        {bars.map((v, i) => (
          <div key={i} className="flex h-full flex-1 flex-col justify-end">
            <div
              className={`${i === BUCKETS - 1 && v > 0 ? 'bg-ink' : v > 0 ? 'bg-dan' : 'bg-mist'} w-full`}
              style={{ height: `${Math.max(v > 0 ? 14 : 4, (v / max) * 100)}%` }}
              title={`${-((BUCKETS - 1 - i) * BUCKET_MS)}s ~ ${-(BUCKETS - 1 - i) * BUCKET_MS + BUCKET_MS}s：${v} 条`}
            />
          </div>
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-ink-faint">
        <span>-60s</span>
        <span>现在</span>
      </div>
    </div>
  )
}
