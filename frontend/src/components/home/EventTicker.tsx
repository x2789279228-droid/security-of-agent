import { useMemo } from 'react'

/**
 * EventTicker · 案卷遥测文字流
 *
 * 替代 ThreatNetwork 的「文字版」实时带：
 * - 单行 telemetry 滚动，删除号 + 时间戳 + 事件类型 + 来源 IP
 * - 自身节奏独立，不与 Hero 控制台抢镜
 */

type LogLike = {
  id?: number | string
  severity?: string
  event_type?: string
  src_ip?: string
  dst_ip?: string
  message?: string
  created_at?: string
}

const SEV_COLOR: Record<string, string> = {
  critical: 'text-[#d0665b]',
  high: 'text-[#c08a3a]',
  medium: 'text-[#7ba9b5]',
  low: 'text-[rgba(28,40,56,0.45)]',
  info: 'text-[rgba(28,40,56,0.45)]',
}

function fmtClock(iso?: string) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString('zh-CN', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return ''
  }
}

export function EventTicker({
  events,
  attackCount,
}: {
  events: LogLike[]
  attackCount: number
}) {
  const rows = useMemo(() => {
    const items = events.slice(0, 24).map((e, i) => ({
      key: `e-${e.id ?? i}`,
      ts: fmtClock(e.created_at),
      sev: (e.severity || 'info').toLowerCase(),
      type: e.event_type || 'log',
      ip: e.src_ip || '—',
      dst: e.dst_ip || '',
      msg: (e.message || '').slice(0, 60),
    }))
    if (attackCount > 0) {
      items.unshift({
        key: 'pulse',
        ts: '·  ·  ·',
        sev: 'critical',
        type: 'pulse',
        ip: `${attackCount}`,
        dst: '',
        msg: 'ATTACK PULSE 攻击脉冲累计',
      })
    }
    return items
  }, [events, attackCount])

  if (rows.length === 0) return null

  // 复制一份用于无缝循环
  const doubled = [...rows, ...rows]

  return (
    <div className="relative border-y border-line bg-[#e3eae6] overflow-hidden">
      {/* 左右羽化 */}
      <div className="pointer-events-none absolute inset-y-0 left-0 w-24 z-10 bg-gradient-to-r from-[#e3eae6] to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-24 z-10 bg-gradient-to-l from-[#e3eae6] to-transparent" />

      <div className="ticker-track py-3">
        {doubled.map((r, i) => (
          <span key={`${r.key}-${i}`} className="ticker-row">
            <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
              {r.ts}
            </span>
            <span
              className={`font-mono text-[10px] tracking-[0.22em] uppercase ${SEV_COLOR[r.sev] || SEV_COLOR.info}`}
            >
              {r.sev}
            </span>
            <span className="font-mono text-ink">{r.type}</span>
            <span className="font-mono text-ink-faint">
              {r.ip}
              {r.dst ? ` → ${r.dst}` : ''}
            </span>
            <span className="text-ink-soft truncate max-w-[18rem]">{r.msg}</span>
            <span className="text-ink-faint/60 select-none">／</span>
          </span>
        ))}
      </div>
    </div>
  )
}