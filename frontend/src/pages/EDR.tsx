import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

interface EdrEvent {
  id: number
  source_type: string
  event_id: number
  event_name: string
  computer_name: string
  user_name: string
  process_name: string
  command_line: string
  src_ip: string
  dst_ip: string
  dst_port: number
  severity: string
  mitre_technique: string
  security_flags: string[]
  created_at: string
}

const sevColor: Record<string, string> = {
  critical: 'text-[#ff3b30]',
  high: 'text-[#ff9f0a]',
  medium: 'text-[#0071e3]',
  info: 'text-ink-soft',
}

export default function EDR() {
  const [events, setEvents] = useState<EdrEvent[]>([])
  const [sourceFilter, setSourceFilter] = useState('all')

  useEffect(() => {
    api.get('/edr/events?limit=100').then(setEvents).catch(() => {})
  }, [])

  const filtered = sourceFilter === 'all'
    ? events
    : events.filter((e) => e.source_type === sourceFilter)

  return (
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="flex items-end justify-between mb-10">
          <div>
            <h1 className="text-4xl font-semibold tracking-tight text-ink">终端检测</h1>
            <p className="text-[15px] text-ink-soft mt-2">Sysmon · Windows Event Log · 跨源关联</p>
          </div>
          <div className="flex gap-2">
            {['all', 'sysmon', 'winevent'].map((s) => (
              <button
                key={s}
                onClick={() => setSourceFilter(s)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  sourceFilter === s ? 'bg-[#0071e3] text-white' : 'bg-ink/5 text-ink-soft hover:bg-ink/10'
                }`}
              >
                {s === 'all' ? '全部' : s}
              </button>
            ))}
          </div>
        </div>

        <div className="grid gap-3">
          {filtered.map((e) => (
            <div key={e.id} className="p-4 rounded-xl border border-ink/8 bg-white/70 backdrop-blur">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-semibold uppercase ${sevColor[e.severity] || 'text-ink-soft'}`}>
                    {e.severity}
                  </span>
                  <span className="font-medium text-sm text-ink">
                    {e.event_name || `Event ${e.event_id}`}
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-ink/5 text-[11px] text-ink-faint">
                    {e.source_type}
                  </span>
                </div>
                {e.mitre_technique && (
                  <span className="px-2 py-0.5 rounded-md bg-[#af52de]/8 text-[#af52de] text-[11px] font-medium">
                    {e.mitre_technique}
                  </span>
                )}
              </div>

              <div className="text-[13px] text-ink-soft space-y-1">
                {e.computer_name && <div>主机: <span className="font-mono">{e.computer_name}</span></div>}
                {e.process_name && <div>进程: <span className="font-mono">{e.process_name}</span></div>}
                {e.command_line && (
                  <div className="font-mono text-xs bg-ink/3 rounded-lg px-3 py-2 mt-1 overflow-x-auto whitespace-nowrap">
                    {e.command_line.slice(0, 200)}
                  </div>
                )}
                {e.src_ip && <div>网络: {e.src_ip} → {e.dst_ip}:{e.dst_port}</div>}
              </div>

              {e.security_flags && e.security_flags.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {e.security_flags.map((f, i) => (
                    <span key={i} className="text-[11px] px-1.5 py-0.5 rounded bg-[#ff3b30]/6 text-[#ff3b30]/80">
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="py-20 text-center text-ink-faint">暂无 EDR 事件数据</div>
          )}
        </div>
      </div>
    </PageTransition>
  )
}
