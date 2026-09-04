import { useState, useEffect } from 'react'
import { PageFrame, tabOn, tabOff } from '../components/common/PageFrame'
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
  critical: 'bg-ink text-white',
  high: 'bg-nong text-white',
  medium: 'bg-hui text-white',
  info: 'bg-mist text-ink-faint',
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
    <PageFrame
      title="终端检测"
      subtitle="Sysmon · Windows Event Log · 跨源关联"
      extra={
        <div className="flex gap-2">
          {['all', 'sysmon', 'winevent'].map((s) => (
            <button key={s} onClick={() => setSourceFilter(s)} className={sourceFilter === s ? tabOn : tabOff}>
              {s === 'all' ? '全部' : s}
            </button>
          ))}
        </div>
      }
    >
      <div className="grid gap-0 border border-line">
        {filtered.map((e, i) => (
          <div key={e.id} className={`p-4 bg-white ${i < filtered.length - 1 ? 'border-b border-line' : ''}`}>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 ${sevColor[e.severity] || 'bg-mist'}`}>
                  {e.severity}
                </span>
                <span className="font-medium text-sm text-ink">
                  {e.event_name || `Event ${e.event_id}`}
                </span>
                <span className="px-1.5 py-0.5 border border-line text-[11px] text-ink-faint">
                  {e.source_type}
                </span>
              </div>
              {e.mitre_technique && (
                <span className="px-2 py-0.5 border border-ink text-[11px] font-medium">
                  {e.mitre_technique}
                </span>
              )}
            </div>
            <div className="text-[13px] text-ink-soft space-y-1 font-light">
              {e.computer_name && <div>主机: <span className="font-mono">{e.computer_name}</span></div>}
              {e.process_name && <div>进程: <span className="font-mono">{e.process_name}</span></div>}
              {e.command_line && (
                <div className="font-mono text-xs bg-mist px-3 py-2 mt-1 overflow-x-auto whitespace-nowrap">
                  {e.command_line.slice(0, 200)}
                </div>
              )}
              {e.src_ip && <div>网络: {e.src_ip} → {e.dst_ip}:{e.dst_port}</div>}
            </div>
            {e.security_flags && e.security_flags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {e.security_flags.map((f, idx) => (
                  <span key={idx} className="text-[11px] px-1.5 py-0.5 bg-mist text-ink">{f}</span>
                ))}
              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="py-20 text-center text-ink-faint">暂无 EDR 事件数据</div>
        )}
      </div>
    </PageFrame>
  )
}
