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
  process_id?: number
  image_hash?: string
  file_path?: string
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
  critical: 'border-[#b03a30] bg-[#b03a30] text-paper',
  high: 'border-[#b88940] bg-[#b88940] text-paper',
  medium: 'border-[#7ba9b5] bg-[#7ba9b5] text-[#0e1a26]',
  info: 'border-line text-ink-faint',
}

export default function EDR() {
  const [events, setEvents] = useState<EdrEvent[]>([])
  const [sourceFilter, setSourceFilter] = useState('all')
  const [actionMsg, setActionMsg] = useState('')

  const runContainment = async (action: string, params: Record<string, unknown>) => {
    setActionMsg('')
    try {
      const data = await api.executeResponse(action, params, 'edr-event')
      setActionMsg(`${action} · ${data.success ? '已提交' : '失败'}`)
    } catch (e: any) {
      setActionMsg(e.message || String(e))
    }
  }

  useEffect(() => {
    api.get('/edr/events?limit=100').then(setEvents).catch(() => {})
  }, [])

  const filtered =
    sourceFilter === 'all'
      ? events
      : events.filter((e) => e.source_type === sourceFilter)

  return (
    <PageFrame
      title="终端检测"
      hint="Sysmon · Windows Event Log · 跨源关联。在主机里看见行为。"
      marginalia="——再聪明的攻击，在主机上也要落地。"
      extra={
        <nav className="flex gap-5 border-b border-line">
          {['all', 'sysmon', 'winevent'].map((s) => (
            <button
              key={s}
              onClick={() => setSourceFilter(s)}
              className={sourceFilter === s ? tabOn : tabOff}
            >
              {s === 'all' ? '全部' : s}
            </button>
          ))}
        </nav>
      }
    >
      <div className="border border-line bg-paper">
        {filtered.map((e, i) => (
          <article
            key={e.id}
            className={`grid grid-cols-1 gap-6 px-7 py-6 md:grid-cols-[1fr_180px] ${
              i < filtered.length - 1 ? 'border-b border-line' : ''
            }`}
          >
            <div>
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`border px-2 py-0.5 font-mono text-[10px] tracking-[0.22em] uppercase ${sevColor[e.severity] || sevColor.info}`}
                >
                  {e.severity}
                </span>
                <span className="font-serif text-[18px] font-bold tracking-tight text-ink">
                  {e.event_name || `Event ${e.event_id}`}
                </span>
                <span className="border border-line px-2 py-0.5 font-mono text-[11px] text-ink-faint">
                  {e.source_type}
                </span>
                {e.mitre_technique && (
                  <span className="border border-ink px-2 py-0.5 font-mono text-[11px] font-bold text-ink">
                    {e.mitre_technique}
                  </span>
                )}
              </div>

              <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1.5 text-[13px] text-ink-soft sm:grid-cols-2">
                {e.computer_name && (
                  <div className="flex gap-2">
                    <dt className="font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint w-12">主机</dt>
                    <dd className="font-mono text-ink">{e.computer_name}</dd>
                  </div>
                )}
                {e.process_name && (
                  <div className="flex gap-2">
                    <dt className="font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint w-12">进程</dt>
                    <dd className="font-mono text-ink">{e.process_name}</dd>
                  </div>
                )}
                {e.src_ip && (
                  <div className="flex gap-2">
                    <dt className="font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint w-12">网络</dt>
                    <dd className="font-mono text-ink">
                      {e.src_ip} → {e.dst_ip}:{e.dst_port}
                    </dd>
                  </div>
                )}
                {e.user_name && (
                  <div className="flex gap-2">
                    <dt className="font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint w-12">用户</dt>
                    <dd className="font-mono text-ink">{e.user_name}</dd>
                  </div>
                )}
              </dl>

              {e.command_line && (
                <pre className="mt-3 overflow-x-auto whitespace-pre border border-line bg-mist px-4 py-2.5 font-mono text-[12px] text-ink">
                  {e.command_line.slice(0, 200)}
                </pre>
              )}

              {e.security_flags && e.security_flags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {e.security_flags.map((f, idx) => (
                    <span
                      key={idx}
                      className="border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink"
                    >
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex flex-col items-start gap-2 md:items-end">
              {(e.process_id || e.image_hash) && (
                <button
                  onClick={() =>
                    runContainment('kill_process', {
                      pid: e.process_id,
                      sha256: e.image_hash,
                      host_ip: e.src_ip,
                      name: e.process_name,
                    })
                  }
                  className="border border-ink px-3 py-1.5 font-mono text-[11px] tracking-[0.18em] uppercase text-ink hover:bg-[#0e1a26] hover:text-[#f1e8d6] transition-colors"
                >
                  终止进程
                </button>
              )}
              {e.file_path && (
                <button
                  onClick={() =>
                    runContainment('quarantine_file', {
                      path: e.file_path,
                      sha256: e.image_hash,
                      host_ip: e.src_ip,
                    })
                  }
                  className="border border-[#b03a30] px-3 py-1.5 font-mono text-[11px] tracking-[0.18em] uppercase text-[#b03a30] hover:bg-[#b03a30] hover:text-paper transition-colors"
                >
                  隔离文件
                </button>
              )}
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                {new Date(e.created_at).toLocaleString('zh-CN', {
                  month: '2-digit',
                  day: '2-digit',
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </span>
            </div>
          </article>
        ))}
        {actionMsg && (
          <div className="border-t border-line px-6 py-3 font-mono text-[11px] tracking-[0.18em] uppercase text-ink-soft">
            {actionMsg}
          </div>
        )}
        {filtered.length === 0 && (
          <div className="px-6 py-20 text-center text-[13px] text-ink-faint">
            暂无 EDR 事件数据
          </div>
        )}
      </div>
    </PageFrame>
  )
}