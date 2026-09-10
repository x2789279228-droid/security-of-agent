import { useState, useEffect } from 'react'
import { PageFrame, tabOn, tabOff } from '../components/common/PageFrame'
import { api } from '../lib/api'

interface Ioc {
  id: number
  ioc_type: string
  ioc_value: string
  threat_type: string
  severity: string
  confidence: number
  source: string
  is_active: boolean
  created_at: string
}

const typeBadge: Record<string, string> = {
  ip: 'bg-[#0e1a26] text-[#f1e8d6]',
  domain: 'bg-[#c9a574] text-[#0e1a26]',
  file_hash: 'bg-[#7ba9b5] text-[#0e1a26]',
  url: 'border border-ink text-ink',
}

export default function Intel() {
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [feeds, setFeeds] = useState<any[]>([])
  const [tab, setTab] = useState<'iocs' | 'feeds'>('iocs')

  useEffect(() => {
    api.get('/intel/iocs?limit=100').then(setIocs).catch(() => {})
    api.get('/intel/feeds').then(setFeeds).catch(() => {})
  }, [])

  return (
    <PageFrame
      title="威胁情报"
      hint="IOC 管理 · 情报源 · 信誉查询。把外部情报变成系统已知。"
      marginalia="——情报的价值在「可用」，不在「很多」。"
    >
      <nav className="mb-8 flex gap-6 border-b border-line">
        {(['iocs', 'feeds'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={tab === t ? tabOn : tabOff}
          >
            {t === 'iocs' ? `IOC 指标 · ${iocs.length}` : `情报源 · ${feeds.length}`}
          </button>
        ))}
      </nav>

      {tab === 'iocs' ? (
        <div className="overflow-x-auto border border-line bg-paper">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left">
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  类型
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  指标
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  威胁
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  严重度
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  来源
                </th>
                <th className="px-4 py-3 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint font-normal">
                  状态
                </th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id} className="border-b border-line last:border-b-0 row-hover">
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 font-mono text-[11px] uppercase tracking-[0.16em] ${typeBadge[ioc.ioc_type] || 'border border-line text-ink-soft'}`}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="max-w-[300px] truncate px-4 py-2.5 font-mono text-[13px] text-ink">
                    {ioc.ioc_value}
                  </td>
                  <td className="px-4 py-2.5 text-[13px] text-ink-soft">{ioc.threat_type || '—'}</td>
                  <td className="px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.18em] text-ink">
                    {ioc.severity}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink-faint">
                    {ioc.source}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block h-1.5 w-1.5 ${ioc.is_active ? 'bg-[#c9a574]' : 'bg-ink-faint/40'}`}
                      aria-hidden
                    />
                  </td>
                </tr>
              ))}
              {iocs.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-20 text-center text-[13px] text-ink-faint">
                    暂无 IOC 数据
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-line bg-paper">
          {feeds.map((f, i) => (
            <div
              key={f.id}
              className={`flex items-center justify-between px-6 py-5 ${i < feeds.length - 1 ? 'border-b border-line' : ''}`}
            >
              <div>
                <p className="font-serif text-[18px] font-bold tracking-tight text-ink">
                  {f.name}
                </p>
                <p className="mt-1 font-mono text-[11px] text-ink-faint">
                  {f.feed_type} · {f.url}
                </p>
              </div>
              <div className="text-right">
                <span
                  className={`inline-flex items-center gap-2 border px-2.5 py-1 font-mono text-[10px] tracking-[0.22em] uppercase ${
                    f.enabled
                      ? 'border-ok text-ok'
                      : 'border-line text-ink-faint'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 ${f.enabled ? 'bg-ok' : 'bg-ink-faint/40'}`}
                    aria-hidden
                  />
                  {f.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
                <p className="mt-1.5 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                  {f.last_poll_status === 'success'
                    ? `上次 · ${f.last_poll_count} 条`
                    : f.last_poll_status}
                </p>
              </div>
            </div>
          ))}
          {feeds.length === 0 && (
            <div className="px-6 py-20 text-center text-[13px] text-ink-faint">
              暂未配置情报源
            </div>
          )}
        </div>
      )}
    </PageFrame>
  )
}