import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
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
  ip: 'bg-[#0071e3]/10 text-[#0071e3]',
  domain: 'bg-[#5e5ce6]/10 text-[#5e5ce6]',
  file_hash: 'bg-[#af52de]/10 text-[#af52de]',
  url: 'bg-[#ff9f0a]/12 text-[#c77700]',
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
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="mb-10">
          <h1 className="text-4xl font-semibold tracking-tight text-ink">威胁情报</h1>
          <p className="text-[15px] text-ink-soft mt-2">IOC 管理 · 情报源 · 信誉查询</p>
        </div>

        <div className="flex gap-2 mb-8">
          {(['iocs', 'feeds'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 rounded-full text-sm font-medium transition-colors ${
                tab === t ? 'bg-[#0071e3] text-white' : 'bg-ink/5 text-ink-soft hover:bg-ink/10'
              }`}
            >
              {t === 'iocs' ? `IOC 指标 (${iocs.length})` : `情报源 (${feeds.length})`}
            </button>
          ))}
        </div>

        {tab === 'iocs' ? (
          <div className="overflow-x-auto rounded-2xl border border-ink/8 bg-white/70 backdrop-blur">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink/8 text-left text-ink-soft">
                  <th className="px-4 py-3 font-medium">类型</th>
                  <th className="px-4 py-3 font-medium">值</th>
                  <th className="px-4 py-3 font-medium">威胁类型</th>
                  <th className="px-4 py-3 font-medium">严重度</th>
                  <th className="px-4 py-3 font-medium">来源</th>
                  <th className="px-4 py-3 font-medium">状态</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="border-b border-ink/5 hover:bg-[#0071e3]/4">
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${typeBadge[ioc.ioc_type] || 'bg-ink/5'}`}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[13px] max-w-[300px] truncate">{ioc.ioc_value}</td>
                    <td className="px-4 py-2.5 text-ink-soft">{ioc.threat_type || '-'}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs font-medium ${
                        ioc.severity === 'critical' ? 'text-[#ff3b30]' :
                        ioc.severity === 'high' ? 'text-[#ff9f0a]' : 'text-ink-soft'
                      }`}>{ioc.severity}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-ink-faint">{ioc.source}</td>
                    <td className="px-4 py-2.5">
                      <span className={`w-2 h-2 rounded-full inline-block ${ioc.is_active ? 'bg-[#34c759]' : 'bg-ink/20'}`} />
                    </td>
                  </tr>
                ))}
                {iocs.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-12 text-center text-ink-faint">暂无 IOC 数据</td></tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="grid gap-4">
            {feeds.map((f) => (
              <div key={f.id} className="p-5 rounded-2xl border border-ink/8 bg-white/70 backdrop-blur flex items-center justify-between">
                <div>
                  <div className="font-medium text-ink">{f.name}</div>
                  <div className="text-xs text-ink-faint mt-1">{f.feed_type} · {f.url}</div>
                </div>
                <div className="text-right">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${
                    f.enabled ? 'bg-[#34c759]/10 text-[#248a3d]' : 'bg-ink/5 text-ink-faint'
                  }`}>{f.enabled ? '启用' : '停用'}</span>
                  <div className="text-xs text-ink-faint mt-1">
                    {f.last_poll_status === 'success' ? `上次: ${f.last_poll_count} 条` : f.last_poll_status}
                  </div>
                </div>
              </div>
            ))}
            {feeds.length === 0 && (
              <div className="py-20 text-center text-ink-faint">暂未配置情报源</div>
            )}
          </div>
        )}
      </div>
    </PageTransition>
  )
}
