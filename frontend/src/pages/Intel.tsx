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
  ip: 'bg-ink text-white',
  domain: 'bg-nong text-white',
  file_hash: 'bg-hui text-white',
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
    <PageFrame title="威胁情报" subtitle="IOC 管理 · 情报源 · 信誉查询">
      <div className="flex gap-2 mb-8">
        {(['iocs', 'feeds'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={tab === t ? tabOn : tabOff}>
            {t === 'iocs' ? `IOC 指标 (${iocs.length})` : `情报源 (${feeds.length})`}
          </button>
        ))}
      </div>

      {tab === 'iocs' ? (
        <div className="overflow-x-auto border border-line bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-ink-faint">
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
                <tr key={ioc.id} className="border-b border-line hover:bg-mist">
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 text-xs font-medium ${typeBadge[ioc.ioc_type] || 'bg-mist'}`}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[13px] max-w-[300px] truncate">{ioc.ioc_value}</td>
                  <td className="px-4 py-2.5 text-ink-soft">{ioc.threat_type || '-'}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs font-medium">{ioc.severity}</span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-ink-faint">{ioc.source}</td>
                  <td className="px-4 py-2.5">
                    <span className={`w-2 h-2 inline-block ${ioc.is_active ? 'bg-ink' : 'bg-dan'}`} />
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
        <div className="grid gap-0 border border-line">
          {feeds.map((f, i) => (
            <div key={f.id} className={`p-5 bg-white flex items-center justify-between ${i < feeds.length - 1 ? 'border-b border-line' : ''}`}>
              <div>
                <div className="font-medium text-ink">{f.name}</div>
                <div className="text-xs text-ink-faint mt-1">{f.feed_type} · {f.url}</div>
              </div>
              <div className="text-right">
                <span className={`px-2.5 py-1 text-xs font-medium ${f.enabled ? 'bg-ink text-white' : 'bg-mist text-ink-faint'}`}>
                  {f.enabled ? '启用' : '停用'}
                </span>
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
    </PageFrame>
  )
}
