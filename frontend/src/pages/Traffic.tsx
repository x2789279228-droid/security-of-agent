import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

interface FlowRecord {
  id: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string
  bytes_in: number
  bytes_out: number
  direction: string
  flow_start: string
}

export default function Traffic() {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [stats, setStats] = useState<any>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    api.get('/ndr/flows?limit=100').then(setFlows).catch(() => {})
    api.get('/ndr/capture/stats').then(setStats).catch(() => {})
  }, [])

  const filtered = filter
    ? flows.filter((f) => f.src_ip.includes(filter) || f.dst_ip.includes(filter) || f.app_protocol.toLowerCase().includes(filter.toLowerCase()))
    : flows

  return (
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="flex items-end justify-between mb-10">
          <div>
            <h1 className="text-4xl font-semibold tracking-tight text-ink">流量采集</h1>
            <p className="text-[15px] text-ink-soft mt-2">网络流 · 协议分布 · 采集状态</p>
          </div>
          {stats && (
            <div className="flex gap-4 text-sm">
              <span className="px-3 py-1.5 rounded-full bg-[#34c759]/10 text-[#248a3d]">
                {stats.packets_captured?.toLocaleString() ?? 0} 包
              </span>
              <span className="px-3 py-1.5 rounded-full bg-[#0071e3]/10 text-[#0071e3]">
                {stats.active_flows ?? 0} 活跃流
              </span>
            </div>
          )}
        </div>

        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="搜索 IP / 协议…"
          className="w-full mb-6 px-4 py-2.5 rounded-xl border border-ink/10 bg-white/60 backdrop-blur text-sm focus:outline-none focus:ring-2 focus:ring-[#0071e3]/30"
        />

        <div className="overflow-x-auto rounded-2xl border border-ink/8 bg-white/70 backdrop-blur">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ink/8 text-left text-ink-soft">
                <th className="px-4 py-3 font-medium">源 IP</th>
                <th className="px-4 py-3 font-medium">目标 IP</th>
                <th className="px-4 py-3 font-medium">端口</th>
                <th className="px-4 py-3 font-medium">协议</th>
                <th className="px-4 py-3 font-medium">方向</th>
                <th className="px-4 py-3 font-medium text-right">流出</th>
                <th className="px-4 py-3 font-medium">时间</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} className="border-b border-ink/5 hover:bg-[#0071e3]/4 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-[13px]">{f.src_ip}</td>
                  <td className="px-4 py-2.5 font-mono text-[13px]">{f.dst_ip}</td>
                  <td className="px-4 py-2.5 font-mono text-[13px]">{f.dst_port}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-2 py-0.5 rounded-md bg-[#5e5ce6]/10 text-[#5e5ce6] text-xs font-medium">
                      {f.app_protocol || f.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-ink-soft">{f.direction}</td>
                  <td className="px-4 py-2.5 text-right font-mono text-[13px]">
                    {(f.bytes_out / 1024).toFixed(1)} KB
                  </td>
                  <td className="px-4 py-2.5 text-xs text-ink-faint">
                    {f.flow_start ? new Date(f.flow_start).toLocaleTimeString() : '-'}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-ink-faint">暂无流量数据</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </PageTransition>
  )
}
