import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

interface Capability {
  name: string
  enabled: boolean
  count: number
}

const CAP_META: Record<string, { label: string; desc: string; icon: string }> = {
  ndr: { label: 'NDR 流量分析', desc: '网络流 / JA3 / TLS', icon: '📡' },
  edr: { label: 'EDR 融合', desc: 'Sysmon / Windows 事件', icon: '🖥️' },
  threat_intel: { label: '威胁情报', desc: 'IOC / MISP / TAXII', icon: '🕵️' },
  zeroday: { label: '0day 检测', desc: '沙箱行为分析', icon: '🧬' },
  phishing: { label: '反钓鱼', desc: '7 类检测器', icon: '🎣' },
}

export default function CapabilitiesDashboard() {
  const [caps, setCaps] = useState<Capability[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/capabilities/status').then((r: any) => setCaps(r?.capabilities ?? [])).catch(() => {}).finally(() => setLoading(false))
  }, [])

  return (
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="mb-10">
          <h1 className="text-4xl font-semibold tracking-tight text-ink">高级能力总览</h1>
          <p className="text-[15px] text-ink-soft mt-2">NDR · EDR · 威胁情报 · 0day · 反钓鱼 状态与指标</p>
        </div>

        {loading ? (
          <p className="text-sm text-ink-soft">加载中…</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {caps.map((c) => {
              const meta = CAP_META[c.name] ?? { label: c.name, desc: '', icon: '▪️' }
              return (
                <div key={c.name} className="rounded-2xl border border-black/5 bg-white p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{meta.icon}</span>
                      <div>
                        <div className="font-semibold text-ink">{meta.label}</div>
                        <div className="text-xs text-ink-soft">{meta.desc}</div>
                      </div>
                    </div>
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${c.enabled ? 'bg-[#34c759]/10 text-[#248a3d]' : 'bg-[#8e8e93]/15 text-[#6e6e73]'}`}>
                      {c.enabled ? '已启用' : '未启用'}
                    </span>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-semibold text-ink">{c.count.toLocaleString()}</span>
                    <span className="text-xs text-ink-soft">事件计数</span>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {!loading && caps.length === 0 && (
          <p className="text-sm text-ink-soft">暂无能力状态数据（调用 /api/capabilities/status）。</p>
        )}
      </div>
    </PageTransition>
  )
}
