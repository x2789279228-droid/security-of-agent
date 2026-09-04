import { useState, useEffect } from 'react'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'

interface Capability {
  name: string
  enabled: boolean
  count: number
}

const CAP_META: Record<string, { label: string; desc: string }> = {
  ndr: { label: 'NDR 流量分析', desc: '网络流 / JA3 / TLS' },
  edr: { label: 'EDR 融合', desc: 'Sysmon / Windows 事件' },
  threat_intel: { label: '威胁情报', desc: 'IOC / MISP / TAXII' },
  zeroday: { label: '0day 检测', desc: '沙箱行为分析' },
  phishing: { label: '反钓鱼', desc: '7 类检测器' },
}

export default function CapabilitiesDashboard() {
  const [caps, setCaps] = useState<Capability[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/capabilities/status').then((r: any) => setCaps(r?.capabilities ?? [])).catch(() => {}).finally(() => setLoading(false))
  }, [])

  return (
    <PageFrame title="高级能力总览" subtitle="NDR · EDR · 威胁情报 · 0day · 反钓鱼 状态与指标">
      {loading ? (
        <p className="text-sm text-ink-faint">加载中…</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 border border-line">
          {caps.map((c, i) => {
            const meta = CAP_META[c.name] ?? { label: c.name, desc: '' }
            return (
              <div
                key={c.name}
                className={`p-6 bg-white ${i % 3 !== 2 ? 'lg:border-r border-line' : ''} ${i < caps.length - (caps.length % 3 || 3) ? 'border-b border-line' : ''}`}
              >
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="font-bold text-ink">{meta.label}</div>
                    <div className="text-xs font-light text-ink-faint mt-0.5">{meta.desc}</div>
                  </div>
                  <span className={`px-2.5 py-1 text-xs ${c.enabled ? 'bg-ink text-white' : 'bg-mist text-ink-faint'}`}>
                    {c.enabled ? '已启用' : '未启用'}
                  </span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-black text-ink">{c.count.toLocaleString()}</span>
                  <span className="text-xs text-ink-faint">事件计数</span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {!loading && caps.length === 0 && (
        <p className="text-sm text-ink-faint">暂无能力状态数据（调用 /api/capabilities/status）。</p>
      )}
    </PageFrame>
  )
}
