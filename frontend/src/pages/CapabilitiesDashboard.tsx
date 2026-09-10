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

  const enabledCount = caps.filter((c) => c.enabled).length
  const totalCount = caps.reduce((s, c) => s + c.count, 0)

  return (
    <PageFrame
      title="高级能力总览"
      hint="NDR · EDR · 威胁情报 · 0day · 反钓鱼 状态与指标。"
      marginalia="——能力是资产，但只有运行起来才是。"
    >
      {/* 顶部摘要 */}
      <div className="mb-10 grid grid-cols-2 gap-px border border-line bg-line md:grid-cols-4">
        <StatCell label="已启用" value={enabledCount} hint={`/ ${caps.length} 总能力`} />
        <StatCell label="未启用" value={caps.length - enabledCount} hint="尚在灰度中" />
        <StatCell label="事件累计" value={totalCount} hint="LIFETIME" />
        <StatCell label="运行状态" value={enabledCount === caps.length ? 'OK' : 'PARTIAL'} hint={enabledCount === caps.length ? '全功能' : '部分能力'} />
      </div>

      {loading ? (
        <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">加载中 …</p>
      ) : (
        <div className="grid grid-cols-1 border-t border-line md:grid-cols-2 lg:grid-cols-3">
          {caps.map((c, i) => {
            const meta = CAP_META[c.name] ?? { label: c.name, desc: '' }
            const enabled = c.enabled
            return (
              <div
                key={c.name}
                className={`group relative p-7 bg-paper transition-colors hover:bg-mist ${
                  i % 3 !== 2 ? 'lg:border-r border-line' : ''
                } ${i < caps.length - (caps.length % 3 || 3) ? 'border-b border-line' : ''}`}
              >
                {/* 顶部编号 + 启用态 */}
                <div className="flex items-center justify-between border-b border-ink/80 pb-3">
                  <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint tabular-nums">
                    CAP · {String(i + 1).padStart(2, '0')}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1.5 font-mono text-[10px] tracking-[0.22em] uppercase ${
                      enabled ? 'text-ok' : 'text-ink-faint'
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 ${enabled ? 'bg-ok' : 'bg-ink-faint/40'}`}
                      aria-hidden
                    />
                    {enabled ? 'ENABLED' : 'DISABLED'}
                  </span>
                </div>

                <div className="mt-5">
                  <div className="font-serif text-[22px] font-black tracking-[-0.02em] text-ink">
                    {meta.label}
                  </div>
                  <div className="mt-1 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                    {meta.desc}
                  </div>
                </div>

                <div className="mt-6 flex items-baseline gap-3 border-t border-line pt-4">
                  <span className="font-serif text-[36px] font-black tabular-nums text-ink leading-none">
                    {c.count.toLocaleString()}
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                    Events · 累计
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {!loading && caps.length === 0 && (
        <p className="border-t border-line py-12 text-[13px] text-ink-faint">
          暂无能力状态数据（调用 <span className="font-mono">/api/capabilities/status</span>）。
        </p>
      )}
    </PageFrame>
  )
}

function StatCell({
  label,
  value,
  hint,
}: {
  label: string
  value: number | string
  hint?: string
}) {
  return (
    <div className="bg-paper px-6 py-5">
      <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
        {label}
      </p>
      <p className="mt-2 font-serif text-[32px] font-black tabular-nums leading-none text-ink">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-2 text-[11px] text-ink-faint">{hint}</p>}
    </div>
  )
}