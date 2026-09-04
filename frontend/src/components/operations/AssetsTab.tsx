import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { GradientNumber, EmptyState } from './badges'

interface Asset {
  id: number
  asset_key: string
  asset_type: string
  ip: string
  hostname: string
  os: string
  business_owner: string
  business_unit: string
  criticality: string
  exposure: string
  tags: string[]
  source: string
  weight: number
  is_active: boolean
  last_seen: string
  updated_at: string
}

interface DiscoveryTask {
  id: number
  task_id: string
  scope: string
  scanner: string
  status: string
  new_count: number
  changed_count: number
  created_at: string
  completed_at: string
}

const CRITICALITY_META: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: '#FF375F', bg: 'rgba(255,55,95,0.10)', label: '核心' },
  high: { color: '#FF9F0A', bg: 'rgba(255,159,10,0.12)', label: '重要' },
  medium: { color: '#0A84FF', bg: 'rgba(10,132,255,0.10)', label: '一般' },
  low: { color: '#86868b', bg: 'rgba(134,134,139,0.10)', label: '低' },
}

export function AssetsTab() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [tasks, setTasks] = useState<DiscoveryTask[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  // 表单
  const [ip, setIp] = useState('')
  const [hostname, setHostname] = useState('')
  const [level, setLevel] = useState('medium')
  const [business, setBusiness] = useState('')
  const [assetType, setAssetType] = useState('host')
  const [submitting, setSubmitting] = useState(false)
  const [msg, setMsg] = useState('')

  // 资产发现
  const [scope, setScope] = useState('all')
  const [scanner, setScanner] = useState('edr')
  const [discovering, setDiscovering] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [a, t] = await Promise.all([
        api.opsAssets().catch(() => ({ assets: [], levels: {} })),
        api.opsAssetDiscoveryTasks(20).catch(() => ({ tasks: [] })),
      ])
      setAssets(Array.isArray((a as any).assets) ? (a as any).assets : [])
      setTasks(Array.isArray((t as any).tasks) ? (t as any).tasks : [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const submit = async () => {
    if (!ip && !hostname) { setMsg('请填写 IP 或 Hostname 之一'); return }
    setSubmitting(true); setMsg('')
    try {
      const r = await api.opsAssetRegister({
        ip, hostname, level, business, asset_type: assetType,
      })
      if (r.success) {
        setMsg('资产已保存')
        setIp(''); setHostname(''); setBusiness('')
        await load()
      } else {
        setMsg(r.error ?? '保存失败')
      }
    } catch (e: any) { setMsg(e.message) }
    finally { setSubmitting(false) }
  }

  const remove = async (assetId: number) => {
    if (!confirm('确定下线该资产？')) return
    try {
      const r = await api.opsAssetRemove(assetId)
      if (r.success) await load()
    } catch (e: any) { setMsg(e.message) }
  }

  const discover = async () => {
    setDiscovering(true); setMsg('')
    try {
      const r = await api.opsAssetDiscovery(scope, scanner)
      setMsg(`发现任务完成：新增 ${r.new_count ?? 0} / 变更 ${r.changed_count ?? 0}`)
      await load()
    } catch (e: any) { setMsg(e.message) }
    finally { setDiscovering(false) }
  }

  const filtered = assets.filter((a) => {
    if (!filter) return true
    const s = filter.toLowerCase()
    return (
      a.ip?.toLowerCase().includes(s) ||
      a.hostname?.toLowerCase().includes(s) ||
      a.business_owner?.toLowerCase().includes(s) ||
      a.business_unit?.toLowerCase().includes(s) ||
      a.asset_key?.toLowerCase().includes(s)
    )
  })

  // 统计
  const counts = {
    total: assets.length,
    critical: assets.filter((a) => a.criticality === 'critical').length,
    high: assets.filter((a) => a.criticality === 'high').length,
    active: assets.filter((a) => a.is_active).length,
  }

  return (
    <div className="space-y-6">
      {/* 顶部指标卡 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="资产总数" value={counts.total} color="#0A84FF" />
        <MetricCard label="核心资产" value={counts.critical} color="#FF375F" />
        <MetricCard label="重要资产" value={counts.high} color="#FF9F0A" />
        <MetricCard label="活跃资产" value={counts.active} color="#34c759" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-6">
        {/* 左：资产表 */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-ink tracking-tight">资产清单</h3>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="搜索 IP / 主机名 / 责任人…"
              className="px-3 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white w-64"
            />
          </div>

          {loading ? (
            <EmptyState icon="⏳" title="加载中…" />
          ) : filtered.length === 0 ? (
            <EmptyState icon="🖥️" title="暂无已注册资产" hint="在右侧表单注册首个资产" />
          ) : (
            <div className="bg-white border border-line rounded-none overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wide text-ink-faint text-left bg-black/[0.02]">
                    <th className="px-4 py-3 font-medium">IP / 主机</th>
                    <th className="px-4 py-3 font-medium">关键性</th>
                    <th className="px-4 py-3 font-medium">责任部门</th>
                    <th className="px-4 py-3 font-medium">来源</th>
                    <th className="px-4 py-3 font-medium">更新</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((a, i) => {
                    const meta = CRITICALITY_META[a.criticality] ?? CRITICALITY_META.medium
                    return (
                      <motion.tr
                        key={a.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...spring.ui, delay: Math.min(i, 8) * 0.03 }}
                        className="border-t border-line hover:bg-black/[0.02] transition-colors"
                      >
                        <td className="px-4 py-3">
                          <div className="font-medium text-ink">{a.ip || a.hostname || a.asset_key}</div>
                          <div className="text-[10px] text-ink-faint font-mono">{a.asset_type} · {a.os || '—'}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold"
                            style={{ color: meta.color, background: meta.bg }}
                          >
                            {meta.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-ink-soft">
                          {a.business_unit || '—'}
                          {a.business_owner && <div className="text-[10px] text-ink-faint">{a.business_owner}</div>}
                        </td>
                        <td className="px-4 py-3 text-ink-faint font-mono text-[10px]">{a.source}</td>
                        <td className="px-4 py-3 text-ink-faint tabular-nums text-[10px]">
                          {a.updated_at ? new Date(a.updated_at).toLocaleDateString('zh-CN') : '—'}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {a.is_active && (
                            <button
                              onClick={() => remove(a.id)}
                              className="text-[10px] text-[#FF375F] hover:underline"
                            >
                              下线
                            </button>
                          )}
                        </td>
                      </motion.tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* 右：注册表单 + 发现 */}
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-ink tracking-tight mb-4">注册资产</h3>
            <div className="bg-white border border-line rounded-none p-5 space-y-3 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-[11px] font-medium text-ink-faint mb-1">IP</p>
                  <input
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    placeholder="10.0.0.5"
                    className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white font-mono"
                  />
                </div>
                <div>
                  <p className="text-[11px] font-medium text-ink-faint mb-1">Hostname</p>
                  <input
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="db-primary"
                    className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
                  />
                </div>
              </div>

              <div>
                <p className="text-[11px] font-medium text-ink-faint mb-1">类型</p>
                <select
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
                >
                  <option value="host">host</option>
                  <option value="server">server</option>
                  <option value="network_device">network_device</option>
                  <option value="endpoint">endpoint</option>
                  <option value="container">container</option>
                  <option value="cloud_asset">cloud_asset</option>
                </select>
              </div>

              <div>
                <p className="text-[11px] font-medium text-ink-faint mb-1">关键性</p>
                <div className="grid grid-cols-4 gap-1.5">
                  {Object.entries(CRITICALITY_META).map(([k, m]) => (
                    <button
                      key={k}
                      onClick={() => setLevel(k)}
                      className={`px-2 py-1 text-[10px] rounded-md border transition-all ${
                        level === k
                          ? 'border-accent bg-accent/[0.08] font-medium'
                          : 'border-line text-ink-soft'
                      }`}
                      style={level === k ? { color: m.color, borderColor: m.color } : {}}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-[11px] font-medium text-ink-faint mb-1">业务部门</p>
                <input
                  value={business}
                  onChange={(e) => setBusiness(e.target.value)}
                  placeholder="db / finance / ops"
                  className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
                />
              </div>

              <button
                onClick={submit}
                disabled={submitting}
                className="w-full py-2 text-xs font-medium text-white rounded-lg hover:opacity-90 disabled:opacity-50"
                style={{ backgroundImage: AI_GRADIENT }}
              >
                {submitting ? '保存中…' : '保存'}
              </button>
              {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{msg}</p>}
            </div>
          </div>

          {/* 资产发现 */}
          <div>
            <h3 className="text-sm font-semibold text-ink tracking-tight mb-4">资产发现</h3>
            <div className="bg-white border border-line rounded-none p-5 space-y-3 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-[11px] font-medium text-ink-faint mb-1">扫描范围</p>
                  <input
                    value={scope}
                    onChange={(e) => setScope(e.target.value)}
                    placeholder="all / 10.0.0.0/24"
                    className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white font-mono"
                  />
                </div>
                <div>
                  <p className="text-[11px] font-medium text-ink-faint mb-1">发现器</p>
                  <select
                    value={scanner}
                    onChange={(e) => setScanner(e.target.value)}
                    className="w-full px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
                  >
                    <option value="edr">EDR 派生</option>
                    <option value="nmap">nmap 扫描</option>
                    <option value="cmdb_api">CMDB API</option>
                  </select>
                </div>
              </div>
              <button
                onClick={discover}
                disabled={discovering}
                className="w-full py-2 text-xs font-medium text-white rounded-lg hover:opacity-90 disabled:opacity-50"
                style={{ backgroundImage: AI_GRADIENT }}
              >
                {discovering ? '扫描中…' : '启动发现'}
              </button>
            </div>
          </div>

          {/* 最近发现任务 */}
          {tasks.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-ink tracking-tight mb-3">最近发现任务</h3>
              <div className="space-y-2">
                {tasks.slice(0, 5).map((t) => (
                  <div key={t.id} className="bg-white border border-line rounded-lg px-3 py-2 text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-ink-soft">{t.task_id.slice(0, 12)}</span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                        style={{
                          color: t.status === 'completed' ? '#34c759' : t.status === 'failed' ? '#FF375F' : '#0A84FF',
                          background: t.status === 'completed' ? 'rgba(52,199,89,0.10)' : 'rgba(10,132,255,0.10)',
                        }}
                      >
                        {t.status}
                      </span>
                    </div>
                    <div className="text-[10px] text-ink-faint mt-1">
                      {t.scanner} · scope={t.scope} · 新增 {t.new_count} / 变更 {t.changed_count}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function MetricCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-white border border-line rounded-none px-4 py-4 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
      <div className="flex items-center gap-1.5 mb-2">
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
        <span className="text-[11px] font-medium text-ink-faint">{label}</span>
      </div>
      <GradientNumber value={value} />
    </div>
  )
}