import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { EmptyState } from './badges'

interface AuditEntry {
  id: number
  actor: string
  actor_role: string
  action: string
  target_type: string
  target_id: string
  before: Record<string, any>
  after: Record<string, any>
  ip: string
  reason: string
  created_at: string
}

const ACTION_COLORS: Record<string, string> = {
  'case.transition': '#0A84FF',
  'case.assign': '#5E5CE6',
  'case.disposition': '#5E5CE6',
  'order.approve': '#34c759',
  'order.reject': '#FF375F',
  'rule.publish': '#BF5AF2',
  'rule.rollback': '#FF9F0A',
  'asset.create': '#0A84FF',
  'asset.update': '#5E5CE6',
  'asset.decommission': '#86868b',
  'source.register': '#0A84FF',
  'source.revoke': '#FF375F',
}

export function AuditTrailTab() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [targetTypeFilter, setTargetTypeFilter] = useState('')
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { limit: '200' }
      if (actionFilter) params.action = actionFilter
      if (targetTypeFilter) params.target_type = targetTypeFilter
      const r = await api.opsAuditTrail(params).catch(() => ({ records: [], count: 0 }))
      setEntries(Array.isArray((r as any).records) ? (r as any).records : [])
    } finally {
      setLoading(false)
    }
  }, [actionFilter, targetTypeFilter])

  useEffect(() => { load() }, [load])

  const flush = async () => {
    try {
      const r = await api.opsAuditTrailFlush()
      alert(`已冲刷 ${r.flushed} 条离线缓冲`)
      await load()
    } catch (e: any) { alert(e.message) }
  }

  const filtered = entries.filter((e) => {
    if (!filter) return true
    const s = filter.toLowerCase()
    return (
      e.actor?.toLowerCase().includes(s) ||
      e.action?.toLowerCase().includes(s) ||
      e.target_id?.toLowerCase().includes(s) ||
      e.reason?.toLowerCase().includes(s)
    )
  })

  // 按 action 统计
  const actionStats: Record<string, number> = {}
  entries.forEach((e) => { actionStats[e.action] = (actionStats[e.action] ?? 0) + 1 })

  const targetTypes = ['case', 'work_order', 'rule', 'asset', 'playbook', 'source']

  return (
    <div className="space-y-5">
      {/* 顶部过滤器 */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="搜索 actor / 目标 ID / 原因…"
          className="px-3 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white w-64"
        />
        <select
          value={targetTypeFilter}
          onChange={(e) => setTargetTypeFilter(e.target.value)}
          className="px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
        >
          <option value="">全部目标</option>
          {targetTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="px-2.5 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
        >
          <option value="">全部动作</option>
          {Object.keys(actionStats).sort().map((a) => (
            <option key={a} value={a}>{a} ({actionStats[a]})</option>
          ))}
        </select>
        <button
          onClick={flush}
          className="ml-auto px-3 py-1.5 text-xs font-medium text-white rounded-lg hover:opacity-90"
          style={{ backgroundImage: AI_GRADIENT }}
        >
          冲刷离线缓冲
        </button>
      </div>

      {/* 列表 + 详情 */}
      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px] gap-5">
        {/* 列表 */}
        <div>
          {loading ? (
            <EmptyState icon="⏳" title="加载中…" />
          ) : filtered.length === 0 ? (
            <EmptyState icon="📜" title="没有匹配的审计记录" />
          ) : (
            <div className="bg-white border border-line rounded-2xl overflow-hidden shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wide text-ink-faint text-left bg-black/[0.02]">
                    <th className="px-4 py-3 font-medium">时间</th>
                    <th className="px-4 py-3 font-medium">操作人</th>
                    <th className="px-4 py-3 font-medium">动作</th>
                    <th className="px-4 py-3 font-medium">目标</th>
                    <th className="px-4 py-3 font-medium">原因</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, 100).map((e, i) => {
                    const color = ACTION_COLORS[e.action] ?? '#86868b'
                    const isSelected = selected?.id === e.id
                    return (
                      <motion.tr
                        key={e.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ ...spring.ui, delay: Math.min(i, 10) * 0.02 }}
                        onClick={() => setSelected(isSelected ? null : e)}
                        className={`border-t border-line cursor-pointer hover:bg-black/[0.02] transition-colors ${
                          isSelected ? 'bg-accent/[0.05]' : ''
                        }`}
                      >
                        <td className="px-4 py-2.5 text-ink-faint tabular-nums">
                          {new Date(e.created_at).toLocaleString('zh-CN', { hour12: false })}
                        </td>
                        <td className="px-4 py-2.5 font-medium text-ink">
                          {e.actor}
                          {e.actor_role && <span className="text-[10px] text-ink-faint ml-1">/{e.actor_role}</span>}
                        </td>
                        <td className="px-4 py-2.5">
                          <span
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium"
                            style={{ color, background: `${color}1a` }}
                          >
                            {e.action}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-ink-soft">
                          <span className="font-mono">{e.target_type}:{e.target_id}</span>
                        </td>
                        <td className="px-4 py-2.5 text-ink-soft max-w-xs truncate">
                          {e.reason || '—'}
                        </td>
                      </motion.tr>
                    )
                  })}
                </tbody>
              </table>
              {filtered.length > 100 && (
                <div className="text-center text-[11px] text-ink-faint py-3 border-t border-line">
                  显示前 100 条，共 {filtered.length} 条
                </div>
              )}
            </div>
          )}
        </div>

        {/* 详情面板 */}
        <div className="self-start xl:sticky xl:top-16">
          {selected ? (
            <div className="bg-white border border-line rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] space-y-4">
              <div>
                <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">操作人</p>
                <p className="text-sm font-medium text-ink mt-1">
                  {selected.actor}
                  {selected.actor_role && <span className="text-[11px] text-ink-faint ml-2">/{selected.actor_role}</span>}
                </p>
              </div>
              <div>
                <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">动作</p>
                <p className="text-sm font-mono mt-1" style={{ color: ACTION_COLORS[selected.action] ?? '#0A84FF' }}>
                  {selected.action}
                </p>
              </div>
              <div>
                <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">目标</p>
                <p className="text-xs font-mono text-ink mt-1">{selected.target_type}:{selected.target_id}</p>
              </div>
              <div>
                <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">时间</p>
                <p className="text-xs text-ink-soft tabular-nums mt-1">
                  {new Date(selected.created_at).toLocaleString('zh-CN', { hour12: false })}
                </p>
              </div>
              {selected.reason && (
                <div>
                  <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">理由</p>
                  <p className="text-xs text-ink mt-1">{selected.reason}</p>
                </div>
              )}
              {selected.ip && (
                <div>
                  <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">来源 IP</p>
                  <p className="text-xs font-mono text-ink mt-1">{selected.ip}</p>
                </div>
              )}
              {Object.keys(selected.before || {}).length > 0 && (
                <div>
                  <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">变更前</p>
                  <pre className="text-[10px] font-mono text-ink-soft bg-black/[0.03] rounded-lg p-2.5 mt-1 overflow-x-auto">
{JSON.stringify(selected.before, null, 2)}
                  </pre>
                </div>
              )}
              {Object.keys(selected.after || {}).length > 0 && (
                <div>
                  <p className="text-[11px] font-medium text-ink-faint uppercase tracking-wide">变更后</p>
                  <pre className="text-[10px] font-mono text-ink-soft bg-black/[0.03] rounded-lg p-2.5 mt-1 overflow-x-auto">
{JSON.stringify(selected.after, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-white border border-line rounded-2xl p-8 text-center shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
              <p className="text-sm text-ink-faint">📋 点击左侧记录</p>
              <p className="text-xs text-ink-faint mt-1">查看完整 before/after 快照</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}