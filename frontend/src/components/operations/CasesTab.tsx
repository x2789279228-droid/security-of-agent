import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { StatusBadge, SeverityChip, PriorityChip, SlaBadge, EmptyState } from './badges'
import { CaseDrawer } from './CaseDrawer'
import type { SecurityCase, CaseStatus } from '../../types/operations'

const STATUS_FILTERS: { value: CaseStatus | ''; label: string }[] = [
  { value: '', label: '全部状态' },
  { value: 'open', label: '待处理' },
  { value: 'investigating', label: '调查中' },
  { value: 'pending_approval', label: '待审批' },
  { value: 'responding', label: '处置中' },
  { value: 'resolved', label: '已解决' },
  { value: 'closed', label: '已关闭' },
  { value: 'false_positive', label: '误报' },
]

export function CasesTab() {
  const [cases, setCases] = useState<SecurityCase[]>([])
  const [statusFilter, setStatusFilter] = useState<CaseStatus | ''>('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [selected, setSelected] = useState<SecurityCase | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { limit: '100' }
      if (statusFilter) params.status = statusFilter
      if (priorityFilter) params.priority = priorityFilter
      const data = await api.opsCases(params)
      setCases(Array.isArray(data) ? data : [])
    } catch {
      setCases([])
    } finally {
      setLoading(false)
    }
  }, [statusFilter, priorityFilter])

  useEffect(() => { load() }, [load])

  return (
    <div>
      {/* 过滤器 */}
      <div className="flex flex-wrap items-center gap-2 mb-5">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as CaseStatus | '')}
          className="px-3 py-1.5 text-xs border border-line rounded-lg bg-white focus:outline-none focus:ring-1 focus:ring-accent"
        >
          {STATUS_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <select
          value={priorityFilter}
          onChange={(e) => setPriorityFilter(e.target.value)}
          className="px-3 py-1.5 text-xs border border-line rounded-lg bg-white focus:outline-none focus:ring-1 focus:ring-accent"
        >
          <option value="">全部优先级</option>
          <option value="critical">P0 紧急</option>
          <option value="high">P1 高</option>
          <option value="medium">P2 中</option>
          <option value="low">P3 低</option>
        </select>
        <button onClick={load} className="px-3 py-1.5 text-xs font-medium bg-black/[0.04] rounded-lg hover:bg-black/[0.07] text-ink-soft">
          刷新
        </button>
        <span className="ml-auto text-xs text-ink-faint tabular-nums">{cases.length} 个案例</span>
      </div>

      {/* 列表 */}
      {loading ? (
        <EmptyState icon="⏳" title="加载中…" />
      ) : cases.length === 0 ? (
        <EmptyState icon="🗂️" title="暂无案例" hint="注入攻击日志后，系统会自动聚合生成案例" />
      ) : (
        <div className="space-y-2.5">
          {cases.map((c, i) => (
            <motion.button
              key={c.id}
              onClick={() => setSelected(c)}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ ...spring.ui, delay: Math.min(i * 0.03, 0.3) }}
              whileHover={{ y: -2 }}
              className="w-full text-left bg-white border border-line rounded-2xl px-5 py-4 shadow-[0_1px_3px_rgba(0,0,0,0.04)] hover:shadow-[0_6px_20px_rgba(0,0,0,0.08)] hover:border-accent/30 transition-all cursor-pointer"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-[11px] font-mono text-ink-faint">{c.case_number}</span>
                    <StatusBadge status={c.status} />
                  </div>
                  <h3 className="text-sm font-semibold text-ink tracking-tight truncate">{c.title}</h3>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-[11px] text-ink-soft">
                    <span>威胁 <span className="font-medium text-ink">{c.threat_type || '—'}</span></span>
                    <span>事件 <span className="font-medium text-ink tabular-nums">{c.event_count}</span></span>
                    <span>负责人 <span className="font-medium text-ink">{c.assignee || '未指派'}</span></span>
                    {(c.src_ips || []).slice(0, 2).map((ip) => (
                      <span key={ip} className="font-mono text-ink-faint">{ip}</span>
                    ))}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-2 shrink-0">
                  <div className="flex items-center gap-1.5">
                    <PriorityChip priority={c.priority} />
                    <SeverityChip severity={c.severity} />
                  </div>
                  <SlaBadge deadline={c.sla_deadline} />
                </div>
              </div>
            </motion.button>
          ))}
        </div>
      )}

      <CaseDrawer caseItem={selected} onClose={() => setSelected(null)} onChanged={load} />
    </div>
  )
}
