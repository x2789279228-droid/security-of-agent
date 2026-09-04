import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { OrderTypeIcon, orderTypeLabel, SlaBadge, EmptyState } from './badges'
import type { WorkOrder, OrderType } from '../../types/operations'

const TYPE_FILTERS: { value: OrderType | ''; label: string }[] = [
  { value: '', label: '全部类型' },
  { value: 'disposition', label: '处置' },
  { value: 'approval', label: '审批' },
  { value: 'review', label: '复盘' },
  { value: 'rollback', label: '回滚' },
]

const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  pending: { label: '待处理', color: '#86868b', bg: 'rgba(134,134,139,0.10)' },
  assigned: { label: '已指派', color: '#111111', bg: '#e8e8e8' },
  in_progress: { label: '进行中', color: '#FF9F0A', bg: 'rgba(255,159,10,0.12)' },
  completed: { label: '已完成', color: '#111111', bg: '#f2f2f2' },
  cancelled: { label: '已取消', color: '#86868b', bg: 'rgba(134,134,139,0.10)' },
}

export function WorkOrdersTab() {
  const [orders, setOrders] = useState<WorkOrder[]>([])
  const [typeFilter, setTypeFilter] = useState<OrderType | ''>('')
  const [loading, setLoading] = useState(true)
  const [rejectId, setRejectId] = useState<number | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = { limit: '100' }
      if (typeFilter) params.order_type = typeFilter
      const data = await api.opsWorkOrders(params)
      setOrders(Array.isArray(data) ? data : [])
    } catch {
      setOrders([])
    } finally {
      setLoading(false)
    }
  }, [typeFilter])

  useEffect(() => { load() }, [load])

  const approve = async (id: number) => {
    setBusy(true)
    try { await api.opsWorkOrderApprove(id); await load() }
    finally { setBusy(false) }
  }

  const reject = async (id: number) => {
    setBusy(true)
    try { await api.opsWorkOrderReject(id, rejectReason || '拒绝'); setRejectId(null); setRejectReason(''); await load() }
    finally { setBusy(false) }
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-5">
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as OrderType | '')}
          className="px-3 py-1.5 text-xs border border-line rounded-lg bg-white focus:outline-none focus:ring-1 focus:ring-accent"
        >
          {TYPE_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <button onClick={load} className="px-3 py-1.5 text-xs font-medium bg-black/[0.04] rounded-lg hover:bg-black/[0.07] text-ink-soft">刷新</button>
        <span className="ml-auto text-xs text-ink-faint tabular-nums">{orders.length} 个工单</span>
      </div>

      {loading ? (
        <EmptyState icon="⏳" title="加载中…" />
      ) : orders.length === 0 ? (
        <EmptyState icon="📋" title="暂无工单" hint="案例流转或审批触发时会自动创建工单" />
      ) : (
        <div className="space-y-2.5">
          {orders.map((o, i) => {
            const sm = STATUS_META[o.status] ?? STATUS_META.pending
            const isApproval = o.order_type === 'approval' && o.approval_status === 'pending'
            return (
              <motion.div
                key={o.id}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring.ui, delay: Math.min(i * 0.03, 0.3) }}
                className="bg-white border border-line rounded-none px-5 py-4 shadow-[0_1px_3px_rgba(0,0,0,0.04)]"
              >
                <div className="flex items-start gap-3">
                  <OrderTypeIcon type={o.order_type} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-mono text-ink-faint">{o.order_number}</span>
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-medium" style={{ color: sm.color, background: sm.bg }}>{sm.label}</span>
                      <span className="text-[10px] text-ink-faint">{orderTypeLabel(o.order_type)}工单</span>
                      {o.sla_breached && !['completed', 'cancelled'].includes(o.status) && (
                        <SlaBadge deadline={o.sla_deadline} breached />
                      )}
                    </div>
                    <h3 className="text-sm font-semibold text-ink tracking-tight mt-1">{o.title || '(无标题)'}</h3>
                    {o.description && <p className="text-xs text-ink-soft mt-1 line-clamp-2">{o.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-[11px] text-ink-faint">
                      {o.assignee && <span>负责人 {o.assignee}</span>}
                      {o.created_by && <span>创建者 {o.created_by}</span>}
                      {o.approval_status && <span>审批 <span className="font-medium">{o.approval_status}</span></span>}
                    </div>

                    {/* 审批操作 */}
                    {isApproval && (
                      <div className="mt-3">
                        {rejectId === o.id ? (
                          <div className="flex gap-2">
                            <input
                              value={rejectReason}
                              onChange={(e) => setRejectReason(e.target.value)}
                              placeholder="拒绝原因"
                              className="flex-1 px-3 py-1.5 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-alert bg-white"
                            />
                            <button onClick={() => reject(o.id)} disabled={busy}
                              className="px-3 py-1.5 text-xs font-medium bg-alert text-white rounded-lg hover:opacity-90 disabled:opacity-50">确认拒绝</button>
                            <button onClick={() => setRejectId(null)} className="px-3 py-1.5 text-xs text-ink-soft hover:bg-black/[0.04] rounded-lg">取消</button>
                          </div>
                        ) : (
                          <div className="flex gap-2">
                            <button onClick={() => approve(o.id)} disabled={busy}
                              className="px-4 py-1.5 text-xs font-medium bg-ok text-white rounded-lg hover:opacity-90 disabled:opacity-50">✓ 批准</button>
                            <button onClick={() => setRejectId(o.id)} disabled={busy}
                              className="px-4 py-1.5 text-xs font-medium bg-alert/90 text-white rounded-lg hover:bg-alert disabled:opacity-50">✕ 拒绝</button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      )}
    </div>
  )
}
