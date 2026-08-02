import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { StatusBadge, SeverityChip, PriorityChip, SlaBadge } from './badges'
import type { SecurityCase, CaseStatus, TimelineEntry } from '../../types/operations'

/** 与后端 case_manager.VALID_TRANSITIONS 保持一致 */
const VALID_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  open: ['investigating', 'closed', 'false_positive'],
  investigating: ['pending_approval', 'responding', 'resolved', 'closed', 'false_positive'],
  pending_approval: ['responding', 'investigating', 'closed'],
  responding: ['resolved', 'investigating', 'closed'],
  resolved: ['closed', 'investigating'],
  closed: [],
  false_positive: ['closed', 'investigating'],
}

const STATUS_LABEL: Record<CaseStatus, string> = {
  open: '开始调查', investigating: '调查中', pending_approval: '提交审批',
  responding: '执行处置', resolved: '标记解决', closed: '关闭案例', false_positive: '标记误报',
}

export function CaseDrawer({
  caseItem,
  onClose,
  onChanged,
}: {
  caseItem: SecurityCase | null
  onClose: () => void
  onChanged: () => void
}) {
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [assignee, setAssignee] = useState('')
  const [disposition, setDisposition] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const loadTimeline = useCallback(async (id: number) => {
    try {
      const t = await api.opsCaseTimeline(id)
      setTimeline(Array.isArray(t) ? t : [])
    } catch {
      setTimeline([])
    }
  }, [])

  useEffect(() => {
    if (caseItem) {
      setAssignee(caseItem.assignee || '')
      setDisposition(caseItem.disposition || '')
      setMsg('')
      loadTimeline(caseItem.id)
    }
  }, [caseItem, loadTimeline])

  if (!caseItem) return null

  const transitions = VALID_TRANSITIONS[caseItem.status] ?? []

  const doTransition = async (status: CaseStatus) => {
    setBusy(true); setMsg('')
    try {
      const r = await api.opsCaseStatus(caseItem.id, status)
      if (r.success) { setMsg(`状态已更新为 ${STATUS_LABEL[status]}`); onChanged(); loadTimeline(caseItem.id) }
      else setMsg(r.error || '操作失败')
    } catch (e: any) { setMsg(e.message) }
    finally { setBusy(false) }
  }

  const doAssign = async () => {
    setBusy(true); setMsg('')
    try {
      await api.opsCaseAssign(caseItem.id, assignee)
      setMsg(`已指派给 ${assignee}`); onChanged()
    } catch (e: any) { setMsg(e.message) }
    finally { setBusy(false) }
  }

  const doDisposition = async () => {
    setBusy(true); setMsg('')
    try {
      await api.opsCaseDisposition(caseItem.id, disposition)
      setMsg('处置结论已保存'); onChanged()
    } catch (e: any) { setMsg(e.message) }
    finally { setBusy(false) }
  }

  const markFalsePositive = async () => {
    setBusy(true); setMsg('')
    try {
      await api.opsSubmitFeedback({
        case_id: caseItem.id,
        event_id: caseItem.event_ids?.[0],
        feedback_type: 'false_positive',
        operator_conclusion: 'false_positive',
        reason: '运营人员标记为误报',
        submitted_by: 'admin',
      })
      await api.opsCaseStatus(caseItem.id, 'false_positive')
      setMsg('已标记为误报并提交反馈'); onChanged()
    } catch (e: any) { setMsg(e.message) }
    finally { setBusy(false) }
  }

  return (
    <AnimatePresence>
      {/* 液态玻璃遮罩 */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="fixed inset-0 z-[60]"
        style={{ background: 'rgba(20,20,25,0.30)', backdropFilter: 'blur(6px)', WebkitBackdropFilter: 'blur(6px)' }}
      />

      {/* 抽屉 */}
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={spring.page}
        className="fixed top-0 right-0 bottom-0 z-[61] w-full max-w-[520px] bg-surface shadow-[-8px_0_40px_rgba(0,0,0,0.12)] flex flex-col"
      >
        {/* 头部 */}
        <div className="px-6 pt-6 pb-4 border-b border-line bg-white">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[11px] font-mono text-ink-faint">{caseItem.case_number}</p>
              <h2
                className="text-xl font-extrabold tracking-tight mt-1 bg-clip-text text-transparent leading-snug"
                style={{ backgroundImage: AI_GRADIENT }}
              >
                {caseItem.title}
              </h2>
              <div className="flex flex-wrap items-center gap-2 mt-3">
                <StatusBadge status={caseItem.status} />
                <PriorityChip priority={caseItem.priority} />
                <SeverityChip severity={caseItem.severity} />
                <SlaBadge deadline={caseItem.sla_deadline} />
              </div>
            </div>
            <button onClick={onClose} className="shrink-0 w-8 h-8 flex items-center justify-center rounded-full hover:bg-black/[0.05] text-ink-soft text-lg">×</button>
          </div>
        </div>

        {/* 内容 */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {/* 基本信息 */}
          <section className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <Info label="威胁类型" value={caseItem.threat_type || '—'} />
            <Info label="置信度" value={`${Math.round((caseItem.confidence || 0) * 100)}%`} />
            <Info label="关联事件" value={`${caseItem.event_count} 条`} />
            <Info label="负责人" value={caseItem.assignee || '未指派'} />
            <Info label="源 IP" value={(caseItem.src_ips || []).join(', ') || '—'} />
            <Info label="目标 IP" value={(caseItem.dst_ips || []).join(', ') || '—'} />
          </section>

          {/* 状态流转 */}
          {transitions.length > 0 && (
            <section>
              <SectionTitle>状态流转</SectionTitle>
              <div className="flex flex-wrap gap-2">
                {transitions.map((t) => (
                  <button
                    key={t}
                    disabled={busy}
                    onClick={() => doTransition(t)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors disabled:opacity-50 ${
                      t === 'false_positive'
                        ? 'border-line text-ink-soft hover:bg-black/[0.04]'
                        : 'border-accent/30 text-accent bg-accent/[0.06] hover:bg-accent/[0.12]'
                    }`}
                  >
                    → {STATUS_LABEL[t]}
                  </button>
                ))}
              </div>
            </section>
          )}

          {/* 指派 */}
          <section>
            <SectionTitle>指派负责人</SectionTitle>
            <div className="flex gap-2">
              <input
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                placeholder="输入负责人"
                className="flex-1 px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white"
              />
              <button onClick={doAssign} disabled={busy || !assignee}
                className="px-4 py-2 text-xs font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                指派
              </button>
            </div>
          </section>

          {/* 处置结论 */}
          <section>
            <SectionTitle>处置结论</SectionTitle>
            <textarea
              value={disposition}
              onChange={(e) => setDisposition(e.target.value)}
              placeholder="记录最终处置结论…"
              rows={3}
              className="w-full px-3 py-2 text-xs border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent bg-white resize-none"
            />
            <button onClick={doDisposition} disabled={busy || !disposition}
              className="mt-2 px-4 py-1.5 text-xs font-medium bg-ink text-white rounded-lg hover:opacity-90 disabled:opacity-50">
              保存结论
            </button>
          </section>

          {/* 时间线 */}
          <section>
            <SectionTitle>案例时间线</SectionTitle>
            {timeline.length === 0 ? (
              <p className="text-xs text-ink-faint py-2">暂无时间线数据</p>
            ) : (
              <div className="relative pl-5">
                <div className="absolute left-[5px] top-1 bottom-1 w-px" style={{ background: AI_GRADIENT, opacity: 0.35 }} />
                {timeline.map((t, i) => (
                  <div key={i} className="relative pb-4 last:pb-0">
                    <span
                      className="absolute -left-5 top-1 w-[11px] h-[11px] rounded-full border-2 border-surface"
                      style={{ background: t.type === 'response' ? '#BF5AF2' : '#0A84FF' }}
                    />
                    <p className="text-[10px] font-mono text-ink-faint tabular-nums">{t.time?.slice(0, 19).replace('T', ' ')}</p>
                    <p className="text-xs text-ink mt-0.5 leading-relaxed">{t.detail}</p>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 误报标记 */}
          <section className="pt-2 border-t border-line">
            <button
              onClick={markFalsePositive}
              disabled={busy || caseItem.status === 'false_positive'}
              className="w-full py-2 text-xs font-medium text-ink-soft border border-line rounded-lg hover:bg-black/[0.04] disabled:opacity-50 transition-colors"
            >
              ⚑ 标记为误报（提交反馈并关闭）
            </button>
          </section>

          {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{msg}</p>}
        </div>
      </motion.div>
    </AnimatePresence>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="text-[11px] font-semibold text-ink-faint uppercase tracking-wide mb-2.5">{children}</h3>
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] text-ink-faint">{label}</p>
      <p className="text-ink font-medium mt-0.5 break-all">{value}</p>
    </div>
  )
}
