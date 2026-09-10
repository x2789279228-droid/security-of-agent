import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { EmptyState } from './badges'
import type { SecurityCase, PostMortem } from '../../types/operations'

const PM_STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  draft: { label: '草稿', color: '#C08A3A', bg: 'rgba(192,138,58,0.12)' },
  reviewed: { label: '已审核', color: '#4A7A88', bg: 'rgba(74,122,136,0.10)' },
  published: { label: '已发布', color: '#3E7A64', bg: 'rgba(52,199,89,0.10)' },
}

export function PostMortemsTab() {
  const [cases, setCases] = useState<SecurityCase[]>([])
  const [postMortems, setPostMortems] = useState<Record<number, PostMortem>>({})
  const [selectedCase, setSelectedCase] = useState<number>(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [generating, setGenerating] = useState(false)
  const [loading, setLoading] = useState(true)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.opsCases({ limit: '100' })
      const list: SecurityCase[] = Array.isArray(data) ? data : []
      // 仅已解决/已关闭的案例可复盘
      const eligible = list.filter((c) => ['resolved', 'closed'].includes(c.status))
      setCases(eligible)

      // 并行加载已有复盘
      const pms: Record<number, PostMortem> = {}
      await Promise.all(
        eligible.map(async (c) => {
          try {
            const pm = await api.opsPostMortem(c.id)
            if (pm && pm.id) pms[c.id] = pm
          } catch { /* 无复盘 */ }
        }),
      )
      setPostMortems(pms)
    } catch {
      setCases([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const generate = async () => {
    if (!selectedCase) { setMsg('请先选择案例'); return }
    setGenerating(true); setMsg('')
    try {
      const r = await api.opsCreatePostMortem(selectedCase)
      if (r.success) {
        setMsg('复盘草稿已生成（含 LLM 根因分析）')
        setExpanded(selectedCase)
        await load()
      } else {
        setMsg(r.error || '生成失败')
      }
    } catch (e: any) { setMsg(e.message) }
    finally { setGenerating(false) }
  }

  const publish = async (caseId: number) => {
    setMsg('')
    try {
      await api.opsPublishPostMortem(caseId)
      setMsg('复盘已发布，规则改进建议已同步到反馈系统')
      await load()
    } catch (e: any) { setMsg(e.message) }
  }

  const withPm = cases.filter((c) => postMortems[c.id])
  const withoutPm = cases.filter((c) => !postMortems[c.id])

  return (
    <div className="space-y-8">
      {/* 生成复盘 */}
      <section className="bg-card/80 border border-line rounded-xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <h3 className="text-sm font-semibold text-ink tracking-tight mb-1">生成复盘报告</h3>
        <p className="text-xs text-ink-faint mb-4">从已解决/已关闭的案例自动生成复盘草稿：时间线 + 误报统计 + LLM 根因分析</p>
        <div className="flex gap-2">
          <select
            value={selectedCase}
            onChange={(e) => setSelectedCase(Number(e.target.value))}
            className="flex-1 px-3 py-2 text-xs border border-line rounded-lg bg-card/80 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value={0}>选择案例…</option>
            {withoutPm.map((c) => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
          <button
            onClick={generate}
            disabled={generating || !selectedCase}
            className="px-5 py-2 text-xs font-medium text-on-accent rounded-lg hover:opacity-90 disabled:opacity-50 transition-opacity"
            style={{ backgroundImage: AI_GRADIENT }}
          >
            {generating ? '生成中（LLM 分析）…' : '✦ 生成复盘'}
          </button>
        </div>
        {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2 mt-3">{msg}</p>}
      </section>

      {/* 复盘列表 */}
      <section>
        <h3 className="text-sm font-semibold text-ink tracking-tight mb-4">复盘报告（{withPm.length}）</h3>
        {loading ? (
          <EmptyState icon="⏳" title="加载中…" />
        ) : withPm.length === 0 ? (
          <EmptyState icon="📝" title="暂无复盘报告" hint="解决案例后，在上方生成复盘草稿" />
        ) : (
          <div className="space-y-3">
            {withPm.map((c, i) => {
              const pm = postMortems[c.id]
              const sm = PM_STATUS_META[pm.status] ?? PM_STATUS_META.draft
              const isOpen = expanded === c.id
              return (
                <motion.div
                  key={c.id}
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ ...spring.ui, delay: Math.min(i * 0.04, 0.3) }}
                  className="bg-card/80 border border-line rounded-xl shadow-[0_1px_3px_rgba(0,0,0,0.04)] overflow-hidden"
                >
                  <button
                    onClick={() => setExpanded(isOpen ? null : c.id)}
                    className="w-full text-left px-5 py-4 flex items-center justify-between gap-3 hover:bg-black/[0.015] transition-colors"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[11px] font-mono text-ink-faint">{c.case_number}</span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-medium" style={{ color: sm.color, background: sm.bg }}>{sm.label}</span>
                        {pm.false_positive_count > 0 && (
                          <span className="text-[10px] text-ink-faint">误报 {pm.false_positive_count}</span>
                        )}
                      </div>
                      <h4 className="text-sm font-semibold text-ink tracking-tight truncate">{pm.title}</h4>
                    </div>
                    <span className={`text-ink-faint transition-transform ${isOpen ? 'rotate-180' : ''}`}>▾</span>
                  </button>

                  <AnimatePresence>
                    {isOpen && (
                      <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: 'auto' }}
                        exit={{ height: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="px-5 pb-5 space-y-5 border-t border-line pt-4">
                          {/* 根因 + 影响 */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <Label>根因分析</Label>
                              <p className="text-xs text-ink leading-relaxed">{pm.root_cause || '待补充'}</p>
                            </div>
                            <div>
                              <Label>影响评估</Label>
                              <p className="text-xs text-ink leading-relaxed">{pm.impact_assessment || '待补充'}</p>
                            </div>
                          </div>

                          {/* 时间线 */}
                          {pm.timeline?.length > 0 && (
                            <div>
                              <Label>事件时间线</Label>
                              <div className="relative pl-5">
                                <div className="absolute left-[5px] top-1 bottom-1 w-px" style={{ background: AI_GRADIENT, opacity: 0.35 }} />
                                {pm.timeline.slice(0, 10).map((t, j) => (
                                  <div key={j} className="relative pb-3 last:pb-0">
                                    <span className="absolute -left-5 top-1 w-[9px] h-[9px] rounded-full" style={{ background: '#4A7A88' }} />
                                    <p className="text-[10px] font-mono text-ink-faint tabular-nums">{t.time?.slice(0, 19).replace('T', ' ')}</p>
                                    <p className="text-xs text-ink">{t.event} <span className="text-ink-soft">— {t.detail}</span></p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* 经验教训 */}
                          {pm.lessons_learned?.length > 0 && (
                            <div>
                              <Label>经验教训</Label>
                              <ul className="space-y-1.5">
                                {pm.lessons_learned.map((l, j) => (
                                  <li key={j} className="text-xs text-ink flex gap-2"><span className="text-accent">▸</span>{l}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* 规则改进 */}
                          {pm.rule_improvements?.length > 0 && (
                            <div>
                              <Label>规则改进建议</Label>
                              <ul className="space-y-1.5">
                                {pm.rule_improvements.map((r, j) => (
                                  <li key={j} className="text-xs text-ink flex gap-2">
                                    <span className="text-[#4A7A88]">⚙</span>
                                    {r.rule_id && <span className="font-mono text-ink-faint">[{r.rule_id}]</span>} {r.suggestion}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* 检测盲区 */}
                          {pm.detection_gaps && (
                            <div>
                              <Label>检测盲区</Label>
                              <p className="text-xs text-ink leading-relaxed">{pm.detection_gaps}</p>
                            </div>
                          )}

                          {/* 发布 */}
                          {pm.status !== 'published' && (
                            <button
                              onClick={() => publish(c.id)}
                              className="px-4 py-2 text-xs font-medium text-on-accent rounded-lg hover:opacity-90"
                              style={{ backgroundImage: AI_GRADIENT }}
                            >
                              发布复盘（同步规则建议到反馈系统）
                            </button>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] font-semibold text-ink-faint uppercase tracking-wide mb-1.5">{children}</p>
}
