import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import { GradientNumber, EmptyState, SeverityChip } from './badges'

// ── 类型 ──

interface BudgetInfo {
  daily_budget: number
  today_usage: number
  today_prompt: number
  today_completion: number
  today_calls: number
  remaining: number
  over_budget: boolean
  usage_pct: number
  price_input_per_1k: number
  price_output_per_1k: number
  estimated_cost_jpy: number
  tracked_events: number
}

interface EventCost {
  event_id: number
  calls: number
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  avg_latency_ms: number
  errors: number
  last_used_at: string
  event_type: string
  severity: string
  src_ip: string
  message: string
  analyzed: boolean
  event_created_at: string
}

interface DailyPoint { day: string; total_tokens: number; calls: number }

interface TraceRow {
  id: number
  caller: string
  operation: string
  model: string
  event_id: number
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  latency_ms: number
  cache_hit: boolean
  status: string
  error_type: string
  retry_count: number
  created_at: string
}

// ── 展示辅助 ──

function fmtTokens(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return String(n)
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms)}ms`
}

function fmtNum(n: number): string {
  return new Intl.NumberFormat('zh-CN').format(Math.round(n))
}

function fmtTime(iso: string): string {
  try {
    const d = new Date(iso)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  } catch {
    return iso
  }
}

function costOf(prompt: number, completion: number, priceIn: number, priceOut: number): string {
  if ((!priceIn || priceIn <= 0) && (!priceOut || priceOut <= 0)) return '—'
  return `¥${(((prompt || 0) / 1000) * (priceIn || 0) + ((completion || 0) / 1000) * (priceOut || 0)).toFixed(2)}`
}

const OPERATION_LABELS: Record<string, string> = {
  decompose: '分解分析',
  execute: '综合审计',
  execute_deep: '深度研判',
  execute_recheck: '结论复核',
  review: '复核裁决',
  sub_audit: '子任务审计',
  verify: '证据验证',
  rerank: '知识重排',
  post_mortem: '事件复盘',
  watchdog_diagnose: '自动诊断',
  audit_component: '流水线组件',
  agent_chat: 'Agent 对话',
  chat: '通用调用',
}

const CALLER_LABELS: Record<string, string> = {
  audit_pipeline: '审计流水线',
  evidence_verifier: '证据验证器',
  post_mortem_service: '复盘服务',
  watchdog: '看门狗',
  agent_a: '分析 Agent',
  agent_b: '决策 Agent',
  agent_c: '报告 Agent',
  agent_d: '审查 Agent',
  decomposer: '分解者',
  tool_builder: '工具构建',
  executor: '执行者',
  reviewer: '复核者',
}

// ── 主组件 ──

export function CostTab() {
  const [events, setEvents] = useState<EventCost[]>([])
  const [totalEvents, setTotalEvents] = useState(0)
  const [grand, setGrand] = useState<{ calls: number; prompt_tokens: number; completion_tokens: number; total_tokens: number; errors: number } | null>(null)
  const [budget, setBudget] = useState<BudgetInfo | null>(null)
  const [daily, setDaily] = useState<DailyPoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [days, setDays] = useState(14)
  const [minTokens, setMinTokens] = useState(0)
  const [eventIdSearch, setEventIdSearch] = useState('')
  const [page, setPage] = useState(0)
  const pageSize = 20

  const [detail, setDetail] = useState<{ event: EventCost; traces: TraceRow[] } | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const load = useCallback(async (resetPage = true) => {
    if (resetPage) setPage(0)
    setLoading(true); setError('')
    try {
      const params: Record<string, string> = {
        days: String(days),
        limit: String(pageSize),
        offset: String((resetPage ? 0 : page) * pageSize),
      }
      if (minTokens > 0) params.min_tokens = String(minTokens)
      const [d, trend] = await Promise.all([
        api.agentTracesByEvent(params),
        api.agentTracesDaily(days),
      ])
      setEvents(d.events ?? [])
      setTotalEvents(d.total_events ?? 0)
      setGrand(d.grand ?? null)
      setBudget(d.budget ?? null)
      setDaily(trend.points ?? [])
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [days, minTokens, page])

  useEffect(() => { load(true) }, [load])

  const filteredEvents = eventIdSearch
    ? events.filter((e) => String(e.event_id).includes(eventIdSearch.trim()))
    : events

  const totalPages = Math.max(1, Math.ceil(totalEvents / pageSize))
  const priceIn = budget?.price_input_per_1k ?? 0
  const priceOut = budget?.price_output_per_1k ?? 0
  const grandCost = costOf(grand?.prompt_tokens ?? 0, grand?.completion_tokens ?? 0, priceIn, priceOut)

  const openDetail = async (event: EventCost) => {
    setDetailLoading(true)
    try {
      const d = await api.agentTracesByEventId(event.event_id)
      setDetail({ event, traces: d.traces ?? [] })
    } catch {
      setDetail({ event, traces: [] })
    } finally {
      setDetailLoading(false)
    }
  }

  const cards = [
    {
      label: '今日用量',
      value: budget ? fmtNum(budget.today_usage) : '—',
      sub: budget ? `${fmtNum(budget.today_calls)} 次调用` : '',
      color: budget?.over_budget ? '#FF375F' : '#0A84FF',
      danger: budget?.over_budget,
    },
    {
      label: '日预算',
      value: budget ? fmtNum(budget.daily_budget) : '—',
      sub: budget ? `已用 ${budget.usage_pct}%` : '',
      color: '#5E5CE6',
    },
    {
      label: '剩余预算',
      value: budget ? fmtNum(budget.remaining) : '—',
      sub: budget?.over_budget ? '已超限，LLM 降级中' : '',
      color: budget?.over_budget ? '#FF375F' : '#34c759',
      danger: budget?.over_budget,
    },
    {
      label: '窗口用量',
      value: grand ? fmtTokens(grand.total_tokens) : '—',
      sub: grand ? `输入 ${fmtTokens(grand.prompt_tokens)} · 输出 ${fmtTokens(grand.completion_tokens)}` : '',
      color: '#FF9F0A',
    },
    {
      label: '估算费用',
      value: priceIn > 0 || priceOut > 0 ? grandCost : '—',
      sub: priceIn > 0 || priceOut > 0 ? `输入 ¥${priceIn}/1K · 输出 ¥${priceOut}/1K` : '未配置单价（.env）',
      color: '#BF5AF2',
    },
  ]

  const maxDaily = Math.max(...daily.map((d) => d.total_tokens), 1)

  return (
    <div className="space-y-6">
      {/* 顶部：过滤 + 刷新 */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-ink-faint">统计窗口</span>
          {[7, 14, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-1 text-xs rounded-full transition-all ${
                days === d ? 'bg-accent text-white font-medium' : 'bg-black/[0.04] text-ink-soft hover:bg-black/[0.07]'
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
        <input
          type="number"
          min={0}
          value={minTokens}
          onChange={(e) => setMinTokens(Number(e.target.value) || 0)}
          placeholder="min tokens"
          className="w-28 px-3 py-1.5 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <input
          type="text"
          value={eventIdSearch}
          onChange={(e) => setEventIdSearch(e.target.value)}
          placeholder="按事件ID搜索"
          className="w-32 px-3 py-1.5 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <button
          onClick={() => load(true)}
          className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200"
        >
          刷新
        </button>
      </div>

      {/* 超限告警 */}
      {budget?.over_budget && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl text-xs font-medium text-alert bg-red-50 border border-red-200">
          <span className="relative flex h-2 w-2">
            <motion.span className="absolute inline-flex h-full w-full rounded-full bg-alert opacity-60"
              animate={{ scale: [1, 1.8], opacity: [0.6, 0] }} transition={{ duration: 1.4, repeat: Infinity }} />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-alert" />
          </span>
          每日 LLM 预算已用尽（{fmtNum(budget.today_usage)} / {fmtNum(budget.daily_budget)} tokens），新调用将降级为 fallback，请调整预算或等待次日重置。
        </div>
      )}

      {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

      {/* 统计卡片 */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-px bg-line border border-line rounded-2xl overflow-hidden">
        {cards.map((c) => (
          <div key={c.label} className="bg-white p-4">
            <div className="flex items-center gap-1.5 mb-2">
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: c.color }} />
              <span className="text-[11px] font-medium text-ink-faint">{c.label}</span>
            </div>
            <GradientNumber value={c.value} />
            {c.sub && <p className={`text-[10px] font-sans mt-1 ${c.danger ? 'text-alert' : 'text-ink-faint'}`}>{c.sub}</p>}
          </div>
        ))}
      </div>

      {/* 每日趋势 */}
      <div className="bg-white border border-line rounded-2xl p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[13px] font-semibold text-ink">每日 Token 用量（近 {days} 天）</h3>
          <span className="text-[10px] text-ink-faint font-sans">总量 {fmtTokens(daily.reduce((s, d) => s + d.total_tokens, 0))}</span>
        </div>
        <div className="flex items-end gap-1 h-24">
          {daily.map((p, i) => {
            const h = Math.max(2, Math.min(100, (p.total_tokens / maxDaily) * 100))
            return (
              <div key={p.day} className="flex-1 flex flex-col items-center gap-1 min-w-0" title={`${p.day}: ${fmtNum(p.total_tokens)} tokens / ${p.calls} 次`}>
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: `${h}%` }}
                  transition={{ ...spring.ui, delay: i * 0.02 }}
                  className="w-full rounded-sm"
                  style={{
                    background: p.total_tokens > 0 ? 'linear-gradient(180deg, #BF5AF2, #0A84FF)' : '#f0f0f2',
                    opacity: p.total_tokens > 0 ? 0.4 + (i / daily.length) * 0.6 : 1,
                  }}
                />
              </div>
            )
          })}
        </div>
        <div className="flex justify-between mt-2">
          <span className="text-[9px] text-ink-faint font-sans">{daily[0]?.day ?? ''}</span>
          <span className="text-[9px] text-ink-faint font-sans">{daily[daily.length - 1]?.day ?? ''}</span>
        </div>
      </div>

      {/* 按事件消耗表 */}
      <div className="bg-white border border-line rounded-2xl shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <div className="flex items-center justify-between px-5 py-4">
          <h3 className="text-[13px] font-semibold text-ink">按事件 Token 消耗</h3>
          <span className="text-[11px] text-ink-faint font-sans">
            {totalEvents} 个事件 · 总计 {grand ? fmtTokens(grand.total_tokens) : '—'} tokens
            {grandCost !== '—' ? ` · ${grandCost}` : ''}
          </span>
        </div>

        {loading && events.length === 0 ? (
          <EmptyState icon="⏳" title="加载 Token 数据中…" />
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            icon="💰"
            title="暂无事件 Token 数据"
            hint="注入安全日志触发审计流水线后，此处将按事件聚合 LLM 消耗"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-sans">
              <thead>
                <tr className="bg-gray-50 text-ink-faint text-left">
                  <th className="px-5 py-2.5 font-medium">事件</th>
                  <th className="px-4 py-2.5 font-medium">类型 / 严重度</th>
                  <th className="px-4 py-2.5 font-medium">源 IP</th>
                  <th className="px-4 py-2.5 font-medium text-right">总 Tokens</th>
                  <th className="px-4 py-2.5 font-medium text-right">输入</th>
                  <th className="px-4 py-2.5 font-medium text-right">输出</th>
                  <th className="px-4 py-2.5 font-medium text-right">调用</th>
                  <th className="px-4 py-2.5 font-medium text-right">平均延迟</th>
                  <th className="px-4 py-2.5 font-medium text-right">错误</th>
                  <th className="px-4 py-2.5 font-medium text-right">费用</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filteredEvents.map((e) => (
                  <tr
                    key={e.event_id}
                    onClick={() => openDetail(e)}
                    className="hover:bg-card transition-colors cursor-pointer"
                  >
                    <td className="px-5 py-2.5 whitespace-nowrap">
                      <span className="font-mono font-semibold text-accent">#{e.event_id}</span>
                      <p className="text-[10px] text-ink-faint max-w-[200px] truncate mt-0.5">{e.message}</p>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-ink-soft">{e.event_type || '—'}</span>
                        <SeverityChip severity={e.severity} />
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-ink-soft font-mono whitespace-nowrap">{e.src_ip || '—'}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums font-semibold text-ink">{fmtTokens(e.total_tokens)}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums text-ink-soft">{fmtTokens(e.prompt_tokens)}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums text-ink-soft">{fmtTokens(e.completion_tokens)}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums">{e.calls}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums text-ink-soft">{fmtMs(e.avg_latency_ms)}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums">
                      {e.errors > 0 ? <span className="text-alert font-semibold">{e.errors}</span> : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right tabular-nums text-ink-soft">{costOf(e.prompt_tokens, e.completion_tokens, priceIn, priceOut)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* 分页 */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-3 py-3 border-t border-line">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="px-4 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-40"
            >
              ← 上一页
            </button>
            <span className="text-xs font-sans text-ink-faint">第 {page + 1} / {totalPages} 页</span>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
              className="px-4 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-40"
            >
              下一页 →
            </button>
          </div>
        )}
      </div>

      {/* 事件明细抽屉 */}
      <AnimatePresence>
        {detail && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-6"
            onClick={() => setDetail(null)}
          >
            <motion.div
              initial={{ scale: 0.96, y: 12, opacity: 0 }}
              animate={{ scale: 1, y: 0, opacity: 1 }}
              exit={{ scale: 0.96, y: 12, opacity: 0 }}
              transition={spring.ui}
              className="bg-white rounded-2xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between px-5 py-4 border-b border-line">
                <div>
                  <h3 className="text-sm font-semibold text-ink">
                    事件 #{detail.event.event_id} 调用明细
                  </h3>
                  <p className="text-[11px] text-ink-faint font-sans mt-0.5">
                    {detail.event.event_type} · {detail.event.severity} · 总 {fmtTokens(detail.event.total_tokens)} tokens · {detail.event.calls} 次调用
                  </p>
                </div>
                <button
                  onClick={() => setDetail(null)}
                  className="w-8 h-8 flex items-center justify-center rounded-full bg-black/[0.05] hover:bg-black/[0.1] text-ink-soft"
                >
                  ✕
                </button>
              </div>

              <div className="overflow-y-auto flex-1">
                {detailLoading ? (
                  <div className="text-center text-xs text-ink-faint font-sans py-10">加载中…</div>
                ) : detail.traces.length === 0 ? (
                  <div className="text-center text-xs text-ink-faint font-sans py-10">该事件暂无 LLM 调用记录</div>
                ) : (
                  <table className="w-full text-xs font-sans">
                    <thead className="sticky top-0 bg-gray-50">
                      <tr className="text-ink-faint text-left">
                        <th className="px-5 py-2.5 font-medium">时间</th>
                        <th className="px-4 py-2.5 font-medium">调用方</th>
                        <th className="px-4 py-2.5 font-medium">操作</th>
                        <th className="px-4 py-2.5 font-medium text-right">输入</th>
                        <th className="px-4 py-2.5 font-medium text-right">输出</th>
                        <th className="px-4 py-2.5 font-medium text-right">延迟</th>
                        <th className="px-4 py-2.5 font-medium">状态</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {detail.traces.map((t) => (
                        <tr key={t.id}>
                          <td className="px-5 py-2.5 text-ink-faint whitespace-nowrap tabular-nums">{fmtTime(t.created_at)}</td>
                          <td className="px-4 py-2.5 whitespace-nowrap">{CALLER_LABELS[t.caller] || t.caller || '—'}</td>
                          <td className="px-4 py-2.5 whitespace-nowrap">
                            <span className="px-1.5 py-0.5 rounded bg-gray-100 text-ink-soft">
                              {OPERATION_LABELS[t.operation] || t.operation || 'chat'}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-right tabular-nums">{fmtTokens(t.prompt_tokens)}</td>
                          <td className="px-4 py-2.5 text-right tabular-nums">{fmtTokens(t.completion_tokens)}</td>
                          <td className="px-4 py-2.5 text-right tabular-nums text-ink-soft">{fmtMs(t.latency_ms)}</td>
                          <td className="px-4 py-2.5 whitespace-nowrap">
                            <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${t.status === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                              {t.status === 'success' ? '成功' : `失败${t.error_type ? `(${t.error_type})` : ''}`}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}