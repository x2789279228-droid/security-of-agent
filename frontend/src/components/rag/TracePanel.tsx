import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'

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

function fmtTokens(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return String(n)
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms)}ms`
}

function fmtTime(iso: string): string {
  try {
    const d = new Date(iso)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  } catch {
    return iso
  }
}

export function TracePanel() {
  const [stats, setStats] = useState<any>(null)
  const [traces, setTraces] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [caller, setCaller] = useState('')
  const [operation, setOperation] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const pageSize = 30

  const load = useCallback(async (resetPage = true) => {
    if (resetPage) setPage(0)
    setLoading(true); setError('')
    try {
      const params: Record<string, string> = {
        limit: String(pageSize),
        offset: String((resetPage ? 0 : page) * pageSize),
      }
      if (caller) params.caller = caller
      if (operation) params.operation = operation
      if (status) params.status = status
      const [d, s] = await Promise.all([api.agentTraces(params), api.agentTraceStats()])
      setTraces(d.traces)
      setTotal(d.total)
      setStats(s)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }, [caller, operation, status, page])

  useEffect(() => { load(true) }, [caller, operation, status])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const statCards = [
    { label: 'LLM 调用次数', value: stats ? String(stats.total_calls) : '—', sub: stats && stats.total_calls > 0 ? `失败 ${stats.error_count}` : '' },
    { label: 'Token 消耗', value: stats ? fmtTokens(stats.total_tokens) : '—', sub: stats ? `输入 ${fmtTokens(stats.total_prompt_tokens)} · 输出 ${fmtTokens(stats.total_completion_tokens)}` : '' },
    { label: '平均延迟', value: stats ? fmtMs(stats.avg_latency_ms) : '—', sub: '' },
    { label: '错误率', value: stats ? `${(stats.error_rate * 100).toFixed(1)}%` : '—', sub: stats && stats.degraded_count ? `降级 ${stats.degraded_count} 次 · ${((stats.degraded_rate ?? 0) * 100).toFixed(1)}%` : '', danger: (stats?.error_rate ?? 0) > 0.1 },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-sans text-ink-faint">
          审计流水线各环节（分解/执行/复核/验证）的 LLM 调用留痕 — 成本、延迟与质量追踪
        </p>
        <button onClick={() => load(true)} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新</button>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-4 gap-px bg-line border border-line rounded-lg overflow-hidden">
        {statCards.map((c) => (
          <div key={c.label} className="bg-card p-4">
            <p className="text-[10px] font-sans text-ink-faint">{c.label}</p>
            <p className={`text-2xl font-serif font-bold tabular-nums mt-1 ${c.danger ? 'text-alert' : ''}`}>{c.value}</p>
            {c.sub && <p className={`text-[10px] font-sans mt-1 ${c.danger ? 'text-alert' : 'text-ink-faint'}`}>{c.sub}</p>}
          </div>
        ))}
      </div>

      {/* 过滤栏 */}
      <div className="flex items-center gap-2 flex-wrap">
        <select value={caller} onChange={e => setCaller(e.target.value)}
          className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
          <option value="">全部调用方</option>
          {Object.entries(CALLER_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={operation} onChange={e => setOperation(e.target.value)}
          className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
          <option value="">全部操作</option>
          {Object.entries(OPERATION_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={status} onChange={e => setStatus(e.target.value)}
          className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
          <option value="">全部状态</option>
          <option value="success">成功</option>
          <option value="degraded">降级</option>
          <option value="error">失败</option>
        </select>
        <span className="text-xs font-sans text-ink-faint ml-auto">共 {total} 条</span>
      </div>

      {/* 失败/降级原因分布 */}
      {(stats?.by_error_type && Object.keys(stats.by_error_type).length > 0) ||
       (stats?.by_degraded_type && Object.keys(stats.by_degraded_type).length > 0) ? (
        <div className="grid grid-cols-2 gap-px bg-line border border-line rounded-lg overflow-hidden">
          {stats?.by_error_type && Object.keys(stats.by_error_type).length > 0 && (
            <div className="bg-card p-3">
              <p className="text-[10px] font-sans text-ink-faint mb-1">失败原因分布 (error)</p>
              <div className="space-y-1">
                {Object.entries(stats.by_error_type).map(([k, v]) => (
                  <div key={`e-${k}`} className="flex justify-between text-xs font-sans text-ink-soft">
                    <span>{k || 'unknown'}</span><span className="tabular-nums text-red-700">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {stats?.by_degraded_type && Object.keys(stats.by_degraded_type).length > 0 && (
            <div className="bg-card p-3">
              <p className="text-[10px] font-sans text-ink-faint mb-1">降级原因分布 (degraded)</p>
              <div className="space-y-1">
                {Object.entries(stats.by_degraded_type).map(([k, v]) => (
                  <div key={`d-${k}`} className="flex justify-between text-xs font-sans text-ink-soft">
                    <span>{k || 'unknown'}</span><span className="tabular-nums text-amber-700">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : null}

      {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

      {/* 轨迹表 */}
      <div className="border border-line rounded-lg overflow-hidden">
        {loading && traces.length === 0 ? (
          <div className="text-center text-xs text-ink-faint font-sans py-10">加载中…</div>
        ) : traces.length === 0 ? (
          <div className="text-center text-xs text-ink-faint font-sans py-10">
            暂无 LLM 调用记录 — 触发一次审计流水线（注入安全日志）后数据将在此显示
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-sans">
              <thead>
                <tr className="bg-gray-50 text-ink-faint text-left">
                  <th className="px-4 py-2.5 font-medium">时间</th>
                  <th className="px-4 py-2.5 font-medium">调用方</th>
                  <th className="px-4 py-2.5 font-medium">操作</th>
                  <th className="px-4 py-2.5 font-medium">事件ID</th>
                  <th className="px-4 py-2.5 font-medium">输入</th>
                  <th className="px-4 py-2.5 font-medium">输出</th>
                  <th className="px-4 py-2.5 font-medium">延迟</th>
                  <th className="px-4 py-2.5 font-medium">重试</th>
                  <th className="px-4 py-2.5 font-medium">状态</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                <AnimatePresence initial={false}>
                  {traces.map((t) => (
                    <motion.tr key={t.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      className="hover:bg-card transition-colors">
                      <td className="px-4 py-2.5 text-ink-faint whitespace-nowrap tabular-nums">{fmtTime(t.created_at)}</td>
                      <td className="px-4 py-2.5 whitespace-nowrap">{CALLER_LABELS[t.caller] || t.caller || '—'}</td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-gray-100 text-ink-soft">
                          {OPERATION_LABELS[t.operation] || t.operation || 'chat'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-ink-faint tabular-nums">{t.event_id || '—'}</td>
                      <td className="px-4 py-2.5 tabular-nums">{fmtTokens(t.prompt_tokens)}</td>
                      <td className="px-4 py-2.5 tabular-nums">{fmtTokens(t.completion_tokens)}</td>
                      <td className="px-4 py-2.5 tabular-nums">{fmtMs(t.latency_ms)}</td>
                      <td className="px-4 py-2.5 tabular-nums">{t.retry_count || '—'}</td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                          t.status === 'success' ? 'bg-green-100 text-green-700'
                          : t.status === 'degraded' ? 'bg-amber-100 text-amber-700'
                          : 'bg-red-100 text-red-700'}`}>
                          {t.status === 'success' ? '成功'
                           : t.status === 'degraded' ? '降级'
                           : `失败${t.error_type ? `(${t.error_type})` : ''}`}
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 分页 */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button disabled={page === 0} onClick={() => setPage(p => Math.max(0, p - 1))}
            className="px-4 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-40">
            ← 上一页
          </button>
          <span className="text-xs font-sans text-ink-faint">第 {page + 1} / {totalPages} 页</span>
          <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
            className="px-4 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-40">
            下一页 →
          </button>
        </div>
      )}
    </div>
  )
}
