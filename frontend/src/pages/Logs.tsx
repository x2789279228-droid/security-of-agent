import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'
import type { SecurityLog, Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const severityMeta: Record<Severity, { label: string; badge: string; dot: string }> = {
  critical: { label: '严重', badge: 'bg-ink text-white', dot: 'bg-white' },
  high: { label: '高危', badge: 'bg-nong text-white', dot: 'bg-white' },
  medium: { label: '中危', badge: 'bg-hui text-white', dot: 'bg-white' },
  low: { label: '低危', badge: 'bg-qing text-ink', dot: 'bg-ink' },
  info: { label: '提示', badge: 'bg-mist text-ink-faint', dot: 'bg-hui' },
}

const PAGE_SIZE = 100

function formatTime(iso: string) {
  try {
    const d = new Date(iso)
    return `${d.toLocaleDateString('zh-CN')} ${d.toLocaleTimeString('zh-CN', { hour12: false })}`
  } catch {
    return iso
  }
}

export default function Logs() {
  const [logs, setLogs] = useState<SecurityLog[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [search, setSearch] = useState('')
  const [connected, setConnected] = useState(false)
  const offsetRef = useRef(0)
  const esRef = useRef<EventSource | null>(null)
  const liveKeysRef = useRef(0)

  const load = useCallback(async (reset = true, offset = 0) => {
    if (reset) setLoading(true); else setLoadingMore(true)
    setError(null)
    try {
      const params: Record<string, string> = {
        limit: String(PAGE_SIZE),
        offset: String(offset),
      }
      if (severity) params.severity = severity
      const data = await api.logsEvents(params)
      setLogs((prev) => {
        const merged = reset ? data : [...prev, ...data]
        const seen = new Set<number>()
        return merged.filter((l) => (seen.has(l.id) ? false : (seen.add(l.id), true)))
      })
      offsetRef.current = offset + data.length
    } catch (e: any) {
      setError(e.message || '加载失败')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [severity])

  useEffect(() => {
    load(true, 0)
  }, [load])

  useEffect(() => {
    const es = api.eventsStream()
    esRef.current = es
    es.addEventListener('connected', () => setConnected(true))
    es.addEventListener('ping', () => {})
    es.addEventListener('security_event', (e) => {
      const data = JSON.parse(e.data)
      liveKeysRef.current += 1
      const live: SecurityLog = {
        id: data.event_id ?? -liveKeysRef.current,
        session_id: '',
        event_type: data.event_type || 'UNKNOWN',
        severity: (data.severity || 'info') as Severity,
        src_ip: data.src_ip || '',
        dst_ip: data.dst_ip || '',
        message: data.message || '',
        analyzed: false,
        is_anomaly: data.is_anomaly,
        anomaly_score: data.anomaly_score,
        created_at: new Date(data._ts * 1000 || Date.now()).toISOString(),
      }
      setLogs((prev) => {
        if (prev.some((l) => l.id === live.id)) return prev
        return [live, ...prev].slice(0, 500)
      })
    })
    es.onerror = () => setConnected(false)
    return () => es.close()
  }, [])

  const filtered = useMemo(() => {
    if (!search.trim()) return logs
    const q = search.trim().toLowerCase()
    return logs.filter(
      (l) =>
        l.event_type.toLowerCase().includes(q) ||
        l.message.toLowerCase().includes(q) ||
        l.src_ip.includes(q) ||
        l.dst_ip.includes(q),
    )
  }, [logs, search])

  const stats = useMemo(() => {
    const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    let reviewed = 0
    for (const l of logs) {
      if (l.severity in bySeverity) bySeverity[l.severity]++
      if (l.analyzed) reviewed++
    }
    return { bySeverity, reviewed, pending: logs.length - reviewed }
  }, [logs])

  return (
    <PageFrame
      title="日志中心"
      subtitle="已接入安全事件 · 按时间倒序 · 实时推送"
      extra={
        <span className="flex items-center gap-2 text-[13px] text-ink">
          <span className={`w-2 h-2 ${connected ? 'bg-ink' : 'bg-hui'}`} />
          {connected ? '实时连接' : '已断开'}
        </span>
      }
    >

        {/* 严重级别统计卡（可点击筛选） */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-8">
          {SEVERITIES.map((s, i) => {
            const active = severity === s
            return (
              <motion.button
                key={s}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: i * 0.05 }}
                onClick={() => setSeverity(active ? '' : s)}
                className={`border p-5 text-left transition-colors ${
                  active ? 'border-ink bg-ink text-white' : 'border-line bg-white hover:bg-mist'
                }`}
              >
                <span className={`inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-full ${severityMeta[s].badge}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${severityMeta[s].dot}`} />
                  {severityMeta[s].label}
                </span>
                <p className="text-3xl font-semibold tracking-tight text-ink tabular-nums mt-3">
                  {stats.bySeverity[s]}
                </p>
              </motion.button>
            )
          })}
        </div>

        {/* 筛选栏 */}
        <div className="flex items-center gap-3 mb-5">
          <div className="relative flex-1">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-faint">
              <circle cx="11" cy="11" r="7" /><path d="M21 21l-4.35-4.35" strokeLinecap="round" />
            </svg>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="搜索事件类型 / 消息 / IP…"
              className="w-full text-sm pl-10 pr-4 py-2.5 rounded-none border-0 border-b border-line bg-transparent text-ink outline-none focus:border-ink"
            />
          </div>
          <button
            onClick={() => load(true, 0)}
            className="px-5 py-2.5 text-sm bg-ink text-white rounded-none hover:bg-accent-hover transition-colors tracking-[0.12em]"
          >
            刷新
          </button>
          <span className="text-[13px] text-ink-faint shrink-0 hidden md:block">
            已审计 {stats.reviewed} · 待审计 {stats.pending}
          </span>
        </div>

        {/* 日志表格 */}
        {loading ? (
          <div className="text-center text-sm text-ink-faint py-20">加载中…</div>
        ) : error ? (
          <div className="text-center text-sm text-alert py-20">{error}</div>
        ) : filtered.length === 0 ? (
          <div className="text-center text-sm text-ink-faint py-20 border border-line">
            {search || severity ? '没有符合筛选条件的日志' : '暂无日志，等待事件接入…'}
          </div>
        ) : (
          <div className="border border-line overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-ink-faint text-left border-b border-line">
                    <th className="px-5 py-3.5 font-medium">级别</th>
                    <th className="px-5 py-3.5 font-medium">事件类型</th>
                    <th className="px-5 py-3.5 font-medium">来源 → 目标</th>
                    <th className="px-5 py-3.5 font-medium w-2/5">消息</th>
                    <th className="px-5 py-3.5 font-medium">审计状态</th>
                    <th className="px-5 py-3.5 font-medium">时间</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  <AnimatePresence initial={false}>
                    {filtered.map((log) => {
                      const meta = severityMeta[log.severity] || severityMeta.info
                      return (
                        <motion.tr
                          key={log.id}
                          layout
                          initial={{ opacity: 0, y: -6 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="hover:bg-surface/60 transition-colors align-top"
                        >
                          <td className="px-5 py-3">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${meta.badge}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                              {meta.label}
                            </span>
                          </td>
                          <td className="px-5 py-3 font-medium text-ink whitespace-nowrap">{log.event_type}</td>
                          <td className="px-5 py-3 text-ink-soft whitespace-nowrap font-mono text-xs">
                            {log.src_ip || '—'} <span className="text-ink-faint">→</span> {log.dst_ip || '—'}
                          </td>
                          <td className="px-5 py-3 text-ink-soft leading-relaxed">
                            <span className="line-clamp-2">{log.message}</span>
                            {log.is_anomaly && (
                              <span className="text-alert text-[11px] font-semibold ml-1.5">
                                ⚠ 异常 {log.anomaly_score?.toFixed(2)}
                              </span>
                            )}
                          </td>
                          <td className="px-5 py-3 whitespace-nowrap">
                            {log.analyzed ? (
                              <span className="text-ink text-[11px] font-semibold">已审计</span>
                            ) : (
                              <span className="text-ink-faint text-[11px] font-semibold">审核中</span>
                            )}
                          </td>
                          <td className="px-5 py-3 text-ink-faint whitespace-nowrap tabular-nums text-xs">
                            {formatTime(log.created_at)}
                          </td>
                        </motion.tr>
                      )
                    })}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
            {filtered.length >= PAGE_SIZE && (
              <button
                onClick={() => load(false, offsetRef.current)}
                disabled={loadingMore}
                className="w-full py-3.5 text-sm text-link hover:bg-surface/60 transition-colors border-t border-line"
              >
                {loadingMore ? '加载中…' : '加载更多'}
              </button>
            )}
          </div>
        )}
    </PageFrame>
  )
}
