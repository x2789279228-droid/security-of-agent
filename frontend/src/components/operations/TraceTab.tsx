import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { api } from '../../lib/api'
import { EmptyState } from './badges'
import { STATUS_TONE, INK_FAINT } from '../../lib/operationsTokens'
import { AI_GRADIENT_STOPS } from '../../lib/constants'

// ── 类型 ──

interface TraceListItem {
  trace_id: string
  last_seen: string | number
  root_service?: string
  root_span?: string
  duration_ms?: number
}

interface TraceSpan {
  span_id: string
  stage?: string
  name?: string
  service?: string
  status: string
  event_id?: number
  session_id?: string
  start_time?: number
  end_time?: number
  latency_ms: number
  error?: string
  event_type?: string
  src_ip?: string
}

function spanLabel(span: TraceSpan): string {
  if (span.stage && STAGE_LABELS[span.stage]) return STAGE_LABELS[span.stage]
  if (span.name) {
    // soc.logval.validate / soc.anomaly.score / kafka.consume.enriched → 短名
    const short = (span.name.match(/\.([a-z_.]+)$/i) || [])[1] || span.name
    return span.service ? `${span.service.replace('soc-', '')}·${short}` : short
  }
  return span.stage || span.service || 'span'
}

interface TraceEvent {
  id: number
  event_type: string
  severity: string
  src_ip: string
  anomaly_score: number
  created_at: string
}

interface TraceDetail {
  trace_id: string
  span_count: number
  spans: TraceSpan[]
  events: TraceEvent[]
  grafana_url: string
  trace_id_note: string
}

const STAGE_LABELS: Record<string, string> = {
  ingest: '接入', anomaly_detect: '异常检测', sigma_detect: 'Sigma 规则',
  store: '存储', decomposer: '任务分解', tool_builder: '工具构建',
  executor: '执行器', reviewer: '评审', cad_verify: 'CAD 验证',
  response: '响应',
}

const STAGE_COLORS: Record<string, string> = {
  ingest: STATUS_TONE.success,
  anomaly_detect: AI_GRADIENT_STOPS[0],
  sigma_detect: STATUS_TONE.active,
  store: STATUS_TONE.info,
  decomposer: STATUS_TONE.pending,
  tool_builder: STATUS_TONE.failed,
  executor: STATUS_TONE.failed,
  reviewer: STATUS_TONE.info,
  cad_verify: AI_GRADIENT_STOPS[3],
  response: STATUS_TONE.success,
}

function fmtMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms)}ms`
}

function fmtTime(iso: string | number): string {
  try {
    const d = new Date(typeof iso === 'number' ? iso / 1e6 : iso)
    return `${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
  } catch {
    return String(iso)
  }
}

// ── 展示 ──

function SpanRow({ span, maxLatency }: { span: TraceSpan; maxLatency: number }) {
  const color = STAGE_COLORS[span.stage || ''] || INK_FAINT
  const pct = maxLatency > 0 ? Math.max(3, (span.latency_ms / maxLatency) * 100) : 3
  const statusColor = span.status === 'error' || span.status === 'timeout' ? STATUS_TONE.failed : STATUS_TONE.success
  return (
    <div className="flex items-center gap-3 py-2.5">
      <div className="w-28 shrink-0">
        <span className="text-[12px] font-semibold text-ink truncate block">{spanLabel(span)}</span>
        {span.event_type && <span className="text-[10px] text-ink-faint truncate block">{span.event_type}</span>}
      </div>
      <div className="flex-1 h-6 bg-mist rounded overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          className="h-full rounded"
          style={{ background: color, opacity: 0.85 }}
        />
      </div>
      <div className="w-20 shrink-0 text-right tabular-nums text-[12px] text-ink-soft">{fmtMs(span.latency_ms)}</div>
      <div className="w-24 shrink-0 flex justify-end">
        <span
          className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
            span.status === 'success' ? 'bg-mist text-ink'
            : span.status === 'error' ? 'bg-alert/20 text-alert'
            : span.status === 'timeout' ? 'bg-warn/20 text-warn'
            : 'bg-ink/5 text-ink-soft'
          }`}
        >
          {span.status}
        </span>
      </div>
      <div className="hidden sm:block w-44 shrink-0 text-right text-[11px] text-ink-faint font-mono truncate">
        {span.event_id ? `#${span.event_id}` : ''} {span.src_ip || ''} {span.error ? `⚠ ${span.error.slice(0, 40)}` : ''}
      </div>
      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: statusColor }} />
    </div>
  )
}

// ── 主组件 ──

export function TraceTab() {
  const [traces, setTraces] = useState<TraceListItem[]>([])
  const [selected, setSelected] = useState<string>('')
  const [detail, setDetail] = useState<TraceDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadList = useCallback(async () => {
    try {
      const data = await api.get<{ traces: TraceListItem[] }>('/observability/traces')
      setTraces(data.traces ?? [])
      if (data.traces?.length && !selected) setSelected(data.traces[0].trace_id)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [selected])

  useEffect(() => {
    loadList()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!selected) return
    setLoading(true)
    setError('')
    api.get<TraceDetail>(`/observability/traces/${selected}`)
      .then(setDetail)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false))
  }, [selected])

  const maxLatency = Math.max(...(detail?.spans?.map((s) => s.latency_ms) ?? [0]), 1)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h3 className="text-lg font-bold text-ink">链路追踪 (OpenTelemetry → Tempo)</h3>
          <span className="text-[11px] px-2 py-0.5 border border-ink font-medium">标准 trace</span>
        </div>
        <a
          href="http://localhost:3002/grafana/explore"
          target="_blank"
          rel="noreferrer"
          className="text-[12px] font-medium text-ink hover:underline"
        >
          Grafana / Tempo →
        </a>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6">
        {/* 左侧: trace 列表 */}
        <div className="rounded-none border border-ink/[0.06] bg-white/70 backdrop-blur p-3 max-h-[520px] overflow-y-auto">
          <div className="text-[11px] uppercase tracking-wide text-ink-faint px-2 pb-2">最近 traces</div>
          {traces.map((t) => (
            <button
              key={t.trace_id}
              onClick={() => setSelected(t.trace_id)}
              className={`w-full text-left px-3 py-2 rounded-xl mb-1 transition-colors ${
                selected === t.trace_id ? 'bg-mist text-ink font-medium' : 'hover:bg-mist'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-mono text-ink truncate">{t.trace_id}</span>
                {typeof t.duration_ms === 'number' && t.duration_ms > 0 && (
                  <span className="text-[10px] text-ink-faint tabular-nums shrink-0">{fmtMs(t.duration_ms)}</span>
                )}
              </div>
              <div className="text-[11px] text-ink-faint truncate">
                {t.root_service ? `${t.root_service} · ${t.root_span || 'trace'}` : fmtTime(t.last_seen)}
              </div>
            </button>
          ))}
          {!traces.length && !loading && (
            <div className="px-3 py-8 text-center text-[12px] text-ink-faint">
              暂无 trace 记录（Flink/Python 处理事件后生成）
            </div>
          )}
        </div>

        {/* 右侧: 详情瀑布 */}
        <div className="rounded-none border border-ink/[0.06] bg-white/70 backdrop-blur p-5">
          {error && <div className="text-[13px] text-ink mb-3">⚠ {error}</div>}
          {loading && <div className="text-[13px] text-ink-faint">加载中...</div>}
          {!loading && !detail && !error && (
            <EmptyState icon="🔍" title="选择一个 trace" hint="从左侧选择一条链路查看瀑布时间线" />
          )}
          {!loading && detail && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-[13px] text-ink">{detail.trace_id}</span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-ink/5 text-ink-soft">{detail.span_count} spans</span>
                <a
                  href="http://localhost:3002/grafana/explore"
                  target="_blank"
                  rel="noreferrer"
                  className="text-[12px] text-ink hover:underline"
                >
                  Grafana 查看完整瀑布 →
                </a>
              </div>
              <p className="text-[11px] text-ink-faint">{detail.trace_id_note}</p>

              {/* 瀑布 */}
              <div className="space-y-0.5">
                {detail.spans.length > 0 ? (
                  detail.spans.map((s) => <SpanRow key={s.span_id} span={s} maxLatency={maxLatency} />)
                ) : (
                  <div className="text-[13px] text-ink-faint py-4 text-center">
                    此 trace 尚无持久化 span（Flink 侧 span 位于 Tempo，可在 Grafana 查看）
                  </div>
                )}
              </div>

              {/* 关联事件 */}
              {detail.events.length > 0 && (
                <div className="border-t border-ink/[0.06] pt-4">
                  <div className="text-[11px] uppercase tracking-wide text-ink-faint pb-2">关联事件</div>
                  <div className="space-y-1.5">
                    {detail.events.map((e) => (
                      <div key={e.id} className="flex items-center gap-3 text-[12px]">
                        <span className="text-ink-faint font-mono">#{e.id}</span>
                        <span className="font-medium text-ink">{e.event_type}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          e.severity === 'critical'
                            ? 'bg-alert/20 text-alert'
                            : e.severity === 'high'
                              ? 'bg-warn/20 text-warn'
                              : e.severity === 'medium'
                                ? 'bg-signal/15 text-signal'
                                : 'bg-mist text-ink-soft'
                        }`}>
                          {e.severity}
                        </span>
                        <span className="text-ink-faint font-mono">{e.src_ip}</span>
                        <span className="ml-auto tabular-nums text-ink-soft">anomaly {e.anomaly_score?.toFixed(2)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
