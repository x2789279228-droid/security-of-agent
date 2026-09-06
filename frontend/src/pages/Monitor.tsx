import { useCallback, useEffect, useMemo, useState } from 'react'
import { List, useDynamicRowHeight } from 'react-window'
import { motion } from 'framer-motion'
import { PageFrame } from '../components/common/PageFrame'
import StreamStatusBar from '../components/monitor/StreamStatusBar'
import AgentRelayStrip from '../components/monitor/AgentRelayStrip'
import ActiveRelayCards from '../components/monitor/ActiveRelayCards'
import EventToolbar, { type Filters } from '../components/monitor/EventToolbar'
import EventRow from '../components/monitor/EventRow'
import ThoughtChainPanel from '../components/monitor/ThoughtChainPanel'
import ToolAnomalyBanner from '../components/monitor/ToolAnomalyBanner'
import { api } from '../lib/api'
import { deriveRelays } from '../lib/agentPipeline'
import { pickThoughtEventId } from '../lib/thoughtChain'
import { useServiceStore } from '../stores/serviceStore'
import {
  severityOf,
  useEventStreamLifecycle,
  useEventStreamStore,
  type StreamEvent,
} from '../lib/eventStream'

const DEMO_EVENT = {
  event: 'C2_BEACON',
  severity: 'critical',
  src_ip: '192.168.1.105',
  dst_ip: '23.129.64.33',
  message: '演示审查：内部主机疑似与C2服务器通信',
  confidence: 85,
  _demo: true,
}

const healthMeta: Record<string, { label: string; color: string; text: string }> = {
  ok: { label: '正常', color: 'bg-ink', text: 'text-ink' },
  warn: { label: '告警', color: 'bg-nong', text: 'text-nong' },
  alert: { label: '异常', color: 'bg-hui', text: 'text-ink' },
}

const STATS_MIN_INTERVAL = 2_000 // stats 刷新最短间隔（/api/stats 已 Redis 计数秒回,可近实时刷新）
let lastStatsAt = 0

export default function Monitor() {
  const services = useServiceStore((s) => s.services)

  // 连接生命周期托管（引用计数单例通道，含断点续传与保活监测）
  useEventStreamLifecycle()

  // 首屏 hydration：进行中 + 最近完成 + 可展示思维链（SSE 窗口可能只剩自博弈行）
  const [hydratedPipelines, setHydratedPipelines] = useState<any[]>([])
  const [hydratedRecent, setHydratedRecent] = useState<any[]>([])
  const [thoughtCandidates, setThoughtCandidates] = useState<any[]>([])
  useEffect(() => {
    api.activePipelines()
      .then((r) => setHydratedPipelines(r.pipelines ?? []))
      .catch(() => {})
    api.recentPipelines()
      .then((r) => setHydratedRecent(r.pipelines ?? []))
      .catch(() => {})
    api.recentThoughtChains()
      .then((r) => setThoughtCandidates(r.chains ?? []))
      .catch(() => {})
  }, [])

  // 运行指标：初始加载 + 任一事件到达后节流刷新（最短间隔 5s，避免高压时高频打全表统计）
  const [stats, setStats] = useState<any>(null)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)
  useEffect(() => {
    api.stats().then(setStats).catch(() => {})
  }, [])
  useEffect(() => {
    if (!arrivalTick) return
    const wait = Math.max(0, lastStatsAt + STATS_MIN_INTERVAL - Date.now())
    const t = setTimeout(() => {
      lastStatsAt = Date.now()
      api.stats().then(setStats).catch(() => {})
    }, wait)
    return () => clearTimeout(t)
  }, [arrivalTick])

  // 实时事件流状态与筛选
  const buffer = useEventStreamStore((s) => s.buffer)
  const [filters, setFilters] = useState<Filters>({
    type: 'all',
    severity: 'all',
    stage: 'all',
    query: '',
  })
  const [paused, setPaused] = useState(false)
  const [frozen, setFrozen] = useState<StreamEvent[] | null>(null)

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase()
    return buffer.filter((e) => {
      if (e.kind !== 'event') return true // 空洞/重启标记行始终保留，保证过程可解释
      if (filters.type !== 'all' && e.type !== filters.type) return false
      if (filters.severity !== 'all' && severityOf(e.type, e.data) !== filters.severity) return false
      if (filters.stage !== 'all') {
        const stage = String(e.data?.stage ?? e.data?.agent_id ?? '')
        if (stage !== filters.stage) return false
      }
      if (q && !JSON.stringify(e.data ?? {}).toLowerCase().includes(q)) return false
      return true
    })
  }, [buffer, filters])

  // 暂停推送：冻结当前视图，新事件继续进入缓冲但不渲染；恢复时一次性放行
  const visible = paused && frozen ? frozen : filtered

  const togglePause = useCallback(() => {
    if (paused) {
      setPaused(false)
      setFrozen(null)
    } else {
      setPaused(true)
      setFrozen(filtered)
    }
  }, [paused, filtered])

  // 暂停期间累计的新事件数
  const pendingNew = useMemo(() => {
    if (!paused || !frozen) return 0
    const maxFrozenId = frozen.reduce((m, e) => Math.max(m, e.id), -1)
    return buffer.reduce((n, e) => (e.id > maxFrozenId && e.kind === 'event' ? n + 1 : n), 0)
  }, [paused, frozen, buffer])

  // 展开状态上提到页面层：虚拟滚动下行的卸载/重挂不应丢失展开状态
  const [expandedIds, setExpandedIds] = useState<Set<number>>(() => new Set())
  const toggleExpanded = useCallback((id: number) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null)
  const [dismissedThought, setDismissedThought] = useState(false)
  const [awaitingLive, setAwaitingLive] = useState(false)
  const [demoBusy, setDemoBusy] = useState(false)
  const [demoError, setDemoError] = useState('')
  const selectEvent = useCallback((eventId: number) => {
    if (!eventId) return
    setDismissedThought(false)
    setAwaitingLive(false)
    setSelectedEventId((prev) => (prev === eventId ? prev : eventId))
  }, [])
  const closeThought = useCallback(() => {
    setSelectedEventId(null)
    setDismissedThought(true)
    setAwaitingLive(false)
  }, [])

  useEffect(() => {
    if (dismissedThought) return
    const liveId = deriveRelays(buffer).active[0]?.eventId || 0
    if (liveId && (awaitingLive || selectedEventId == null)) {
      setSelectedEventId(liveId)
      setAwaitingLive(false)
      return
    }
    if (selectedEventId != null) return
    const fromBuffer = pickThoughtEventId(buffer)
    if (fromBuffer) {
      setSelectedEventId(fromBuffer)
      return
    }
    if (awaitingLive) return
    const fromDb = Number(thoughtCandidates[0]?.event_id) || 0
    if (fromDb) setSelectedEventId(fromDb)
  }, [buffer, dismissedThought, selectedEventId, thoughtCandidates, awaitingLive])

  const runDemo = useCallback(async () => {
    setDemoBusy(true)
    setDemoError('')
    setDismissedThought(false)
    setAwaitingLive(true)
    try {
      const sid = `demo-monitor-${crypto.randomUUID().slice(0, 8)}`
      const data = await api.ingestLog(DEMO_EVENT, sid)
      const eid = Number(data?.event_id) || 0
      if (eid) {
        setAwaitingLive(false)
        setSelectedEventId(eid)
      }
    } catch (e: any) {
      setDemoError(e?.message || '演示审查启动失败')
      setAwaitingLive(false)
    } finally {
      setDemoBusy(false)
    }
  }, [])

  const recentFromThoughts = useMemo(
    () => thoughtCandidates.map((c) => ({
      event_id: c.event_id,
      current_stage: 'reviewer',
      completed_stages: ['decomposer', 'tool_builder', 'executor', 'reviewer'],
      done: true,
      started_at: c.created_at ? Date.parse(String(c.created_at)) / 1000 : 0,
      session_id: '',
      trace_id: '',
    })),
    [thoughtCandidates],
  )
  const recentHydration = hydratedRecent.length > 0 ? hydratedRecent : recentFromThoughts

  const candidateId = Number(thoughtCandidates[0]?.event_id) || 0
  const idleHint = dismissedThought
    ? (candidateId
      ? `已关闭。点击接力卡片或最近完成，查看该事件思维链（最近 #${candidateId}）`
      : '已关闭。点击接力卡片、最近完成或带 event_id 的审计行，查看思维链。')
    : awaitingLive
      ? '演示审查已提交，流水线事件到达后将自动打开该事件思维链'
      : '当前没有可展示的 Audit-LLM 思维链。请注入一条安全事件，或在本页跑演示审查。'

  // 虚拟滚动：仅 mount 可视区行（此前 500 行全量 mount + framer-motion FLIP 是渲染卡顿主因）
  const rowHeight = useDynamicRowHeight({ defaultRowHeight: 56 })

  // 类型计数由 store 增量维护（eventStream flushBatch），避免每条事件 O(n) 重扫
  const typeCounts = useEventStreamStore((s) => s.typeCounts)

  const shownEvents = useMemo(
    () => visible.reduce((n, e) => (e.kind === 'event' ? n + 1 : n), 0),
    [visible],
  )

  return (
    <PageFrame title="系统监控" subtitle="服务健康 · 多 Agent 审查接力 · 实时事件流">

      {/* 服务状态卡 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-8">
        {Object.entries(services).map(([id, health], i) => {
          const hm = healthMeta[health] || healthMeta.alert
          return (
            <motion.div
              key={id}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.06 }}
              className="border border-line bg-white p-5 flex items-center gap-4"
            >
              <span className={`w-3 h-3 rounded-full ${hm.color} ${health === 'ok' ? '' : 'animate-pulse'}`} />
              <div className="flex-1">
                <p className="text-[15px] font-semibold text-ink">
                  {id === 'pgvector' ? 'pgvector' : id === 'redis' ? 'Redis' : 'LLM'}
                </p>
                <p className="text-xs text-ink-faint mt-0.5">
                  {id === 'pgvector' ? '向量检索' : id === 'redis' ? '滑动窗口' : '摘要压缩'}
                </p>
              </div>
              <span className={`text-[13px] font-semibold ${hm.text}`}>{hm.label}</span>
            </motion.div>
          )
        })}
      </div>

      {/* 指标带 */}
      {stats && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="border border-line bg-white px-8 py-8 mb-10 grid grid-cols-2 md:grid-cols-5 gap-y-8 text-center"
        >
          {[
            { label: '安全事件', value: stats.security_events ?? 0 },
            { label: '已分析', value: stats.audit_llm?.completed ?? 0 },
            { label: '待处理', value: stats.security_pending ?? 0 },
            { label: '记忆树节点', value: stats.tree_nodes ?? 0 },
            { label: 'Redis Keys', value: stats.redis_keys ?? 0 },
          ].map((item) => (
            <div key={item.label}>
              <p className="text-4xl font-semibold tracking-tight text-ink tabular-nums">{item.value}</p>
              <p className="text-[13px] text-ink-soft mt-1.5">{item.label}</p>
            </div>
          ))}
        </motion.div>
      )}

      {/* ── 多 Agent 审查接力 ── */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[22px] font-black tracking-tight text-ink">多 Agent 审查接力</h2>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={runDemo}
            disabled={demoBusy}
            className="border border-ink bg-ink px-3 py-1 text-[12px] text-white disabled:opacity-60"
          >
            {demoBusy ? '演示启动中…' : '跑一条演示审查'}
          </button>
          <span className="font-mono text-[13px] text-ink-faint tabular-nums">
            显示 {shownEvents} / 缓冲 {buffer.length} 条
          </span>
        </div>
      </div>
      {demoError && (
        <p className="mb-3 text-[12px] text-alert">{demoError}</p>
      )}

      <ToolAnomalyBanner />

      <div className="mb-5 border border-line bg-white">
        <StreamStatusBar paused={paused} onTogglePause={togglePause} />
        <div className="border-t border-line">
          <AgentRelayStrip />
        </div>
        <EventToolbar filters={filters} onChange={setFilters} typeCounts={typeCounts} />
      </div>

      <ActiveRelayCards
        hydrated={hydratedPipelines}
        hydratedRecent={recentHydration}
        selectedEventId={selectedEventId}
        onSelect={selectEvent}
        onDemo={runDemo}
        demoBusy={demoBusy}
      />

      <ThoughtChainPanel
        eventId={selectedEventId}
        onClose={closeThought}
        onJumpEvent={selectEvent}
        idleHint={idleHint}
      />

      {/* 事件列表 */}
      <div className="relative border border-line bg-white">
        {visible.length === 0 ? (
          <div className="p-14 text-center text-sm text-ink-faint">
            {buffer.length === 0
              ? '等待 Agent 接力… 连接建立后将自动回放最近的历史事件'
              : '当前筛选条件下没有匹配的事件'}
          </div>
        ) : (
          <List
            rowComponent={EventRow}
            rowCount={visible.length}
            rowHeight={rowHeight}
            rowProps={{
              events: visible,
              expandedIds,
              onToggle: toggleExpanded,
              selectedEventId,
              onSelectEvent: selectEvent,
            }}
            overscanCount={8}
            style={{ height: 520 }}
          />
        )}

        {paused && pendingNew > 0 && (
          <button
            onClick={togglePause}
            className="absolute bottom-4 right-6 flex items-center gap-1.5 bg-ink px-3 py-1.5 text-[12px] font-medium text-white shadow-md"
          >
            ↓ {pendingNew} 条新事件 · 点击恢复推送
          </button>
        )}
      </div>
    </PageFrame>
  )
}
