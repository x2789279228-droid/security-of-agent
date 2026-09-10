import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import { HealthGauge } from '../components/ui/HealthGauge'
import { KpiStat } from '../components/ui/KpiStat'
import { LiveBadge } from '../components/ui/LiveBadge'
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

// 0.1s 扫描规则：健康=松绿、告警=柿黄、异常=朱砂；标签颜色随健康度走
const serviceMeta: Record<string, { label: string; desc: string }> = {
  pgvector: { label: 'pgvector', desc: '向量检索' },
  redis: { label: 'Redis', desc: '滑动窗口' },
  llm: { label: 'LLM', desc: '摘要压缩' },
}

const SERVICE_TONE: Record<string, { gauge: 'ok' | 'warn' | 'error'; bar: string; text: string; dot: string; glow: string; badge: string }> = {
  ok: {
    gauge: 'ok',
    bar: 'bg-ok',
    text: 'text-ok',
    dot: 'bg-ok',
    glow: '',
    badge: 'border-ok text-ok',
  },
  warn: {
    gauge: 'warn',
    bar: 'bg-warn',
    text: 'text-warn',
    dot: 'bg-warn',
    glow: '',
    badge: 'border-warn text-warn',
  },
  alert: {
    gauge: 'error',
    bar: 'bg-alert',
    text: 'text-alert',
    dot: 'bg-alert',
    glow: '',
    badge: 'border-alert text-alert',
  },
  error: {
    gauge: 'error',
    bar: 'bg-alert',
    text: 'text-alert',
    dot: 'bg-alert',
    glow: '',
    badge: 'border-alert text-alert',
  },
}

const STREAM_EXTRA_LABEL: Record<string, string> = {
  idle: '未连接',
  connecting: '连接中',
  online: 'LIVE',
  reconnecting: '重连中',
  offline: '离线',
}

const STATS_MIN_INTERVAL = 2_000 // stats 刷新最短间隔（/api/stats 已 Redis 计数秒回,可近实时刷新）
let lastStatsAt = 0

export default function Monitor() {
  const services = useServiceStore((s) => s.services)
  const streamStatus = useEventStreamStore((s) => s.status)

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

  // 待处理 KPI 的滚动窗口：每次 stats 到达推入真实样本；首帧用当前值播种一段平滑合成
  // 历史（仅形状，不改变数值语义），后续全部由真实刷新覆盖。窗口 ≤ 24 点。
  const pendingSparkRef = useRef<number[]>([])
  const [pendingSpark, setPendingSpark] = useState<number[]>([])
  useEffect(() => {
    if (!stats) return
    const v = Math.max(0, Number(stats.security_pending ?? 0) || 0)
    const buf = pendingSparkRef.current
    if (buf.length === 0) {
      for (let i = 0; i < 11; i++) {
        const t = i / 10
        buf.push(Math.max(0, Math.round(v * (0.72 + 0.28 * t) + Math.sin(i * 1.9) * v * 0.07)))
      }
    }
    buf.push(v)
    if (buf.length > 24) buf.splice(0, buf.length - 24)
    setPendingSpark([...buf])
  }, [stats])

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

  const securityPending = Math.max(0, Number(stats?.security_pending ?? 0) || 0)

  return (
    <PageFrame
      title="系统监控"
      hint="服务健康 · 多 Agent 审查接力 · 实时事件流。"
      marginalia="——系统在跳，证明它活着。"
      extra={
        <LiveBadge
          live={streamStatus === 'online'}
          label={STREAM_EXTRA_LABEL[streamStatus] ?? streamStatus}
        />
      }
    >

      {/* 服务状态卡 — 顶部细线 + 健康环 + 状态点 */}
      <div className="mb-10 border border-line bg-paper">
        {Object.entries(services).map(([id, health], i) => {
          const tone = SERVICE_TONE[health] ?? SERVICE_TONE.alert
          const meta = serviceMeta[id] ?? { label: id, desc: id }
          return (
            <motion.div
              key={id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: i * 0.05 }}
              className={`relative flex items-center gap-5 border-line px-6 py-5 ${tone.glow} ${
                i < Object.entries(services).length - 1 ? 'border-b' : ''
              }`}
            >
              <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${tone.bar}`} />
              <div className="relative shrink-0">
                <HealthGauge health={tone.gauge} />
                <span
                  className={`absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rotate-45 ${tone.dot} ${
                    health === 'ok' ? '' : 'animate-pulse'
                  }`}
                  aria-hidden
                />
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                  {id}
                </p>
                <p className="mt-1 font-serif text-[18px] font-bold text-ink tracking-tight">
                  {meta.label}
                </p>
                <p className="text-xs text-ink-soft mt-0.5">{meta.desc}</p>
              </div>
              <span className={`border px-3 py-1 font-mono text-[11px] tracking-[0.18em] uppercase ${tone.badge}`}>
                {health === 'ok' ? 'NOMINAL' : health === 'warn' ? 'WARN' : 'ALERT'}
              </span>
            </motion.div>
          )
        })}
      </div>

      {/* 指标带 — 待处理 > 0 时是整个视图的裂口（rupture），其余 KPI 静默。无 stats 时仍占位，避免 401 把主次结构吃掉 */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.15 }}
        className="mb-10 grid grid-cols-2 md:grid-cols-6 gap-3"
      >
        <KpiStat
          label="待处理"
          value={securityPending}
          tone={securityPending > 0 ? 'hero' : 'ok'}
          spark={pendingSpark}
          live={securityPending > 0}
          hint={securityPending > 0 ? '待审查队列 · 优先消化' : '队列已清空'}
          className="col-span-2"
        />
        <KpiStat
          label="已分析"
          value={Number(stats?.audit_llm?.completed ?? 0) || 0}
          tone="ok"
        />
        <KpiStat
          label="安全事件"
          value={Number(stats?.security_events ?? 0) || 0}
          tone="neutral"
        />
        <KpiStat
          label="记忆树节点"
          value={Number(stats?.tree_nodes ?? 0) || 0}
          tone="neutral"
          size="sm"
        />
        <KpiStat
          label="Redis Keys"
          value={Number(stats?.redis_keys ?? 0) || 0}
          tone="neutral"
          size="sm"
        />
      </motion.div>

      {/* ── 多 Agent 审查接力 ── */}
      <div className="flex items-center justify-between mb-4 border-b border-ink/80 pb-3">
        <div className="flex items-baseline gap-4">
          <h2 className="font-serif text-[22px] font-black tracking-tight text-ink">
            多 Agent 审查接力
          </h2>
          <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
            Decomposer → Builder → Exec → Reviewer
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={runDemo}
            disabled={demoBusy}
            className="border border-[#0e1a26] bg-[#0e1a26] px-3 py-1.5 text-[12px] font-mono tracking-[0.16em] uppercase text-[#f1e8d6] hover:bg-[#182838] transition-colors disabled:opacity-50"
          >
            {demoBusy ? '演示启动中 …' : '跑一条演示'}
          </button>
          <span className="font-mono text-[11px] tracking-[0.18em] uppercase text-ink-faint tabular-nums">
            显示 {shownEvents} / 缓冲 {buffer.length}
          </span>
        </div>
      </div>
      {demoError && (
        <p className="mb-3 text-[12px] text-alert">{demoError}</p>
      )}

      <ToolAnomalyBanner />

      <div className="mb-5 border border-line bg-paper overflow-hidden">
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
      <div className="relative border border-line bg-paper overflow-hidden">
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
            className="absolute bottom-4 right-6 flex items-center gap-1.5 border border-[#0e1a26] bg-paper px-3 py-1.5 text-[12px] font-medium text-ink"
          >
            ↓ {pendingNew} 条新事件 · 点击恢复推送
          </button>
        )}
      </div>
    </PageFrame>
  )
}
