import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { PageFrame } from '../components/common/PageFrame'
import { Button } from '../components/ui/Button'
import { api } from '../lib/api'

const MATCH_STORAGE_KEY = 'sm_selfplay_match'

type MatchSnap = {
  match_id: string
  status?: string
  winner?: string
  round_num?: number
  completed_rounds?: number
  total_rounds?: number
  level?: number
  curriculum_level?: number
  metrics?: Record<string, number>
  rounds?: any[]
  last_round?: any
  config?: Record<string, any>
  via?: string
}

const METRIC_KEYS: { key: string; label: string }[] = [
  { key: 'asr', label: 'ASR 红队成功率' },
  { key: 'recall', label: 'Blue Recall' },
  { key: 'precision', label: 'Blue Precision' },
  { key: 'fbeta', label: 'Fβ 1.5' },
  { key: 'blue_score', label: 'Blue Score' },
  { key: 'mttd_ms', label: 'MTTD ms' },
]

const RADAR_AXES: { key: string; label: string }[] = [
  { key: 'coverage', label: '覆盖' },
  { key: 'precision', label: '精确' },
  { key: 'mttd', label: '时效' },
  { key: 'novelty_response', label: '新颖响应' },
  { key: 'compounding', label: '复合检出' },
  { key: 'robustness', label: '稳健' },
]

function RadarChart({ values }: { values: Record<string, number> }) {
  const n = RADAR_AXES.length
  const cx = 90
  const cy = 90
  const r = 68
  const pt = (i: number, v: number) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / n
    return [cx + r * v * Math.cos(a), cy + r * v * Math.sin(a)] as const
  }
  const grid = [0.25, 0.5, 0.75, 1].map((g) =>
    RADAR_AXES.map((_, i) => pt(i, g).join(',')).join(' '),
  )
  const data = RADAR_AXES.map((ax, i) => {
    const v = Math.max(0, Math.min(1, Number(values[ax.key] || 0)))
    return pt(i, v).join(',')
  }).join(' ')
  return (
    <svg viewBox="0 0 180 180" className="w-full max-w-[220px] mx-auto">
      {grid.map((pts, i) => (
        <polygon key={i} points={pts} fill="none" stroke="currentColor" strokeOpacity={0.15} />
      ))}
      <polygon points={data} fill="currentColor" fillOpacity={0.18} stroke="currentColor" strokeWidth={1.5} />
      {RADAR_AXES.map((ax, i) => {
        const [x, y] = pt(i, 1.18)
        return (
          <text key={ax.key} x={x} y={y} textAnchor="middle" fontSize="9" fill="currentColor" opacity={0.7}>
            {ax.label}
          </text>
        )
      })}
    </svg>
  )
}

function pct(v: unknown) {
  const n = Number(v || 0)
  if (Number.isNaN(n)) return '—'
  return `${Math.round(n * 1000) / 10}%`
}

function outcomeTone(o: string) {
  if (o === 'blue_win') return 'bg-ink text-white'
  if (o === 'red_win') return 'border border-ink text-ink'
  return 'bg-mist text-ink-soft'
}

function readStoredMatchId() {
  try {
    return sessionStorage.getItem(MATCH_STORAGE_KEY) || ''
  } catch {
    return ''
  }
}

function writeStoredMatchId(id: string) {
  try {
    if (id) sessionStorage.setItem(MATCH_STORAGE_KEY, id)
    else sessionStorage.removeItem(MATCH_STORAGE_KEY)
  } catch {
    /* private mode */
  }
}

function pickResumeId(matches: MatchSnap[], preferred: string) {
  if (preferred && matches.some((m) => m.match_id === preferred)) return preferred
  const running = matches.find((m) => m.status === 'running' || m.status === 'stopping')
  return running?.match_id || matches[0]?.match_id || ''
}

function normalizeMatch(d: MatchSnap): MatchSnap {
  const rounds = Array.isArray(d.rounds) ? d.rounds : []
  const last = d.last_round || rounds[rounds.length - 1] || null
  return {
    ...d,
    rounds,
    last_round: last,
    level: d.level ?? d.curriculum_level ?? last?.curriculum_level ?? 0,
  }
}

export default function SelfPlay() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [catalog, setCatalog] = useState<any>(null)
  const [matches, setMatches] = useState<MatchSnap[]>([])
  const [activeId, setActiveId] = useState(() => searchParams.get('match') || readStoredMatchId())
  const [detail, setDetail] = useState<MatchSnap | null>(null)
  const [rules, setRules] = useState<any[]>([])
  const [hist, setHist] = useState<any>(null)
  const [rounds, setRounds] = useState(8)
  const [inject, setInject] = useState(false)
  const [useLlm, setUseLlm] = useState(false)
  const [diverse, setDiverse] = useState(false)
  const [background, setBackground] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const hydratedRef = useRef(false)

  const selectMatch = useCallback((id: string) => {
    setActiveId(id)
    writeStoredMatchId(id)
    const current = searchParams.get('match') || ''
    if (current === id) return
    const next = new URLSearchParams(searchParams)
    if (id) next.set('match', id)
    else next.delete('match')
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  const loadList = useCallback(async () => {
    try {
      const r = await api.selfPlayMatches()
      setMatches(r?.matches || [])
    } catch {
      /* 未登录/后端未起 */
    }
  }, [])

  const loadDetail = useCallback(async (id: string) => {
    if (!id) return
    try {
      const d = await api.selfPlayMatch(id)
      setDetail(normalizeMatch(d))
    } catch {
      /* ignore */
    }
  }, [])

  const loadSide = useCallback(async () => {
    try {
      const [c, m, ru] = await Promise.all([
        api.selfPlayCatalog(),
        api.selfPlayMetrics(),
        api.selfPlayLearnedRules(),
      ])
      setCatalog(c)
      setHist(m)
      setRules(ru?.rules || [])
    } catch {
      /* ignore */
    }
  }, [])

  useEffect(() => {
    loadList()
    loadSide()
  }, [loadList, loadSide])

  useEffect(() => {
    if (hydratedRef.current) return
    if (!matches.length) return
    hydratedRef.current = true
    const preferred = searchParams.get('match') || readStoredMatchId() || activeId
    const pick = pickResumeId(matches, preferred)
    if (pick) selectMatch(pick)
  }, [matches, searchParams, activeId, selectMatch])

  const running = (detail?.status === 'running' || detail?.status === 'stopping')
    || matches.some((m) => m.match_id === activeId && (m.status === 'running' || m.status === 'stopping'))

  useEffect(() => {
    if (!activeId) return
    loadDetail(activeId)
    if (!running) return
    const t = setInterval(() => {
      loadDetail(activeId)
      loadList()
    }, 900)
    return () => clearInterval(t)
  }, [activeId, running, loadDetail, loadList])

  const start = async () => {
    setBusy(true)
    setError('')
    try {
      const r = await api.selfPlayStart({
        rounds,
        curriculum: true,
        inject,
        use_llm: useLlm,
        decoy_ratio: 0.2,
        diverse_env: diverse,
        background_traffic: background,
      })
      selectMatch(r.match_id)
      await loadList()
      await loadDetail(r.match_id)
    } catch (e: any) {
      setError(e?.message || '开局失败(需要登录 operator/admin)')
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    if (!activeId) return
    setBusy(true)
    try {
      await api.selfPlayStop(activeId)
      await loadDetail(activeId)
    } catch (e: any) {
      setError(e?.message || '停止失败')
    } finally {
      setBusy(false)
    }
  }

  const metrics = detail?.metrics || {}
  const timeline = (detail?.rounds || []) as any[]
  const last = detail?.last_round || timeline[timeline.length - 1]
  const redStep = last?.red_plan?.steps?.[0] || last?.red?.steps?.[0] || last?.plan?.steps?.[0]
  const blueObs = last?.blue_obs?.[0] || last?.blue

  const level = detail?.level ?? detail?.curriculum_level ?? 0
  const maxLevel = catalog?.max_level ?? 6

  const ttps = catalog?.ttps || []
  const hosts = catalog?.topology?.hosts || []

  const liveHint = useMemo(() => {
    if (!detail) return '选择或开一局,观看红队生成对抗场景、蓝队实时响应、漏报反哺。'
    if (detail.status === 'running') return `对局进行中 · 第 ${detail.round_num || 0} 回合 · 课程 L${level}`
    if (detail.status === 'completed') return `结束 · 胜者 ${detail.winner || 'draw'}`
    return `状态 ${detail.status}`
  }, [detail, level])

  return (
    <PageFrame
      title="红蓝自博弈"
      hint="Red Agent 生成对抗场景,Blue Agent 复用 Audit-LLM 流水线实时响应,漏报进入 overlay 课程学习。"
      marginalia="——不自动改生产规则，是底线。"
      extra={
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-[12px] text-ink-faint">
            回合
            <input
              type="number"
              min={2}
              max={30}
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value) || 8)}
              className="ml-2 w-16 border-b border-line bg-transparent text-ink outline-none"
            />
          </label>
          <label className="text-[12px] text-ink-faint flex items-center gap-1" title="勾选后仿真事件进入 ingest，监控页会出现接力卡片与思维链">
            <input type="checkbox" checked={inject} onChange={(e) => setInject(e.target.checked)} />
            注入生产 ingest
          </label>
          <label className="text-[12px] text-ink-faint flex items-center gap-1">
            <input type="checkbox" checked={useLlm} onChange={(e) => {
              const on = e.target.checked
              setUseLlm(on)
              if (on && rounds > 5) setRounds(5)
            }} />
            LLM 规划
          </label>
          <label className="text-[12px] text-ink-faint flex items-center gap-1" title="随机 8–30 主机拓扑,避免蓝队记忆固定 IP">
            <input type="checkbox" checked={diverse} onChange={(e) => setDiverse(e.target.checked)} />
            随机拓扑
          </label>
          <label className="text-[12px] text-ink-faint flex items-center gap-1" title="附加 DNS / 内部 HTTP / 登录等良性背景流量">
            <input type="checkbox" checked={background} onChange={(e) => setBackground(e.target.checked)} />
            背景流量
          </label>
          <Button onClick={start} disabled={busy}>{busy ? '启动中…' : '开一局'}</Button>
          {running && (
            <Button variant="outline" onClick={stop} disabled={busy}>停止</Button>
          )}
        </div>
      }
    >
      {error && <p className="mb-4 text-sm text-ink">{error}</p>}
      <p className="mb-3 text-[13px] text-ink-soft">{liveHint}</p>
      <p className="mb-8 text-[12px] text-ink-faint">
        「注入生产 ingest」默认关闭：不勾选时监控页只有自博弈行，没有审查接力与思维链。勾选后仿真事件标记 _self_play 进入 ingest，不写生产 Sigma。
      </p>
      {useLlm && (
        <p className="mb-6 text-[12px] text-ink-faint">
          LLM 规划会检索 ATT&CK 并编排 2–5 步杀伤链，一局可能数分钟；失败自动回退课程规则。不调用真实攻击工具。
        </p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-6 border border-line mb-10">
        {METRIC_KEYS.map((m) => (
          <div key={m.key} className="p-4 border-r border-b border-line last:border-r-0">
            <div className="text-[11px] tracking-[0.14em] text-ink-faint uppercase">{m.label}</div>
            <div className="mt-2 text-2xl font-black">
              {m.key === 'mttd_ms'
                ? `${Math.round(Number(metrics[m.key] || 0))}ms`
                : pct(metrics[m.key])}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] border border-line mb-10">
        <div className="p-4 border-b lg:border-b-0 lg:border-r border-line">
          <div className="text-[12px] tracking-[0.2em] text-ink-faint mb-2">能力雷达</div>
          <RadarChart values={((detail as any)?.radar || (metrics as any)?.radar || last?.metrics?.radar || {}) as Record<string, number>} />
        </div>
        <div className="p-6 text-[13px] text-ink-soft space-y-2">
          <p>
            本轮目标{' '}
            <span className="text-ink font-medium">
              {(last?.goal?.sub_technique_id || last?.goal?.technique_id || last?.red_plan?.goal?.technique_id || '—')}
            </span>
            {last?.goal?.event_type ? ` · ${last.goal.event_type}` : ''}
          </p>
          <p>
            P(level_clear) {pct(last?.p_level_clear ?? (detail as any)?.capability?.p_level_clear)}
            {' · '}胜者判定用加权综合分,不再只看 ASR/Recall 硬阈值
          </p>
          <p>candidate 规则本回合只评估,验证通过后下一回合才进 overlay 评分。</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 border border-line mb-10">
        <div className="p-6 border-b lg:border-b-0 lg:border-r border-line">
          <div className="text-[12px] tracking-[0.2em] text-ink-faint mb-3">RED AGENT</div>
          <h2 className="text-xl font-black mb-2">攻击规划</h2>
          {redStep ? (
            <>
              <p className="text-sm font-medium">{redStep.name || redStep.event || redStep.event_type}</p>
              <p className="text-[13px] text-ink-soft mt-1">
                {redStep.mitre_id} · {redStep.event || redStep.event_type}
                {redStep.evasion ? ' · 规避变体' : ' · 规范样本'}
              </p>
              <p className="text-[13px] text-ink-soft mt-3 leading-relaxed">
                {redStep.message || last?.red_plan?.rationale || last?.red?.rationale}
              </p>
            </>
          ) : (
            <p className="text-sm text-ink-faint">等待红队出招。</p>
          )}
        </div>
        <div className="p-6">
          <div className="text-[12px] tracking-[0.2em] text-ink-faint mb-3">BLUE AGENT</div>
          <h2 className="text-xl font-black mb-2">检测与学习</h2>
          {blueObs ? (
            <>
              <p className="text-sm font-medium">
                {Array.isArray(blueObs.detected)
                  ? (blueObs.detected[0] ? '检出' : '漏报')
                  : (blueObs.detected ? `检出 · ${blueObs.detector || 'sigma'}` : '漏报,写入 overlay')}
              </p>
              <p className="text-[13px] text-ink-soft mt-1">
                规则 {(blueObs.rule_ids || []).join(', ') || (blueObs.detectors || []).join(', ') || '—'}
              </p>
              <p className="text-[13px] text-ink-soft mt-3">
                本回合学到 {(last?.learned || last?.blue?.learned || []).length} 条候选规则
              </p>
            </>
          ) : (
            <p className="text-sm text-ink-faint">复用 Decomposer → Executor → Reviewer + Sigma。</p>
          )}
        </div>
      </div>

      <div className="mb-10">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-bold">课程等级 L{level} / {maxLevel} · 能力模型升级</h3>
          <span className="text-[12px] text-ink-faint">侦察 → 初始访问 → 执行 → 横向 → C2/外泄 → 规避</span>
        </div>
        <div className="flex gap-1">
          {Array.from({ length: maxLevel + 1 }).map((_, i) => (
            <div
              key={i}
              className={`h-2 flex-1 ${i <= level ? 'bg-ink' : 'bg-qing'}`}
            />
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-8 mb-10">
        <div>
          <h3 className="font-bold mb-3">回合时间线</h3>
          {timeline.length === 0 && <p className="text-sm text-ink-faint">尚无回合。</p>}
          <ol className="border-t border-line">
            {timeline.map((r: any) => (
              <li key={r.round_num} className="py-3 border-b border-line flex items-start gap-4">
                <span className="text-[12px] text-ink-faint w-10">R{r.round_num}</span>
                <span className={`text-[11px] px-2 py-0.5 ${outcomeTone(r.outcome)}`}>{r.outcome}</span>
                <span className="text-[13px] flex-1">
                  {(r.plan?.steps || r.red_plan?.steps || []).map((s: any) => s.event || s.event_type).join(', ') || '—'}
                  {r.learned?.length ? ` · +${r.learned.length} 规则` : ''}
                </span>
                <span className="text-[12px] text-ink-faint">
                  rec {pct(r.metrics?.recall)} · asr {pct(r.metrics?.asr)}
                </span>
              </li>
            ))}
          </ol>
        </div>
        <div>
          <h3 className="font-bold mb-3">对局</h3>
          <ul className="border border-line divide-y divide-line">
            {matches.length === 0 && <li className="p-3 text-sm text-ink-faint">暂无</li>}
            {matches.map((m) => (
              <li key={m.match_id}>
                <button
                  className={`w-full text-left p-3 text-[13px] ${activeId === m.match_id ? 'bg-ink text-white' : 'hover:bg-mist'}`}
                  onClick={() => selectMatch(m.match_id)}
                >
                  <div className="font-mono text-[12px]">{m.match_id}</div>
                  <div className="mt-1 opacity-80">
                    {m.status} · L{m.level ?? m.curriculum_level ?? 0} · {m.winner || '—'}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-bold">学到的规则(审核 Agent → shadow YAML)</h3>
            <Button
              variant="outline"
              className="h-8 text-[12px]"
              disabled={busy}
              onClick={async () => {
                setBusy(true)
                setError('')
                try {
                  await api.selfPlayReviewRun(20)
                  await loadSide()
                } catch (e: any) {
                  setError(e?.message || '审核失败(需要登录)')
                } finally {
                  setBusy(false)
                }
              }}
            >
              跑审核
            </Button>
          </div>
          <ul className="border border-line divide-y divide-line max-h-80 overflow-auto">
            {rules.length === 0 && <li className="p-3 text-sm text-ink-faint">对局漏报后会出现在这里。</li>}
            {rules.slice(0, 20).map((r) => (
              <li key={r.id} className="p-3 text-[13px]">
                <div className="font-medium">{r.title}</div>
                <div className="text-ink-faint mt-1">
                  {r.rule_id} · {r.mitre_id || '—'} · {r.status}
                  {r.review_report?.failed?.length ? ` · 未过 ${r.review_report.failed.join(',')}` : ''}
                </div>
              </li>
            ))}
          </ul>
          {hist && (
            <p className="mt-3 text-[12px] text-ink-faint">
              历史 {hist.matches || 0} 局 · 蓝胜 {hist.winners?.blue || 0} · 红胜 {hist.winners?.red || 0} ·
              均 recall {pct(hist.avg_recall)}
            </p>
          )}
        </div>
        <div>
          <h3 className="font-bold mb-3">仿真拓扑(隔离,无真实利用)</h3>
          <div className="border border-line p-4 text-[12px] grid grid-cols-2 gap-2">
            {hosts.map((h: any) => (
              <div key={h.id} className="flex justify-between border-b border-line py-1">
                <span>{h.id}</span>
                <span className="text-ink-faint">{h.ip} · {h.zone}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[12px] text-ink-faint">
            课程 {catalog?.curriculum_count ?? ttps.length} 条金标 · Enterprise 父技术 {catalog?.enterprise_count ?? '—'} 条。
            默认走课程;勾选 LLM 规划后按 RAG 候选编排多步链。
          </p>
        </div>
      </div>
    </PageFrame>
  )
}
