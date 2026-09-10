import { useState, useEffect, useRef, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { BrandCrest } from '../components/brand/BrandCrest'
import { PageTransition } from '../components/common/PageTransition'
import { ShiftConsole } from '../components/home/ShiftConsole'
import { EventTicker } from '../components/home/EventTicker'
import { Blueprint } from '../components/home/Blueprint'
import { ROUTES } from '../lib/constants'
import { BRAND } from '../lib/brand'
import { formatWatchClock, watchShiftAt } from '../lib/watchShift'
import { api } from '../lib/api'

const capabilities = [
  {
    path: ROUTES.LOGS,
    tag: 'I',
    label: '日志中心',
    title: '每一次访问，都被记录。',
    desc: '多源安全日志实时接入，按级别、来源、目标全维度追踪。',
  },
  {
    path: ROUTES.SECURITY_AUDIT,
    tag: 'II',
    label: '智能审计',
    title: '四层 Agent，层层把关。',
    desc: '分解、构建、执行、复核。CAD 独立监督，防幻觉熔断。',
  },
  {
    path: ROUTES.RESPONSE,
    tag: 'III',
    label: '响应引擎',
    title: '发现威胁，即刻阻断。',
    desc: '策略匹配后封禁、隔离、限速。高危走审批，全程可回滚。',
  },
  {
    path: ROUTES.RAG,
    tag: 'IV',
    label: '知识库',
    title: 'MITRE ATT&CK 加持。',
    desc: '攻击战术与响应预案检索，给每一次审计提供依据。',
  },
  {
    path: ROUTES.SELF_PLAY,
    tag: 'V',
    label: '红蓝自博弈',
    title: '红队出招，蓝队进化。',
    desc: '按 ATT&CK 生成对抗，漏报回到检测，不自动改生产规则。',
  },
]

const capabilityTiers = [
  {
    tier: '一',
    name: '感知',
    subtitle: '规则驱动',
    features: ['Sigma 规则', 'Flink CEP 攻击链', '因果图', '多维异常评分'],
  },
  {
    tier: '二',
    name: '研判',
    subtitle: 'LLM 驱动',
    features: ['四层 Audit-LLM', 'RAG 检索', 'Grounding 验证', 'CAD 监督'],
  },
  {
    tier: '三',
    name: '处置',
    subtitle: '闭环自治',
    features: ['真实防火墙操作', '六层安全执行', 'TTL 自动解封', '误报抑制'],
  },
  {
    tier: '四',
    name: '进化',
    subtitle: '红蓝自博弈',
    features: ['红队课程', '蓝队闭环', '漏报写入 overlay', '论文级指标'],
  },
]

function SectionRule({
  num,
  label,
  hint,
  marginalia,
  children,
  last = false,
}: {
  num: string
  label: string
  hint?: string
  marginalia?: string
  children: ReactNode
  last?: boolean
}) {
  return (
    <section
      className={`relative grid grid-cols-1 gap-10 py-14 md:grid-cols-[180px_1fr] md:gap-16 md:py-16 ${
        last ? '' : 'border-b border-line'
      }`}
    >
      <header className="md:pt-1">
        <p className="font-serif text-[44px] font-black leading-none text-ink tabular-nums">
          {num}
        </p>
        <h2 className="mt-4 font-serif text-[22px] font-black tracking-[-0.02em] text-ink">
          {label}
        </h2>
        {hint && (
          <p className="mt-2 text-[12px] leading-relaxed text-ink-soft max-w-[14rem]">
            {hint}
          </p>
        )}
        {marginalia && (
          <p className="mt-6 font-serif italic text-[12px] leading-relaxed text-ink-faint max-w-[12rem] hidden md:block">
            <span aria-hidden className="mr-1 text-ink-faint">¶</span>
            {marginalia}
          </p>
        )}
      </header>
      <div className="min-w-0">{children}</div>
    </section>
  )
}

export default function Home() {
  const navigate = useNavigate()
  const [recentLogs, setRecentLogs] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [attackCount, setAttackCount] = useState(0)
  const [now, setNow] = useState(() => new Date())
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    api.logsEvents({ limit: '8' }).then((d) => setRecentLogs(Array.isArray(d) ? d : [])).catch(() => {})
    api.stats().then(setStats).catch(() => {})

    const es = api.eventsStream()
    if (!es) return
    esRef.current = es
    const onSecurity = (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data)
        if (d.is_anomaly) setAttackCount((c) => c + 1)
      } catch { /* noop */ }
    }
    const onAudit = (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data)
        if (d.threat_detected) setAttackCount((c) => c + 2)
      } catch { /* noop */ }
    }
    es.addEventListener('security_event', onSecurity)
    es.addEventListener('audit_complete', onAudit)
    return () => es.close()
  }, [])

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])

  const audited = stats?.audit_llm?.completed ?? 0
  const total = stats?.security_events ?? 0
  const pending = stats?.security_pending ?? 0
  const memories = stats?.memories_count ?? 0
  const responseMs = stats?.audit_llm?.response_ms_median ?? stats?.response_ms_median ?? 240

  const shift = watchShiftAt(now)
  const clock = formatWatchClock(now)
  // 派生：本小时均值 = 总量 / 当前小时位移
  const hourFraction = Math.max(0.25, (now.getHours() + now.getMinutes() / 60) || 1)
  const perHour = Math.round(total / hourFraction)
  // 派生：下次交接班次 + 剩余小时
  const handoffAtHour = shift.night ? 5 : 19
  const hoursUntilHandoff = (() => {
    const cur = now.getHours() + now.getMinutes() / 60
    const diff = handoffAtHour - cur
    return diff > 0 ? diff : diff + 24
  })()
  const nextShiftName = shift.night ? '卯时 · 平旦' : '戌时 · 一更'

  return (
    <PageTransition>
      <div className="bg-surface text-ink">
        {/* ======================== Hero · 机要室 · 电影感 ======================== */}
        <section className="vault vault-concentric relative overflow-hidden">
          <div className="vault-light" aria-hidden />

          <div className="page-shell relative z-10 grid items-end gap-12 pt-6 pb-14 lg:grid-cols-[minmax(0,1.1fr)_minmax(420px,0.9fr)] lg:gap-20 lg:pt-8 lg:pb-16">
            {/* 左：标题 + 拉句 + CTA */}
            <div>
              {/* 顶栏：紧凑 shift status 区 —— 不用大型圆形徽章 */}
              <div className="fade-up-soft flex items-center gap-4">
                <span className="live-arc live-arc-lg text-[#c9a574]" aria-hidden />
                <div className="flex items-baseline gap-4 border-l border-[rgba(201,165,116,0.35)] pl-4">
                  <span className="font-mono text-[10px] tracking-[0.28em] uppercase text-[#c9a574] font-semibold">
                    Now in Service
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.28em] uppercase text-[rgba(216,222,224,0.55)]">
                    · {clock} Local
                  </span>
                </div>
              </div>

              {/* 字标：级联揭示 */}
              <h1
                aria-label="守望"
                className="mt-8 text-[#f5ecd8] flex items-baseline"
                style={{
                  fontFamily: 'var(--font-serif)',
                  fontWeight: 900,
                  lineHeight: 0.86,
                  letterSpacing: '-0.04em',
                  textShadow: '0 2px 60px rgba(0,0,0,0.6)',
                }}
              >
                <span className="glyph glyph-1 text-[120px] sm:text-[160px] lg:text-[200px]">守</span>
                <span className="glyph glyph-2 text-[120px] sm:text-[160px] lg:text-[200px] ml-1 sm:ml-2">望</span>
              </h1>

              {/* 大号斜体拉句 */}
              <p className="fade-up-soft mt-7 max-w-2xl font-serif italic text-[24px] leading-[1.45] text-[#f1e8d6] md:text-[30px] md:leading-[1.4]">
                在寂静里守候，让每一个威胁被察觉、被理解、被挡住。
              </p>
              <p className="fade-up-soft mt-3 max-w-2xl font-serif text-[15px] leading-relaxed text-[rgba(216,222,224,0.85)]">
                {BRAND.tagline}
              </p>

              {/* CTA */}
              <div className="fade-up-soft mt-12 flex flex-wrap items-center gap-5">
                <button
                  type="button"
                  onClick={() => navigate(ROUTES.LOGS)}
                  className="btn-prime"
                >
                  进入值班台
                  <span className="prime-mark" aria-hidden>→</span>
                </button>
                <button
                  type="button"
                  onClick={() => navigate(ROUTES.MONITOR)}
                  className="btn-ghost"
                >
                  <span>实时事件流</span>
                  <span aria-hidden>↗</span>
                </button>
              </div>

              {/* 底部 meta 行 */}
              <div className="fade-up-soft mt-14 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-[rgba(201,165,116,0.35)] pt-6 sm:grid-cols-4">
                <FooterField k="SOC" v="自主安全运营" />
                <FooterField k="STACK" v="Kafka · Flink · LLM" />
                <FooterField k="OPS" v="四层 + CAD" />
                <FooterField k="MODE" v="红蓝自博弈" />
              </div>
            </div>

            {/* 右：控制台 */}
            <div className="relative">
              <ShiftConsole
                ingested={total}
                pending={pending}
                audited={audited}
                memories={memories}
                attackCount={attackCount}
                shiftLabel={shift.night ? shift.label : `${shift.earthly}时 · ${shift.label}`}
                clock={clock}
                perHour={perHour}
                responseMs={responseMs}
              />
              <div className="fade-up-soft mt-4 flex items-center justify-between border-t border-[rgba(201,165,116,0.12)] pt-3">
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[rgba(216,222,224,0.55)]">
                  {BRAND.nameEn} · Night Watch SOC
                </p>
                <p className="font-mono text-[10px] tabular-nums tracking-[0.26em] uppercase text-[#c9a574]">
                  v3.1
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ======================== 横向 telemetry ticker ======================== */}
        <EventTicker events={recentLogs} attackCount={attackCount} />

        {/* ======================== Pull Quote 拉句 ======================== */}
        <section className="bg-paper border-b border-line">
          <div className="page-shell grid grid-cols-1 gap-10 py-14 md:grid-cols-[180px_1fr] md:gap-16 md:py-16">
            <div className="md:pt-3">
              <p className="font-serif text-[44px] font-black leading-none text-ink tabular-nums">
                ¶
              </p>
              <p className="mt-4 font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
                Pull Quote
              </p>
            </div>
            <div className="max-w-3xl">
              <p className="font-serif italic text-[28px] leading-[1.4] text-ink md:text-[36px] md:leading-[1.32] tracking-[-0.01em]">
                「我们不预测下一次攻击。我们确保，每一次攻击被发现时，下一秒它已无处可逃。」
              </p>
              <div className="mt-8 flex items-center gap-4">
                <span className="h-px w-12 bg-[#c9a574]" />
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-soft">
                  Platform Charter · 守望约章
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ======================== 主体 · 纸面案卷 ======================== */}
        <div className="page-shell">
          <SectionRule
            num="I"
            label="此刻 · 现在"
            hint="平台的实时运行态势 —— 数据每 1s 跳动。"
            marginalia="——所有判断，从看见这一刻开始。"
          >
            <div className="grid stagger-in gap-x-10 gap-y-10 sm:grid-cols-2 xl:grid-cols-4">
              <KpiCell label="待处理" value={pending} hint={pending > 0 ? '等待复核或自动处置' : '队列已清空'} hero={pending > 0} />
              <KpiCell label="已完成审计" value={audited} hint={`${audited}/${total || 0} · ${total > 0 ? Math.round((audited / total) * 100) : 0}%`} />
              <KpiCell label="已接入事件" value={total} hint="实时接入总量" />
              <KpiCell label="语义记忆" value={memories} hint="RAG 知识沉淀" />
            </div>
          </SectionRule>

          <SectionRule
            num="II"
            label="能力 · 守望"
            hint="从日志采集到红蓝进化，五条主航道。"
            marginalia="——五条主航道，不重叠。"
          >
            <div className="divide-y divide-line border-y border-line">
              {capabilities.map((cap) => (
                <button
                  key={cap.path}
                  onClick={() => navigate(cap.path)}
                  className="cap-row group relative grid w-full grid-cols-[4rem_8rem_1fr_auto] items-baseline gap-6 py-6 text-left"
                >
                  <span aria-hidden className="cap-reveal" />
                  <span className="cap-num font-serif text-[20px] font-black tabular-nums self-center">
                    {cap.tag}
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint self-center">
                    {cap.label}
                  </span>
                  <span>
                    <span className="block font-serif text-[20px] font-bold text-ink">
                      {cap.title}
                    </span>
                    <span className="mt-1 block text-[13px] leading-relaxed text-ink-soft">
                      {cap.desc}
                    </span>
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint group-hover:text-ink self-center whitespace-nowrap">
                    打开
                  </span>
                </button>
              ))}
            </div>
          </SectionRule>
        </div>

        {/* §III 层次 — vault 深底（在 page-shell 外才能全宽） */}
        <section className="tier-vault relative overflow-hidden">
          <div className="page-shell grid grid-cols-1 gap-10 py-16 md:grid-cols-[180px_1fr] md:gap-16 md:py-20">
            <header className="md:pt-1">
              <p className="font-serif text-[44px] font-black leading-none text-[#c9a574] tabular-nums">
                III
              </p>
              <h2 className="mt-4 font-serif text-[22px] font-black tracking-[-0.02em] text-[rgba(241,232,214,0.95)]">
                层次 · 自下而上
              </h2>
              <p className="mt-2 text-[12px] leading-relaxed text-[rgba(216,222,224,0.6)] max-w-[14rem]">
                感知 → 研判 → 处置 → 进化，四层闭环自治。
              </p>
              <p className="mt-6 font-serif italic text-[12px] leading-relaxed text-[rgba(216,222,224,0.7)] max-w-[12rem] hidden md:block">
                <span aria-hidden className="mr-1 text-[#c9a574]">¶</span>
                ——越往上，越需要解释；越往下，越需要速度。
              </p>
            </header>
            <div className="relative grid grid-cols-2 gap-x-6 gap-y-8 md:grid-cols-4 md:gap-x-4">
              {capabilityTiers.map((tier, i) => (
                <div key={tier.tier} className="relative flex flex-col gap-4 pt-7">
                  <div className="flex items-baseline justify-between border-t border-[rgba(201,165,116,0.45)] pt-4">
                    <span className="font-serif text-[44px] font-black leading-none text-[#c9a574] tabular-nums tracking-[-0.04em]">
                      {tier.tier}
                    </span>
                    <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-[rgba(216,222,224,0.7)]">
                      Tier {i + 1}
                    </span>
                  </div>
                  <div>
                    <p className="font-serif text-[22px] font-bold tracking-tight text-[#f1e8d6]">
                      {tier.name}
                    </p>
                    <p className="mt-1 font-mono text-[10px] tracking-[0.22em] uppercase text-[rgba(216,222,224,0.75)]">
                      {tier.subtitle}
                    </p>
                  </div>
                  <ul className="mt-1 space-y-1.5">
                    {tier.features.map((f) => (
                      <li key={f} className="flex items-baseline gap-2 text-[13px] leading-relaxed text-[rgba(241,232,214,0.7)]">
                        <span className="font-mono text-[10px] text-[rgba(216,222,224,0.6)] tabular-nums">
                          {String(i + 1).padStart(2, '0')}.
                        </span>
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="page-shell">
          <SectionRule
            num="IV"
            label="流程 · 一张图"
            hint="数据从日志源到进化的全程。"
            marginalia="——一张能讲清楚系统的图，比一千行说明更可靠。"
          >
            <div>
              <div className="flex items-end justify-between mb-5">
                <p className="font-serif text-[20px] font-bold tracking-tight">
                  系统架构蓝图
                </p>
                <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
                  Fig. 04 · Data Journey
                </p>
              </div>
              <Blueprint />
              <div className="mt-5 flex items-center justify-between font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
                <span>Ingest → Evolve</span>
                <span>实线 · 数据 / 虚线 · 反馈</span>
              </div>
            </div>
          </SectionRule>

          <SectionRule
            num="V"
            label="约章 · Manifesto"
            hint="我们对 SOC 工作的判断。"
            marginalia="——给正在或打算做安全的同行。"
          >
            <div className="max-w-3xl">
              <p className="font-serif text-[20px] leading-[1.65] text-ink drop-cap">
                守望不相信「AI 让安全更简单」。AI 让攻击更便宜，AI 让响应更慢，AI 让审计更复杂；它改变的是节奏，不是难度。
              </p>
              <p className="mt-7 font-serif text-[18px] leading-[1.7] text-ink-soft">
                我们相信的是另一套东西：<span className="font-bold text-ink">规则先于模型，证据先于解释。</span>一条高确定性的 Sigma 规则，永远比一千次模糊的 LLM 推断更可靠。四层审计的意义，是把每一条结论拆到可被穿透验证；CAD 的意义，是承认 LLM 会撒谎，所以需要一道独立监督。
              </p>
              <p className="mt-5 font-serif text-[18px] leading-[1.7] text-ink-soft">
                我们的目标不是预测下一次攻击，是确保每一次攻击被发现时，下一秒它已无处可逃。<span className="font-bold text-ink">确定性优先于聪明，透明优先于能力。</span>
              </p>

              <div className="mt-10 flex items-center gap-6 border-t border-line pt-5">
                <BrandCrest size={40} tone="paper" />
                <div>
                  <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
                    Filed · 2026.09.09
                  </p>
                  <p className="mt-1 font-serif italic text-[13px] text-ink-soft">
                    守望 · Platform Charter
                  </p>
                </div>
              </div>
            </div>
          </SectionRule>

          <SectionRule
            num="VI"
            label="值守交接 · Shift Handoff"
            hint="当下班次、下次交接、当班要点。"
            marginalia="——每一次交接，都是一道审计。"
            last
          >
            <div className="grid gap-10 md:grid-cols-3">
              <HandoffCard
                tag="当前"
                title={shift.night ? shift.label : `${shift.earthly}时`}
                meta={shift.night ? '夜巡' : '白昼'}
                body={BRAND.tagline}
                accent="vault"
              />
              <HandoffCard
                tag="下次交接"
                title={nextShiftName}
                meta={`${hoursUntilHandoff.toFixed(1)} 小时后`}
                body="未处置工单将自动跟随班次流转。"
                accent="paper"
              />
              <HandoffCard
                tag="当班要点"
                title={`${pending} 件待复核`}
                meta={attackCount > 0 ? '当前有攻击脉冲' : '当前无活跃威胁'}
                body="建议在交接前确认 CAD 复核通过、响应链 TTL 状态、误报抑制覆盖。"
                accent="paper"
              />
            </div>
          </SectionRule>
        </div>

        <footer className="relative overflow-hidden border-t border-line bg-[#0e1a26] text-[#d8dee0]">
          {/* 中央徽记水印 */}
          <div
            aria-hidden
            className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 opacity-[0.04]"
          >
            <BrandCrest size={520} tone="dark" />
          </div>

          {/* 封底刊头 */}
          <div className="page-shell relative z-10 flex flex-col items-center gap-6 border-b border-[rgba(201,165,116,0.12)] py-14 md:py-20">
            <BrandCrest size={140} tone="dark" />
            <p className="font-serif text-[64px] font-black tracking-[-0.05em] leading-none text-[#f1e8d6] md:text-[88px]">
              守望
            </p>
            <p className="font-mono text-[10px] tracking-[0.36em] uppercase text-[#c9a574]">
              Night Watch SOC · Edition {new Date().getFullYear()}
            </p>
            <p className="mt-2 max-w-md text-center font-serif italic text-[16px] leading-relaxed text-[rgba(216,222,224,0.7)]">
              「灯火未熄。每一条日志，都在被守望。」
            </p>
          </div>

          {/* 主体：刊尾 + 跳读 + 系统 */}
          <div className="page-shell relative z-10 grid gap-10 py-12 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1fr)] md:gap-16 md:py-16">
            {/* 刊尾宣言 */}
            <div>
              <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#c9a574]">
                Colophon · 刊尾
              </p>
              <p className="mt-4 max-w-sm font-serif text-[15px] leading-[1.7] text-[rgba(241,232,214,0.85)]">
                自 2026 年起，每一条日志在每一班次里被守望。本卷以「案卷深室」为制式：黛墨主字、暮青动作、朱砂留险、暮金置铭。
              </p>
              <div className="mt-6 h-px w-12 bg-[rgba(201,165,116,0.4)]" />
              <p className="mt-4 font-mono text-[10px] tracking-[0.22em] uppercase text-[#c9a574]">
                Platform Charter
              </p>
            </div>

            {/* 跳读 */}
            <div>
              <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#c9a574]">
                Skip To · 跳读
              </p>
              <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3">
                <FooterLink k="值班" v="监控" onClick={() => navigate(ROUTES.MONITOR)} />
                <FooterLink k="日志" v="日志中心" onClick={() => navigate(ROUTES.LOGS)} />
                <FooterLink k="审计" v="安全审计" onClick={() => navigate(ROUTES.SECURITY_AUDIT)} />
                <FooterLink k="响应" v="响应引擎" onClick={() => navigate(ROUTES.RESPONSE)} />
                <FooterLink k="运营" v="运营中心" onClick={() => navigate(ROUTES.OPERATIONS)} />
                <FooterLink k="知识" v="RAG 库" onClick={() => navigate(ROUTES.RAG)} />
              </div>
            </div>

            {/* 系统刊头 */}
            <div>
              <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-[#c9a574]">
                Masthead · 系统
              </p>
              <dl className="mt-4 grid grid-cols-[5rem_1fr] gap-x-3 gap-y-2 text-[12px]">
                <dt className="font-mono tracking-[0.2em] uppercase text-[#c9a574]">Bus</dt>
                <dd className="text-[rgba(216,222,224,0.85)]">Kafka 3.7 · KRaft</dd>
                <dt className="font-mono tracking-[0.2em] uppercase text-[#c9a574]">Stream</dt>
                <dd className="text-[rgba(216,222,224,0.85)]">Flink 1.19.3 · CEP</dd>
                <dt className="font-mono tracking-[0.2em] uppercase text-[#c9a574]">Audit</dt>
                <dd className="text-[rgba(216,222,224,0.85)]">四层 Agent + CAD</dd>
                <dt className="font-mono tracking-[0.2em] uppercase text-[#c9a574]">Evolve</dt>
                <dd className="text-[rgba(216,222,224,0.85)]">红蓝自博弈</dd>
                <dt className="font-mono tracking-[0.2em] uppercase text-[#c9a574]">Stack</dt>
                <dd className="text-[rgba(216,222,224,0.85)]">React 19 · Tailwind 4 · Three</dd>
              </dl>
            </div>
          </div>

          {/* 底部：版权 + 排版 + 期号 */}
          <div className="relative z-10 border-t border-[rgba(201,165,116,0.12)]">
            <div className="page-shell flex flex-col gap-3 py-6 text-[11px] text-[rgba(216,222,224,0.45)] sm:flex-row sm:items-center sm:justify-between">
              <p className="font-mono tracking-[0.2em] uppercase">
                © Shouwang SOC · MMXXVI
              </p>
              <p className="font-mono tracking-[0.2em] uppercase">
                Set in Noto Serif SC · IBM Plex Mono
              </p>
              <p className="font-mono tracking-[0.2em] uppercase tabular-nums">
                NODE · {BRAND.nameEn}
              </p>
            </div>
          </div>
        </footer>
      </div>
    </PageTransition>
  )
}

function KpiCell({
  label,
  value,
  hint,
  hero = false,
}: {
  label: string
  value: number
  hint?: string
  hero?: boolean
}) {
  return (
    <div className={hero ? 'relative pl-4 border-l border-[#0e1a26]' : ''}>
      <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
        {label}
      </p>
      <p className="mt-2 font-serif text-[44px] font-black leading-[0.95] tracking-[-0.04em] text-ink tabular-nums">
        {value.toLocaleString()}
      </p>
      {hint && (
        <p className="mt-2 text-[12px] text-ink-faint">{hint}</p>
      )}
    </div>
  )
}

function FooterField({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <p className="font-mono text-[10px] tracking-[0.28em] uppercase text-[#c9a574]">
        {k}
      </p>
      <p className="mt-1.5 font-serif text-[14px] font-bold text-[#f1e8d6] leading-tight">
        {v}
      </p>
    </div>
  )
}

function FooterLink({ k, v, onClick }: { k: string; v: string; path?: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} className="group text-left">
      <p className="font-mono text-[10px] tracking-[0.28em] uppercase text-[#c9a574]/85 group-hover:text-[#c9a574]">
        {k}
      </p>
      <p className="mt-1 font-serif text-[14px] text-[rgba(241,232,214,0.85)] group-hover:text-[#c9a574]">
        {v}
      </p>
    </button>
  )
}

function HandoffCard({
  tag,
  title,
  meta,
  body,
  accent,
}: {
  tag: string
  title: string
  meta: string
  body: string
  accent: 'vault' | 'paper'
}) {
  const isVault = accent === 'vault'
  return (
    <div
      className={`relative border ${
        isVault ? 'bg-[#0e1a26] text-[#d8dee0] border-[#0e1a26]' : 'bg-paper border-line text-ink'
      } p-7`}
    >
      <p
        className={`font-mono text-[10px] tracking-[0.26em] uppercase ${
          isVault ? 'text-[#c9a574]' : 'text-ink-faint'
        }`}
      >
        {tag}
      </p>
      <p
        className={`mt-3 font-serif text-[28px] font-black tracking-[-0.02em] leading-tight ${
          isVault ? 'text-[#f1e8d6]' : 'text-ink'
        }`}
      >
        {title}
      </p>
      <p
        className={`mt-2 font-mono text-[10px] tracking-[0.22em] uppercase ${
          isVault ? 'text-[rgba(216,222,224,0.5)]' : 'text-ink-faint'
        }`}
      >
        {meta}
      </p>
      <p
        className={`mt-5 text-[13px] leading-relaxed ${
          isVault ? 'text-[rgba(216,222,224,0.7)]' : 'text-ink-soft'
        }`}
      >
        {body}
      </p>
      <span
        aria-hidden
        className={`absolute right-5 top-5 font-mono text-[10px] tracking-[0.22em] uppercase ${
          isVault ? 'text-[#c9a574]/80' : 'text-ink-faint/60'
        }`}
      >
        06
      </span>
    </div>
  )
}