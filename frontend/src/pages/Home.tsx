import { useState, useEffect, useRef, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import ThreatNetwork from '../components/hero/ThreatNetwork'
import PhishingDetect from '../components/phishing/PhishingDetect'
import { Button, TextLink } from '../components/ui/Button'
import { GlassPanel } from '../components/ui/GlassPanel'
import { PageTransition } from '../components/common/PageTransition'
import { spring, ROUTES } from '../lib/constants'
import { api } from '../lib/api'

const reveal = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-60px' },
  transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const },
}

const capabilities = [
  {
    path: ROUTES.LOGS,
    tag: '日志中心',
    title: '每一次访问，都被记录。',
    desc: '多源安全日志实时接入，按级别、来源、目标全维度追踪，审计状态一目了然。',
  },
  {
    path: ROUTES.SECURITY_AUDIT,
    tag: '智能审计',
    title: '四层 Agent，层层把关。',
    desc: '分解、构建、执行、复核。Audit-LLM 流水线交叉验证，CAD 独立监督防幻觉。',
  },
  {
    path: ROUTES.RESPONSE,
    tag: '响应引擎',
    title: '发现威胁，即刻阻断。',
    desc: '策略匹配自动执行防火墙封禁、主机隔离与限速，高危操作走审批，全程可回滚。',
  },
  {
    path: ROUTES.RAG,
    tag: '知识库',
    title: 'MITRE ATT&CK 加持。',
    desc: '内置攻击战术与响应预案，RAG 检索增强为每一次审计提供权威知识支撑。',
  },
]

const capabilityTiers = [
  {
    tier: 'L1',
    name: '基础感知层',
    subtitle: '规则驱动 · 实时检测',
    features: [
      { name: 'Sigma 规则引擎', desc: '11 条规则覆盖 8 类攻击，<1ms 延迟' },
      { name: 'Flink CEP 攻击链', desc: '3 种模式实时检测 (端口扫描→C2 / 横向移动 / 数据外泄)' },
      { name: '多维异常评分', desc: '频率 + 严重度 + 时段三维评分，智能分级路由' },
      { name: '数据源认证', desc: 'API Key 白名单 + SCRAM-SHA-512 + TLS 加密' },
    ],
  },
  {
    tier: 'L2',
    name: '智能研判层',
    subtitle: 'LLM 驱动 · 深度分析',
    features: [
      { name: 'Audit-LLM 四层流水线', desc: 'Decomposer→ToolBuilder→Executor→Reviewer 交叉验证' },
      { name: 'RAG 知识增强', desc: 'MITRE ATT&CK + CAPEC 向量检索 + LLM 重排' },
      { name: 'Grounding 7 层验证', desc: '字段溯源 + 实体一致性 + 知识库交叉 + 证据新鲜度' },
      { name: 'CAD 独立监督', desc: '穿透验证 + 上下文审计 + 熔断器保护' },
    ],
  },
  {
    tier: 'L3',
    name: '自主处置层',
    subtitle: '零干预 · 闭环自治',
    features: [
      { name: '自动响应执行', desc: 'SSH + iptables 真实防火墙操作，8 策略 5 动作' },
      { name: '6 层安全执行器', desc: '命令白名单→参数校验→资产保护→幂等→模式→权限' },
      { name: 'TTL 自动解封', desc: '临时封禁到期自动回滚，无需人工干预' },
      { name: '反馈闭环优化', desc: '处置结果回灌检测引擎，误报抑制、漏报补偿' },
    ],
  },
]

const pipeline = [
  { step: '01', name: '接入', desc: '日志实时采集' },
  { step: '02', name: '审计', desc: 'Audit-LLM 分析' },
  { step: '03', name: '响应', desc: '自动封禁隔离' },
  { step: '04', name: '复盘', desc: 'CAD 穿透验证' },
]

const sevTone: Record<string, string> = {
  critical: 'bg-ink text-white',
  high: 'bg-nong text-white',
  medium: 'bg-hui text-white',
  low: 'bg-qing text-ink',
  info: 'bg-mist text-ink-soft',
}

function SpecRow({
  label,
  children,
  last = false,
}: {
  label: string
  children: ReactNode
  last?: boolean
}) {
  return (
    <div
      className={`grid grid-cols-1 md:grid-cols-[120px_1fr] gap-4 md:gap-12 py-10 ${
        last ? '' : 'border-b border-line'
      }`}
    >
      <div className="text-[13px] text-ink-faint pt-1">{label}</div>
      <div>{children}</div>
    </div>
  )
}

export default function Home() {
  const navigate = useNavigate()
  const [recentLogs, setRecentLogs] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [attackCount, setAttackCount] = useState(0)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    api.logsEvents({ limit: '6' }).then((d) => setRecentLogs(Array.isArray(d) ? d : [])).catch(() => {})
    api.stats().then(setStats).catch(() => {})

    const es = api.eventsStream()
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

  const audited = stats?.audit_llm?.completed ?? 0
  const total = stats?.security_events ?? 0
  const pending = stats?.security_pending ?? 0
  const memories = stats?.memories_count ?? 0
  const progress = total > 0 ? Math.min(100, Math.round((audited / total) * 100)) : 0

  return (
    <PageTransition>
      <div className="bg-surface">
        {/* 英雄区 — 对齐参考图刊头 */}
        <section className="page-shell pt-20 pb-16 text-center border-b border-line">
          <h1 className="text-[44px] md:text-[56px] font-black tracking-tight text-ink leading-none">
            共享记忆
          </h1>
          <p className="mt-4 text-[12px] font-light tracking-[0.38em] text-ink-faint uppercase">
            Shared Memory · Security Audit
          </p>
          <div className="rule-ink mx-auto mt-5 mb-6" />
          <p className="text-[15px] font-light text-ink-soft max-w-xl mx-auto leading-relaxed">
            舍弃喧嚣，只留判断。从黑到白的灰阶，静默地承载每一次威胁的重量。
            字重的对比取代色彩的区分，网格的秩序定义每一处精确的位置。
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Button onClick={() => navigate(ROUTES.LOGS)}>进入控制台</Button>
            <Button variant="outline" onClick={() => navigate(ROUTES.MONITOR)}>
              了解系统
            </Button>
            <Button variant="underline" onClick={() => navigate(ROUTES.SECURITY_AUDIT)}>
              阅读审计
            </Button>
            <Button variant="ghost" onClick={() => navigate(ROUTES.RAG)}>
              更多
            </Button>
          </div>
        </section>

        <div className="page-shell">
          <SpecRow label="态势">
            <div className="border border-line">
              <ThreatNetwork attackCount={attackCount} />
            </div>
          </SpecRow>

          <SpecRow label="数据">
            <motion.div {...reveal} className="grid grid-cols-2 md:grid-cols-4">
              {[
                { value: total, label: '安全事件已接入' },
                { value: audited, label: '事件完成审计' },
                { value: pending, label: '待处理队列' },
                { value: memories, label: '语义记忆条数' },
              ].map((item, i) => (
                <div
                  key={item.label}
                  className={`px-2 py-2 ${i < 3 ? 'md:border-r border-line' : ''} ${i % 2 === 0 ? 'border-r md:border-r' : ''} ${i < 2 ? 'border-b md:border-b-0 border-line' : ''}`}
                >
                  <p className="text-4xl font-black tabular-nums tracking-tight text-ink">{item.value}</p>
                  <p className="mt-2 text-[12px] font-light text-ink-faint">{item.label}</p>
                </div>
              ))}
            </motion.div>
          </SpecRow>

          <SpecRow label="进度">
            <div className="flex items-center gap-6">
              <div className="relative w-14 h-14 shrink-0">
                <svg viewBox="0 0 36 36" className="w-14 h-14 -rotate-90">
                  <circle cx="18" cy="18" r="15.5" fill="none" stroke="#e6e6e6" strokeWidth="2" />
                  <circle
                    cx="18"
                    cy="18"
                    r="15.5"
                    fill="none"
                    stroke="#111"
                    strokeWidth="2"
                    strokeDasharray={`${progress} 100`}
                    strokeLinecap="butt"
                  />
                </svg>
                <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold">
                  {progress}%
                </span>
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] tracking-[0.2em] font-medium">AUDIT PROGRESS</span>
                  <span className="text-[12px] text-ink-faint">{audited} / {total || 0}</span>
                </div>
                <div className="h-px bg-line relative">
                  <div className="absolute left-0 top-0 h-px bg-ink" style={{ width: `${progress}%` }} />
                </div>
              </div>
            </div>
          </SpecRow>

          <SpecRow label="能力">
            <motion.div {...reveal}>
              <p className="text-[22px] font-black mb-6">一个平台，全栈安全。</p>
              <div className="grid md:grid-cols-2 gap-0 border border-line">
                {capabilities.map((cap, i) => (
                  <button
                    key={cap.path}
                    onClick={() => navigate(cap.path)}
                    className={`text-left p-7 hover:bg-mist/60 transition-colors ${
                      i % 2 === 0 ? 'md:border-r border-line' : ''
                    } ${i < 2 ? 'border-b border-line' : ''}`}
                  >
                    <p className="text-[12px] font-light text-ink-faint mb-2">{cap.tag}</p>
                    <h3 className="text-[18px] font-bold text-ink mb-2">{cap.title}</h3>
                    <p className="text-[13px] font-light text-ink-soft leading-relaxed">{cap.desc}</p>
                    <span className="inline-block mt-4 text-[13px] border-b-2 border-ink pb-0.5">进入</span>
                  </button>
                ))}
              </div>
            </motion.div>
          </SpecRow>
        </div>

        <PhishingDetect />

        <div className="page-shell">
          <SpecRow label="架构">
            <motion.div {...reveal}>
              <p className="text-[22px] font-black mb-2">分层递进，从感知到自治。</p>
              <p className="text-[13px] font-light text-ink-soft mb-8">
                L1 规则检测 → L2 智能研判 → L3 自主处置，零人工干预的安全运营闭环。
              </p>
              <div className="grid md:grid-cols-3 border border-line">
                {capabilityTiers.map((tier, ti) => (
                  <div
                    key={tier.tier}
                    className={`p-7 ${ti < 2 ? 'md:border-r border-b md:border-b-0 border-line' : ''}`}
                  >
                    <div className="flex items-center gap-3 mb-6">
                      <span className="w-9 h-9 bg-ink text-white text-[12px] font-bold flex items-center justify-center">
                        {tier.tier}
                      </span>
                      <div>
                        <p className="text-[15px] font-bold">{tier.name}</p>
                        <p className="text-[11px] font-light text-ink-faint">{tier.subtitle}</p>
                      </div>
                    </div>
                    <div className="space-y-4">
                      {tier.features.map((f) => (
                        <div key={f.name}>
                          <p className="text-[13px] font-medium">{f.name}</p>
                          <p className="text-[12px] font-light text-ink-faint leading-relaxed">{f.desc}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-6 text-[12px] font-light text-ink-faint">
                对标《人工智能安全治理框架》2.0 — 技术防护 · 价值对齐 · 协同治理 · 人类控制
              </p>
            </motion.div>
          </SpecRow>

          <SpecRow label="流程">
            <motion.div {...reveal}>
              <p className="text-[22px] font-black mb-8">四层流水线，闭环守护。</p>
              <div className="grid grid-cols-2 md:grid-cols-4">
                {pipeline.map((p, i) => (
                  <div key={p.step} className="relative pb-2">
                    <p className="text-[11px] tracking-[0.2em] text-ink-faint mb-2">{p.step}</p>
                    <p className="text-[18px] font-bold">{p.name}</p>
                    <p className="text-[12px] font-light text-ink-faint mt-1">{p.desc}</p>
                    {i < pipeline.length - 1 && (
                      <div className="hidden md:block absolute top-3 left-[72px] right-2 h-px bg-ink" />
                    )}
                  </div>
                ))}
              </div>
            </motion.div>
          </SpecRow>

          <SpecRow label="事件" last>
            <motion.div {...reveal}>
              <div className="flex items-end justify-between mb-6">
                <p className="text-[22px] font-black">最新安全事件</p>
                <TextLink onClick={() => navigate(ROUTES.LOGS)}>查看全部</TextLink>
              </div>
              {recentLogs.length === 0 ? (
                <GlassPanel className="py-14 text-center text-[13px] font-light text-ink-faint">
                  暂无事件，启动日志模拟器后将实时显示
                </GlassPanel>
              ) : (
                <div className="border-t border-line">
                  {recentLogs.map((log, i) => (
                    <motion.div
                      key={log.id}
                      initial={{ opacity: 0 }}
                      whileInView={{ opacity: 1 }}
                      viewport={{ once: true }}
                      transition={{ ...spring.gentle, delay: i * 0.03 }}
                      className="flex items-center gap-4 py-3.5 border-b border-line"
                    >
                      <span className={`shrink-0 text-[10px] tracking-wide px-2 py-0.5 ${sevTone[log.severity] || sevTone.info}`}>
                        {log.severity}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[13px] truncate">
                          <span className="font-mono text-[12px]">{log.event_type}</span>
                          {log.src_ip && (
                            <span className="text-ink-faint font-mono text-[12px]">
                              {' '}
                              · {log.src_ip} → {log.dst_ip}
                            </span>
                          )}
                        </p>
                        <p className="text-[12px] font-light text-ink-faint truncate mt-0.5">{log.message}</p>
                      </div>
                      <span className="shrink-0 text-[11px] text-ink-faint tabular-nums font-mono">
                        {log.created_at
                          ? new Date(log.created_at).toLocaleString('zh-CN', {
                              month: '2-digit',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit',
                              hour12: false,
                            })
                          : ''}
                      </span>
                    </motion.div>
                  ))}
                </div>
              )}
            </motion.div>
          </SpecRow>
        </div>

        <footer className="border-t border-line">
          <div className="page-shell py-10">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-sm">
              {[
                { h: '平台', links: [['日志中心', ROUTES.LOGS], ['系统监控', ROUTES.MONITOR]] },
                { h: '安全', links: [['安全审计', ROUTES.SECURITY_AUDIT], ['响应引擎', ROUTES.RESPONSE]] },
                { h: '知识', links: [['知识库', ROUTES.RAG]] },
                { h: '账户', links: [['退出登录', '/login']] },
              ].map((col) => (
                <div key={col.h}>
                  <p className="font-bold text-[13px] mb-3">{col.h}</p>
                  {col.links.map(([label, path]) => (
                    <button
                      key={label}
                      onClick={() => navigate(path)}
                      className="block text-[13px] font-light text-ink-faint hover:text-ink mb-2"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              ))}
            </div>
            <div className="mt-10 pt-6 border-t border-line flex flex-col md:flex-row justify-between gap-2 text-[11px] tracking-[0.16em] text-ink-faint uppercase">
              <p>Shared Memory · Monochrome</p>
              <p>Service Layer · v1.0</p>
            </div>
          </div>
        </footer>
      </div>
    </PageTransition>
  )
}
