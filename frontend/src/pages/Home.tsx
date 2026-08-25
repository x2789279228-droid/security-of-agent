import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import ThreatNetwork from '../components/hero/ThreatNetwork'
import PhishingDetect from '../components/phishing/PhishingDetect'
import { Button, TextLink } from '../components/ui/Button'
import { PageTransition } from '../components/common/PageTransition'
import { spring, ROUTES } from '../lib/constants'
import { api } from '../lib/api'

const reveal = {
  initial: { opacity: 0, y: 28 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] as const },
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

/** 分层递进能力模型 — 对标赛题"分层递进"要求 */
const capabilityTiers = [
  {
    tier: 'L1',
    name: '基础感知层',
    color: '#0A84FF',
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
    color: '#5E5CE6',
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
    color: '#BF5AF2',
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

const sevStyle: Record<string, string> = {
  critical: 'bg-[#ff3b30]/10 text-[#ff3b30]',
  high: 'bg-[#ff9f0a]/12 text-[#c77700]',
  medium: 'bg-[#0071e3]/10 text-[#0071e3]',
  low: 'bg-black/[0.05] text-ink-soft',
  info: 'bg-black/[0.05] text-ink-soft',
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

    // 实时事件 → 驱动威胁态势图
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

  return (
    <PageTransition>
      <div className="bg-surface">
        {/* ══════════ 英雄区 ══════════ */}
        <section className="pt-28 text-center">
          <p className="text-sm font-semibold text-accent tracking-wide mb-4">
            SHARED MEMORY · 安全审计平台
          </p>
          <h1 className="text-[56px] md:text-[72px] leading-[1.05] font-semibold tracking-[-0.02em] text-ink px-6">
            安全审计。
            <br />
            快人一步。
          </h1>
          <p className="mt-6 text-xl text-ink-soft max-w-2xl mx-auto px-6 leading-relaxed">
            从日志接入到自动响应，四层 Agent 流水线实时守护每一次访问。
          </p>
          <div className="mt-8 flex items-center justify-center gap-6">
            <Button onClick={() => navigate(ROUTES.LOGS)}>进入控制台</Button>
            <TextLink onClick={() => navigate(ROUTES.MONITOR)}>了解系统状态</TextLink>
          </div>

          {/* 威胁态势网络 */}
          <div className="mt-6">
            <ThreatNetwork attackCount={attackCount} />
          </div>
        </section>

        {/* ══════════ 数据带 ══════════ */}
        <section className="max-w-[980px] mx-auto px-6 py-16">
          <motion.div
            {...reveal}
            className="grid grid-cols-2 md:grid-cols-4 gap-y-10 text-center"
          >
            {[
              { value: total, label: '安全事件已接入' },
              { value: audited, label: '事件完成审计' },
              { value: stats?.security_pending ?? 0, label: '待处理队列' },
              { value: stats?.memories_count ?? 0, label: '语义记忆条数' },
            ].map((item) => (
              <div key={item.label}>
                <p className="text-5xl font-semibold tracking-tight text-ink tabular-nums">
                  {item.value}
                </p>
                <p className="mt-2 text-sm text-ink-soft">{item.label}</p>
              </div>
            ))}
          </motion.div>
        </section>

        {/* ══════════ 能力瓦片 ══════════ */}
        <section className="max-w-[1200px] mx-auto px-6 pb-4">
          <motion.h2
            {...reveal}
            className="text-4xl font-semibold tracking-tight text-ink mb-10"
          >
            一个平台，全栈安全。
          </motion.h2>
          <div className="grid md:grid-cols-2 gap-4">
            {capabilities.map((cap, i) => (
              <motion.div
                key={cap.path}
                initial={{ opacity: 0, y: 28 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-60px' }}
                transition={{ duration: 0.6, delay: (i % 2) * 0.08, ease: [0.22, 1, 0.36, 1] }}
                onClick={() => navigate(cap.path)}
                className="group bg-card rounded-[24px] px-10 pt-12 pb-10 cursor-pointer overflow-hidden relative transition-shadow hover:shadow-[0_12px_40px_rgba(0,0,0,0.08)]"
              >
                <p className="text-xs font-semibold text-accent tracking-wide mb-3">{cap.tag}</p>
                <h3 className="text-3xl font-semibold tracking-tight text-ink mb-3 group-hover:text-accent transition-colors">
                  {cap.title}
                </h3>
                <p className="text-[15px] text-ink-soft leading-relaxed max-w-md">{cap.desc}</p>
                <span className="inline-flex items-center gap-0.5 mt-6 text-sm text-link">
                  进入
                  <span className="text-base leading-none translate-y-[-0.5px] transition-transform group-hover:translate-x-0.5">›</span>
                </span>
              </motion.div>
            ))}
          </div>
        </section>

        {/* ══════════ 钓鱼检测 ══════════ */}
        <PhishingDetect />

        {/* ══════════ 分层递进能力模型 ══════════ */}
        <section className="py-24 bg-card mt-16">
          <motion.div {...reveal} className="max-w-[1100px] mx-auto px-6">
            <p className="text-sm font-semibold text-accent tracking-wide mb-3 text-center">能力架构</p>
            <h2 className="text-4xl font-semibold tracking-tight text-ink mb-4 text-center">
              分层递进，从感知到自治。
            </h2>
            <p className="text-lg text-ink-soft mb-14 text-center max-w-2xl mx-auto">
              三层能力逐级递进：L1 规则检测 → L2 智能研判 → L3 自主处置，实现零人工干预的安全运营闭环。
            </p>

            <div className="grid md:grid-cols-3 gap-6">
              {capabilityTiers.map((tier, ti) => (
                <motion.div
                  key={tier.tier}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.6, delay: ti * 0.12 }}
                  className="relative bg-surface rounded-[20px] p-8 border border-line"
                >
                  {/* 层级标识 */}
                  <div className="flex items-center gap-3 mb-6">
                    <div
                      className="w-12 h-12 rounded-xl flex items-center justify-center text-white text-lg font-bold"
                      style={{ backgroundColor: tier.color }}
                    >
                      {tier.tier}
                    </div>
                    <div>
                      <p className="text-lg font-semibold text-ink">{tier.name}</p>
                      <p className="text-xs text-ink-soft">{tier.subtitle}</p>
                    </div>
                  </div>

                  {/* 特性列表 */}
                  <div className="space-y-4">
                    {tier.features.map((f) => (
                      <div key={f.name} className="flex items-start gap-3">
                        <div
                          className="w-1.5 h-1.5 rounded-full mt-2 shrink-0"
                          style={{ backgroundColor: tier.color }}
                        />
                        <div>
                          <p className="text-sm font-medium text-ink">{f.name}</p>
                          <p className="text-xs text-ink-soft leading-relaxed">{f.desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* 递进箭头 (非最后一层) */}
                  {ti < capabilityTiers.length - 1 && (
                    <div className="hidden md:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                        <path d="M9 6l6 6-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-ink-faint" />
                      </svg>
                    </div>
                  )}
                </motion.div>
              ))}
            </div>

            {/* 底部说明 */}
            <div className="mt-10 text-center">
              <p className="text-sm text-ink-soft">
                对标《人工智能安全治理框架》2.0 — 技术防护 · 价值对齐 · 协同治理 · 人类控制
              </p>
            </div>
          </motion.div>
        </section>

        {/* ══════════ 流水线 ══════════ */}
        <section className="py-24 text-center bg-card mt-16">
          <motion.div {...reveal} className="max-w-[980px] mx-auto px-6">
            <p className="text-sm font-semibold text-accent tracking-wide mb-3">工作原理</p>
            <h2 className="text-4xl font-semibold tracking-tight text-ink mb-4">
              四层流水线，闭环守护。
            </h2>
            <p className="text-lg text-ink-soft mb-14">
              每一条日志，都经过完整的感知—研判—响应—复盘链路。
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              {pipeline.map((p, i) => (
                <motion.div
                  key={p.step}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: i * 0.1 }}
                  className="relative"
                >
                  <div className="w-14 h-14 mx-auto rounded-full bg-accent/10 text-accent flex items-center justify-center text-lg font-semibold mb-4">
                    {p.step}
                  </div>
                  <p className="text-xl font-semibold text-ink">{p.name}</p>
                  <p className="text-sm text-ink-soft mt-1">{p.desc}</p>
                  {i < pipeline.length - 1 && (
                    <div className="hidden md:block absolute top-7 left-[calc(50%+36px)] w-[calc(100%-72px)] h-px bg-line" />
                  )}
                </motion.div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* ══════════ 实时事件 ══════════ */}
        <section className="max-w-[980px] mx-auto px-6 py-20">
          <motion.div {...reveal} className="flex items-end justify-between mb-8">
            <h2 className="text-3xl font-semibold tracking-tight text-ink">最新安全事件</h2>
            <TextLink onClick={() => navigate(ROUTES.LOGS)}>查看全部</TextLink>
          </motion.div>

          {recentLogs.length === 0 ? (
            <p className="text-center text-ink-faint py-16 bg-card rounded-[20px]">
              暂无事件，启动日志模拟器后将实时显示
            </p>
          ) : (
            <div className="bg-card rounded-[20px] divide-y divide-line overflow-hidden">
              {recentLogs.map((log, i) => (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ ...spring.gentle, delay: i * 0.04 }}
                  className="flex items-center gap-4 px-6 py-4 hover:bg-surface/60 transition-colors"
                >
                  <span className={`shrink-0 text-[11px] font-semibold px-2.5 py-1 rounded-full ${sevStyle[log.severity] || sevStyle.info}`}>
                    {log.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-ink truncate">
                      <span className="font-mono text-[13px]">{log.event_type}</span>
                      {log.src_ip && (
                        <span className="text-ink-faint font-mono text-[12px]"> · {log.src_ip} → {log.dst_ip}</span>
                      )}
                    </p>
                    <p className="text-[13px] text-ink-soft truncate mt-0.5">{log.message}</p>
                  </div>
                  <span className="shrink-0 text-xs text-ink-faint tabular-nums">
                    {log.created_at
                      ? new Date(log.created_at).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
                      : ''}
                  </span>
                </motion.div>
              ))}
            </div>
          )}
        </section>

        {/* ══════════ 页脚 ══════════ */}
        <footer className="border-t border-line">
          <div className="max-w-[980px] mx-auto px-6 py-10">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-sm">
              {[
                { h: '平台', links: [['日志中心', ROUTES.LOGS], ['系统监控', ROUTES.MONITOR]] },
                { h: '安全', links: [['安全审计', ROUTES.SECURITY_AUDIT], ['响应引擎', ROUTES.RESPONSE]] },
                { h: '知识', links: [['知识库', ROUTES.RAG]] },
                { h: '账户', links: [['退出登录', '/login']] },
              ].map((col) => (
                <div key={col.h}>
                  <p className="font-semibold text-ink mb-3 text-[13px]">{col.h}</p>
                  {col.links.map(([label, path]) => (
                    <button
                      key={label}
                      onClick={() => navigate(path)}
                      className="block text-[13px] text-ink-soft hover:text-link hover:underline mb-2"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              ))}
            </div>
            <div className="mt-10 pt-6 border-t border-line flex flex-col md:flex-row justify-between gap-2 text-xs text-ink-faint">
              <p>Copyright © 2026 共享记忆安全审计平台。保留所有权利。</p>
              <p>Shared Memory Service Layer · v1.0</p>
            </div>
          </div>
        </footer>
      </div>
    </PageTransition>
  )
}
