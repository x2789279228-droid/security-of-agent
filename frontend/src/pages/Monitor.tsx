import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'
import { useServiceStore } from '../stores/serviceStore'

interface LiveEvent {
  id: number
  type: string
  data: any
  ts: number
}

const typeMeta: Record<string, { label: string; badge: string }> = {
  security_event: { label: '事件接入', badge: 'bg-[#0071e3]/10 text-[#0071e3]' },
  audit_complete: { label: '审计完成', badge: 'bg-[#af52de]/10 text-[#af52de]' },
  response_action: { label: '响应执行', badge: 'bg-[#ff3b30]/10 text-[#ff3b30]' },
  alert: { label: '告警', badge: 'bg-[#ff9f0a]/12 text-[#c77700]' },
}

const healthMeta: Record<string, { label: string; color: string; text: string }> = {
  ok: { label: '正常', color: 'bg-[#34c759]', text: 'text-[#248a3d]' },
  warn: { label: '告警', color: 'bg-[#ff9f0a]', text: 'text-[#c77700]' },
  alert: { label: '异常', color: 'bg-[#ff3b30]', text: 'text-[#ff3b30]' },
}

export default function Monitor() {
  const services = useServiceStore((s) => s.services)
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [stats, setStats] = useState<any>(null)
  const [connected, setConnected] = useState(false)
  const idRef = useRef(0)

  const addEvent = useCallback((type: string, data: any) => {
    idRef.current += 1
    setEvents((prev) => [{ id: idRef.current, type, data, ts: Date.now() }, ...prev].slice(0, 100))
  }, [])

  useEffect(() => {
    api.stats().then(setStats).catch(() => {})
    const es = api.eventsStream()
    es.addEventListener('connected', () => setConnected(true))
    es.addEventListener('security_event', (e) => addEvent('security_event', JSON.parse(e.data)))
    es.addEventListener('audit_complete', (e) => {
      addEvent('audit_complete', JSON.parse(e.data))
      api.stats().then(setStats).catch(() => {})
    })
    es.addEventListener('response_action', (e) => addEvent('response_action', JSON.parse(e.data)))
    es.onerror = () => setConnected(false)
    return () => es.close()
  }, [addEvent])

  return (
    <PageTransition>
      <div className="max-w-5xl mx-auto px-6 pt-14 pb-16">
        {/* 页头 */}
        <div className="flex items-end justify-between mb-10">
          <div>
            <h1 className="text-4xl font-semibold tracking-tight text-ink">系统监控</h1>
            <p className="text-[15px] text-ink-soft mt-2">服务健康 · 运行指标 · 实时事件流</p>
          </div>
          <span className={`flex items-center gap-2 text-[13px] ${connected ? 'text-[#248a3d]' : 'text-alert'}`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-[#34c759] animate-pulse' : 'bg-alert'}`} />
            {connected ? '实时连接' : '已断开'}
          </span>
        </div>

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
                className="bg-card rounded-2xl p-5 flex items-center gap-4"
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
            className="bg-card rounded-[20px] px-8 py-8 mb-10 grid grid-cols-2 md:grid-cols-5 gap-y-8 text-center"
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

        {/* 实时事件流 */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-semibold tracking-tight text-ink">实时事件流</h2>
          <span className="text-[13px] text-ink-faint">{events.length} 条</span>
        </div>

        <div className="bg-card rounded-[20px] overflow-hidden">
          {events.length === 0 ? (
            <div className="p-14 text-center text-sm text-ink-faint">
              等待事件… 启动日志模拟器后将在此显示实时数据
            </div>
          ) : (
            <div className="max-h-[440px] overflow-y-auto divide-y divide-line">
              <AnimatePresence initial={false}>
                {events.map((evt) => {
                  const tm = typeMeta[evt.type] || typeMeta.alert
                  return (
                    <motion.div
                      key={evt.id}
                      initial={{ opacity: 0, x: -12 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.25 }}
                      className="flex items-center gap-3.5 px-5 py-3 hover:bg-surface/60 transition-colors"
                    >
                      <span className={`shrink-0 text-[11px] font-semibold px-2.5 py-1 rounded-full ${tm.badge}`}>
                        {tm.label}
                      </span>

                      <div className="flex-1 min-w-0 text-[13px] truncate">
                        {evt.type === 'security_event' && (
                          <span className="text-ink-soft">
                            <span className="font-mono text-ink font-medium">{evt.data.event_type}</span>
                            {' · '}{evt.data.src_ip}
                            {evt.data.is_anomaly && (
                              <span className="text-alert font-semibold ml-1.5">⚠ 异常 {evt.data.anomaly_score?.toFixed(2)}</span>
                            )}
                          </span>
                        )}
                        {evt.type === 'audit_complete' && (
                          <span className="text-ink-soft">
                            #{evt.data.event_id} <span className="font-mono">{evt.data.event_type}</span> —{' '}
                            {evt.data.threat_detected ? (
                              <span className="text-alert font-semibold">威胁确认（置信度 {evt.data.confidence?.toFixed(2)}）</span>
                            ) : (
                              <span className="text-[#248a3d] font-semibold">安全</span>
                            )}
                            {' · '}{evt.data.rounds} 轮 · {evt.data.duration_s}s
                          </span>
                        )}
                        {evt.type === 'response_action' && (
                          <span className="text-ink-soft">
                            <span className="text-alert font-semibold">响应触发</span>{' '}
                            <span className="font-mono">{evt.data.threat_type}</span> — {evt.data.src_ip}
                          </span>
                        )}
                      </div>

                      <span className="shrink-0 text-xs text-ink-faint tabular-nums">
                        {new Date(evt.ts).toLocaleTimeString('zh-CN', { hour12: false })}
                      </span>
                    </motion.div>
                  )
                })}
              </AnimatePresence>
            </div>
          )}
        </div>
      </div>
    </PageTransition>
  )
}
