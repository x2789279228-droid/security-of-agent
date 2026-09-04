import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'

interface Drill {
  id: number
  name: string
  drill_type: string
  template_subject: string
  template_body: string
  target_count: number
  status: string
  sent_count: number
  opened_count: number
  clicked_count: number
  reported_count: number
  start_time: string | null
  created_at: string | null
  stats?: {
    total: number
    sent: number
    opened: number
    clicked: number
    reported: number
    open_rate: number
    click_rate: number
    report_rate: number
  }
}

const statusStyle: Record<string, { bg: string; text: string; label: string }> = {
  draft: { bg: 'bg-black/[0.05]', text: 'text-ink-soft', label: '草稿' },
  running: { bg: 'bg-nong', text: 'text-white', label: '进行中' },
  completed: { bg: 'bg-ink', text: 'text-white', label: '已完成' },
}

export default function PhishingDrill() {
  const [drills, setDrills] = useState<Drill[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [selectedDrill, setSelectedDrill] = useState<Drill | null>(null)

  // 创建表单
  const [name, setName] = useState('')
  const [drillType, setDrillType] = useState('email')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [targets, setTargets] = useState('')

  const loadDrills = useCallback(() => {
    api.phishingDrillList().then(setDrills).catch(() => {})
  }, [])

  useEffect(() => { loadDrills() }, [loadDrills])

  const handleCreate = async () => {
    setLoading(true)
    setError('')
    try {
      const drill = await api.phishingDrillCreate({
        name,
        drill_type: drillType,
        template_subject: subject,
        template_body: body,
      })
      const targetList = targets.split(/[,，\n]/).map((s: string) => s.trim()).filter(Boolean)
      if (targetList.length > 0) {
        await api.phishingDrillLaunch(drill.id, targetList)
      }
      setShowCreate(false)
      setName('')
      setSubject('')
      setBody('')
      setTargets('')
      loadDrills()
    } catch (e: any) {
      setError(e.message || '创建失败')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.phishingDrillDelete(id)
      if (selectedDrill?.id === id) setSelectedDrill(null)
      loadDrills()
    } catch { /* noop */ }
  }

  const handleViewDetail = async (id: number) => {
    try {
      const detail = await api.phishingDrillGet(id)
      setSelectedDrill(detail)
    } catch { /* noop */ }
  }

  return (
    <div>
      {/* 标题栏 */}
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs font-semibold text-ink-soft">
          演练活动 ({drills.length})
        </p>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-3 py-1.5 rounded-lg text-xs font-medium bg-accent text-white hover:bg-accent-hover transition-colors"
        >
          {showCreate ? '取消' : '+ 新建演练'}
        </button>
      </div>

      {error && <p className="text-xs text-alert mb-3">{error}</p>}

      {/* 创建表单 */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden mb-4"
          >
            <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="演练名称，如：2026年Q3全员钓鱼演练"
                className="w-full rounded-lg border border-line bg-card px-3 py-2 text-sm text-ink placeholder:text-ink-faint/50 focus:outline-none focus:ring-2 focus:ring-accent/30"
              />
              <div className="flex gap-2">
                {(['email', 'sms'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setDrillType(t)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      drillType === t ? 'bg-accent text-white' : 'bg-card text-ink-soft border border-line'
                    }`}
                  >
                    {t === 'email' ? '📧 邮件' : '💬 短信'}
                  </button>
                ))}
              </div>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="模板主题，如：紧急：您的账户安全验证"
                className="w-full rounded-lg border border-line bg-card px-3 py-2 text-sm text-ink placeholder:text-ink-faint/50 focus:outline-none focus:ring-2 focus:ring-accent/30"
              />
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="模板正文…"
                rows={3}
                className="w-full rounded-lg border border-line bg-card px-3 py-2 text-sm text-ink placeholder:text-ink-faint/50 focus:outline-none focus:ring-2 focus:ring-accent/30 resize-y"
              />
              <textarea
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="目标列表（逗号或换行分隔）：user1@company.com, user2@company.com"
                rows={2}
                className="w-full rounded-lg border border-line bg-card px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-faint/50 focus:outline-none focus:ring-2 focus:ring-accent/30 resize-y"
              />
              <button
                onClick={handleCreate}
                disabled={!name.trim() || loading}
                className="w-full py-2 rounded-lg text-xs font-semibold text-white bg-accent hover:bg-accent-hover disabled:opacity-40 transition-colors"
              >
                {loading ? '创建中…' : '创建并发起'}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 演练详情 */}
      <AnimatePresence>
        {selectedDrill && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border border-line bg-surface p-4 mb-4"
          >
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm font-semibold text-ink">{selectedDrill.name}</p>
              <button onClick={() => setSelectedDrill(null)} className="text-xs text-ink-faint hover:text-ink">✕</button>
            </div>
            {selectedDrill.stats && (
              <div className="grid grid-cols-4 gap-3 text-center mb-3">
                {[
                  { value: `${selectedDrill.stats.open_rate}%`, label: '打开率', color: 'text-[#0071e3]' },
                  { value: `${selectedDrill.stats.click_rate}%`, label: '点击率', color: 'text-[#ff9f0a]' },
                  { value: `${selectedDrill.stats.report_rate}%`, label: '上报率', color: 'text-[#34c759]' },
                  { value: selectedDrill.stats.total, label: '目标数', color: 'text-ink' },
                ].map((s) => (
                  <div key={s.label}>
                    <p className={`text-xl font-semibold tabular-nums ${s.color}`}>{s.value}</p>
                    <p className="text-[11px] text-ink-faint mt-0.5">{s.label}</p>
                  </div>
                ))}
              </div>
            )}
            {/* 进度条 */}
            {selectedDrill.stats && selectedDrill.stats.sent > 0 && (
              <div className="space-y-1.5">
                {[
                  { label: '已打开', count: selectedDrill.stats.opened, color: 'bg-[#0071e3]' },
                  { label: '已点击', count: selectedDrill.stats.clicked, color: 'bg-[#ff9f0a]' },
                  { label: '已上报', count: selectedDrill.stats.reported, color: 'bg-[#34c759]' },
                ].map((bar) => (
                  <div key={bar.label} className="flex items-center gap-2 text-[11px]">
                    <span className="w-10 text-ink-faint shrink-0">{bar.label}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-black/[0.06] overflow-hidden">
                      <div
                        className={`h-full rounded-full ${bar.color} transition-all duration-500`}
                        style={{ width: `${(bar.count / selectedDrill.stats!.sent) * 100}%` }}
                      />
                    </div>
                    <span className="w-6 text-right text-ink-faint tabular-nums">{bar.count}</span>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* 演练列表 */}
      {drills.length === 0 ? (
        <p className="text-center text-xs text-ink-faint py-8">
          暂无演练活动，点击「新建演练」开始
        </p>
      ) : (
        <div className="space-y-2">
          {drills.map((d) => (
            <div
              key={d.id}
              className="flex items-center gap-3 rounded-xl border border-line bg-card px-4 py-3 hover:shadow-sm transition-shadow cursor-pointer"
              onClick={() => handleViewDetail(d.id)}
            >
              <span className="text-base shrink-0">{d.drill_type === 'email' ? '📧' : '💬'}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-ink truncate font-medium">{d.name}</p>
                <p className="text-[11px] text-ink-faint mt-0.5">
                  {d.target_count} 目标 · {d.created_at ? new Date(d.created_at).toLocaleDateString('zh-CN') : ''}
                </p>
              </div>
              {d.status === 'running' && d.sent_count > 0 && (
                <span className="text-[11px] text-ink-faint tabular-nums shrink-0">
                  点击 {d.clicked_count}/{d.sent_count}
                </span>
              )}
              <span className={`text-[11px] font-semibold px-2 py-1 rounded-full shrink-0 ${statusStyle[d.status]?.bg} ${statusStyle[d.status]?.text}`}>
                {statusStyle[d.status]?.label ?? d.status}
              </span>
              <button
                onClick={(e) => { e.stopPropagation(); handleDelete(d.id) }}
                className="text-ink-faint hover:text-alert text-xs shrink-0 transition-colors"
                title="删除"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
