import { useState, useEffect } from 'react'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'

interface SandboxTask {
  id: number
  task_id: string
  sample_name: string
  sample_type: string
  source: string
  status: string
  verdict: string
  score: number
  behavior_summary: string
  mitre_techniques: { id: string; name: string }[]
  submitted_at: string
  completed_at: string | null
}

const statusBadge: Record<string, string> = {
  pending: 'border border-line text-ink-faint',
  running: 'border border-[#c9a574] text-[#c9a574]',
  completed: 'border border-[#0e1a26] bg-[#0e1a26] text-[#f1e8d6]',
  failed: 'border border-[#b03a30] text-[#b03a30]',
}

const verdictBadge: Record<string, string> = {
  clean: 'border border-ok text-ok',
  suspicious: 'border border-[#b88940] text-[#b88940]',
  malicious: 'border border-[#b03a30] bg-[#b03a30] text-paper',
}

export default function Sandbox() {
  const [tasks, setTasks] = useState<SandboxTask[]>([])

  useEffect(() => {
    api.get('/sandbox/tasks?limit=50').then(setTasks).catch(() => {})
  }, [])

  return (
    <PageFrame
      title="沙箱检测"
      hint="CAPE 动态分析 · 行为报告 · 变种聚类。怀疑但无法判断时，扔进沙箱。"
      marginalia="——真伪的最后一道，不靠签名，靠行为。"
    >
      <div className="border border-line bg-paper">
        {tasks.map((t, i) => (
          <article
            key={t.id}
            className={`grid grid-cols-1 gap-6 px-7 py-6 md:grid-cols-[1fr_140px] ${
              i < tasks.length - 1 ? 'border-b border-line' : ''
            }`}
          >
            <div>
              <div className="flex items-center gap-3">
                <span className="font-serif text-[20px] font-bold tracking-tight text-ink">
                  {t.sample_name || t.sample_type}
                </span>
                <span
                  className={`px-2 py-0.5 font-mono text-[10px] tracking-[0.22em] uppercase ${statusBadge[t.status] || 'border border-line'}`}
                >
                  {t.status}
                </span>
                {t.verdict && (
                  <span
                    className={`px-2 py-0.5 font-mono text-[10px] tracking-[0.22em] uppercase ${verdictBadge[t.verdict] || 'border border-line'}`}
                  >
                    {t.verdict}
                  </span>
                )}
              </div>
              {t.behavior_summary && (
                <p className="mt-3 text-[13px] leading-relaxed text-ink-soft">
                  {t.behavior_summary}
                </p>
              )}
              {t.mitre_techniques && t.mitre_techniques.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {t.mitre_techniques.slice(0, 6).map((tech, idx) => (
                    <span
                      key={idx}
                      className="border border-line px-2 py-0.5 font-mono text-[11px] text-ink"
                    >
                      <span className="text-[#c9a574]">{tech.id}</span> {tech.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="flex flex-col items-start gap-1 md:items-end">
              {t.score > 0 && (
                <span className="font-serif text-[36px] font-black tabular-nums leading-none text-ink">
                  {(t.score * 10).toFixed(1)}
                  <span className="font-mono text-[11px] tracking-[0.22em] uppercase text-ink-faint">
                    {' '}/ 10
                  </span>
                </span>
              )}
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                Risk · 风险评分
              </span>
              <span className="font-mono text-[10px] text-ink-faint/80">
                {t.task_id}
              </span>
            </div>
          </article>
        ))}
        {tasks.length === 0 && (
          <div className="px-6 py-20 text-center text-[13px] text-ink-faint">
            暂无沙箱任务
          </div>
        )}
      </div>
    </PageFrame>
  )
}