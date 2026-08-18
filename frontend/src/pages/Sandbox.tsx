import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
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
  pending: 'bg-ink/5 text-ink-soft',
  running: 'bg-[#0071e3]/10 text-[#0071e3]',
  completed: 'bg-[#34c759]/10 text-[#248a3d]',
  failed: 'bg-[#ff3b30]/10 text-[#ff3b30]',
}

const verdictBadge: Record<string, string> = {
  clean: 'bg-[#34c759]/10 text-[#248a3d]',
  suspicious: 'bg-[#ff9f0a]/12 text-[#c77700]',
  malicious: 'bg-[#ff3b30]/12 text-[#ff3b30]',
}

export default function Sandbox() {
  const [tasks, setTasks] = useState<SandboxTask[]>([])

  useEffect(() => {
    api.get('/sandbox/tasks?limit=50').then(setTasks).catch(() => {})
  }, [])

  return (
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="mb-10">
          <h1 className="text-4xl font-semibold tracking-tight text-ink">沙箱检测</h1>
          <p className="text-[15px] text-ink-soft mt-2">CAPE 动态分析 · 行为报告 · 变种聚类</p>
        </div>

        <div className="grid gap-4">
          {tasks.map((t) => (
            <div key={t.id} className="p-5 rounded-2xl border border-ink/8 bg-white/70 backdrop-blur">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="font-medium text-ink">{t.sample_name || t.sample_type}</span>
                  <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${statusBadge[t.status] || ''}`}>
                    {t.status}
                  </span>
                  {t.verdict && (
                    <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${verdictBadge[t.verdict] || ''}`}>
                      {t.verdict}
                    </span>
                  )}
                </div>
                {t.score > 0 && (
                  <span className="text-sm font-mono text-ink-soft">{(t.score * 10).toFixed(1)}/10</span>
                )}
              </div>

              {t.behavior_summary && (
                <p className="text-sm text-ink-soft mb-3">{t.behavior_summary}</p>
              )}

              {t.mitre_techniques && t.mitre_techniques.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {t.mitre_techniques.slice(0, 6).map((tech, i) => (
                    <span key={i} className="px-2 py-0.5 rounded-md bg-[#af52de]/8 text-[#af52de] text-[11px] font-medium">
                      {tech.id} {tech.name}
                    </span>
                  ))}
                </div>
              )}

              <div className="mt-3 text-xs text-ink-faint">
                来源: {t.source} · 提交: {t.submitted_at ? new Date(t.submitted_at).toLocaleString() : '-'}
              </div>
            </div>
          ))}
          {tasks.length === 0 && (
            <div className="py-20 text-center text-ink-faint">暂无沙箱分析任务</div>
          )}
        </div>
      </div>
    </PageTransition>
  )
}
