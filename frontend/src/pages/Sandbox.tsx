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
  pending: 'bg-mist text-ink-faint',
  running: 'bg-nong text-white',
  completed: 'bg-ink text-white',
  failed: 'bg-hui text-white',
}

const verdictBadge: Record<string, string> = {
  clean: 'border border-ink text-ink',
  suspicious: 'bg-nong text-white',
  malicious: 'bg-ink text-white',
}

export default function Sandbox() {
  const [tasks, setTasks] = useState<SandboxTask[]>([])

  useEffect(() => {
    api.get('/sandbox/tasks?limit=50').then(setTasks).catch(() => {})
  }, [])

  return (
    <PageFrame title="沙箱检测" subtitle="CAPE 动态分析 · 行为报告 · 变种聚类">
      <div className="grid gap-0 border border-line">
        {tasks.map((t, i) => (
          <div key={t.id} className={`p-5 bg-white ${i < tasks.length - 1 ? 'border-b border-line' : ''}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <span className="font-medium text-ink">{t.sample_name || t.sample_type}</span>
                <span className={`px-2 py-0.5 text-xs font-medium ${statusBadge[t.status] || ''}`}>
                  {t.status}
                </span>
                {t.verdict && (
                  <span className={`px-2 py-0.5 text-xs font-medium ${verdictBadge[t.verdict] || ''}`}>
                    {t.verdict}
                  </span>
                )}
              </div>
              {t.score > 0 && (
                <span className="text-sm font-mono text-ink-soft">{(t.score * 10).toFixed(1)}/10</span>
              )}
            </div>
            {t.behavior_summary && (
              <p className="text-sm font-light text-ink-soft mb-3">{t.behavior_summary}</p>
            )}
            {t.mitre_techniques && t.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {t.mitre_techniques.slice(0, 6).map((tech, idx) => (
                  <span key={idx} className="px-2 py-0.5 border border-line text-[11px]">
                    {tech.id} {tech.name}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
        {tasks.length === 0 && (
          <div className="py-20 text-center text-ink-faint">暂无沙箱任务</div>
        )}
      </div>
    </PageFrame>
  )
}
