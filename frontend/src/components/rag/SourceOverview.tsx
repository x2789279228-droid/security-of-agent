import { useState, useEffect } from 'react'
import { api } from '../../lib/api'

const SOURCE_COLORS: Record<string, string> = {
  'mitre-attack': 'bg-purple-50 border-purple-200 text-purple-700',
  'capec': 'bg-indigo-50 border-indigo-200 text-indigo-700',
  'cve': 'bg-red-50 border-red-200 text-red-700',
  'kev': 'bg-rose-50 border-rose-200 text-rose-700',
  'vulnerability': 'bg-orange-50 border-orange-200 text-orange-700',
  'policy': 'bg-emerald-50 border-emerald-200 text-emerald-700',
  'playbook': 'bg-sky-50 border-sky-200 text-sky-700',
  'internal': 'bg-gray-50 border-gray-200 text-gray-600',
}

/**
 * 知识库类型分布卡片 — 横向 8 类来源文档数。
 * 点击卡片切换检索/文档管理的 source 过滤（再次点击取消）。
 */
export function SourceOverview({
  activeSource,
  onSelect,
}: {
  activeSource: string
  onSelect: (source: string) => void
}) {
  const [sources, setSources] = useState<any[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.ragSources()
      .then(d => setSources(d.sources || []))
      .catch((e: any) => setError(e.message))
  }, [])

  return (
    <div className="mb-6">
      {error && <p className="text-[10px] font-sans text-red-500 mb-2">分类统计加载失败: {error}</p>}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
        {sources.map(s => {
          const active = activeSource === s.source
          return (
            <button
              key={s.source}
              onClick={() => onSelect(active ? '' : s.source)}
              title={s.label}
              className={[
                'text-left px-3 py-2 rounded-xl border transition-all',
                SOURCE_COLORS[s.source] || 'bg-gray-50 border-gray-200 text-gray-600',
                active ? 'ring-2 ring-offset-1 ring-accent shadow-sm' : 'opacity-85 hover:opacity-100',
              ].join(' ')}
            >
              <span className="block text-[10px] font-sans font-medium truncate">{s.label}</span>
              <span className="block text-lg font-semibold leading-tight">{s.documents}</span>
              <span className="block text-[10px] font-sans opacity-70">文档</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}
