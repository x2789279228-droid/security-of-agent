import { useState } from 'react'
import { api } from '../../lib/api'

const IMPORTS = [
  {
    id: 'cve',
    label: '导入 CVE 漏洞库',
    desc: 'NVD 聚焦导入（近1年 + CVSS≥7），可分页/限流',
    color: 'bg-red-600 hover:bg-red-700',
    run: () => api.ragImportCVE(0, 365, 7),
  },
  {
    id: 'kev',
    label: '导入 0day/KEV',
    desc: 'CISA 已知被利用漏洞全量，按 CVE-ID 联动标记',
    color: 'bg-rose-600 hover:bg-rose-700',
    run: () => api.ragImportKEV(),
  },
  {
    id: 'policy',
    label: '导入监管政策库',
    desc: '网络安全法/等保2.0/GDPR/ISO27001 等 11 篇',
    color: 'bg-emerald-600 hover:bg-emerald-700',
    run: () => api.ragImportPolicy(false),
  },
  {
    id: 'vulnerability',
    label: '导入精选漏洞库',
    desc: 'Log4Shell/EternalBlue 等 26 个高影响漏洞',
    color: 'bg-orange-600 hover:bg-orange-700',
    run: () => api.ragImportVulnerability(false),
  },
]

const SOURCE_LABEL: Record<string, string> = {
  cve: 'CVE 漏洞库',
  kev: '0day/KEV',
  policy: '监管政策',
  vulnerability: '精选漏洞',
}

/**
 * 知识库导入操作区 — CVE / KEV / 政策 / 精选漏洞 4 个导入按钮。
 * 导入期间轮询 /rag/import/status 展示进度；完成后回调 onImported 刷新统计。
 */
export function ImportActions({ onImported }: { onImported?: () => void }) {
  const [importing, setImporting] = useState<string>('')
  const [status, setStatus] = useState<any>(null)
  const [error, setError] = useState('')

  const runImport = async (id: string, run: () => Promise<any>) => {
    if (importing) return
    setError('')
    setStatus(null)
    setImporting(id)

    // 轮询导入进度（仅展示，完成信号以接口返回为准）
    const timer = window.setInterval(async () => {
      try {
        const s = await api.ragImportStatus()
        setStatus(s)
      } catch { /* 轮询失败忽略 */ }
    }, 1500)

    try {
      const r = await run()
      setStatus(r)
      onImported?.()
    } catch (e: any) {
      setError(e.message)
    } finally {
      window.clearInterval(timer)
      setImporting('')
      try { setStatus(await api.ragImportStatus()) } catch { /* ignore */ }
    }
  }

  const running = status?.running
  const statusPct = status?.progress != null ? Math.round(status.progress * 100) : 0

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {IMPORTS.map(imp => {
          const isActive = importing === imp.id
          return (
            <div key={imp.id} className="border border-line rounded-lg p-4 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-xs font-sans font-semibold text-ink">{imp.label}</p>
                <p className="text-[10px] font-sans text-ink-faint mt-0.5">{imp.desc}</p>
              </div>
              <button
                onClick={() => runImport(imp.id, imp.run)}
                disabled={!!importing}
                className={[
                  'px-4 py-2 text-xs font-sans font-medium text-white rounded-lg shrink-0 transition-colors',
                  imp.color,
                  importing ? 'opacity-40 cursor-not-allowed' : '',
                ].join(' ')}
              >
                {isActive ? '导入中...' : '导入'}
              </button>
            </div>
          )
        })}
      </div>

      {running && (
        <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center justify-between text-xs font-sans text-blue-700 mb-1.5">
            <span>正在导入 {status?.source ? (SOURCE_LABEL[status.source] || status.source) : '知识库'}...</span>
            <span>{statusPct}%</span>
          </div>
          <div className="w-full h-1.5 bg-blue-100 rounded-full overflow-hidden">
            <div className="h-full bg-blue-600 rounded-full transition-all" style={{ width: `${statusPct}%` }} />
          </div>
          {status?.message && <p className="text-[10px] font-sans text-blue-600 mt-1.5 truncate">{status.message}</p>}
        </div>
      )}

      {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

      {!running && importing === '' && status?.finished_at && (
        <div className="p-3 bg-green-50 border border-green-200 rounded-lg text-xs text-green-700">
          {status?.source ? (SOURCE_LABEL[status.source] || status.source) : ''} 导入完成：
          新增 {status.imported ?? 0} · 更新 {status.updated ?? 0} · 跳过 {status.skipped ?? 0} · 错误 {status.errors ?? 0}
          {(status.error_details || []).length > 0 && (
            <span className="block text-[10px] mt-1 text-red-500">{(status.error_details || []).join('; ')}</span>
          )}
        </div>
      )}
    </div>
  )
}
