import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-700 bg-red-50 border-red-200',
  high: 'text-orange-700 bg-orange-50 border-orange-200',
  medium: 'text-yellow-700 bg-yellow-50 border-yellow-200',
  low: 'text-gray-600 bg-gray-50 border-gray-200',
  info: 'text-blue-700 bg-blue-50 border-blue-200',
}

const SOURCE_LABEL: Record<string, string> = {
  cve: 'CVE 漏洞库',
  kev: '0day/已知被利用',
  vulnerability: '漏洞知识库',
}

/**
 * CVE 速查 — 输入 CVE-ID 精确查询知识库文档。
 * 结果卡片带 CVSS 分数/严重度/受影响产品/KEV 利用标记。
 */
export function CVEQuickCheck() {
  const [cveId, setCveId] = useState('')
  const [doc, setDoc] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notFound, setNotFound] = useState(false)

  const check = async () => {
    const id = cveId.trim().toUpperCase()
    if (!id) return
    setLoading(true)
    setError('')
    setDoc(null)
    setNotFound(false)
    try {
      const d = await api.ragCve(id)
      setDoc(d)
    } catch (e: any) {
      if (String(e.message).includes('404')) setNotFound(true)
      else setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const m = doc?.metadata || {}
  const exploited = !!(m.exploit_available || m.known_exploited || (doc?.tags || []).includes('kev-exploited'))

  return (
    <div className="border border-line rounded-lg p-4">
      <p className="text-xs font-sans font-medium text-ink-faint mb-3">CVE 速查（精确匹配知识库）</p>
      <div className="flex items-center gap-2">
        <input
          type="text"
          placeholder="如 CVE-2021-44228"
          value={cveId}
          onChange={e => setCveId(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && check()}
          className="flex-1 px-3 py-2 text-xs font-mono border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <button onClick={check} disabled={loading || !cveId.trim()}
          className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
          {loading ? '查询中...' : '查询'}
        </button>
      </div>

      {error && <div className="p-3 mt-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

      {notFound && (
        <div className="p-3 mt-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-700">
          知识库中未找到 {cveId.trim().toUpperCase()} — 可在「知识管理」中导入 CVE 漏洞库或 0day/KEV。
        </div>
      )}

      <AnimatePresence>
        {doc && (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="mt-3 border border-line rounded-lg p-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold font-sans">{doc.title || m.cve_id || cveId.trim().toUpperCase()}</span>
                {exploited && (
                  <span className="px-1.5 py-0.5 text-[10px] font-sans font-semibold rounded border bg-red-50 border-red-200 text-red-700">
                    已在野外利用
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {m.cvss_score != null && (
                  <span className={`px-2 py-0.5 text-[11px] font-mono font-semibold rounded border ${SEVERITY_COLORS[m.cvss_severity] || ''}`}>
                    CVSS {m.cvss_score}{m.cvss_severity ? ` (${m.cvss_severity})` : ''}
                  </span>
                )}
                <span className="text-[10px] font-sans text-ink-faint bg-gray-50 px-2 py-0.5 rounded">
                  {SOURCE_LABEL[doc.source] || doc.source}
                </span>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] font-sans text-ink-soft">
              {m.published && (
                <>
                  <span className="text-ink-faint">发布时间</span>
                  <span>{String(m.published).slice(0, 10)}</span>
                </>
              )}
              {m.cvss_vector && (
                <>
                  <span className="text-ink-faint">CVSS 向量</span>
                  <span className="font-mono break-all">{m.cvss_vector}</span>
                </>
              )}
              {(m.products?.length > 0 || m.affected_products?.length > 0) && (
                <>
                  <span className="text-ink-faint">受影响产品</span>
                  <span>{(m.products || m.affected_products || []).slice(0, 5).join(', ')}</span>
                </>
              )}
              {m.fix_version && (
                <>
                  <span className="text-ink-faint">修复版本</span>
                  <span>{m.fix_version}</span>
                </>
              )}
              {m.kev_date_added && (
                <>
                  <span className="text-ink-faint">KEV 收录日期</span>
                  <span>{String(m.kev_date_added).slice(0, 10)}</span>
                </>
              )}
              {m.kev_due_date && (
                <>
                  <span className="text-ink-faint">处置截止</span>
                  <span>{String(m.kev_due_date).slice(0, 10)}</span>
                </>
              )}
            </div>

            {doc.content && (
              <p className="mt-3 text-xs text-ink-soft font-sans whitespace-pre-wrap line-clamp-6">{doc.content}</p>
            )}

            {(m.references?.length > 0 || (doc.tags || []).length > 0) && (
              <div className="mt-3 flex gap-1.5 flex-wrap">
                {(doc.tags || []).map((t: string) => (
                  <span key={t} className="text-[10px] font-sans text-ink-faint bg-gray-50 px-1.5 py-0.5 rounded">{t}</span>
                ))}
                {(m.references || []).slice(0, 2).map((r: string, i: number) => (
                  <a key={i} href={r} target="_blank" rel="noreferrer"
                    className="text-[10px] font-sans text-accent underline decoration-accent/30 hover:decoration-accent/60">
                    参考{i + 1}
                  </a>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
