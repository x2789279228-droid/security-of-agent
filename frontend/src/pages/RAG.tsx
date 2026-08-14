import { useState, useCallback, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { QualityPanel } from '../components/rag/QualityPanel'
import { TracePanel } from '../components/rag/TracePanel'
import { SourceOverview } from '../components/rag/SourceOverview'
import { ImportActions } from '../components/rag/ImportActions'
import { CVEQuickCheck } from '../components/rag/CVEQuickCheck'
import { api } from '../lib/api'

type Tab = 'search' | 'docs' | 'verify' | 'manage' | 'quality' | 'traces'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-600 bg-red-50 border-red-200',
  high: 'text-orange-600 bg-orange-50 border-orange-200',
  medium: 'text-yellow-600 bg-yellow-50 border-yellow-200',
  low: 'text-gray-600 bg-gray-50 border-gray-200',
  info: 'text-blue-600 bg-blue-50 border-blue-200',
}

const THREAT_OPTIONS = [
  { value: 'C2_BEACON', label: 'C2回连' },
  { value: 'DATA_EXFIL', label: '数据外泄' },
  { value: 'BRUTE_FORCE', label: '暴力破解' },
  { value: 'PORT_SCAN', label: '端口扫描' },
  { value: 'MALWARE_DETECT', label: '恶意软件' },
  { value: 'DDoS_TRAFFIC', label: 'DDoS' },
  { value: 'LATERAL_MOVE', label: '横向移动' },
  { value: 'PRIVILEGE_ESCALATION', label: '权限提升' },
  { value: 'PERSISTENCE', label: '持久化' },
  { value: 'CREDENTIAL_ACCESS', label: '凭证窃取' },
  { value: 'DISCOVERY', label: '发现侦察' },
  { value: 'DEFENSE_EVASION', label: '防御绕过' },
  { value: 'WEB_ATTACK', label: 'Web攻击' },
  { value: 'SUPPLY_CHAIN', label: '供应链攻击' },
]

const SOURCE_OPTIONS = [
  { value: '', label: '所有知识库' },
  { value: 'mitre-attack', label: 'MITRE ATT&CK' },
  { value: 'capec', label: 'CAPEC 攻击模式' },
  { value: 'cve', label: 'CVE 漏洞库' },
  { value: 'kev', label: '0day/已知被利用' },
  { value: 'vulnerability', label: '漏洞知识库' },
  { value: 'policy', label: '监管政策库' },
  { value: 'playbook', label: '应急 Playbook' },
  { value: 'internal', label: '内部知识' },
]

function classNames(...classes: (string | false | undefined | null)[]) {
  return classes.filter(Boolean).join(' ')
}

function Collapse({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-line rounded-lg overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-4 py-2.5 bg-gray-50 text-sm font-medium text-ink">
        {title}
        <span className={`transition-transform ${open ? 'rotate-180' : ''}`}>▼</span>
      </button>
      <AnimatePresence>
        {open && <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
          <div className="p-4 text-xs font-mono text-ink-soft whitespace-pre-wrap break-words max-h-96 overflow-y-auto">{children}</div>
        </motion.div>}
      </AnimatePresence>
    </div>
  )
}

export default function RAG() {
  const [activeTab, setActiveTab] = useState<Tab>('search')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<any>(null)

  // Search
  const [query, setQuery] = useState('')
  const [threatType, setThreatType] = useState('')
  const [topK, setTopK] = useState(5)
  // 知识库类型过滤（SourceOverview 卡片与搜索/文档管理下拉共用）
  const [sourceFilter, setSourceFilter] = useState('')

  // Docs
  const [docs, setDocs] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)

  // Bulk import
  const [bulkInput, setBulkInput] = useState('')
  const [bulkStatus, setBulkStatus] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const loadStats = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([api.ragStats(), api.ragDocuments('', sourceFilter)])
      setStats(s)
      setDocs(d?.documents || [])
    } catch (e: any) { setError(e.message) }
  }, [sourceFilter])

  // 挂载 + source 过滤变化时刷新
  useEffect(() => {
    loadStats()
  }, [loadStats])

  const doSearch = useCallback(async () => {
    if (!query && !threatType) { setError('请输入查询内容或选择威胁类型'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await api.ragSearch({ query, threat_type: threatType, top_k: topK, source: sourceFilter })
      setResult(data)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }, [query, threatType, topK, sourceFilter])

  const doVerify = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      const claim = (document.getElementById('verify-claim') as HTMLTextAreaElement)?.value
      const vt = (document.getElementById('verify-type') as HTMLSelectElement)?.value
      if (!claim) { setError('请输入要验证的断言'); return }
      const data = await api.ragVerify({ claim, threat_type: vt })
      setResult(data)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const doSeed = async () => {
    setLoading(true); setError('')
    try {
      await api.ragReseed()
      await loadStats()
      setResult('知识库播种完成！已载入预置安全知识文档。')
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const doBulkImport = async () => {
    if (!bulkInput.trim()) { setError('请输入或粘贴 JSON 数据'); return }
    setBulkStatus('正在导入...')
    setError('')
    let docs: any[]
    try {
      docs = JSON.parse(bulkInput)
      if (!Array.isArray(docs)) docs = [docs]
    } catch {
      setError('JSON 格式无效'); setBulkStatus(''); return
    }
    let success = 0, fail = 0
    for (const doc of docs) {
      try {
        await api.ragAddDocument({
          title: doc.title || '未命名',
          content: doc.content || '',
          source: doc.source || 'internal',
          severity: doc.severity || 'medium',
          threat_types: doc.threat_types || [],
          tags: doc.tags || [],
        })
        success++
      } catch { fail++ }
    }
    setBulkStatus(`导入完成: 成功 ${success}, 失败 ${fail}`)
    setBulkInput('')
    await loadStats()
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (evt) => { setBulkInput(evt.target?.result as string || '') }
    reader.readAsText(file)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const isEmpty = stats?.documents === 0 || !stats

  return (
    <PageTransition>
      <div className="max-w-5xl mx-auto px-6 pt-14 pb-16">
        <div className="flex items-end justify-between mb-2">
          <div>
            <h1 className="text-4xl font-semibold tracking-tight text-ink">安全知识库</h1>
            <p className="text-[15px] text-ink-soft mt-2">
              检索增强生成（RAG）— 用预置安全知识减少 LLM 幻觉
            </p>
          </div>
          <div className="flex items-center gap-2 text-[13px]">
            {stats && (
              <span className="px-3.5 py-1.5 rounded-full bg-[#0071e3]/10 text-[#0071e3] font-medium">
                文档 {stats.documents} · 分块 {stats.chunks}
              </span>
            )}
            <button onClick={loadStats} className="px-3.5 py-1.5 rounded-full bg-black/[0.05] hover:bg-black/[0.08] text-ink-soft transition-colors">刷新</button>
          </div>
        </div>
        <div className="mb-8" />

        {/* ═══ 知识库类型分布卡片（点击过滤检索/文档管理） ═══ */}
        <SourceOverview activeSource={sourceFilter} onSelect={setSourceFilter} />

        {/* ═══ 知识库为空提示 ═══ */}
        {isEmpty && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 bg-amber-50 border border-amber-200 rounded-xl">
            <p className="text-sm font-semibold text-amber-800 mb-1">知识库为空 — 立即载入安全知识</p>
            <p className="text-xs text-amber-600 mb-3">从 MITRE 官方源获取完整攻击知识库，或导入 CVE/KEV/政策/精选漏洞库</p>
            <div className="flex gap-2 flex-wrap">
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try {
                  const r = await api.ragImportMITRE()
                  setResult(`MITRE ATT&CK 导入完成: ${r.imported} 篇`)
                  await loadStats()
                } catch (e: any) { setError(e.message) }
                finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50">
                {loading ? '导入中...' : '导入 ATT&CK 完整库'}
              </button>
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try {
                  const r = await api.ragImportCAPEC()
                  setResult(`CAPEC 导入完成: ${r.imported} 篇`)
                  await loadStats()
                } catch (e: any) { setError(e.message) }
                finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
                {loading ? '导入中...' : '导入 CAPEC 完整库'}
              </button>
              <button onClick={doSeed} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-amber-600 text-white rounded-lg hover:bg-amber-700 disabled:opacity-50">
                {loading ? '播种中...' : '填充预置知识 (31篇)'}
              </button>
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try {
                  const r = await api.ragImportKEV()
                  setResult(`0day/KEV 导入完成: ${r.imported} 篇新文档, 联动 ${r.updated}`)
                  await loadStats()
                } catch (e: any) { setError(e.message) }
                finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50">
                {loading ? '导入中...' : '导入 0day/KEV'}
              </button>
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try {
                  const r = await api.ragImportPolicy()
                  setResult(`监管政策库导入完成: ${r.imported} 篇`)
                  await loadStats()
                } catch (e: any) { setError(e.message) }
                finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 disabled:opacity-50">
                {loading ? '导入中...' : '导入监管政策库'}
              </button>
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try {
                  const r = await api.ragImportVulnerability()
                  setResult(`精选漏洞库导入完成: ${r.imported} 篇`)
                  await loadStats()
                } catch (e: any) { setError(e.message) }
                finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50">
                {loading ? '导入中...' : '导入精选漏洞库'}
              </button>
            </div>
          </motion.div>
        )}

        {/* ═══ 已填充但文档较少时也显示补充按钮 ═══ */}
        {!isEmpty && stats?.documents < 5 && (
          <div className="mb-6 p-3 bg-blue-50 border border-blue-200 rounded-lg flex items-center justify-between">
            <p className="text-xs text-blue-700">知识库文档较少，建议填充更全面的预置安全知识</p>
            <button onClick={doSeed} disabled={loading}
              className="px-4 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
              补充预置知识
            </button>
          </div>
        )}

        {/* ═══ Tab 导航 — Apple 分段控件 ═══ */}
        <div className="flex gap-1 mb-8 p-1 bg-black/[0.05] rounded-full w-fit">
          {[
            { id: 'search', label: '知识检索' },
            { id: 'docs', label: '文档管理' },
            { id: 'verify', label: '断言验证' },
            { id: 'manage', label: '知识管理' },
            { id: 'quality', label: '质量评估' },
            { id: 'traces', label: 'Agent 轨迹' },
          ].map(tab => (
            <button key={tab.id} onClick={() => { setActiveTab(tab.id as Tab); if (tab.id === 'docs') loadStats() }}
              className={classNames('px-5 py-2 text-[13px] font-medium rounded-full transition-all',
                activeTab === tab.id ? 'bg-card text-ink shadow-[0_1px_4px_rgba(0,0,0,0.1)]' : 'text-ink-soft hover:text-ink')}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* ═══ Tab: 知识检索 ═══ */}
        {activeTab === 'search' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <input type="text" placeholder="搜索查询（如 C2通信、暴力破解）" value={query}
                onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && doSearch()}
                className="flex-1 min-w-[160px] px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
                className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                {SOURCE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <select value={threatType} onChange={e => setThreatType(e.target.value)}
                className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                <option value="">所有类型</option>
                {THREAT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <select value={topK} onChange={e => setTopK(Number(e.target.value))}
                className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                <option value={3}>Top 3</option>
                <option value={5}>Top 5</option>
                <option value={10}>Top 10</option>
              </select>
              <button onClick={doSearch} disabled={loading}
                className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                {loading ? '搜索中...' : '搜索'}
              </button>
            </div>

            {/* CVE 速查 */}
            <CVEQuickCheck />

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {result && result.total === 0 && (
              <div className="p-4 text-center text-xs text-ink-faint font-sans bg-gray-50 rounded-lg">未找到匹配的知识文档</div>
            )}

            {result && result.total > 0 && (
              <div className="space-y-3">
                <p className="text-xs text-ink-faint font-sans">
                  检索策略: {result.strategy} · 共 {result.total} 条结果
                </p>
                {(result.chunks || []).map((chunk: any, i: number) => (
                  <div key={i} className="border border-line rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-sans font-semibold">{chunk.title}</span>
                        <span className={classNames('px-1.5 py-0.5 text-[10px] font-sans rounded border', SEVERITY_COLORS[chunk.severity] || '')}>
                          {chunk.severity}
                        </span>
                      </div>
                      <span className="text-[10px] font-sans text-ink-faint">score: {(chunk.score * 100).toFixed(0)}%</span>
                    </div>
                    <p className="text-xs text-ink-soft font-sans whitespace-pre-wrap line-clamp-4">{chunk.content}</p>
                    <div className="flex gap-2 mt-2 flex-wrap">
                      <span className="text-[10px] font-sans text-ink-faint bg-gray-50 px-2 py-0.5 rounded">{chunk.source}</span>
                      {(chunk.threat_types || []).map((t: string) => (
                        <span key={t} className="text-[10px] font-sans text-ink-faint bg-gray-50 px-2 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ═══ Tab: 文档管理 ═══ */}
        {activeTab === 'docs' && (
          <div className="space-y-4">
            <div className="flex gap-2 flex-wrap items-center">
              <button onClick={loadStats} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新列表</button>
              <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
                className="px-3 py-1.5 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                {SOURCE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <button onClick={doSeed} disabled={loading}
                className="px-3 py-1.5 text-xs font-sans font-medium bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 disabled:opacity-50">
                {loading ? '播种中...' : '重新播种预置知识'}
              </button>
            </div>
            {stats && (
              <div className="flex gap-3 text-xs font-sans">
                <span className="px-3 py-1.5 bg-blue-50 text-blue-700 rounded-lg">文档: {stats.documents}</span>
                <span className="px-3 py-1.5 bg-green-50 text-green-700 rounded-lg">分块: {stats.chunks}</span>
              </div>
            )}
            {isEmpty ? (
              <div className="text-center text-xs text-ink-faint font-sans py-8">
                <p className="mb-3">知识库为空</p>
                <button onClick={doSeed} disabled={loading}
                  className="px-5 py-2 text-xs font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                  一键填充预置安全知识（25+ 篇）
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {docs.map((doc: any) => (
                  <div key={doc.id} className="flex items-start gap-3 p-3 border border-line rounded-lg">
                    <div className="flex-1 min-w-0 text-xs font-sans">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-ink">{doc.title}</span>
                        <span className={classNames('px-1 py-0.5 text-[10px] rounded border', SEVERITY_COLORS[doc.severity] || '')}>{doc.severity}</span>
                      </div>
                      <p className="text-ink-faint mt-1 truncate">{doc.content}</p>
                      <div className="flex gap-2 mt-1.5 flex-wrap">
                        <span className="text-[10px] text-ink-faint bg-gray-50 px-1.5 py-0.5 rounded">{doc.source}</span>
                        {(doc.threat_types || []).map((t: string) => (
                          <span key={t} className="text-[10px] text-ink-faint bg-gray-50 px-1.5 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    </div>
                    <button onClick={async () => { try { await api.ragDeleteDocument(doc.id); await loadStats() } catch {} }}
                      className="text-[10px] text-red-500 hover:text-red-700 shrink-0">删除</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ═══ Tab: 断言验证 ═══ */}
        {activeTab === 'verify' && (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">输入要验证的断言</label>
              <textarea id="verify-claim" rows={4} placeholder='例如: "C2通信应立即封禁源IP"'
                className="w-full px-3 py-2 text-xs font-mono border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent" />
            </div>
            <div className="flex items-center gap-3">
              <select id="verify-type" defaultValue=""
                className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                <option value="">所有类型</option>
                {THREAT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <button onClick={doVerify} disabled={loading}
                className="px-5 py-2 text-xs font-sans font-medium bg-purple-600 text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                {loading ? '验证中...' : '验证断言'}
              </button>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {result && result.claim && (
              <div className="space-y-3">
                <div className={classNames('p-3 rounded-lg border text-xs font-sans',
                  result.verdict === 'supported' ? 'bg-green-50 border-green-200 text-green-700' :
                  result.verdict === 'contradicted' ? 'bg-red-50 border-red-200 text-red-700' :
                  'bg-yellow-50 border-yellow-200 text-yellow-700')}>
                  <p><strong>断言:</strong> {result.claim}</p>
                  <p className="mt-1"><strong>裁决:</strong> {result.verdict} (置信度: {(result.confidence * 100).toFixed(0)}%)</p>
                  {result.suggestion && <p className="mt-1"><strong>建议:</strong> {result.suggestion}</p>}
                </div>
                {result.supporting_evidence?.length > 0 && (
                  <Collapse title="支撑证据" defaultOpen>
                    {result.supporting_evidence.map((e: string, i: number) => (
                      <p key={i} className="mb-1">[{i + 1}] {e}</p>
                    ))}
                  </Collapse>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══ Tab: 知识管理 ═══ */}
        {activeTab === 'manage' && (
          <div className="space-y-6">
            {/* ── 从 MITRE 官方导入 ╴─ */}
            <div className="p-4 bg-gradient-to-r from-purple-50 to-violet-50 border border-purple-200 rounded-xl">
              <p className="text-sm font-semibold text-purple-800 mb-2">从 MITRE 官方导入完整知识库</p>
              <p className="text-xs text-purple-600 mb-3">从互联网实时获取 MITRE ATT&CK（数百种攻击技术）和 CAPEC（五百余种攻击模式）官方数据</p>
              <div className="flex gap-2 flex-wrap">
                <button onClick={async () => {
                  setLoading(true); setError(''); setResult(null)
                  try {
                    const r = await api.ragImportMITRE()
                    setResult(`MITRE ATT&CK 导入完成: ${r.imported} 篇新文档, 跳过 ${r.skipped}, 错误 ${r.errors}`)
                    await loadStats()
                  } catch (e: any) { setError(e.message) }
                  finally { setLoading(false) }
                }} disabled={loading}
                  className="px-4 py-2 text-xs font-sans font-medium bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50">
                  {loading ? '导入中...' : '导入 ATT&CK 完整库'}
                </button>
                <button onClick={async () => {
                  setLoading(true); setError(''); setResult(null)
                  try {
                    const r = await api.ragImportCAPEC()
                    setResult(`CAPEC 导入完成: ${r.imported} 篇新文档, 跳过 ${r.skipped}, 错误 ${r.errors}`)
                    await loadStats()
                  } catch (e: any) { setError(e.message) }
                  finally { setLoading(false) }
                }} disabled={loading}
                  className="px-4 py-2 text-xs font-sans font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
                  {loading ? '导入中...' : '导入 CAPEC 完整库'}
                </button>
                <button onClick={async () => {
                  setLoading(true); setError(''); setResult(null)
                  try {
                    await api.ragImportAll()
                    await loadStats()
                    setResult('所有 MITRE 知识库导入完成！')
                  } catch (e: any) { setError(e.message) }
                  finally { setLoading(false) }
                }} disabled={loading}
                  className="px-4 py-2 text-xs font-sans font-medium bg-pink-600 text-white rounded-lg hover:bg-pink-700 disabled:opacity-50">
                  {loading ? '导入中...' : '导入全部 (ATT&CK+CAPEC)'}
                </button>
              </div>
            </div>

            {/* ── CVE/KEV/政策/精选漏洞 导入 ── */}
            <div className="border border-line rounded-xl p-4">
              <p className="text-sm font-semibold text-ink mb-2">导入漏洞 / 政策知识库</p>
              <p className="text-xs text-ink-soft mb-3">
                CVE（NVD 聚焦）· 0day/已知被利用（CISA KEV）· 监管政策 · 手工精选漏洞 — 均幂等，可重复导入
              </p>
              <ImportActions onImported={loadStats} />
            </div>

            {/* ── 一键填充预置知识 ── */}
            <div className="p-4 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-xl">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-blue-800">一键填充预置安全知识</p>
                  <p className="text-xs text-blue-600 mt-0.5">
                    包含 31 篇 MITRE ATT&CK 攻击技术、应急响应 Playbook、安全基线、IOC规则等
                  </p>
                </div>
                <button onClick={doSeed} disabled={loading}
                  className="px-5 py-2 text-xs font-sans font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 shrink-0">
                  {loading ? '播种中...' : '一键填充'}
                </button>
              </div>
            </div>

            {/* ── 文件批量导入 ── */}
            <div className="border border-line rounded-lg p-4">
              <p className="text-xs font-sans font-medium text-ink-faint mb-3">批量导入知识文档（JSON）</p>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <input ref={fileInputRef} type="file" accept=".json,.txt" onChange={handleFileUpload}
                    className="block text-xs text-ink-faint file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-sans file:font-medium file:bg-gray-100 file:text-ink hover:file:bg-gray-200" />
                  <span className="text-xs text-ink-faint self-center">或粘贴 JSON: </span>
                </div>
                <textarea value={bulkInput} onChange={e => setBulkInput(e.target.value)} rows={6}
                  placeholder='[{"title":"示例知识","content":"知识正文...","source":"internal","severity":"medium","threat_types":["C2_BEACON"]}]'
                  className="w-full px-3 py-2 text-xs font-mono border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <div className="flex items-center gap-2">
                  <button onClick={doBulkImport} disabled={loading || !bulkInput.trim()}
                    className="px-4 py-1.5 text-xs font-sans font-medium bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50">
                    批量导入
                  </button>
                  {bulkStatus && <span className="text-xs text-green-600">{bulkStatus}</span>}
                </div>
              </div>
            </div>

            {/* ── 手动添加 ── */}
            <div className="border border-line rounded-lg p-4">
              <p className="text-xs font-sans font-medium text-ink-faint mb-3">手动添加知识文档（自动分块+向量化）</p>
              <div className="space-y-3">
                <input id="doc-title" type="text" placeholder="文档标题"
                  className="w-full px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <textarea id="doc-content" rows={6} placeholder="文档内容..."
                  className="w-full px-3 py-2 text-xs font-mono border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <div className="flex items-center gap-3 flex-wrap">
                  <select id="doc-source" defaultValue="internal"
                    className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                    <option value="mitre-attack">MITRE ATT&CK</option>
                    <option value="playbook">Playbook</option>
                    <option value="internal">内部文档</option>
                    <option value="cve">CVE</option>
                  </select>
                  <select id="doc-severity" defaultValue="medium"
                    className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                    <option value="info">Info</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                  <input id="doc-threats" type="text" placeholder="威胁类型(逗号分隔)"
                    className="flex-1 min-w-[120px] px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                  <button onClick={async () => {
                    const title = (document.getElementById('doc-title') as HTMLInputElement)?.value
                    const content = (document.getElementById('doc-content') as HTMLTextAreaElement)?.value
                    const source = (document.getElementById('doc-source') as HTMLSelectElement)?.value
                    const severity = (document.getElementById('doc-severity') as HTMLSelectElement)?.value
                    const threats = (document.getElementById('doc-threats') as HTMLInputElement)?.value
                    if (!title || !content) { setError('标题和内容为必填'); return }
                    setLoading(true); setError(''); setResult(null)
                    try {
                      const data = await api.ragAddDocument({
                        title, content, source, severity,
                        threat_types: threats ? threats.split(',').map((t: string) => t.trim()) : [],
                      })
                      setResult(data)
                      ;(document.getElementById('doc-title') as HTMLInputElement).value = ''
                      ;(document.getElementById('doc-content') as HTMLTextAreaElement).value = ''
                      await loadStats()
                    } catch (e: any) { setError(e.message) }
                    finally { setLoading(false) }
                  }} disabled={loading}
                    className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                    添加文档
                  </button>
                </div>
              </div>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}
            {result && typeof result === 'string' && (
              <div className="p-3 bg-green-50 border border-green-200 rounded-lg text-xs text-green-700">{result}</div>
            )}
            {result && typeof result === 'object' && result.doc_id !== undefined && (
              <Collapse title="添加成功" defaultOpen>
                {JSON.stringify(result, null, 2)}
              </Collapse>
            )}
          </div>
        )}

        {/* ═══ Tab: 质量评估 ═══ */}
        {activeTab === 'quality' && (
          <QualityPanel />
        )}

        {/* ═══ Tab: Agent 轨迹 ═══ */}
        {activeTab === 'traces' && (
          <TracePanel />
        )}
      </div>
    </PageTransition>
  )
}
