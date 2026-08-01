import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

type Tab = 'inject' | 'batch' | 'pipeline' | 'cad' | 'chains'

const EVENT_PRESETS = [
  { label: 'C2通信 (critical)', value: { event: 'C2_BEACON', severity: 'critical', src_ip: '192.168.1.105', dst_ip: '23.129.64.33', message: '内部主机疑似与C2服务器通信', confidence: 85 } },
  { label: '端口扫描 (medium)', value: { event: 'PORT_SCAN', severity: 'medium', src_ip: '45.33.32.156', dst_ip: '192.168.1.100', message: '检测到端口扫描行为' } },
  { label: '暴力破解 (critical)', value: { event: 'BRUTE_FORCE', severity: 'critical', src_ip: '103.235.46.22', dst_ip: '192.168.1.100', message: 'SSH暴力破解攻击已拦截', confidence: 95 } },
  { label: '数据外泄 (critical)', value: { event: 'DATA_EXFIL', severity: 'critical', src_ip: '10.0.0.5', dst_ip: '45.63.1.22', message: '检测到大量数据外传', confidence: 88 } },
  { label: '登录成功 (info)', value: { event: 'USER_LOGIN', severity: 'info', src_ip: '192.168.1.50', dst_ip: '10.0.0.1', message: '管理员登录成功' } },
  { label: 'DNS查询 (low)', value: { event: 'DNS_QUERY', severity: 'low', src_ip: '192.168.1.200', dst_ip: '8.8.8.8', message: 'DNS解析请求' } },
]

const ATTACK_TYPES = ['PORT_SCAN', 'BRUTE_FORCE', 'SQL_INJECTION', 'C2_BEACON', 'MALWARE_DETECT', 'DATA_EXFIL', 'DDoS_TRAFFIC', 'XSS_ATTACK']
const NORMAL_TYPES = ['USER_LOGIN', 'FILE_ACCESS', 'DNS_QUERY', 'EMAIL_SENT', 'VPN_CONNECT']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

function generateBatch(count: number): Record<string, any>[] {
  const events: Record<string, any>[] = []
  for (let i = 0; i < count; i++) {
    const isAttack = i % 4 === 0
    const octet = (i % 253) + 1
    if (isAttack) {
      events.push({
        event: ATTACK_TYPES[i % ATTACK_TYPES.length],
        severity: SEVERITIES[3 + (i % 2)],
        src_ip: `45.33.32.${octet}`,
        dst_ip: '192.168.1.100',
        message: `批量测试攻击事件 #${i + 1}`,
        confidence: 70 + (i % 25),
      })
    } else {
      events.push({
        event: NORMAL_TYPES[i % NORMAL_TYPES.length],
        severity: SEVERITIES[i % 3],
        src_ip: `192.168.1.${octet}`,
        dst_ip: `10.0.0.${(i % 254) + 1}`,
        message: `批量测试正常事件 #${i + 1}`,
      })
    }
  }
  return events
}

function classNames(...classes: (string | false | undefined)[]) {
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

export default function SecurityAudit() {
  const [activeTab, setActiveTab] = useState<Tab>('inject')
  const [eventJson, setEventJson] = useState(JSON.stringify(EVENT_PRESETS[0].value, null, 2))
  const [sessionId, setSessionId] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')

  // Pipeline
  const [pipelineEventId, setPipelineEventId] = useState<number | null>(null)
  const [pipelineData, setPipelineData] = useState<any>(null)

  // CAD
  const [cbStatus, setCbStatus] = useState<any>(null)

  // Chains
  const [chainSessionId, setChainSessionId] = useState('')
  const [chainData, setChainData] = useState<any>(null)

  // Batch
  const [batchInput, setBatchInput] = useState('')
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; eventIds: number[] } | null>(null)
  const [batchResult, setBatchResult] = useState<any>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const applyPreset = (preset: typeof EVENT_PRESETS[0]) => {
    setEventJson(JSON.stringify(preset.value, null, 2))
  }

  const handleInject = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      const event = JSON.parse(eventJson)
      const data = await api.ingestLog(event, sessionId || undefined)
      setResult(data)
      setSessionId(data.session_id || sessionId)
      if (data.event_id) setPipelineEventId(data.event_id)
    } catch (e: any) {
      setError(e.message || '注入失败')
    } finally { setLoading(false) }
  }

  const queryPipeline = useCallback(async () => {
    if (!pipelineEventId) return
    try {
      const data = await api.getPipeline(pipelineEventId)
      setPipelineData(data)
    } catch { /* ignore polling errors */ }
  }, [pipelineEventId])

  useEffect(() => {
    if (!pipelineEventId) return
    queryPipeline()
    const interval = setInterval(queryPipeline, 3000)
    return () => clearInterval(interval)
  }, [pipelineEventId, queryPipeline])

  const loadCadStatus = async () => {
    try {
      const cb = await api.getCircuitBreaker()
      setCbStatus(cb)
    } catch (e: any) { setError(e.message) }
  }

  useEffect(() => { loadCadStatus() }, [])

  const queryChains = async () => {
    if (!chainSessionId) return
    try {
      const data = await api.getChains(chainSessionId)
      setChainData(data)
    } catch (e: any) { setError(e.message) }
  }

  // ── 批量导入 ──

  const parseBatchInput = (): Record<string, any>[] => {
    const trimmed = batchInput.trim()
    if (!trimmed) return []
    try {
      const parsed = JSON.parse(trimmed)
      return Array.isArray(parsed) ? parsed : [parsed]
    } catch {
      // 尝试按行解析 JSON
      const lines = trimmed.split('\n').filter(l => l.trim())
      return lines.map(l => JSON.parse(l))
    }
  }

  const runBatchImport = async (events: Record<string, any>[]) => {
    if (events.length === 0) { setError('没有可导入的事件'); return }
    setLoading(true); setError(''); setBatchResult(null)
    const batchSid = sessionId || crypto.randomUUID()
    setSessionId(batchSid)
    const ids: number[] = []
    let failureCount = 0
    setBatchProgress({ current: 0, total: events.length, eventIds: ids })

    for (let i = 0; i < events.length; i++) {
      try {
        const data = await api.ingestLog(events[i], batchSid)
        if (data.event_id) ids.push(data.event_id)
        else failureCount++
      } catch (e: any) {
        failureCount++
        setError(`事件 #${i + 1} 注入失败: ${e.message || e}`)
      }
      setBatchProgress({ current: i + 1, total: events.length, eventIds: ids })
    }

    setBatchProgress(null)
    setBatchResult({ total: events.length, succeed: ids.length, failed: failureCount, session_id: batchSid, event_ids: ids })
    if (failureCount > 0) setError(`${failureCount} 条事件注入失败，请查看详情`)
    setLoading(false)
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (evt) => {
      const text = evt.target?.result as string
      setBatchInput(text)
    }
    reader.readAsText(file)
  }

  return (
    <PageTransition>
      <div className="max-w-5xl mx-auto px-6 pt-14 pb-16">
        <h1 className="text-4xl font-semibold tracking-tight text-ink">安全审计测试台</h1>
        <p className="text-[15px] text-ink-soft mt-2 mb-8">Audit-LLM + CAD 系统可靠性测试 — 支持单条 / 批量 / 文件导入</p>

        {/* Tab Bar — Apple 分段控件 */}
        <div className="flex gap-1 mb-8 p-1 bg-black/[0.05] rounded-full w-fit">
          {([{ id: 'inject', label: '单条注入' }, { id: 'batch', label: '批量导入' }, { id: 'pipeline', label: '流水线' }, { id: 'cad', label: 'CAD审计' }, { id: 'chains', label: '攻击链' }] as { id: Tab; label: string }[]).map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={classNames('px-5 py-2 text-[13px] font-medium rounded-full transition-all',
                activeTab === tab.id ? 'bg-card text-ink shadow-[0_1px_4px_rgba(0,0,0,0.1)]' : 'text-ink-soft hover:text-ink')}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab: 单条注入 ── */}
        {activeTab === 'inject' && (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">快速选择事件</label>
              <div className="flex flex-wrap gap-2">
                {EVENT_PRESETS.map(p => (
                  <button key={p.label} onClick={() => applyPreset(p)}
                    className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">事件 JSON</label>
              <textarea value={eventJson} onChange={e => setEventJson(e.target.value)}
                className="w-full h-40 px-3 py-2 text-xs font-mono border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent" />
            </div>
            <div className="flex items-center gap-3">
              <input type="text" placeholder="Session ID (可选)" value={sessionId}
                onChange={e => setSessionId(e.target.value)}
                className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              <button onClick={handleInject} disabled={loading}
                className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                {loading ? '注入中...' : '注入事件'}
              </button>
            </div>
            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}
            {result && <Collapse title="注入结果" defaultOpen>{JSON.stringify(result, null, 2)}</Collapse>}
            <div className="pt-4 border-t border-line">
              <p className="text-xs font-sans font-medium text-ink-faint mb-2">或手动触发 Audit-LLM 完整流水线</p>
              <button onClick={async () => {
                setLoading(true); setError(''); setResult(null)
                try { const data = await api.runAuditLLM(JSON.parse(eventJson)); setResult(data) }
                catch (e: any) { setError(e.message) } finally { setLoading(false) }
              }} disabled={loading}
                className="px-4 py-2 text-xs font-sans font-medium bg-purple-600 text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                运行 Audit-LLM
              </button>
            </div>
          </div>
        )}

        {/* ── Tab: 批量导入 ── */}
        {activeTab === 'batch' && (
          <div className="space-y-4">
            {/* 生成模拟数据 */}
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">生成模拟数据</label>
              <div className="flex flex-wrap gap-2">
                {[10, 50, 100, 500].map(n => (
                  <button key={n} onClick={() => {
                    const events = generateBatch(n)
                    setBatchInput(JSON.stringify(events, null, 2))
                  }} className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors">
                    生成 {n} 条
                  </button>
                ))}
                <button onClick={() => {
                  const events = generateBatch(60).map((e, i) => ({
                    ...e,
                    event: i < 20 ? 'USER_LOGIN' : (i < 40 ? 'DNS_QUERY' : (ATTACK_TYPES[i % ATTACK_TYPES.length])),
                    severity: i < 40 ? 'info' : 'high',
                    src_ip: `192.168.1.${(i % 254) + 1}`,
                    message: i < 40 ? `正常操作 #${i + 1}` : `攻击行为 #${i + 1}`,
                  }))
                  setBatchInput(JSON.stringify(events, null, 2))
                }} className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors">
                  模拟攻击链场景 (60条)
                </button>
              </div>
            </div>

            {/* 文件上传 */}
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">上传 JSON 文件</label>
              <input ref={fileInputRef} type="file" accept=".json,.txt" onChange={handleFileUpload}
                className="text-xs font-sans text-ink-faint file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border file:border-line file:text-xs file:font-sans file:font-medium file:bg-white file:text-ink hover:file:bg-gray-50" />
            </div>

            {/* JSON 编辑区 */}
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">
                事件列表 JSON（数组 或 每行一条）
                {batchInput && <span className="text-ink-faint ml-2">
                  （{(() => { try { const p = JSON.parse(batchInput); return Array.isArray(p) ? p.length : 1 } catch { return batchInput.trim().split('\n').filter(l => l.trim()).length } })()} 条事件）
                </span>}
              </label>
              <textarea value={batchInput} onChange={e => setBatchInput(e.target.value)}
                className="w-full h-48 px-3 py-2 text-xs font-mono border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent"
                placeholder='[{"event":"PORT_SCAN","severity":"high","src_ip":"10.0.0.1","message":"扫描"}, ...]' />
            </div>

            {/* 进度条 */}
            {batchProgress && (
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-sans text-ink-faint">
                  <span>正在导入... {batchProgress.current}/{batchProgress.total}</span>
                  <span>{batchProgress.eventIds.length} 条成功</span>
                </div>
                <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-full bg-accent rounded-full transition-all duration-300"
                    style={{ width: `${(batchProgress.current / batchProgress.total) * 100}%` }} />
                </div>
              </div>
            )}

            {/* 操作按钮组 */}
            <div className="flex items-center gap-3">
              <input type="text" placeholder="Session ID (可选，同组事件共享)" value={sessionId}
                onChange={e => setSessionId(e.target.value)}
                className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              <button onClick={async () => {
                  setError('')
                  try {
                    const events = parseBatchInput()
                    if (events.length === 0) { setError('没有可导入的事件'); return }
                    await runBatchImport(events)
                  } catch (e: any) {
                    setError(`解析失败: ${e.message || e}。请确保是 JSON 数组格式`)
                  }
                }} disabled={loading || !batchInput.trim()}
                className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                {loading ? '导入中...' : '开始批量导入'}
              </button>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {/* 批量结果 */}
            {batchResult && (
              <div className="space-y-3">
                <div className="flex gap-3 text-xs font-sans">
                  <span className="px-3 py-1.5 bg-green-50 text-green-700 rounded-lg">成功: {batchResult.succeed}/{batchResult.total}</span>
                  <span className="px-3 py-1.5 bg-blue-50 text-blue-700 rounded-lg">Session: {batchResult.session_id.slice(0, 12)}...</span>
                  <button onClick={() => { setSessionId(batchResult.session_id); setChainSessionId(batchResult.session_id); setActiveTab('chains') }}
                    className="px-3 py-1.5 bg-purple-50 text-purple-700 rounded-lg hover:bg-purple-100">
                    查看攻击链
                  </button>
                </div>
                <Collapse title="批量导入详情">{JSON.stringify(batchResult, null, 2)}</Collapse>
              </div>
            )}
          </div>
        )}

        {/* ── Tab: 流水线 ── */}
        {activeTab === 'pipeline' && (
          <div className="space-y-4">
            {pipelineEventId && <div className="text-xs text-ink-faint font-sans">查看事件 #{pipelineEventId} 的流水线结果</div>}
            {pipelineData ? (
              <>
                <Collapse title="合并结论" defaultOpen>{JSON.stringify(pipelineData.pipeline_result?.merged, null, 2)}</Collapse>
                <Collapse title="各轮次详情" defaultOpen>{JSON.stringify(pipelineData.pipeline_result?.rounds_detail, null, 2)}</Collapse>
                <Collapse title="证据链 (断言↔事件ID)">{JSON.stringify(pipelineData.pipeline_result?.evidence_trail, null, 2)}</Collapse>
                <Collapse title="Reviewer 裁决">{JSON.stringify(pipelineData.pipeline_result?.final_verdict, null, 2)}</Collapse>
                <Collapse title="CAD 穿透验证">{JSON.stringify(pipelineData.pipeline_result?.hallucination, null, 2)}</Collapse>
              </>
            ) : (
              <div className="text-xs text-ink-faint font-sans p-8 text-center">
                {pipelineEventId ? '等待流水线完成...' : '请先在"单条注入"或"批量导入"页签注入事件'}
              </div>
            )}
          </div>
        )}

        {/* ── Tab: CAD审计 ── */}
        {activeTab === 'cad' && (
          <div className="space-y-4">
            <Collapse title="熔断器状态" defaultOpen>{cbStatus ? JSON.stringify(cbStatus, null, 2) : '加载中...'}</Collapse>
            <div className="flex gap-2 flex-wrap">
              <button onClick={loadCadStatus} className="px-4 py-2 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新CAD状态</button>
              <button onClick={async () => { try { const data = await api.triggerContextAudit(); setResult(data) } catch (e: any) { setError(e.message) } }}
                className="px-4 py-2 text-xs font-sans font-medium bg-orange-500 text-white rounded-lg hover:opacity-90">运行上下文审计</button>
              <button onClick={async () => { try { await api.resetCircuitBreaker(); await loadCadStatus() } catch (e: any) { setError(e.message) } }}
                className="px-4 py-2 text-xs font-sans font-medium bg-red-500 text-white rounded-lg hover:opacity-90">重置熔断器</button>
            </div>
            {result && activeTab === 'cad' && <Collapse title="上下文审计结果" defaultOpen>{JSON.stringify(result, null, 2)}</Collapse>}
            <div className="pt-4 border-t border-line">
              <p className="text-xs font-sans font-medium text-ink-faint mb-2">按事件ID查询 CAD 穿透验证</p>
              <input type="number" placeholder="Event ID" onChange={e => { const id = parseInt(e.target.value); if (id) api.getCadVerification(id).then(setResult).catch(e => setError(e.message)) }}
                className="w-32 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              {result && activeTab === 'cad' && <Collapse title="CAD 验证结果" defaultOpen>{JSON.stringify(result, null, 2)}</Collapse>}
            </div>
          </div>
        )}

        {/* ── Tab: 攻击链 ── */}
        {activeTab === 'chains' && (
          <div className="space-y-4">
            <div className="flex gap-2 items-center">
              <input type="text" placeholder="Session ID" value={chainSessionId}
                onChange={e => setChainSessionId(e.target.value)}
                className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              <button onClick={queryChains} className="px-4 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90">查询攻击链</button>
            </div>
            {chainData && (
              <>
                <Collapse title="攻击链列表" defaultOpen>
                  {chainData.chains?.length > 0 ? chainData.chains.map((c: any, i: number) => (
                    <div key={i} className="mb-3 pb-3 border-b border-line last:border-0">
                      <p className="font-medium text-ink">[{c.pattern_name}] conf={c.confidence}</p>
                      <p className="text-ink-faint mt-1">{c.alert}</p>
                      <p className="text-ink-faint text-[10px] mt-1">事件IDs: {c.event_ids?.join(', ')}</p>
                    </div>
                  )) : '未发现攻击链'}
                </Collapse>
                <Collapse title="时间窗口分组">{JSON.stringify(chainData.temporal_groups, null, 2)}</Collapse>
              </>
            )}
          </div>
        )}

        {/* 全局统计 */}
        <div className="mt-8 pt-6 border-t border-line">
          <button onClick={async () => { try { const data = await api.getAuditStats(); setResult(data) } catch (e: any) { setError(e.message) } }}
            className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新统计</button>
        </div>
      </div>
    </PageTransition>
  )
}
