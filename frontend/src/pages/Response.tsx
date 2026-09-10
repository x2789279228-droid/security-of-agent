import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

type Tab = 'threats' | 'policies' | 'approvals' | 'logs'

const THREAT_PRESETS = [
  { label: 'C2回连 (critical)', value: { threat_type: 'C2_BEACON', confidence: 0.85, severity: 'critical', src_ip: '192.168.1.105', message: '检测到内部主机与已知C2服务器通信' } },
  { label: '数据外泄 (critical)', value: { threat_type: 'DATA_EXFIL', confidence: 0.9, severity: 'critical', src_ip: '10.0.0.5', message: '大量数据外传到外部IP' } },
  { label: '暴力破解 (high)', value: { threat_type: 'BRUTE_FORCE', confidence: 0.75, severity: 'high', src_ip: '103.235.46.22', message: 'SSH暴力破解攻击已拦截' } },
  { label: '端口扫描 (medium)', value: { threat_type: 'PORT_SCAN', confidence: 0.6, severity: 'medium', src_ip: '45.33.32.156', message: '检测到端口扫描行为' } },
  { label: '恶意软件 (critical)', value: { threat_type: 'MALWARE_DETECT', confidence: 0.8, severity: 'critical', src_ip: '192.168.1.50', message: '终端检测到恶意软件' } },
  { label: 'DDoS (high)', value: { threat_type: 'DDoS_TRAFFIC', confidence: 0.7, severity: 'high', src_ip: '203.0.113.1', message: '检测到DDoS攻击流量' } },
]

function classNames(...classes: (string | false | undefined | null)[]) {
  return classes.filter(Boolean).join(' ')
}

function Collapse({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-line overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-4 py-2.5 bg-mist text-sm font-medium text-ink">
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

export default function Response() {
  const [activeTab, setActiveTab] = useState<Tab>('threats')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<any>(null)
  const [sessionId, setSessionId] = useState('')

  // Policies
  const [policies, setPolicies] = useState<any[]>([])
  const [actions, setActions] = useState<any[]>([])

  // Approvals
  const [approvals, setApprovals] = useState<any[]>([])
  const [previews, setPreviews] = useState<Record<string, any>>({})
  const [previewingId, setPreviewingId] = useState('')
  const [logs, setLogs] = useState<any[]>([])

  // Execute
  const [execAction, setExecAction] = useState('block_ip')
  const [execTarget, setExecTarget] = useState('')
  const [execPid, setExecPid] = useState('')
  const [execSha, setExecSha] = useState('')
  const [execPath, setExecPath] = useState('')
  const [execAccount, setExecAccount] = useState('')
  const [execDomain, setExecDomain] = useState('')
  const [execMsgId, setExecMsgId] = useState('')
  const [rollbackToken, setRollbackToken] = useState('')

  const loadPolicies = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([api.getResponsePolicies(), api.getResponseActions()])
      setPolicies(p)
      setActions(a)
    } catch (e: any) { setError(e.message) }
  }, [])

  const loadApprovals = useCallback(async () => {
    try {
      const data = await api.getApprovals(true)
      setApprovals(data)
    } catch (e: any) { setError(e.message) }
  }, [])

  const loadLogs = useCallback(async () => {
    try {
      const data = await api.getResponseLogs({})
      setLogs(data)
    } catch (e: any) { setError(e.message) }
  }, [])

  useEffect(() => { loadPolicies() }, [loadPolicies])

  const simulateThreat = async (threat: any) => {
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await api.simulateThreat({ ...threat, session_id: sessionId || undefined })
      setResult(data)
      if (data.approval_ticket_id) loadApprovals()
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const handleExecResponse = async () => {
    const needsIp = ['block_ip', 'isolate_host', 'rate_limit', 'kill_session'].includes(execAction)
    if (needsIp && !execTarget) { setError('请输入目标IP'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const params: Record<string, unknown> = {}
      if (execTarget) { params.src_ip = execTarget; params.host_ip = execTarget }
      if (execPid) params.pid = Number(execPid)
      if (execSha) params.sha256 = execSha
      if (execPath) params.path = execPath
      if (execAccount) params.account = execAccount
      if (execDomain) params.domain = execDomain
      if (execMsgId) params.internet_message_id = execMsgId
      const data = await api.executeResponse(execAction, params, '手动执行')
      setResult(data)
      if (data.rollback_token) setRollbackToken(data.rollback_token)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const handleRollback = async () => {
    if (!rollbackToken) { setError('没有回滚令牌'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await api.rollbackResponse(rollbackToken)
      setResult(data)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'text-white bg-ink border-ink'
      case 'high': return 'text-white bg-nong border-nong'
      case 'medium': return 'text-ink bg-qing border-line'
      default: return 'text-ink-faint bg-mist border-line'
    }
  }

  return (
    <PageTransition>
      <div className="page-shell pt-4 pb-12">
        <header className="flex flex-col gap-2 border-b border-line pb-3 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0 md:max-w-[44rem]">
            <h1 className="font-serif text-[28px] font-black tracking-[-0.04em] text-ink leading-[1.1]">
              响应引擎
            </h1>
            <p className="mt-1 text-[13px] leading-snug text-ink-soft">
              自动威胁响应 · 策略管理 · 审批流程 · 回滚。
            </p>
            <p className="mt-1 hidden font-serif italic text-[12px] leading-snug text-ink-faint/80 md:block">
              <span aria-hidden className="mr-1 text-[#c9a574]/70">¶</span>
              ——封禁要快，回滚要快。
            </p>
          </div>
        </header>

        <div className="mt-5 flex flex-wrap gap-2 mb-6">
          {([
            { id: 'threats', label: '威胁模拟' },
            { id: 'policies', label: '响应策略' },
            { id: 'approvals', label: `审批队列${approvals.length ? ` (${approvals.length})` : ''}` },
            { id: 'logs', label: '响应日志' },
          ] as { id: Tab; label: string }[]).map(tab => (
            <button key={tab.id} onClick={() => { setActiveTab(tab.id); if (tab.id === 'approvals') loadApprovals(); if (tab.id === 'logs') loadLogs() }}
              className={classNames('px-4 py-2 text-[13px] tracking-[0.08em] border border-ink',
                activeTab === tab.id ? 'bg-ink text-white' : 'bg-transparent text-ink hover:bg-ink hover:text-white')}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab: 威胁模拟 ── */}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">快速选择威胁场景</label>
              <div className="flex flex-wrap gap-2">
                {THREAT_PRESETS.map(p => (
                  <button key={p.label} onClick={() => simulateThreat(p.value)}
                    className="px-3 py-1.5 text-xs font-sans rounded-none border border-line hover:bg-gray-50 transition-colors">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">自定义威胁参数</label>
              <div className="flex items-center gap-3 mb-3">
                <select defaultValue="C2_BEACON" id="threat-type-select"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent">
                  <option value="C2_BEACON">C2回连</option>
                  <option value="DATA_EXFIL">数据外泄</option>
                  <option value="BRUTE_FORCE">暴力破解</option>
                  <option value="PORT_SCAN">端口扫描</option>
                  <option value="MALWARE_DETECT">恶意软件</option>
                  <option value="DDoS_TRAFFIC">DDoS</option>
                  <option value="LATERAL_MOVE">横向移动</option>
                </select>
                <input type="text" placeholder="源IP" defaultValue="192.168.1.100" id="threat-ip-input"
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <select id="threat-severity-select" defaultValue="high"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
                <input type="text" placeholder="Session ID (可选)" value={sessionId} onChange={e => setSessionId(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={async () => {
                  const type = (document.getElementById('threat-type-select') as HTMLSelectElement)?.value || 'C2_BEACON'
                  const ip = (document.getElementById('threat-ip-input') as HTMLInputElement)?.value || '192.168.1.100'
                  const sev = (document.getElementById('threat-severity-select') as HTMLSelectElement)?.value || 'high'
                  await simulateThreat({ threat_type: type, confidence: 0.8, severity: sev, src_ip: ip, message: `模拟${type}事件` })
                }} disabled={loading}
                  className="border border-[#0e1a26] bg-[#0e1a26] px-5 py-2 font-mono text-[11px] tracking-[0.18em] uppercase text-[#f1e8d6] hover:bg-[#182838] transition-colors disabled:opacity-50">
                  {loading ? '执行中 …' : '模拟威胁'}
                </button>
              </div>
            </div>

            {/* 手动执行 */}
            <div className="border-t border-line pt-4">
              <label className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint mb-2 block">手动执行响应动作</label>
              <div className="flex items-center gap-3">
                <select value={execAction} onChange={e => setExecAction(e.target.value)}
                  className="px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent">
                  {actions.map(a => (
                    <option key={a.name} value={a.name}>{a.name} ({a.description})</option>
                  ))}
                </select>
                <input type="text" placeholder="目标IP / 主机" value={execTarget} onChange={e => setExecTarget(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={handleExecResponse} disabled={loading}
                  className="border border-alert bg-alert px-4 py-2 font-mono text-[11px] tracking-[0.18em] uppercase text-paper hover:opacity-90 disabled:opacity-50">
                  执行
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-2 mt-2">
                <input type="text" placeholder="PID" value={execPid} onChange={e => setExecPid(e.target.value)}
                  className="w-24 px-3 py-2 text-xs font-sans border border-line rounded-none" />
                <input type="text" placeholder="SHA256" value={execSha} onChange={e => setExecSha(e.target.value)}
                  className="flex-1 min-w-[12rem] px-3 py-2 text-xs font-sans border border-line rounded-none" />
                <input type="text" placeholder="文件路径" value={execPath} onChange={e => setExecPath(e.target.value)}
                  className="flex-1 min-w-[10rem] px-3 py-2 text-xs font-sans border border-line rounded-none" />
                <input type="text" placeholder="账户" value={execAccount} onChange={e => setExecAccount(e.target.value)}
                  className="w-36 px-3 py-2 text-xs font-sans border border-line rounded-none" />
                <input type="text" placeholder="域名" value={execDomain} onChange={e => setExecDomain(e.target.value)}
                  className="w-40 px-3 py-2 text-xs font-sans border border-line rounded-none" />
                <input type="text" placeholder="邮件 Message-ID" value={execMsgId} onChange={e => setExecMsgId(e.target.value)}
                  className="flex-1 min-w-[10rem] px-3 py-2 text-xs font-sans border border-line rounded-none" />
              </div>
            </div>

            {/* 回滚 */}
            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">回滚操作</label>
              <div className="flex items-center gap-3">
                <input type="text" placeholder="回滚令牌" value={rollbackToken} onChange={e => setRollbackToken(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-none focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={handleRollback} disabled={loading || !rollbackToken}
                  className="px-4 py-2 text-xs font-sans font-medium bg-orange-500 text-white rounded-none hover:opacity-90 disabled:opacity-50">
                  回滚
                </button>
              </div>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-none text-xs text-red-700">{error}</div>}
            {result && <Collapse title="执行结果" defaultOpen>{JSON.stringify(result, null, 2)}</Collapse>}
          </div>
        )}

        {/* ── Tab: 响应策略 ── */}
        {activeTab === 'policies' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <button onClick={loadPolicies} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-none hover:bg-gray-200">刷新策略</button>
              <button onClick={async () => { try { await api.clearCooldowns(); setResult('冷却已清除') } catch (e: any) { setError(e.message) } }}
                className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-none hover:bg-gray-200">清除冷却</button>
            </div>
            {policies.map((p, i) => (
              <Collapse key={p.name} title={`${p.name} [${p.threat_type}] auto=${p.auto_execute} approval=${p.require_approval}`} defaultOpen={i < 2}>
                <div className="space-y-2">
                  <p><strong>描述:</strong> {p.description}</p>
                  <p><strong>威胁类型:</strong> {p.threat_type} | <strong>最低置信度:</strong> {p.min_confidence} | <strong>最低严重度:</strong> {p.min_severity}</p>
                  <p><strong>自动执行:</strong> {p.auto_execute ? '✅' : '❌'} | <strong>需审批:</strong> {p.require_approval ? '✅' : '❌'} | <strong>冷却:</strong> {p.cooldown_minutes}分钟</p>
                  <div>
                    <strong>响应动作:</strong>
                    <ul className="list-disc ml-4 mt-1 space-y-1">
                      {p.actions?.map((a: any, j: number) => (
                        <li key={j}><strong>{a.name}</strong> {JSON.stringify(a.params)}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <button onClick={async () => {
                      try { await api.updateResponsePolicy({ name: p.name, auto_execute: !p.auto_execute }); await loadPolicies() } catch (e: any) { setError(e.message) }
                    }} className="px-2 py-1 text-[10px] font-sans border border-line rounded hover:bg-gray-50">
                      切换自动执行
                    </button>
                    <button onClick={async () => {
                      try { await api.updateResponsePolicy({ name: p.name, require_approval: !p.require_approval }); await loadPolicies() } catch (e: any) { setError(e.message) }
                    }} className="px-2 py-1 text-[10px] font-sans border border-line rounded hover:bg-gray-50">
                      切换审批要求
                    </button>
                  </div>
                </div>
              </Collapse>
            ))}
            {result && <Collapse title="操作结果">{JSON.stringify(result, null, 2)}</Collapse>}
          </div>
        )}

        {/* ── Tab: 审批队列 ── */}
        {activeTab === 'approvals' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <button onClick={loadApprovals} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-none hover:bg-gray-200">刷新审批</button>
            </div>
            {approvals.length === 0 ? (
              <div className="text-center text-xs text-ink-faint font-sans py-8">暂无待审批工单</div>
            ) : (
              approvals.map(t => (
                <div key={t.id} className="border border-line rounded-none p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-sans font-semibold">{t.policy_name}</span>
                    <span className={classNames('px-2 py-0.5 text-[10px] font-sans rounded border', severityColor(t.severity))}>{t.severity}</span>
                  </div>
                  <div className="text-xs font-sans text-ink-soft space-y-1">
                    <p>威胁: {t.threat_type} | 置信度: {t.confidence} | 源IP: {t.src_ip}</p>
                    <p>动作: {t.actions?.map((a: any) => a.name).join(', ')}</p>
                    <p>状态: <span className="font-medium text-warn">{t.status}</span></p>
                  </div>
                  <div className="flex gap-2 mt-3">
                    <button onClick={async () => {
                      try {
                        // 批准前先 dry-run 预览动作效果（无真实变更），再带 sig 批准
                        setPreviewingId(t.id)
                        const pv = await api.previewApproval(t.id)
                        setPreviews(prev => ({ ...prev, [t.id]: pv }))
                        await api.approveTicket(t.id, 'admin', t.sig)
                        await loadApprovals()
                        setResult(`工单 ${t.id} 已批准`)
                      } catch (e: any) { setError(e.message) } finally { setPreviewingId('') }
                    }} className="px-3 py-1.5 text-[10px] font-sans font-medium bg-green-500 text-white rounded-none hover:opacity-90">
                      {previewingId === t.id ? '预览中...' : '批准'}
                    </button>
                    <button onClick={async () => {
                      try { await api.rejectTicket(t.id, '自动拒绝'); await loadApprovals(); setResult(`工单 ${t.id} 已拒绝`) } catch (e: any) { setError(e.message) }
                    }} className="px-3 py-1.5 text-[10px] font-sans font-medium bg-red-400 text-white rounded-none hover:opacity-90">
                      拒绝
                    </button>
                  </div>
                  {previews[t.id] && (
                    <div className="mt-3">
                      <Collapse title="批准前预览 (dry-run)">{JSON.stringify(previews[t.id], null, 2)}</Collapse>
                    </div>
                  )}
                </div>
              ))
            )}
            {result && <Collapse title="操作结果">{JSON.stringify(result, null, 2)}</Collapse>}
          </div>
        )}

        {/* ── Tab: 响应日志 ── */}
        {activeTab === 'logs' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <button onClick={loadLogs} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-none hover:bg-gray-200">刷新日志</button>
            </div>
            {logs.length === 0 ? (
              <div className="text-center text-xs text-ink-faint font-sans py-8">暂无响应日志</div>
            ) : (
              <div className="space-y-2">
                {logs.map(log => (
                  <div key={log.id} className="flex items-start gap-3 p-3 border border-line rounded-none">
                    <span className={classNames('shrink-0 w-2 h-2 mt-1.5 rounded-full', log.action_success ? 'bg-green-500' : 'bg-red-500')} />
                    <div className="flex-1 min-w-0 text-xs font-sans">
                      <p className="text-ink font-medium">
                        [{log.threat_type}] {log.action_name}
                        <span className={classNames('ml-2 px-1.5 py-0.5 rounded text-[10px]', severityColor(log.threat_severity))}>{log.threat_severity}</span>
                      </p>
                      <p className="text-ink-faint mt-0.5">
                        IP: {log.src_ip} | 策略: {log.policy_name} | 成功: {log.action_success ? '✅' : '❌'}
                        {log.execution_mode ? (' | 模式: ' + log.execution_mode) : ''}
                        {log.verified === false ? ' | 未校验' : ''}
                      </p>
                      {log.rollback_token && <p className="text-ink-faint text-[10px]">回滚令牌: {log.rollback_token.slice(0, 24)}...</p>}
                      <p className="text-ink-faint text-[10px] mt-0.5">{log.created_at}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stats Button */}
        <div className="mt-8 pt-6 border-t border-line">
          <button onClick={loadPolicies}
            className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-none hover:bg-gray-200">刷新响应引擎状态</button>
        </div>
      </div>
    </PageTransition>
  )
}
