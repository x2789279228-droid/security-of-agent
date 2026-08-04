import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { api } from '../lib/api'

type Tab = 'threats' | 'policies' | 'approvals' | 'logs' | 'ddos' | 'a4'

const THREAT_PRESETS = [
  { label: 'C2回连 (critical)', value: { threat_type: 'C2_BEACON', confidence: 0.85, severity: 'critical', src_ip: '192.168.1.105', message: '检测到内部主机与已知C2服务器通信' } },
  { label: '数据外泄 (critical)', value: { threat_type: 'DATA_EXFIL', confidence: 0.9, severity: 'critical', src_ip: '10.0.0.5', message: '大量数据外传到外部IP' } },
  { label: '暴力破解 (high)', value: { threat_type: 'BRUTE_FORCE', confidence: 0.75, severity: 'high', src_ip: '103.235.46.22', message: 'SSH暴力破解攻击已拦截' } },
  { label: '端口扫描 (medium)', value: { threat_type: 'PORT_SCAN', confidence: 0.6, severity: 'medium', src_ip: '45.33.32.156', message: '检测到端口扫描行为' } },
  { label: '恶意软件 (critical)', value: { threat_type: 'MALWARE_DETECT', confidence: 0.8, severity: 'critical', src_ip: '192.168.1.50', message: '终端检测到恶意软件' } },
  { label: 'DDoS (high)', value: { threat_type: 'DDoS_TRAFFIC', confidence: 0.7, severity: 'high', src_ip: '203.0.113.1', message: '检测到DDoS攻击流量' } },
]

// DDoS 6 场景预设 (用于 DDoS 决策预演 Tab)
const DDOS_PRESETS = [
  { label: '外部单IP', value: { src_ips: ['203.0.113.77'], target_service: 'web_server', traffic_pps: 10000, traffic_gbps: 1.0, evidence_confidence: 0.9 } },
  { label: '外部CIDR', value: { src_cidrs: ['203.0.113.0/24'], target_service: 'web_server', traffic_pps: 20000, traffic_gbps: 2.0, evidence_confidence: 0.9 } },
  { label: '外部CIDR (/16 过宽)', value: { src_cidrs: ['203.0.0.0/16'], target_service: 'web_server', traffic_pps: 20000, evidence_confidence: 0.9 } },
  { label: '分布式外部', value: { src_ips: Array.from({length: 20}, (_, i) => `203.0.113.${i}`), target_service: 'web_server', traffic_pps: 50000, evidence_confidence: 0.85 } },
  { label: '内部单主机', value: { src_ips: ['10.0.0.100'], target_service: 'web_server', traffic_pps: 10000, evidence_confidence: 0.9 } },
  { label: '内部多主机', value: { src_ips: ['10.0.0.100', '10.0.0.101', '10.0.0.102'], target_service: 'web_server', traffic_pps: 30000, evidence_confidence: 0.9 } },
  { label: '核心网络', value: { src_ips: ['203.0.113.77'], target_service: 'core_router', traffic_pps: 5000, evidence_confidence: 0.9 } },
  { label: '大规模DDoS', value: { src_ips: Array.from({length: 50}, (_, i) => `203.0.${Math.floor(i/10)}.${i%10}`), target_service: 'web_server', traffic_pps: 200000, traffic_gbps: 15.0, evidence_confidence: 0.95 } },
  { label: '封禁10.0.0.0/8 (拒绝)', value: { src_cidrs: ['10.0.0.0/8'], target_service: 'web_server', evidence_confidence: 0.9 } },
  { label: '封禁172.16.0.0/12 (拒绝)', value: { src_cidrs: ['172.16.0.0/12'], target_service: 'web_server', evidence_confidence: 0.9 } },
  { label: '封禁192.168.0.0/16 (拒绝)', value: { src_cidrs: ['192.168.0.0/16'], target_service: 'web_server', evidence_confidence: 0.9 } },
]

// A4 危险工具预设 (用于 A4 预检 Tab)
const A4_TOOL_PRESETS = [
  { label: 'drop_database', value: { tool_name: 'drop_database', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'drop_table', value: { tool_name: 'drop_table', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'truncate_table', value: { tool_name: 'truncate_table', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'wipe_disk', value: { tool_name: 'wipe_disk', target: 'host-01' } },
  { label: 'delete_backup', value: { tool_name: 'delete_backup', target: 'backup-01' } },
  { label: 'bulk_delete_users', value: { tool_name: 'bulk_delete_users' } },
  { label: 'modify_core_route', value: { tool_name: 'modify_core_route' } },
  { label: 'block_10.0.0.0_8_permanent', value: { tool_name: 'block_10_0_0_0_8_permanent' } },
  { label: 'db_query_status (允许)', value: { tool_name: 'db_query_status', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'db_create_snapshot (允许)', value: { tool_name: 'db_create_snapshot', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'db_isolate_instance (允许)', value: { tool_name: 'db_isolate_instance', target: 'db-prod-01', asset_type: 'database' } },
  { label: 'block_ip (普通)', value: { tool_name: 'block_ip', target: '203.0.113.1' } },
]

// DDoS 决策中文名映射
const DDOS_DECISION_LABEL: Record<string, string> = {
  allow_auto_block: '允许自动封禁',
  allow_cidr_block: '允许 CIDR 封禁 (严格条件)',
  use_scrubbing_device: '切换清洗设备',
  use_rate_limit_only: '仅限速',
  isolate_internal_host: '隔离内部主机',
  deny_auto_response: '拒绝自动响应',
  require_human_approval: '需人工审批',
}

const DDOS_CATEGORY_LABEL: Record<string, string> = {
  external_single_ip: '外部单 IP',
  external_cidr: '外部 CIDR',
  distributed_external: '分布式外部 DDoS',
  internal_single_host: '内部单主机',
  internal_multi_host: '内部多主机',
  core_network: '核心网络级攻击',
  unknown: '未知',
}

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
  const [logs, setLogs] = useState<any[]>([])

  // Execute
  const [execAction, setExecAction] = useState('block_ip')
  const [execTarget, setExecTarget] = useState('')
  const [rollbackToken, setRollbackToken] = useState('')

  // DDoS / A4 预检
  const [ddosPreview, setDdosPreview] = useState<any>(null)
  const [a4Decision, setA4Decision] = useState<any>(null)
  const [a4Prohibited, setA4Prohibited] = useState<{ prohibited_tools: string[]; allowed_db_actions: string[] } | null>(null)
  const [a4CustomTool, setA4CustomTool] = useState('')
  const [a4CustomTarget, setA4CustomTarget] = useState('')

  const loadPolicies = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([api.getResponsePolicies(), api.getResponseActions()])
      setPolicies(p)
      setActions(a)
    } catch (e: any) { setError(e.message) }
  }, [])

  const loadA4Prohibited = useCallback(async () => {
    try {
      const data = await api.a4ProhibitedTools()
      setA4Prohibited(data)
    } catch (e: any) { setError(e.message) }
  }, [])

  const runDdosPreview = useCallback(async (payload: any) => {
    setLoading(true); setError(''); setDdosPreview(null)
    try {
      const data = await api.ddosPreview(payload)
      setDdosPreview(data)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }, [])

  const runA4Check = useCallback(async (payload: any) => {
    setLoading(true); setError(''); setA4Decision(null)
    try {
      const data = await api.a4Check(payload)
      setA4Decision(data)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
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

  useEffect(() => { loadPolicies(); loadA4Prohibited() }, [loadPolicies, loadA4Prohibited])

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
    if (!execTarget) { setError('请输入目标IP'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await api.executeResponse(execAction, execTarget, '手动执行')
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
      case 'critical': return 'text-red-600 bg-red-50 border-red-200'
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      default: return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  return (
    <PageTransition>
      <div className="max-w-5xl mx-auto px-6 pt-14 pb-16">
        <h1 className="text-4xl font-semibold tracking-tight text-ink">响应引擎</h1>
        <p className="text-[15px] text-ink-soft mt-2 mb-8">Response Engine — 自动威胁响应 + 策略管理 + 审批流程 + 回滚</p>

        {/* Tab Bar — Apple 分段控件 */}
        <div className="flex gap-1 mb-8 p-1 bg-black/[0.05] rounded-full w-fit">
          {([
            { id: 'threats', label: '威胁模拟' },
            { id: 'policies', label: '响应策略' },
            { id: 'approvals', label: `审批队列${approvals.length ? ` (${approvals.length})` : ''}` },
            { id: 'logs', label: '响应日志' },
            { id: 'ddos', label: 'DDoS 决策' },
            { id: 'a4', label: 'A4 预检' },
          ] as { id: Tab; label: string }[]).map(tab => (
            <button key={tab.id} onClick={() => { setActiveTab(tab.id); if (tab.id === 'approvals') loadApprovals(); if (tab.id === 'logs') loadLogs() }}
              className={classNames('px-5 py-2 text-[13px] font-medium rounded-full transition-all',
                activeTab === tab.id ? 'bg-card text-ink shadow-[0_1px_4px_rgba(0,0,0,0.1)]' : 'text-ink-soft hover:text-ink')}>
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
                    className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">自定义威胁参数</label>
              <div className="flex items-center gap-3 mb-3">
                <select defaultValue="C2_BEACON" id="threat-type-select"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                  <option value="C2_BEACON">C2回连</option>
                  <option value="DATA_EXFIL">数据外泄</option>
                  <option value="BRUTE_FORCE">暴力破解</option>
                  <option value="PORT_SCAN">端口扫描</option>
                  <option value="MALWARE_DETECT">恶意软件</option>
                  <option value="DDoS_TRAFFIC">DDoS</option>
                  <option value="LATERAL_MOVE">横向移动</option>
                </select>
                <input type="text" placeholder="源IP" defaultValue="192.168.1.100" id="threat-ip-input"
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <select id="threat-severity-select" defaultValue="high"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
                <input type="text" placeholder="Session ID (可选)" value={sessionId} onChange={e => setSessionId(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={async () => {
                  const type = (document.getElementById('threat-type-select') as HTMLSelectElement)?.value || 'C2_BEACON'
                  const ip = (document.getElementById('threat-ip-input') as HTMLInputElement)?.value || '192.168.1.100'
                  const sev = (document.getElementById('threat-severity-select') as HTMLSelectElement)?.value || 'high'
                  await simulateThreat({ threat_type: type, confidence: 0.8, severity: sev, src_ip: ip, message: `模拟${type}事件` })
                }} disabled={loading}
                  className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                  {loading ? '执行中...' : '模拟威胁'}
                </button>
              </div>
            </div>

            {/* 手动执行 */}
            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">手动执行响应动作</label>
              <div className="flex items-center gap-3">
                <select value={execAction} onChange={e => setExecAction(e.target.value)}
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
                  {actions.map(a => (
                    <option key={a.name} value={a.name}>{a.name} ({a.description})</option>
                  ))}
                </select>
                <input type="text" placeholder="目标IP" value={execTarget} onChange={e => setExecTarget(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={handleExecResponse} disabled={loading}
                  className="px-4 py-2 text-xs font-sans font-medium bg-red-500 text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                  执行
                </button>
              </div>
            </div>

            {/* 回滚 */}
            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">回滚操作</label>
              <div className="flex items-center gap-3">
                <input type="text" placeholder="回滚令牌" value={rollbackToken} onChange={e => setRollbackToken(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={handleRollback} disabled={loading || !rollbackToken}
                  className="px-4 py-2 text-xs font-sans font-medium bg-orange-500 text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                  回滚
                </button>
              </div>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {/* A4 拦截提示 — 当 result 含 a4_blocked 字段时显示 */}
            {result?.a4_blocked && (
              <div className="border border-red-300 bg-red-50 rounded-lg p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 text-red-700 font-semibold">
                  <span className="shrink-0 w-2 h-2 rounded-full bg-red-500" />
                  A4 危险动作已拦截 — 已创建人工审批工单
                </div>
                <p className="text-red-600">{result.reason || 'A4 策略阻止自动执行'}</p>
                {result.a4_violations?.map((v: any, i: number) => (
                  <div key={i} className="border-t border-red-200 pt-2 mt-2">
                    <p><strong>动作:</strong> {v.action} | <strong>拦截器:</strong> {v.blocked_by}</p>
                    <p className="text-red-600">{v.reason}</p>
                    {v.recommendations?.length > 0 && (
                      <ul className="list-disc ml-4 mt-1 space-y-0.5 text-red-700">
                        {v.recommendations.map((r: string, j: number) => <li key={j}>{r}</li>)}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* DDoS 决策卡片 — 当 result 含 ddos_decision 字段时显示 */}
            {result?.ddos_decision && (
              <div className="border border-orange-200 bg-orange-50 rounded-lg p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 text-orange-700 font-semibold">
                  <span className="shrink-0 w-2 h-2 rounded-full bg-orange-500" />
                  DDoS 决策: {DDOS_DECISION_LABEL[result.ddos_decision] || result.ddos_decision}
                </div>
                {result.policy_name && <p className="text-orange-700"><strong>分类:</strong> {result.policy_name}</p>}
                {result.reason && <p className="text-ink-soft">{result.reason}</p>}
                {result.scrubbing_device_required && (
                  <p className="text-orange-700 font-medium">⚠ 需切换到清洗设备 — 单机 iptables 不足以处置</p>
                )}
                {result.allowed_actions?.length > 0 && (
                  <p><strong className="text-green-700">允许动作:</strong> {result.allowed_actions.join(', ')}</p>
                )}
                {result.denied_actions?.length > 0 && (
                  <p><strong className="text-red-700">拒绝动作:</strong> {result.denied_actions.join(', ')}</p>
                )}
                {result.safe_targets?.length > 0 && (
                  <p><strong>安全目标:</strong> {result.safe_targets.join(', ')}</p>
                )}
                {result.require_human_approval && <p className="text-warn">需人工审批</p>}
                {result.require_canary && <p className="text-ink-soft"> Canary 执行</p>}
                {result.require_auto_rollback && <p className="text-ink-soft"> 自动回滚</p>}
                {result.require_health_check && <p className="text-ink-soft"> 业务健康检查</p>}
                {result.recommendations?.length > 0 && (
                  <ul className="list-disc ml-4 mt-1 space-y-0.5 text-ink-soft">
                    {result.recommendations.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                )}
                {result.approval_ticket_id && (
                  <p className="text-ink-faint">工单 ID: <span className="font-mono">{result.approval_ticket_id}</span></p>
                )}
              </div>
            )}

            {/* 原始结果 Collapse — 保留 */}
            {result && <Collapse title="执行结果" defaultOpen>{JSON.stringify(result, null, 2)}</Collapse>}
          </div>
        )}

        {/* ── Tab: 响应策略 ── */}
        {activeTab === 'policies' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <button onClick={loadPolicies} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新策略</button>
              <button onClick={async () => { try { await api.clearCooldowns(); setResult('冷却已清除') } catch (e: any) { setError(e.message) } }}
                className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">清除冷却</button>
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
              <button onClick={loadApprovals} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新审批</button>
            </div>
            {approvals.length === 0 ? (
              <div className="text-center text-xs text-ink-faint font-sans py-8">暂无待审批工单</div>
            ) : (
              approvals.map(t => (
                <div key={t.id} className="border border-line rounded-lg p-4">
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
                      try { await api.approveTicket(t.id); await loadApprovals(); setResult(`工单 ${t.id} 已批准`) } catch (e: any) { setError(e.message) }
                    }} className="px-3 py-1.5 text-[10px] font-sans font-medium bg-green-500 text-white rounded-lg hover:opacity-90">
                      批准
                    </button>
                    <button onClick={async () => {
                      try { await api.rejectTicket(t.id, '自动拒绝'); await loadApprovals(); setResult(`工单 ${t.id} 已拒绝`) } catch (e: any) { setError(e.message) }
                    }} className="px-3 py-1.5 text-[10px] font-sans font-medium bg-red-400 text-white rounded-lg hover:opacity-90">
                      拒绝
                    </button>
                  </div>
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
              <button onClick={loadLogs} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新日志</button>
            </div>
            {logs.length === 0 ? (
              <div className="text-center text-xs text-ink-faint font-sans py-8">暂无响应日志</div>
            ) : (
              <div className="space-y-2">
                {logs.map(log => (
                  <div key={log.id} className="flex items-start gap-3 p-3 border border-line rounded-lg">
                    <span className={classNames('shrink-0 w-2 h-2 mt-1.5 rounded-full', log.action_success ? 'bg-green-500' : 'bg-red-500')} />
                    <div className="flex-1 min-w-0 text-xs font-sans">
                      <p className="text-ink font-medium">
                        [{log.threat_type}] {log.action_name}
                        <span className={classNames('ml-2 px-1.5 py-0.5 rounded text-[10px]', severityColor(log.threat_severity))}>{log.threat_severity}</span>
                      </p>
                      <p className="text-ink-faint mt-0.5">IP: {log.src_ip} | 策略: {log.policy_name} | 成功: {log.action_success ? '✅' : '❌'}</p>
                      {log.rollback_token && <p className="text-ink-faint text-[10px]">回滚令牌: {log.rollback_token.slice(0, 24)}...</p>}
                      <p className="text-ink-faint text-[10px] mt-0.5">{log.created_at}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Tab: DDoS 决策 ── */}
        {activeTab === 'ddos' && (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">选择 DDoS 场景预设</label>
              <div className="flex flex-wrap gap-2">
                {DDOS_PRESETS.map(p => (
                  <button key={p.label} onClick={() => runDdosPreview(p.value)} disabled={loading}
                    className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors disabled:opacity-50">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">自定义 DDoS 场景</label>
              <div className="grid grid-cols-2 gap-3 mb-3 text-xs">
                <input type="text" placeholder="源IP, 逗号分隔 (如 203.0.113.1,203.0.113.2)"
                  id="ddos-src-ips"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="text" placeholder="源 CIDR, 逗号分隔 (如 203.0.113.0/24)"
                  id="ddos-src-cidrs"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="text" placeholder="目标服务 (web_server/core_router/...)"
                  id="ddos-target-service"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="number" placeholder="流量 pps"
                  id="ddos-pps"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="number" step="0.1" placeholder="流量 Gbps"
                  id="ddos-gbps"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="number" step="0.05" placeholder="证据置信度 (0-1)"
                  id="ddos-confidence"
                  className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
              </div>
              <button onClick={() => {
                const ips = (document.getElementById('ddos-src-ips') as HTMLInputElement)?.value
                const cidrs = (document.getElementById('ddos-src-cidrs') as HTMLInputElement)?.value
                const svc = (document.getElementById('ddos-target-service') as HTMLInputElement)?.value
                const pps = (document.getElementById('ddos-pps') as HTMLInputElement)?.value
                const gbps = (document.getElementById('ddos-gbps') as HTMLInputElement)?.value
                const conf = (document.getElementById('ddos-confidence') as HTMLInputElement)?.value
                runDdosPreview({
                  src_ips: ips ? ips.split(',').map(s => s.trim()).filter(Boolean) : [],
                  src_cidrs: cidrs ? cidrs.split(',').map(s => s.trim()).filter(Boolean) : [],
                  target_service: svc || 'web_server',
                  traffic_pps: pps ? parseInt(pps) : 0,
                  traffic_gbps: gbps ? parseFloat(gbps) : 0.0,
                  evidence_confidence: conf ? parseFloat(conf) : 0.9,
                })
              }} disabled={loading}
                className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                {loading ? '预演中...' : '预演决策'}
              </button>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {ddosPreview && (
              <div className="border border-orange-200 bg-orange-50 rounded-lg p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 text-orange-700 font-semibold">
                  <span className="shrink-0 w-2 h-2 rounded-full bg-orange-500" />
                  DDoS 决策: {DDOS_DECISION_LABEL[ddosPreview.decision] || ddosPreview.decision}
                </div>
                <p><strong>分类:</strong> {DDOS_CATEGORY_LABEL[ddosPreview.category] || ddosPreview.category}</p>
                <p className="text-ink-soft">{ddosPreview.reason}</p>
                {ddosPreview.scrubbing_device_required && (
                  <p className="text-orange-700 font-medium">⚠ 需切换到清洗设备/运营商/云 Anti-DDoS</p>
                )}
                {ddosPreview.allowed_actions?.length > 0 && (
                  <p><strong className="text-green-700">允许动作:</strong> {ddosPreview.allowed_actions.join(', ')}</p>
                )}
                {ddosPreview.denied_actions?.length > 0 && (
                  <p><strong className="text-red-700">拒绝动作:</strong> {ddosPreview.denied_actions.join(', ')}</p>
                )}
                {ddosPreview.safe_targets?.length > 0 && (
                  <p><strong>安全目标:</strong> {ddosPreview.safe_targets.join(', ')}</p>
                )}
                <div className="flex flex-wrap gap-3 text-ink-soft">
                  {ddosPreview.require_human_approval && <span>需人工审批</span>}
                  {ddosPreview.require_canary && <span> Canary</span>}
                  {ddosPreview.require_auto_rollback && <span> 自动回滚</span>}
                  {ddosPreview.require_health_check && <span> 健康检查</span>}
                  {ddosPreview.max_ttl_seconds > 0 && <span> TTL={ddosPreview.max_ttl_seconds}s</span>}
                </div>
                {ddosPreview.recommendations?.length > 0 && (
                  <ul className="list-disc ml-4 mt-1 space-y-0.5 text-ink-soft">
                    {ddosPreview.recommendations.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                )}
              </div>
            )}
            {ddosPreview && <Collapse title="完整决策结果">{JSON.stringify(ddosPreview, null, 2)}</Collapse>}
          </div>
        )}

        {/* ── Tab: A4 预检 ── */}
        {activeTab === 'a4' && (
          <div className="space-y-4">
            {/* A4 永久禁止工具清单 */}
            {a4Prohibited && (
              <div className="grid grid-cols-2 gap-4">
                <div className="border border-red-200 bg-red-50 rounded-lg p-3">
                  <p className="text-xs font-sans font-semibold text-red-700 mb-2">A4 永久禁止工具 (LLM Agent 不得注册)</p>
                  <div className="flex flex-wrap gap-1">
                    {a4Prohibited.prohibited_tools.map(t => (
                      <span key={t} className="px-1.5 py-0.5 text-[10px] font-mono bg-white border border-red-200 rounded text-red-700">{t}</span>
                    ))}
                  </div>
                </div>
                <div className="border border-green-200 bg-green-50 rounded-lg p-3">
                  <p className="text-xs font-sans font-semibold text-green-700 mb-2">数据库安全事件允许动作</p>
                  <div className="flex flex-wrap gap-1">
                    {a4Prohibited.allowed_db_actions.map(t => (
                      <span key={t} className="px-1.5 py-0.5 text-[10px] font-mono bg-white border border-green-200 rounded text-green-700">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            <div>
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">选择工具预设预检</label>
              <div className="flex flex-wrap gap-2">
                {A4_TOOL_PRESETS.map(p => (
                  <button key={p.label} onClick={() => runA4Check(p.value)} disabled={loading}
                    className="px-3 py-1.5 text-xs font-sans rounded-lg border border-line hover:bg-gray-50 transition-colors disabled:opacity-50">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-line pt-4">
              <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">自定义工具预检</label>
              <div className="flex items-center gap-3 mb-3">
                <input type="text" placeholder="工具名 (如 drop_database)" value={a4CustomTool} onChange={e => setA4CustomTool(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <input type="text" placeholder="目标 (可选)" value={a4CustomTarget} onChange={e => setA4CustomTarget(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
                <button onClick={() => runA4Check({ tool_name: a4CustomTool, target: a4CustomTarget, asset_type: a4CustomTarget.startsWith('db') ? 'database' : '' })} disabled={loading || !a4CustomTool}
                  className="px-4 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
                  预检
                </button>
              </div>
            </div>

            {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

            {a4Decision && (
              <div className={classNames('border rounded-lg p-4 text-xs space-y-2',
                a4Decision.is_a4 ? 'border-red-300 bg-red-50' : 'border-green-200 bg-green-50')}>
                <div className={classNames('flex items-center gap-2 font-semibold',
                  a4Decision.is_a4 ? 'text-red-700' : 'text-green-700')}>
                  <span className={classNames('shrink-0 w-2 h-2 rounded-full',
                    a4Decision.is_a4 ? 'bg-red-500' : 'bg-green-500')} />
                  {a4Decision.is_a4 ? `A4 拦截 — 拦截器: ${a4Decision.blocked_by || 'unknown'}` : '通过 — 非危险动作'}
                </div>
                <p className="text-ink-soft">{a4Decision.reason}</p>
                {a4Decision.is_prohibited_tool && (
                  <p className="text-red-700 font-medium">永久禁止工具 — 系统不得向 LLM Agent 注册此能力</p>
                )}
                {a4Decision.is_db_destructive && (
                  <p className="text-red-700 font-medium">数据库破坏性操作 — 不得自动删除数据库/表/文件/备份</p>
                )}
                {a4Decision.require_ticket && (
                  <p className="text-warn">需创建人工审批工单</p>
                )}
                {a4Decision.recommendations?.length > 0 && (
                  <div className="border-t border-line pt-2 mt-2">
                    <p className="font-medium text-ink">处置建议:</p>
                    <ul className="list-disc ml-4 mt-1 space-y-0.5 text-ink-soft">
                      {a4Decision.recommendations.map((r: string, i: number) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
                {a4Decision.allowed_db_actions?.length > 0 && (
                  <p className="text-green-700"><strong>允许动作:</strong> {a4Decision.allowed_db_actions.join(', ')}</p>
                )}
              </div>
            )}
            {a4Decision && <Collapse title="完整决策结果">{JSON.stringify(a4Decision, null, 2)}</Collapse>}
          </div>
        )}

        {/* Stats Button */}
        <div className="mt-8 pt-6 border-t border-line">
          <button onClick={loadPolicies}
            className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新响应引擎状态</button>
        </div>
      </div>
    </PageTransition>
  )
}
