import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'
import { spring, AI_GRADIENT } from '../../lib/constants'
import { SeverityChip, EmptyState } from './badges'
import type { RuleVersion, SandboxResult } from '../../types/operations'

const EMPTY_POLICY_FORM = {
  name: '',
  threat_type: '',
  category: '',
  min_confidence: 0.5,
  min_severity: 'medium',
  duration_minutes: 60,
  auto_execute: true,
  require_approval: false,
  priority: 50,
  cooldown_minutes: 30,
  description: '',
}

export function RulesTab() {
  const [ruleType, setRuleType] = useState<'sigma' | 'response_policy'>('sigma')
  const [rules, setRules] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [versions, setVersions] = useState<Record<string, RuleVersion[]>>({})
  const [msg, setMsg] = useState('')

  // 沙箱
  const [sandboxRule, setSandboxRule] = useState('')
  const [sandboxResult, setSandboxResult] = useState<SandboxResult | null>(null)
  const [sandboxing, setSandboxing] = useState(false)

  // 响应策略新建
  const [showCreate, setShowCreate] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ ...EMPTY_POLICY_FORM })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.opsRules(ruleType)
      setRules(Array.isArray(data) ? data : [])
    } catch {
      setRules([])
    } finally {
      setLoading(false)
    }
  }, [ruleType])

  useEffect(() => { load(); setVersions({}); setExpanded(null); setShowCreate(false) }, [load])

  const toggleExpand = async (ruleId: string) => {
    if (expanded === ruleId) { setExpanded(null); return }
    setExpanded(ruleId)
    if (!versions[ruleId]) {
      try {
        const v = await api.opsRuleVersions(ruleType, ruleId)
        setVersions((prev) => ({ ...prev, [ruleId]: Array.isArray(v) ? v : [] }))
      } catch {
        setVersions((prev) => ({ ...prev, [ruleId]: [] }))
      }
    }
  }

  const rollback = async (ruleId: string, version: number) => {
    setMsg('')
    try {
      const r = await api.opsRuleRollback(ruleType, ruleId, version)
      setMsg(r.success ? `已回滚 ${ruleId} 到版本 v${version}` : (r.error || '回滚失败'))
      setVersions((prev) => ({ ...prev, [ruleId]: [] }))
      await load()
    } catch (e: any) { setMsg(e.message) }
  }

  const createPolicy = async () => {
    setMsg('')
    if (!form.name.trim() || !form.threat_type.trim()) {
      setMsg('请填写策略名称与 threat_type')
      return
    }
    setCreating(true)
    try {
      const actions: Record<string, any>[] = [
        { name: 'send_alert', params: { severity: form.min_severity === 'low' ? 'medium' : 'high' } },
      ]
      if (form.duration_minutes > 0) {
        actions.unshift({
          name: 'block_ip',
          params: { duration_minutes: Number(form.duration_minutes) },
        })
      }
      const r = await api.createResponsePolicy({
        name: form.name.trim(),
        threat_type: form.threat_type.trim().toUpperCase(),
        category: form.category.trim(),
        min_confidence: Number(form.min_confidence),
        min_severity: form.min_severity,
        auto_execute: form.auto_execute,
        require_approval: form.require_approval,
        priority: Number(form.priority),
        cooldown_minutes: Number(form.cooldown_minutes),
        description: form.description.trim(),
        actions,
      })
      if (r.success === false) {
        setMsg(r.error || '创建失败')
      } else {
        setMsg(`已创建策略 ${form.name}（YAML 热加载生效）`)
        setForm({ ...EMPTY_POLICY_FORM })
        setShowCreate(false)
        await load()
      }
    } catch (e: any) {
      setMsg(e.message || '创建失败')
    } finally {
      setCreating(false)
    }
  }

  const disablePolicy = async (ruleId: string) => {
    setMsg('')
    try {
      const r = await api.deleteResponsePolicy(ruleId)
      setMsg(r.success === false ? (r.error || '禁用失败') : `已禁用 ${ruleId}`)
      await load()
    } catch (e: any) { setMsg(e.message) }
  }

  const reloadPolicies = async () => {
    setMsg('')
    try {
      const r = await api.reloadResponsePolicies()
      setMsg(`已热加载 ${r.count ?? '?'} 条策略（source=${r.source || '?'}）`)
      await load()
    } catch (e: any) { setMsg(e.message) }
  }

  const runSandbox = async () => {
    const rule = rules.find((r) => (r.rule_id || r.name) === sandboxRule)
    if (!rule) { setMsg('请选择要测试的规则'); return }
    setSandboxing(true); setMsg(''); setSandboxResult(null)
    try {
      const content = ruleType === 'sigma'
        ? { name: rule.name, severity: rule.severity, attack_type: rule.attack_type, conditions: rule.conditions }
        : { name: rule.name }
      const r = await api.opsRuleSandbox(content, undefined, 100)
      setSandboxResult(r)
    } catch (e: any) { setMsg(e.message) }
    finally { setSandboxing(false) }
  }

  return (
    <div className="space-y-8">
      {/* 类型切换 + 沙箱 */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1 p-1 bg-black/[0.05] rounded-full">
          {([
            { id: 'sigma', label: 'Sigma 检测规则' },
            { id: 'response_policy', label: '响应策略' },
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setRuleType(t.id)}
              className={`px-4 py-1.5 text-xs font-medium rounded-full transition-all ${
                ruleType === t.id ? 'bg-white text-ink shadow-[0_1px_4px_rgba(0,0,0,0.1)]' : 'text-ink-soft hover:text-ink'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <button onClick={load} className="px-3 py-1.5 text-xs font-medium bg-black/[0.04] rounded-lg hover:bg-black/[0.07] text-ink-soft">刷新</button>
        {ruleType === 'response_policy' && (
          <>
            <button
              onClick={() => setShowCreate((v) => !v)}
              className="px-3 py-1.5 text-xs font-medium text-white rounded-lg hover:opacity-90"
              style={{ backgroundImage: AI_GRADIENT }}
            >
              {showCreate ? '收起表单' : '+ 新建策略'}
            </button>
            <button
              onClick={reloadPolicies}
              className="px-3 py-1.5 text-xs font-medium bg-black/[0.04] rounded-lg hover:bg-black/[0.07] text-ink-soft"
            >
              热加载 YAML
            </button>
          </>
        )}
        <span className="ml-auto text-xs text-ink-faint tabular-nums">{rules.length} 条规则</span>
      </div>

      {msg && <p className="text-xs text-accent bg-accent/[0.06] rounded-lg px-3 py-2">{msg}</p>}

      {ruleType === 'response_policy' && showCreate && (
        <section className="bg-white border border-line rounded-none p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)] space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-ink tracking-tight">新建响应策略</h3>
            <p className="text-xs text-ink-faint mt-1">写入 YAML 并热加载，无需重新打包发版。例如 threat_type=BRUTE_WEAK → 封禁 24h。</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Field label="策略名称">
              <input className={inputCls} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="弱口令暴力遏制" />
            </Field>
            <Field label="threat_type">
              <input className={inputCls} value={form.threat_type} onChange={(e) => setForm({ ...form, threat_type: e.target.value })} placeholder="BRUTE_WEAK" />
            </Field>
            <Field label="category（可选，L3）">
              <input className={inputCls} value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} placeholder="AUTH_ATTACK" />
            </Field>
            <Field label="最低严重度">
              <select className={inputCls} value={form.min_severity} onChange={(e) => setForm({ ...form, min_severity: e.target.value })}>
                {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="最低置信度">
              <input type="number" step="0.05" min={0} max={1} className={inputCls} value={form.min_confidence}
                onChange={(e) => setForm({ ...form, min_confidence: Number(e.target.value) })} />
            </Field>
            <Field label="封禁时长（分钟，0=只告警）">
              <input type="number" min={0} max={43200} className={inputCls} value={form.duration_minutes}
                onChange={(e) => setForm({ ...form, duration_minutes: Number(e.target.value) })} />
            </Field>
            <Field label="优先级">
              <input type="number" className={inputCls} value={form.priority}
                onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
            </Field>
            <Field label="冷却（分钟）">
              <input type="number" min={0} className={inputCls} value={form.cooldown_minutes}
                onChange={(e) => setForm({ ...form, cooldown_minutes: Number(e.target.value) })} />
            </Field>
          </div>
          <Field label="描述">
            <input className={inputCls} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="可选说明" />
          </Field>
          <div className="flex flex-wrap items-center gap-4 text-xs">
            <label className="flex items-center gap-2 text-ink-soft">
              <input type="checkbox" checked={form.auto_execute} onChange={(e) => setForm({ ...form, auto_execute: e.target.checked })} />
              自动执行
            </label>
            <label className="flex items-center gap-2 text-ink-soft">
              <input type="checkbox" checked={form.require_approval} onChange={(e) => setForm({ ...form, require_approval: e.target.checked })} />
              强制审批
            </label>
            <button
              onClick={createPolicy}
              disabled={creating}
              className="ml-auto px-5 py-2 text-xs font-medium text-white rounded-lg hover:opacity-90 disabled:opacity-50"
              style={{ backgroundImage: AI_GRADIENT }}
            >
              {creating ? '创建中…' : '创建并热加载'}
            </button>
          </div>
        </section>
      )}

      {/* 规则列表 */}
      {loading ? (
        <EmptyState icon="⏳" title="加载中…" />
      ) : rules.length === 0 ? (
        <EmptyState icon="📐" title="暂无规则" />
      ) : (
        <div className="space-y-2.5">
          {rules.map((r, i) => {
            const ruleId = r.rule_id || r.name
            const isOpen = expanded === ruleId
            const vList = versions[ruleId] ?? []
            return (
              <motion.div
                key={ruleId}
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring.ui, delay: Math.min(i * 0.03, 0.3) }}
                className="bg-white border border-line rounded-none shadow-[0_1px_3px_rgba(0,0,0,0.04)] overflow-hidden"
              >
                <button
                  onClick={() => toggleExpand(ruleId)}
                  className="w-full text-left px-5 py-4 flex items-center justify-between gap-3 hover:bg-black/[0.015] transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-mono text-ink-faint">{ruleId}</span>
                      <SeverityChip severity={r.severity} />
                      {ruleType === 'sigma' && r.attack_type && (
                        <span className="text-[10px] px-2 py-0.5 rounded-md bg-black/[0.04] text-ink-soft">{r.attack_type}</span>
                      )}
                      {ruleType === 'response_policy' && (
                        <span className="text-[10px] text-ink-faint">
                          {r.enabled === false ? '已禁用 · ' : ''}
                          {r.auto_execute ? '自动执行' : '需审批'} · {r.threat_type}
                          {r.role === 'uncertain_template' ? ' · Uncertain 模板' : ''}
                        </span>
                      )}
                    </div>
                    <h4 className="text-sm font-semibold text-ink tracking-tight mt-1">{r.name}</h4>
                    {r.description && <p className="text-xs text-ink-soft mt-0.5 line-clamp-1">{r.description}</p>}
                  </div>
                  <span className={`text-ink-faint transition-transform shrink-0 ${isOpen ? 'rotate-180' : ''}`}>▾</span>
                </button>

                <AnimatePresence>
                  {isOpen && (
                    <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                      <div className="px-5 pb-5 border-t border-line pt-4 space-y-4">
                        {/* 规则详情 */}
                        {ruleType === 'sigma' && r.conditions && (
                          <div>
                            <Label>匹配条件</Label>
                            <pre className="text-[11px] font-mono text-ink-soft bg-black/[0.03] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words">
                              {JSON.stringify(r.conditions, null, 2)}
                            </pre>
                          </div>
                        )}
                        {ruleType === 'sigma' && (
                          <div className="grid grid-cols-3 gap-3 text-xs">
                            <div><Label>置信度</Label><p className="text-ink font-medium">{r.confidence}</p></div>
                            <div><Label>建议动作</Label><p className="text-ink font-medium font-mono">{r.action_recommend}</p></div>
                            <div><Label>攻击类型</Label><p className="text-ink font-medium">{r.attack_type}</p></div>
                          </div>
                        )}
                        {ruleType === 'response_policy' && (
                          <div className="space-y-3">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                              <div><Label>threat_type</Label><p className="text-ink font-medium font-mono">{r.threat_type}</p></div>
                              <div><Label>category</Label><p className="text-ink font-medium font-mono">{r.category || '—'}</p></div>
                              <div><Label>置信度门槛</Label><p className="text-ink font-medium">{r.min_confidence ?? '—'}</p></div>
                              <div><Label>优先级</Label><p className="text-ink font-medium">{r.priority ?? '—'}</p></div>
                            </div>
                            <div>
                              <Label>动作</Label>
                              <pre className="text-[11px] font-mono text-ink-soft bg-black/[0.03] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words">
                                {JSON.stringify(r.actions || [], null, 2)}
                              </pre>
                            </div>
                            {r.enabled !== false && r.role !== 'uncertain_template' && (
                              <button
                                onClick={() => disablePolicy(ruleId)}
                                className="px-3 py-1.5 text-[10px] font-medium text-[#FF375F] border border-[#FF375F]/30 rounded-md hover:bg-[#FF375F]/5"
                              >
                                禁用此策略
                              </button>
                            )}
                          </div>
                        )}

                        {/* 版本历史 */}
                        <div>
                          <Label>版本历史</Label>
                          {vList.length === 0 ? (
                            <p className="text-xs text-ink-faint">暂无版本记录（修改规则后自动创建版本）</p>
                          ) : (
                            <div className="space-y-1.5">
                              {vList.map((v) => (
                                <div key={v.id} className="flex items-center justify-between gap-3 px-3 py-2 bg-black/[0.02] rounded-lg">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className={`text-[11px] font-mono font-semibold ${v.is_active ? 'text-accent' : 'text-ink-faint'}`}>v{v.version}</span>
                                    {v.is_active && <span className="text-[9px] px-1.5 py-0.5 rounded bg-accent/10 text-accent font-medium">当前</span>}
                                    <span className="text-[11px] text-ink-soft truncate">{v.change_summary || '(无说明)'}</span>
                                    <span className="text-[10px] text-ink-faint shrink-0">{v.changed_by}</span>
                                  </div>
                                  {!v.is_active && (
                                    <button
                                      onClick={() => rollback(ruleId, v.version)}
                                      className="shrink-0 px-2.5 py-1 text-[10px] font-medium text-ink-soft border border-line rounded-md hover:bg-black/[0.04] transition-colors"
                                    >
                                      回滚到此版本
                                    </button>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )
          })}
        </div>
      )}

      {/* 沙箱测试 */}
      <section className="bg-white border border-line rounded-none p-5 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <h3 className="text-sm font-semibold text-ink tracking-tight mb-1">规则沙箱测试</h3>
        <p className="text-xs text-ink-faint mb-4">用最近的历史事件回放测试规则，评估命中率与误报率（不影响线上）</p>
        <div className="flex gap-2">
          <select
            value={sandboxRule}
            onChange={(e) => setSandboxRule(e.target.value)}
            className="flex-1 px-3 py-2 text-xs border border-line rounded-lg bg-white focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="">选择规则…</option>
            {rules.map((r) => (
              <option key={r.rule_id || r.name} value={r.rule_id || r.name}>{r.rule_id || r.name} — {r.name}</option>
            ))}
          </select>
          <button
            onClick={runSandbox}
            disabled={sandboxing || !sandboxRule}
            className="px-5 py-2 text-xs font-medium text-white rounded-lg hover:opacity-90 disabled:opacity-50"
            style={{ backgroundImage: AI_GRADIENT }}
          >
            {sandboxing ? '回放测试中…' : '▶ 沙箱测试'}
          </button>
        </div>

        {sandboxResult && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={spring.ui}
            className="mt-4"
          >
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
              <SandboxStat label="测试事件" value={sandboxResult.total_tested} color="#0A84FF" />
              <SandboxStat label="命中数" value={sandboxResult.hit_count} color="#5E5CE6" />
              <SandboxStat label="命中率" value={`${Math.round(sandboxResult.hit_rate * 100)}%`} color="#BF5AF2" />
              <SandboxStat label="误报率" value={`${Math.round(sandboxResult.fp_rate * 100)}%`} color="#FF375F" />
            </div>
            <p className="text-[10px] text-ink-faint">回放耗时 {sandboxResult.elapsed_ms}ms · 命中 {sandboxResult.hits.length} 条（展示前 20）</p>
            {sandboxResult.hits.length > 0 && (
              <div className="mt-2 space-y-1 max-h-48 overflow-y-auto">
                {sandboxResult.hits.map((h) => (
                  <div key={h.event_id} className="flex items-center gap-3 text-[11px] px-3 py-1.5 bg-black/[0.02] rounded-lg">
                    <span className="font-mono text-ink-faint">#{h.event_id}</span>
                    <span className="text-ink">{h.event_type}</span>
                    <span className="font-mono text-ink-faint">{h.src_ip}</span>
                    <SeverityChip severity={h.severity} />
                    {h.status === 'false_positive' && <span className="text-[10px] text-[#FF375F]">已标记误报</span>}
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </section>
    </div>
  )
}

const inputCls = 'w-full px-3 py-2 text-xs border border-line rounded-lg bg-white focus:outline-none focus:ring-1 focus:ring-accent'

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Label>{label}</Label>
      {children}
    </div>
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] font-semibold text-ink-faint uppercase tracking-wide mb-1.5">{children}</p>
}

function SandboxStat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-black/[0.02] rounded-xl px-4 py-3 text-center">
      <p className="text-2xl font-extrabold tracking-tight tabular-nums" style={{ color }}>{value}</p>
      <p className="text-[10px] text-ink-faint mt-0.5">{label}</p>
    </div>
  )
}
