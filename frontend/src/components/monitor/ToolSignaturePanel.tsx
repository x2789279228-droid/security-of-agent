import { useCallback, useEffect, useState } from 'react'
import { api } from '../../lib/api'

type PlaybookId = 's1' | 's2' | 's3' | 's4'

const PLAYBOOKS: { id: PlaybookId; label: string; hint: string }[] = [
  { id: 's1', label: 'S1 公网扫描后打内网', hint: '40 次公网 vulnerability_scan 后扫描 192.168.1.1' },
  { id: 's2', label: 'S2 告警后隔离', hint: '40 次 alert_only 后 isolate_host' },
  { id: 's3', label: 'S3 快扫翻成全量', hint: '40 次 fast 扫描后一次 full' },
  { id: 's4', label: 'S4 调查角色调响应工具', hint: '基线来自 response_engine，再由 decomposer 调 block_ip' },
]

function HourBars({ counts }: { counts: number[] }) {
  const hours = Array.isArray(counts) && counts.length === 24 ? counts : Array(24).fill(0)
  const max = Math.max(1, ...hours)
  return (
    <div className="flex items-end gap-px h-8" title="24 小时调用分布">
      {hours.map((n, i) => (
        <div
          key={i}
          className="flex-1 bg-ink min-w-0"
          style={{ height: `${Math.max(6, (n / max) * 100)}%`, opacity: n ? 1 : 0.15 }}
          title={`${String(i).padStart(2, '0')}:00 · ${n}`}
        />
      ))}
    </div>
  )
}

function Chip({ children }: { children: string }) {
  return (
    <span className="inline-block mr-1 mb-1 px-1.5 py-0.5 text-[10px] font-mono border border-line text-ink-soft">
      {children}
    </span>
  )
}

async function runPlaybook(id: PlaybookId, onProgress: (cur: number, total: number, label: string) => void) {
  const n = 40
  if (id === 's1') {
    for (let i = 0; i < n; i++) {
      onProgress(i + 1, n + 1, `公网扫描 ${i + 1}/${n}`)
      await api.guardCall({
        tool_name: 'vulnerability_scan',
        arguments: { target: `8.8.${i}.1`, scan_type: 'fast' },
        caller: 'ops',
        reason: 'baseline public scan',
      })
    }
    onProgress(n + 1, n + 1, '内网目标')
    return api.guardCall({
      tool_name: 'vulnerability_scan',
      arguments: { target: '192.168.1.1', scan_type: 'fast' },
      caller: 'ops',
      reason: 'scan gateway',
    })
  }
  if (id === 's2') {
    for (let i = 0; i < n; i++) {
      onProgress(i + 1, n + 1, `告警 ${i + 1}/${n}`)
      await api.guardCall({
        tool_name: 'alert_only',
        arguments: { message: `heartbeat ${i}` },
        caller: 'ops',
        reason: 'baseline alert',
      })
    }
    onProgress(n + 1, n + 1, '隔离主机')
    return api.guardCall({
      tool_name: 'isolate_host',
      arguments: { host: 'gw-core', isolation_type: 'network' },
      caller: 'ops',
      reason: 'isolate after alerts',
    })
  }
  if (id === 's3') {
    for (let i = 0; i < n; i++) {
      onProgress(i + 1, n + 1, `fast 扫描 ${i + 1}/${n}`)
      await api.guardCall({
        tool_name: 'vulnerability_scan',
        arguments: { target: `1.1.${i}.1`, scan_type: 'fast' },
        caller: 'ops',
        reason: 'fast baseline',
      })
    }
    onProgress(n + 1, n + 1, 'full 扫描')
    return api.guardCall({
      tool_name: 'vulnerability_scan',
      arguments: { target: '1.1.0.1', scan_type: 'full' },
      caller: 'ops',
      reason: 'unexpected full scan',
    })
  }
  for (let i = 0; i < n; i++) {
    onProgress(i + 1, n + 1, `响应侧封禁 ${i + 1}/${n}`)
    await api.guardCall({
      tool_name: 'block_ip',
      arguments: { ip: `9.9.${i}.1`, duration: 3600 },
      caller: 'response_engine',
      user_role: 'security_operator',
      reason: 'c2 block',
    })
  }
  onProgress(n + 1, n + 1, 'decomposer 调用 block_ip')
  return api.guardCall({
    tool_name: 'block_ip',
    arguments: { ip: '10.0.0.1', duration: 3600 },
    caller: 'decomposer',
    user_role: 'security_operator',
    reason: 'unexpected caller',
  })
}

export default function ToolSignaturePanel() {
  const [status, setStatus] = useState<any>(null)
  const [signatures, setSignatures] = useState<any[]>([])
  const [anomalies, setAnomalies] = useState<any[]>([])
  const [approvals, setApprovals] = useState<any[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<PlaybookId | 'refresh' | null>(null)
  const [progress, setProgress] = useState('')
  const [lastResult, setLastResult] = useState<any>(null)
  const [openId, setOpenId] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setError('')
    const [st, sig, anom, appr] = await Promise.all([
      api.guardStatus(),
      api.guardSignatures(),
      api.guardAnomalies(40),
      api.guardApprovals(1, 10),
    ])
    setStatus(st)
    setSignatures(Array.isArray(sig?.items) ? sig.items : [])
    setAnomalies(Array.isArray(anom?.items) ? anom.items : [])
    setApprovals(Array.isArray(appr?.items) ? appr.items : [])
  }, [])

  useEffect(() => {
    refresh().catch((e) => setError(e.message || '加载失败'))
  }, [refresh])

  const handlePlaybook = async (id: PlaybookId) => {
    setBusy(id)
    setError('')
    setLastResult(null)
    setProgress('启动…')
    try {
      const result = await runPlaybook(id, (cur, total, label) => {
        setProgress(`${label}（${cur}/${total}）`)
      })
      setLastResult(result)
      await refresh()
    } catch (e: any) {
      setError(e.message || '剧本执行失败')
    } finally {
      setBusy(null)
      setProgress('')
    }
  }

  const handleRefresh = async () => {
    setBusy('refresh')
    try {
      await refresh()
    } catch (e: any) {
      setError(e.message || '刷新失败')
    } finally {
      setBusy(null)
    }
  }

  const sigInfo = status?.signature || {}
  const cards = [...signatures].sort((a, b) => {
    const t = String(a.tool_name).localeCompare(String(b.tool_name))
    if (t !== 0) return t
    if (a.caller === '*') return -1
    if (b.caller === '*') return 1
    return String(a.caller).localeCompare(String(b.caller))
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-ink-soft">
          模式 {sigInfo.mode || 'confirm'}
          {' · '}指纹 {sigInfo.fingerprints ?? signatures.length}
          {' · '}就绪 {sigInfo.ready ?? 0}
          {' · '}偏离 {sigInfo.anomalies ?? anomalies.length}
          {' · '}待确认 {status?.approvals_pending ?? 0}
        </p>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={busy !== null}
          className="px-4 py-2 text-xs font-sans font-medium border border-ink text-ink disabled:opacity-50"
        >
          {busy === 'refresh' ? '刷新中…' : '刷新'}
        </button>
      </div>

      <div>
        <label className="text-xs font-sans font-medium text-ink-faint mb-2 block">一键剧本（先灌基线再打偏离）</label>
        <div className="flex flex-wrap gap-2">
          {PLAYBOOKS.map((p) => (
            <button
              key={p.id}
              type="button"
              title={p.hint}
              disabled={busy !== null}
              onClick={() => handlePlaybook(p.id)}
              className="px-3 py-1.5 text-xs font-sans border border-ink text-ink hover:bg-ink hover:text-white disabled:opacity-50"
            >
              {busy === p.id ? '执行中…' : p.label}
            </button>
          ))}
        </div>
        {progress && <p className="mt-2 text-[11px] font-mono text-ink-faint">{progress}</p>}
      </div>

      {error && (
        <div className="p-3 border border-ink text-xs text-ink">{error}</div>
      )}

      {lastResult && (
        <div className="border border-line bg-white p-4 text-xs">
          <p className="font-medium text-ink mb-1">
            末次调用 {lastResult.decision}
            {lastResult.signature?.is_anomaly ? ` · 偏离 ${lastResult.signature.score}` : ''}
            {lastResult.ticket_id ? ` · 工单 ${lastResult.ticket_id}` : ''}
          </p>
          {Array.isArray(lastResult.signature?.reasons) && lastResult.signature.reasons.length > 0 && (
            <ul className="text-ink-soft font-mono space-y-0.5">
              {lastResult.signature.reasons.map((r: string, i: number) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div>
        <p className="text-xs font-sans font-medium text-ink-faint mb-2">指纹</p>
        {cards.length === 0 && (
          <p className="text-xs text-ink-faint">尚无指纹。先跑一个剧本灌基线。</p>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {cards.map((s) => {
            const key = `${s.tool_name}:${s.caller}`
            const ip = s.ip_class || {}
            return (
              <button
                type="button"
                key={key}
                onClick={() => setOpenId(openId === key ? null : key)}
                className="text-left border border-line bg-white p-4 hover:border-ink"
              >
                <div className="flex items-baseline justify-between gap-2 mb-2">
                  <p className="text-sm font-semibold font-mono text-ink">{s.tool_name}</p>
                  <p className="text-[10px] text-ink-faint">
                    {s.ready ? '就绪' : '学习中'} · {s.sample_count} 次
                  </p>
                </div>
                <p className="text-[10px] font-mono text-ink-faint mb-2">caller={s.caller}</p>
                <HourBars counts={s.hourly_counts || []} />
                <div className="mt-2">
                  {Object.entries(ip).map(([k, v]) => (
                    <Chip key={k}>{`${k} ${v}`}</Chip>
                  ))}
                </div>
                {openId === key && s.categorical && (
                  <pre className="mt-2 text-[10px] font-mono text-ink-soft whitespace-pre-wrap">
                    {JSON.stringify(s.categorical, null, 2)}
                  </pre>
                )}
              </button>
            )
          })}
        </div>
      </div>

      <div>
        <p className="text-xs font-sans font-medium text-ink-faint mb-2">偏离时间线</p>
        {anomalies.length === 0 && <p className="text-xs text-ink-faint">暂无偏离。</p>}
        <ul className="space-y-2">
          {anomalies.map((a, i) => (
            <li key={`${a.ts}-${i}`} className="border border-line bg-white px-4 py-3">
              <p className="text-xs font-medium text-ink">
                <span className="font-mono">{a.tool_name}</span>
                {' · '}{a.caller}
                {' · '}得分 {Number(a.score ?? 0).toFixed(2)}
                {a.action_taken && a.action_taken !== 'logged' ? ` · ${a.action_taken}` : ''}
              </p>
              {Array.isArray(a.reasons) && a.reasons[0] && (
                <p className="mt-1 text-[11px] font-mono text-ink-soft">{a.reasons[0]}</p>
              )}
              <p className="mt-1 text-[10px] text-ink-faint">{a.ts}</p>
            </li>
          ))}
        </ul>
      </div>

      {approvals.length > 0 && (
        <div>
          <p className="text-xs font-sans font-medium text-ink-faint mb-2">待确认工单</p>
          <ul className="space-y-2">
            {approvals.filter((t) => t.status === 'pending').map((t) => (
              <li key={t.ticket_id} className="border border-ink bg-white px-4 py-3 text-xs">
                <p className="font-medium font-mono">{t.ticket_id} · {t.tool_name}</p>
                <p className="text-ink-soft mt-1">{t.decision_reason}</p>
                <p className="text-[10px] text-ink-faint mt-1">trigger={t.trigger}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
