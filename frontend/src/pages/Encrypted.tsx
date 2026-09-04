import { useState, useEffect } from 'react'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'

interface TlsSession {
  id: number
  src_ip: string
  dst_ip: string
  sni: string
  ja3_hash: string
  tls_version: string
  cipher_suite: string
  cert_is_self_signed: boolean
  is_expired: boolean
  risk_score: number
  risk_reasons: string[]
  session_start: string
}

const riskTone = (score: number) =>
  score >= 0.7 ? 'bg-ink text-white' :
  score >= 0.4 ? 'bg-nong text-white' :
  'bg-qing text-ink'

const riskLabel = (score: number) =>
  score >= 0.7 ? '高危' : score >= 0.4 ? '可疑' : '正常'

export default function Encrypted() {
  const [sessions, setSessions] = useState<TlsSession[]>([])

  useEffect(() => {
    api.get('/ndr/tls?limit=100').then(setSessions).catch(() => {})
  }, [])

  return (
    <PageFrame title="加密流量" subtitle="TLS 指纹 · 证书分析 · 风险评估">
      <div className="grid gap-0 border border-line">
        {sessions.map((s, i) => (
          <div key={s.id} className={`p-5 bg-white ${i < sessions.length - 1 ? 'border-b border-line' : ''}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <span className="font-mono text-[13px] text-ink">{s.src_ip} → {s.dst_ip}</span>
                <span className="text-sm font-medium text-ink">{s.sni || '(无 SNI)'}</span>
              </div>
              <span className={`px-2.5 py-1 text-xs font-medium ${riskTone(s.risk_score)}`}>
                {riskLabel(s.risk_score)} {(s.risk_score * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-0.5 border border-line text-ink-soft">{s.tls_version}</span>
              <span className="px-2 py-0.5 border border-line text-ink-soft font-mono">{s.cipher_suite}</span>
              {s.ja3_hash && (
                <span className="px-2 py-0.5 border border-ink font-mono">JA3: {s.ja3_hash.slice(0, 12)}…</span>
              )}
              {s.cert_is_self_signed && <span className="px-2 py-0.5 bg-ink text-white">自签名</span>}
              {s.is_expired && <span className="px-2 py-0.5 bg-nong text-white">已过期</span>}
            </div>
            {s.risk_reasons.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {s.risk_reasons.map((r, idx) => (
                  <span key={idx} className="text-[11px] px-1.5 py-0.5 bg-mist text-ink">{r}</span>
                ))}
              </div>
            )}
          </div>
        ))}
        {sessions.length === 0 && (
          <div className="py-20 text-center text-ink-faint">暂无 TLS 会话数据</div>
        )}
      </div>
    </PageFrame>
  )
}
