import { useState, useEffect } from 'react'
import { PageTransition } from '../components/common/PageTransition'
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

const riskColor = (score: number) =>
  score >= 0.7 ? 'bg-[#ff3b30]/12 text-[#ff3b30]' :
  score >= 0.4 ? 'bg-[#ff9f0a]/12 text-[#c77700]' :
  'bg-[#34c759]/10 text-[#248a3d]'

const riskLabel = (score: number) =>
  score >= 0.7 ? '高危' : score >= 0.4 ? '可疑' : '正常'

export default function Encrypted() {
  const [sessions, setSessions] = useState<TlsSession[]>([])

  useEffect(() => {
    api.get('/ndr/tls?limit=100').then(setSessions).catch(() => {})
  }, [])

  return (
    <PageTransition>
      <div className="max-w-6xl mx-auto px-6 pt-14 pb-16">
        <div className="mb-10">
          <h1 className="text-4xl font-semibold tracking-tight text-ink">加密流量</h1>
          <p className="text-[15px] text-ink-soft mt-2">TLS 指纹 · 证书分析 · 风险评估</p>
        </div>

        <div className="grid gap-4">
          {sessions.map((s) => (
            <div key={s.id} className="p-5 rounded-2xl border border-ink/8 bg-white/70 backdrop-blur">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[13px] text-ink">{s.src_ip} → {s.dst_ip}</span>
                  <span className="text-sm font-medium text-ink">{s.sni || '(无 SNI)'}</span>
                </div>
                <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${riskColor(s.risk_score)}`}>
                  {riskLabel(s.risk_score)} {(s.risk_score * 100).toFixed(0)}%
                </span>
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                <span className="px-2 py-0.5 rounded-md bg-ink/5 text-ink-soft">{s.tls_version}</span>
                <span className="px-2 py-0.5 rounded-md bg-ink/5 text-ink-soft font-mono">{s.cipher_suite}</span>
                {s.ja3_hash && (
                  <span className="px-2 py-0.5 rounded-md bg-[#5e5ce6]/8 text-[#5e5ce6] font-mono">
                    JA3: {s.ja3_hash.slice(0, 12)}…
                  </span>
                )}
                {s.cert_is_self_signed && (
                  <span className="px-2 py-0.5 rounded-md bg-[#ff3b30]/10 text-[#ff3b30]">自签名</span>
                )}
                {s.is_expired && (
                  <span className="px-2 py-0.5 rounded-md bg-[#ff9f0a]/10 text-[#c77700]">已过期</span>
                )}
              </div>
              {s.risk_reasons.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {s.risk_reasons.map((r, i) => (
                    <span key={i} className="text-[11px] px-1.5 py-0.5 rounded bg-[#ff3b30]/6 text-[#ff3b30]/80">{r}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
          {sessions.length === 0 && (
            <div className="py-20 text-center text-ink-faint">暂无 TLS 会话数据</div>
          )}
        </div>
      </div>
    </PageTransition>
  )
}
