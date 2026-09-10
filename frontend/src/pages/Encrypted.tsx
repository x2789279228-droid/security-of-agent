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
  score >= 0.7
    ? 'border-[#b03a30] text-[#b03a30]'
    : score >= 0.4
      ? 'border-[#b88940] text-[#b88940]'
      : 'border-ok text-ok'

const riskLabel = (score: number) =>
  score >= 0.7 ? 'HIGH' : score >= 0.4 ? 'SUSPICIOUS' : 'CLEAN'

export default function Encrypted() {
  const [sessions, setSessions] = useState<TlsSession[]>([])

  useEffect(() => {
    api.get('/ndr/tls?limit=100').then(setSessions).catch(() => {})
  }, [])

  return (
    <PageFrame
      title="加密流量"
      hint="TLS 指纹 · 证书分析 · 风险评估。看不见内容，看得见形状。"
      marginalia="——加密保护的也是形状。"
    >
      <div className="border border-line bg-paper">
        {sessions.map((s, i) => (
          <article
            key={s.id}
            className={`grid grid-cols-1 gap-4 px-7 py-5 md:grid-cols-[1fr_140px] ${
              i < sessions.length - 1 ? 'border-b border-line' : ''
            }`}
          >
            <div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[13px] text-ink">
                  {s.src_ip} → {s.dst_ip}
                </span>
                <span className="font-serif text-[16px] font-bold text-ink">
                  {s.sni || '（无 SNI）'}
                </span>
              </div>
              <div className="mt-2.5 flex flex-wrap gap-2 font-mono text-[11px]">
                <span className="border border-line px-2 py-0.5 text-ink-soft">
                  {s.tls_version}
                </span>
                <span className="border border-line px-2 py-0.5 text-ink-soft">
                  {s.cipher_suite}
                </span>
                {s.ja3_hash && (
                  <span className="border border-ink px-2 py-0.5 text-ink">
                    JA3 · {s.ja3_hash.slice(0, 12)}…
                  </span>
                )}
                {s.cert_is_self_signed && (
                  <span className="border border-[#b03a30] px-2 py-0.5 text-[#b03a30]">
                    自签名
                  </span>
                )}
                {s.is_expired && (
                  <span className="border border-[#b88940] px-2 py-0.5 text-[#b88940]">
                    已过期
                  </span>
                )}
              </div>
              {s.risk_reasons.length > 0 && (
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {s.risk_reasons.map((r, idx) => (
                    <span
                      key={idx}
                      className="border border-line bg-mist px-1.5 py-0.5 font-mono text-[11px] text-ink"
                    >
                      {r}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="flex flex-col items-start gap-1 md:items-end">
              <span
                className={`inline-flex items-center gap-2 border px-3 py-1.5 font-mono text-[10px] tracking-[0.22em] uppercase ${riskTone(s.risk_score)}`}
              >
                <span
                  className={`h-1.5 w-1.5 ${
                    s.risk_score >= 0.7
                      ? 'bg-[#b03a30]'
                      : s.risk_score >= 0.4
                        ? 'bg-[#b88940]'
                        : 'bg-ok'
                  }`}
                  aria-hidden
                />
                {riskLabel(s.risk_score)}
              </span>
              <span className="font-serif text-[28px] font-black tabular-nums leading-none text-ink">
                {(s.risk_score * 100).toFixed(0)}
                <span className="font-mono text-[11px] tracking-[0.22em] uppercase text-ink-faint">
                  {' '}/ 100
                </span>
              </span>
            </div>
          </article>
        ))}
        {sessions.length === 0 && (
          <div className="px-6 py-20 text-center text-[13px] text-ink-faint">
            暂无 TLS 会话数据
          </div>
        )}
      </div>
    </PageFrame>
  )
}