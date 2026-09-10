import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'
import { spring } from '../../lib/constants'
import PhishingDrill from './PhishingDrill'

type PhishTab = 'email' | 'web' | 'domain' | 'attachment' | 'sms' | 'qrcode' | 'bec' | 'drill'

interface PhishingIndicator {
  name: string
  category: string
  severity: string
  detail: string
  score: number
}

interface PhishingVerdict {
  detection_type: string
  target: string
  risk_level: 'safe' | 'suspicious' | 'phishing'
  confidence: number
  score: number
  indicators: PhishingIndicator[]
  summary: string
  suggested_actions: string[]
}

interface HistoryItem {
  id: number
  detection_type: string
  target: string
  risk_level: string
  score: number
  summary: string
  created_at: string
}

/** 钓鱼检测 Tab 图标 — 16×16 stroke SVG，与 Sidebar/TopNav 同风格 heroicons 路径 */
const TAB_ICONS: Record<PhishTab, string> = {
  email: 'M3 8l9 6 9-6m-18 0V6a2 2 0 012-2h14a2 2 0 012 2v2m-18 0v8a2 2 0 002 2h14a2 2 0 002-2V8',
  web: 'M12 21a9 9 0 100-18 9 9 0 000 18zm0 0c2.5-2.5 4-6.5 4-9s-1.5-6.5-4-9m0 18c-2.5-2.5-4-6.5-4-9s1.5-6.5 4-9M3 12h18',
  domain: 'M13.828 10.172a4 4 0 015.656 0l1 1a4 4 0 010 5.656l-1 1a4 4 0 01-5.656 0l-5-5a4 4 0 010-5.656l1-1a4 4 0 015.656 0l5 5',
  attachment: 'M21.444 11.05l-9.19 9.19a6 6 0 01-8.485-8.485l9.19-9.19a4 4 0 015.656 5.657l-9.2 9.19a2 2 0 01-2.828-2.828l8.485-8.486',
  sms: 'M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.86 9.86 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z',
  qrcode: 'M3 4h6v6H3V4zm0 10h6v6H3v-6zm10-10h6v6h-6V4zm2 10h2v2h-2v-2zm2 2h2v2h-2v-2zm-2 2h2v2h-2v-2zm2-2h2v2h-2v-2zm-2-2h2v2h-2v-2zm2-2h2v2h-2v-2zM13 14h2v2h-2v-2zm0 4h4v2h-4v-2z',
  bec: 'M20 7H4a2 2 0 00-2 2v6a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2zM16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16',
  drill: 'M12 2v8m0 0l-3-3m3 3l3-3M12 22a10 10 0 100-20 10 10 0 000 20z',
}

const TAB_ROW_1: { key: PhishTab; label: string }[] = [
  { key: 'email', label: '邮件' },
  { key: 'web', label: '网页' },
  { key: 'domain', label: '域名' },
  { key: 'attachment', label: '附件' },
]

const TAB_ROW_2: { key: PhishTab; label: string }[] = [
  { key: 'sms', label: '短信' },
  { key: 'qrcode', label: '二维码' },
  { key: 'bec', label: '商务诈骗' },
  { key: 'drill', label: '钓鱼演练' },
]

const riskStyle: Record<string, { bg: string; text: string; label: string }> = {
  safe: { bg: 'border border-accent/40 bg-accent/10', text: 'text-accent', label: '安全' },
  suspicious: { bg: 'border border-warn/40 bg-warn/10', text: 'text-warn', label: '可疑' },
  phishing: { bg: 'border border-alert/50 bg-alert/15', text: 'text-alert', label: '钓鱼' },
}

const sevDot: Record<string, string> = {
  info: 'bg-line',
  low: 'bg-signal/60',
  medium: 'bg-signal',
  high: 'bg-warn',
  critical: 'bg-alert',
}

const typeIcon: Record<string, string> = {
  email: TAB_ICONS.email,
  web: TAB_ICONS.web,
  domain: TAB_ICONS.domain,
  attachment: TAB_ICONS.attachment,
  sms: TAB_ICONS.sms,
  qrcode: TAB_ICONS.qrcode,
  bec: TAB_ICONS.bec,
}

const EMAIL_PLACEHOLDER = `From: "PayPal Security" <security@paypa1-verify.com>
Subject: 您的账户已被限制，请立即验证
Received: from mail.paypa1-verify.com
SPF: fail

尊敬的客户，我们检测到您的账户存在异常活动。
请在24小时内点击以下链接验证您的身份，否则账户将被永久冻结：
http://192.168.1.100/paypal/login/verify.php

附件: 账户明细.exe`

const inputCls = "mono-input text-sm"
const monoInputCls = `${inputCls} font-mono py-3`
const labelCls = "block text-xs font-semibold text-ink-soft mb-2"

export default function PhishingDetect() {
  const [tab, setTab] = useState<PhishTab>('email')
  const [loading, setLoading] = useState(false)
  const [verdict, setVerdict] = useState<PhishingVerdict | null>(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState<HistoryItem[]>([])

  // 邮件表单
  const [emailRaw, setEmailRaw] = useState('')
  const [emailAttachments, setEmailAttachments] = useState('')
  // 网页表单
  const [webUrl, setWebUrl] = useState('')
  const [webTitle, setWebTitle] = useState('')
  // 域名表单
  const [domainInput, setDomainInput] = useState('')
  // 附件表单
  const [attFilename, setAttFilename] = useState('')
  const [attSize, setAttSize] = useState('')
  const [attMime, setAttMime] = useState('')
  const [attMagic, setAttMagic] = useState('')
  const [attEncrypted, setAttEncrypted] = useState(false)
  const [attMacros, setAttMacros] = useState(false)
  const [attUrls, setAttUrls] = useState('')
  // 短信表单
  const [smsSender, setSmsSender] = useState('')
  const [smsBody, setSmsBody] = useState('')
  // 二维码表单
  const [qrUrl, setQrUrl] = useState('')
  const [qrContext, setQrContext] = useState('')
  const [qrBrand, setQrBrand] = useState('')
  // BEC 表单
  const [becSender, setBecSender] = useState('')
  const [becReplyTo, setBecReplyTo] = useState('')
  const [becSubject, setBecSubject] = useState('')
  const [becBody, setBecBody] = useState('')
  const [becHasAtt, setBecHasAtt] = useState(false)

  const loadHistory = useCallback(() => {
    api.phishingHistory(5).then(setHistory).catch(() => {})
  }, [])

  useEffect(() => { loadHistory() }, [loadHistory])

  const handleDetect = async () => {
    setLoading(true)
    setError('')
    setVerdict(null)
    try {
      let result: any
      if (tab === 'email') {
        const lines = emailRaw.split('\n')
        const headerLines: string[] = []
        const bodyLines: string[] = []
        let inBody = false
        let sender = ''
        let subject = ''
        for (const line of lines) {
          if (!inBody && line.trim() === '') { inBody = true; continue }
          if (!inBody) {
            headerLines.push(line)
            if (line.toLowerCase().startsWith('from:')) sender = line.slice(5).trim()
            if (line.toLowerCase().startsWith('subject:')) subject = line.slice(8).trim()
          } else {
            bodyLines.push(line)
          }
        }
        result = await api.phishingDetectEmail({
          headers: headerLines.join('\n'),
          sender,
          subject,
          body: bodyLines.join('\n'),
          attachments: emailAttachments
            ? emailAttachments.split(/[,，\n]/).map((s) => s.trim()).filter(Boolean)
            : [],
        })
      } else if (tab === 'web') {
        result = await api.phishingDetectWeb({ url: webUrl, page_title: webTitle })
      } else if (tab === 'domain') {
        result = await api.phishingDetectDomain({ domain: domainInput })
      } else if (tab === 'attachment') {
        result = await api.phishingDetectAttachment({
          filename: attFilename,
          file_size: attSize ? parseInt(attSize, 10) : 0,
          mime_type: attMime,
          magic_bytes: attMagic,
          is_encrypted: attEncrypted,
          has_macros: attMacros,
          embedded_urls: attUrls ? attUrls.split(/[,，\n]/).map((s) => s.trim()).filter(Boolean) : [],
        })
      } else if (tab === 'sms') {
        result = await api.phishingDetectSms({
          sender_number: smsSender,
          message_body: smsBody,
        })
      } else if (tab === 'qrcode') {
        result = await api.phishingDetectQrcode({
          decoded_url: qrUrl,
          source_context: qrContext,
          brand_hint: qrBrand,
        })
      } else if (tab === 'bec') {
        result = await api.phishingDetectBec({
          sender: becSender,
          reply_to: becReplyTo,
          subject: becSubject,
          body: becBody,
          has_attachment: becHasAtt,
        })
      }
      if (result) {
        setVerdict(result)
        loadHistory()
      }
    } catch (e: any) {
      setError(e.message || '检测请求失败')
    } finally {
      setLoading(false)
    }
  }

  const canSubmit =
    (tab === 'email' && emailRaw.trim().length > 0) ||
    (tab === 'web' && webUrl.trim().length > 0) ||
    (tab === 'domain' && domainInput.trim().length > 0) ||
    (tab === 'attachment' && attFilename.trim().length > 0) ||
    (tab === 'sms' && smsBody.trim().length > 0) ||
    (tab === 'qrcode' && qrUrl.trim().length > 0) ||
    (tab === 'bec' && (becBody.trim().length > 0 || becSubject.trim().length > 0))

  const isDrill = tab === 'drill'

  const switchTab = (key: PhishTab) => {
    setTab(key)
    setVerdict(null)
    setError('')
  }

  const renderTabButton = (t: { key: PhishTab; label: string }) => (
    <button
      key={t.key}
      onClick={() => switchTab(t.key)}
      className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border text-[13px] tracking-[0.08em] transition-colors ${
        tab === t.key
          ? 'border-accent/50 bg-accent/15 text-accent'
          : 'border-line text-ink-soft hover:border-accent hover:text-accent'
      }`}
    >
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="w-[15px] h-[15px] shrink-0"
      >
        <path d={TAB_ICONS[t.key]} />
      </svg>
      {t.label}
    </button>
  )

  return (
    <section className="page-shell py-4 border-b border-line">
      <motion.div
        initial={{ opacity: 0, y: 28 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-80px' }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
      >
        {/* 标题 */}
        <p className="text-[13px] text-ink-faint mb-3">检测</p>
        <h2 className="text-[22px] font-black text-ink mb-3">
          钓鱼检测，三秒识破。
        </h2>
        <p className="text-[13px] font-light text-ink-soft mb-10 max-w-2xl leading-relaxed">
          覆盖八大攻击面，多维度指标聚合评分，即时识别钓鱼威胁。
        </p>

        <div className="grid lg:grid-cols-[1fr_380px] gap-6">
          {/* 左侧：输入区 */}
          <div className="mono-card p-8">
            {/* Tab 切换 — 两行 */}
            <div className="space-y-2 mb-6">
              <div className="flex gap-2">{TAB_ROW_1.map(renderTabButton)}</div>
              <div className="flex gap-2">{TAB_ROW_2.map(renderTabButton)}</div>
            </div>

            {/* 钓鱼演练 — 独立面板 */}
            {isDrill ? (
              <PhishingDrill />
            ) : (
              <>
                {/* 检测表单 */}
                <AnimatePresence mode="wait">
                  {tab === 'email' && (
                    <motion.div key="email" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>粘贴邮件原文（含头部 + 正文）</label>
                      <textarea value={emailRaw} onChange={(e) => setEmailRaw(e.target.value)} placeholder={EMAIL_PLACEHOLDER} rows={10} className={`${monoInputCls} resize-y`} />
                      <label className={`${labelCls} mt-4`}>附件文件名（逗号分隔，可选）</label>
                      <input value={emailAttachments} onChange={(e) => setEmailAttachments(e.target.value)} placeholder="例如: 发票.exe, 报表.xlsm" className={inputCls} />
                    </motion.div>
                  )}

                  {tab === 'web' && (
                    <motion.div key="web" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>待检测 URL</label>
                      <input value={webUrl} onChange={(e) => setWebUrl(e.target.value)} placeholder="https://paypa1-secure.login.verify-account.tk/signin" className={monoInputCls} />
                      <label className={`${labelCls} mt-4`}>页面标题（可选）</label>
                      <input value={webTitle} onChange={(e) => setWebTitle(e.target.value)} placeholder="PayPal - 安全验证" className={inputCls} />
                    </motion.div>
                  )}

                  {tab === 'domain' && (
                    <motion.div key="domain" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>待检测域名</label>
                      <input value={domainInput} onChange={(e) => setDomainInput(e.target.value)} placeholder="paypa1-verify.com" className={monoInputCls} />
                      <p className="mt-3 text-xs text-ink-faint">支持 Typosquatting、Homograph、DGA、高风险 TLD 等多维度检测</p>
                    </motion.div>
                  )}

                  {tab === 'attachment' && (
                    <motion.div key="attachment" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>文件名</label>
                      <input value={attFilename} onChange={(e) => setAttFilename(e.target.value)} placeholder="发票.pdf.exe" className={monoInputCls} />
                      <div className="grid grid-cols-2 gap-3 mt-3">
                        <div>
                          <label className={labelCls}>文件大小（字节）</label>
                          <input value={attSize} onChange={(e) => setAttSize(e.target.value)} placeholder="102400" type="number" className={inputCls} />
                        </div>
                        <div>
                          <label className={labelCls}>MIME 类型</label>
                          <input value={attMime} onChange={(e) => setAttMime(e.target.value)} placeholder="application/pdf" className={inputCls} />
                        </div>
                      </div>
                      <label className={`${labelCls} mt-3`}>Magic Bytes（hex，可选）</label>
                      <input value={attMagic} onChange={(e) => setAttMagic(e.target.value)} placeholder="4d5a9000" className={monoInputCls} />
                      <div className="flex gap-6 mt-3">
                        <label className="flex items-center gap-2 text-xs text-ink-soft cursor-pointer">
                          <input type="checkbox" checked={attEncrypted} onChange={(e) => setAttEncrypted(e.target.checked)} className="rounded accent-accent" />
                          加密/密码保护
                        </label>
                        <label className="flex items-center gap-2 text-xs text-ink-soft cursor-pointer">
                          <input type="checkbox" checked={attMacros} onChange={(e) => setAttMacros(e.target.checked)} className="rounded accent-accent" />
                          含宏/脚本
                        </label>
                      </div>
                      <label className={`${labelCls} mt-3`}>内嵌 URL（逗号分隔，可选）</label>
                      <input value={attUrls} onChange={(e) => setAttUrls(e.target.value)} placeholder="http://evil.tk/payload" className={inputCls} />
                    </motion.div>
                  )}

                  {tab === 'sms' && (
                    <motion.div key="sms" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>发送号码</label>
                      <input value={smsSender} onChange={(e) => setSmsSender(e.target.value)} placeholder="10086 或 +8613800138000" className={monoInputCls} />
                      <label className={`${labelCls} mt-4`}>短信内容</label>
                      <textarea value={smsBody} onChange={(e) => setSmsBody(e.target.value)} placeholder={'【银行通知】您的账户积分即将到期，请点击 http://bank-vip.tk 兑换礼品，退订请回复TD'} rows={4} className={`${inputCls} resize-y`} />
                    </motion.div>
                  )}

                  {tab === 'qrcode' && (
                    <motion.div key="qrcode" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>二维码解码内容（URL）</label>
                      <input value={qrUrl} onChange={(e) => setQrUrl(e.target.value)} placeholder="https://alipay-pay.tk/transfer" className={monoInputCls} />
                      <div className="grid grid-cols-2 gap-3 mt-3">
                        <div>
                          <label className={labelCls}>来源场景</label>
                          <select value={qrContext} onChange={(e) => setQrContext(e.target.value)} className={inputCls}>
                            <option value="">请选择</option>
                            <option value="email">邮件</option>
                            <option value="poster">海报/贴纸</option>
                            <option value="webpage">网页</option>
                            <option value="payment">支付/收款</option>
                          </select>
                        </div>
                        <div>
                          <label className={labelCls}>声称品牌（可选）</label>
                          <input value={qrBrand} onChange={(e) => setQrBrand(e.target.value)} placeholder="支付宝" className={inputCls} />
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {tab === 'bec' && (
                    <motion.div key="bec" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>
                      <label className={labelCls}>发件人</label>
                      <input value={becSender} onChange={(e) => setBecSender(e.target.value)} placeholder={'CEO 张总 <zhang@gmail.com>'} className={monoInputCls} />
                      <div className="grid grid-cols-2 gap-3 mt-3">
                        <div>
                          <label className={labelCls}>回复地址（可选）</label>
                          <input value={becReplyTo} onChange={(e) => setBecReplyTo(e.target.value)} placeholder="zhang.ceo@outlook.com" className={inputCls} />
                        </div>
                        <div>
                          <label className={labelCls}>邮件主题</label>
                          <input value={becSubject} onChange={(e) => setBecSubject(e.target.value)} placeholder="紧急：今日下班前完成汇款" className={inputCls} />
                        </div>
                      </div>
                      <label className={`${labelCls} mt-3`}>邮件正文</label>
                      <textarea value={becBody} onChange={(e) => setBecBody(e.target.value)} placeholder={'请立即向以下账户汇款50万元，不要告诉任何人，这是机密操作。'} rows={5} className={`${inputCls} resize-y`} />
                      <label className="flex items-center gap-2 text-xs text-ink-soft cursor-pointer mt-3">
                        <input type="checkbox" checked={becHasAtt} onChange={(e) => setBecHasAtt(e.target.checked)} className="rounded accent-accent" />
                        含附件
                      </label>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* 检测按钮 */}
                <button
                  onClick={handleDetect}
                  disabled={!canSubmit || loading}
                  className="mt-6 w-full rounded-lg bg-accent py-3 text-sm tracking-[0.16em] text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {loading ? '检测中…' : '开始检测'}
                </button>

                {error && (
                  <p className="mt-3 text-sm text-alert">{error}</p>
                )}
              </>
            )}
          </div>

          {/* 右侧：结果区 */}
          <div className="space-y-4">
            <AnimatePresence mode="wait">
              {verdict ? (
                <motion.div
                  key={verdict.target + verdict.score}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={spring.gentle}
                  className="mono-card p-6"
                >
                  {/* 风险等级 + 分数 */}
                  <div className="flex items-center justify-between mb-4">
                    <span className={`rounded-lg text-xs font-bold px-3 py-1.5 ${riskStyle[verdict.risk_level]?.bg} ${riskStyle[verdict.risk_level]?.text}`}>
                      {riskStyle[verdict.risk_level]?.label ?? verdict.risk_level}
                    </span>
                    <div className="text-right">
                      <span className="text-3xl font-semibold tracking-tight text-ink tabular-nums">
                        {verdict.score}
                      </span>
                      <span className="text-xs text-ink-faint ml-1">/ 100</span>
                    </div>
                  </div>

                  {/* 摘要 */}
                  <p className="text-sm text-ink-soft mb-4 leading-relaxed">{verdict.summary}</p>

                  {/* 置信度 */}
                  <div className="mb-4">
                    <div className="flex justify-between text-xs text-ink-faint mb-1">
                      <span>置信度</span>
                      <span>{(verdict.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div className="h-[3px] overflow-hidden rounded-full bg-line">
                      <div
                        className="h-[3px] rounded-full bg-accent transition-all duration-500"
                        style={{ width: `${verdict.confidence * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* 指标列表 */}
                  {verdict.indicators.length > 0 && (
                    <div className="mb-4">
                      <p className="text-xs font-semibold text-ink-soft mb-2">
                        检测指标 ({verdict.indicators.length})
                      </p>
                      <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                        {verdict.indicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            <span className={`mt-1 w-2 h-2 rounded-full shrink-0 ${sevDot[ind.severity] || sevDot.info}`} />
                            <div>
                              <span className="font-medium text-ink">{ind.name}</span>
                              <span className="text-ink-faint ml-1.5">{ind.detail}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 建议动作 */}
                  {verdict.suggested_actions.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-ink-soft mb-2">建议动作</p>
                      <ul className="space-y-1">
                        {verdict.suggested_actions.map((a, i) => (
                          <li key={i} className="text-xs text-ink-soft flex items-start gap-1.5">
                            <span className="text-accent mt-px">→</span> {a}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="mono-card p-8 flex flex-col items-center justify-center min-h-[280px] text-center"
                >
                  <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-xl border border-accent/30 bg-accent/5 text-2xl">
                    🛡️
                  </div>
                  <p className="text-sm text-ink-soft">输入检测目标，即时获取钓鱼风险评估</p>
                  <p className="text-xs text-ink-faint mt-2">支持邮件 / 网页 / 域名 / 附件 / 短信 / 二维码 / 商务诈骗七大检测模式</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* 最近检测 */}
            {history.length > 0 && (
              <div className="mono-card p-6">
                <p className="text-xs font-semibold text-ink-soft mb-3">最近检测</p>
                <div className="space-y-2.5">
                  {history.map((h) => (
                    <div key={h.id} className="flex items-center gap-3 text-xs">
                      <span className={`shrink-0 w-2 h-2 rounded-full ${
                        h.risk_level === 'phishing' ? 'bg-alert'
                        : h.risk_level === 'suspicious' ? 'bg-warn'
                        : 'bg-line'
                      }`} />
                      <span className="text-ink-faint shrink-0 inline-flex">
                        {typeIcon[h.detection_type] ? (
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-[14px] h-[14px]">
                            <path d={typeIcon[h.detection_type]} />
                          </svg>
                        ) : (
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-[14px] h-[14px]">
                            <circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" />
                          </svg>
                        )}
                      </span>
                      <span className="flex-1 text-ink truncate font-mono">{h.target}</span>
                      <span className="shrink-0 text-ink-faint tabular-nums">{h.score}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </section>
  )
}
