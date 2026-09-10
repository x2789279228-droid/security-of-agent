import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import { BRAND } from '../lib/brand'
import LoginForm from '../components/login/LoginForm'
import { BrandSeal } from '../components/brand/BrandSeal'

const PILLARS = [
  '四层审计交叉验证，独立监督防幻觉',
  '发现威胁后自动封禁、隔离、可回滚',
  '红蓝自博弈，漏报回到检测',
] as const

export default function Login() {
  const navigate = useNavigate()
  const token = useAuthStore((s) => s.token)
  const setAuth = useAuthStore((s) => s.setAuth)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('请输入用户名和密码')
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await api.login(username.trim(), password)
      setAuth(data.access_token, username.trim())
      navigate('/')
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : ''
      if (msg.includes('401') || msg.includes('认证') || msg.includes('Unauthorized')) {
        setError('用户名或密码错误')
      } else if (msg.includes('Failed to fetch') || msg.includes('Network') || msg.includes('网络')) {
        setError('无法连接服务器，请稍后重试')
      } else if (msg) {
        setError(msg.replace(/^API \d+:\s*/, '') || '用户名或密码错误')
      } else {
        setError('用户名或密码错误')
      }
    } finally {
      setLoading(false)
    }
  }

  const today = new Date().toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'long',
  })

  return (
    <div className="relative min-h-screen bg-surface text-ink">
      {/* 顶部 meta 带 */}
      <div className="border-b border-line bg-[#0e1a26] text-[#d8dee0]">
        <div className="page-shell h-10 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[rgba(216,222,224,0.55)]">
              {today}
            </span>
            <span className="hidden sm:inline-flex items-center gap-2 font-mono text-[10px] tracking-[0.3em] uppercase text-[#c9a574]">
              <span className="live-arc text-[#c9a574]" aria-hidden />
              Shift Active
            </span>
          </div>
          <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[rgba(216,222,224,0.4)]">
            {BRAND.nameEn} · NIGHT WATCH SOC
          </span>
        </div>
      </div>

      {/* 主舞台 */}
      <div className="page-shell relative grid min-h-[calc(100vh-2.5rem)] items-center gap-12 py-16 lg:grid-cols-[minmax(0,1.15fr)_420px] lg:gap-20 lg:py-24">
        {/* 左：案卷封面 */}
        <div className="relative">
          <div className="flex items-center gap-4">
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
              ENTRY · CHAPTER 00
            </span>
            <span className="h-px w-12 bg-line" />
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
              CLEARANCE REQUIRED
            </span>
          </div>

          <h1 className="display-serif mt-8 text-[120px] text-ink sm:text-[160px] lg:text-[192px]">
            守望
          </h1>

          <p className="mt-6 max-w-md font-serif text-[20px] leading-snug text-ink md:text-[22px]">
            {BRAND.tagline}
          </p>
          <p className="mt-3 max-w-md text-[14px] leading-relaxed text-ink-soft">
            {BRAND.manifesto}
          </p>

          {/* 流程 chip 行 */}
          <div className="mt-10 flex flex-wrap items-center gap-x-3 gap-y-3">
            {(['接入', '审计', '响应', '复盘'] as const).map((step, i) => (
              <span key={step} className="flex items-center gap-3">
                <span className="flex items-center gap-2 border border-line bg-paper px-3 py-1.5">
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                    0{i + 1}
                  </span>
                  <span className="font-serif text-[14px] font-bold">{step}</span>
                </span>
                {i < 3 && (
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint" aria-hidden>
                    →
                  </span>
                )}
              </span>
            ))}
          </div>

          {/* 印章区：左下 · 大胆正印替代小徽记 */}
          <div className="mt-16 grid grid-cols-[auto_minmax(0,1fr)] items-start gap-8 border-t border-line pt-8">
            <BrandSeal size={176} tone="paper" />
            <ul className="space-y-3 pt-1 max-w-md text-[14px] leading-relaxed text-ink-soft">
              {PILLARS.map((p, i) => (
                <li key={p} className="flex items-start gap-3">
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#a8392f] mt-1 tabular-nums">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* 右：登录面板 */}
        <div className="relative">
          <div className="border border-line bg-paper">
            {/* 面板 header */}
            <div className="flex items-center justify-between border-b border-line px-7 py-4">
              <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
                CREDENTIALS · 00
              </span>
              <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#a8392f]">
                RESTRICTED
              </span>
            </div>

            <div className="px-7 py-9">
              <p className="font-serif text-[24px] font-black tracking-[-0.02em]">
                请登录
              </p>
              <p className="mt-1 text-[12px] text-ink-faint">
                Authorized personnel only · 输入凭证以进入值班台
              </p>

              <div className="mt-7">
                <LoginForm
                  username={username}
                  password={password}
                  error={error}
                  loading={loading}
                  onUsernameChange={setUsername}
                  onPasswordChange={setPassword}
                  onSubmit={handleSubmit}
                />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-line px-7 py-3.5 text-[11px] text-ink-faint">
              <span className="font-mono tracking-[0.2em] uppercase">JWT · 24h</span>
              <span className="font-mono tracking-[0.2em] uppercase">HTTPS · TLS 1.3</span>
            </div>
          </div>

          {/* 底部 meta */}
          <div className="mt-4 flex items-center justify-between font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
            <span>NODE · 守望 / VAULT</span>
            <span>v3 · 2026</span>
          </div>
        </div>
      </div>
    </div>
  )
}