import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import { BRAND } from '../lib/brand'
import { BrandCrest } from '../components/brand/BrandCrest'

export default function Register() {
  const navigate = useNavigate()
  const token = useAuthStore((s) => s.token)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

  const today = new Date().toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'long',
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!username.trim() || !password.trim()) {
      setError('请填写完整')
      return
    }
    if (password.length < 6) {
      setError('密码至少 6 位')
      return
    }
    if (password !== confirm) {
      setError('两次密码不一致')
      return
    }
    setLoading(true)
    try {
      await api.register(username.trim(), password)
      const data = await api.login(username.trim(), password)
      useAuthStore.getState().setAuth(data.access_token, username.trim())
      navigate('/')
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : ''
      if (msg.includes('409') || msg.includes('exists') || msg.includes('已存在')) {
        setError('该用户名已被注册')
      } else if (msg) {
        setError(msg.replace(/^API \d+:\s*/, '') || '注册失败')
      } else {
        setError('注册失败，请稍后再试')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative min-h-screen bg-surface text-ink">
      {/* 顶部 meta 带 */}
      <div className="border-b border-line bg-[#0e1a26] text-[#d8dee0]">
        <div className="page-shell h-10 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[rgba(216,222,224,0.55)]">
              {today}
            </span>
            <span className="h-3 w-px bg-line" />
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#c9a574]">
              New Operator
            </span>
          </div>
          <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[rgba(216,222,224,0.4)]">
            {BRAND.nameEn} · NIGHT WATCH SOC
          </span>
        </div>
      </div>

      <div className="page-shell relative grid min-h-[calc(100vh-2.5rem)] items-center gap-12 py-16 lg:grid-cols-[minmax(0,1.15fr)_420px] lg:gap-20 lg:py-24">
        {/* 左：刊头 */}
        <div className="relative">
          <div className="flex items-center gap-4">
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
              Sign Up · CHAPTER 00
            </span>
            <span className="h-px w-12 bg-line" />
            <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
              New Operator Enlistment
            </span>
          </div>

          <h1 className="display-serif mt-8 text-[120px] text-ink sm:text-[160px] lg:text-[192px]">
            入列
          </h1>

          <p className="mt-6 max-w-md font-serif text-[20px] leading-snug text-ink md:text-[22px]">
            自今日起，凡所守望，与君相关。
          </p>
          <p className="mt-3 max-w-md text-[14px] leading-relaxed text-ink-soft">
            {BRAND.tagline}
          </p>

          <div className="mt-10 flex flex-wrap items-center gap-x-3 gap-y-3">
            {(['注册', '认证', '入列'] as const).map((step, i) => (
              <span key={step} className="flex items-center gap-3">
                <span className="flex items-center gap-2 border border-line bg-paper px-3 py-1.5">
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                    0{i + 1}
                  </span>
                  <span className="font-serif text-[14px] font-bold">{step}</span>
                </span>
                {i < 2 && (
                  <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint" aria-hidden>
                    →
                  </span>
                )}
              </span>
            ))}
          </div>

          <div className="mt-14 flex items-center gap-6 border-t border-line pt-6">
            <BrandCrest size={64} tone="paper" withSubtitle />
            <ul className="space-y-2 max-w-md text-[14px] text-ink-soft">
              <li className="flex items-start gap-3">
                <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#a8392f] mt-1">
                  01
                </span>
                <span>注册仅限内部演练与实验环境，请勿用于生产值班。</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#a8392f] mt-1">
                  02
                </span>
                <span>完成注册后将自动登录并跳转到值班台。</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#a8392f] mt-1">
                  03
                </span>
                <span>已有账号？前往登录页面验证身份。</span>
              </li>
            </ul>
          </div>
        </div>

        {/* 右：注册面板 */}
        <div className="relative">
          <div className="border border-line bg-paper">
            <div className="flex items-center justify-between border-b border-line px-7 py-4">
              <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-ink-faint">
                Enlistment · 00
              </span>
              <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-[#a8392f]">
                NEW OPERATOR
              </span>
            </div>

            <div className="px-7 py-9">
              <p className="font-serif text-[24px] font-black tracking-[-0.02em]">
                入列登记
              </p>
              <p className="mt-1 text-[12px] text-ink-faint">
                New Operator Enlistment · 填写凭证完成入列
              </p>

              <form onSubmit={handleSubmit} className="mt-7 space-y-4">
                <Field label="用户名 · Username">
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="operator"
                    autoComplete="username"
                    className="auth-input"
                  />
                </Field>
                <Field label="密码 · Password">
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="至少 6 位"
                    autoComplete="new-password"
                    className="auth-input"
                  />
                </Field>
                <Field label="再次输入 · Confirm">
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="再次输入密码"
                    autoComplete="new-password"
                    className="auth-input"
                  />
                </Field>

                {error && (
                  <p className="border border-[#b03a30] bg-[#b03a30]/10 px-3 py-2 text-[12px] text-[#b03a30]">
                    {error}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-[#0e1a26] text-[#f1e8d6] border border-[#0e1a26] h-12 text-[14px] tracking-[0.08em] hover:bg-[#182838] transition-colors disabled:opacity-50"
                >
                  {loading ? '入列中 …' : '入列'}
                </button>
              </form>

              <div className="mt-5 flex items-center justify-between border-t border-line pt-4 text-[12px] text-ink-soft">
                <span>已有账号？</span>
                <button
                  onClick={() => navigate('/login')}
                  className="border-b border-ink pb-px hover:opacity-70"
                >
                  前往登录
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-line px-7 py-3.5 text-[11px] text-ink-faint">
              <span className="font-mono tracking-[0.2em] uppercase">JWT · 24h</span>
              <span className="font-mono tracking-[0.2em] uppercase">HTTPS · TLS 1.3</span>
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
            <span>NODE · 守望 / VAULT</span>
            <span>v3 · 2026</span>
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint mb-1.5">
        {label}
      </span>
      {children}
    </label>
  )
}