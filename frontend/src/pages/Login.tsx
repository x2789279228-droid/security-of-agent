import { useState } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'

export default function Login() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((s) => s.setAuth)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

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
    } catch {
      setError('用户名或密码错误')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        className="w-full max-w-[400px]"
      >
        <div className="text-center mb-10">
          <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-accent/10 flex items-center justify-center">
            <svg viewBox="0 0 24 24" className="w-7 h-7 text-accent" fill="currentColor">
              <path d="M12 2L4 5.5v5.1c0 4.97 3.41 9.62 8 10.9 4.59-1.28 8-5.93 8-10.9V5.5L12 2zm0 2.2l6 2.63v4.77c0 3.94-2.63 7.63-6 8.83-3.37-1.2-6-4.89-6-8.83V6.83l6-2.63zm-1 9.3l-2.5-2.5-1.4 1.4L11 16.3l5.9-5.9-1.4-1.4L11 13.5z" />
            </svg>
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-ink">共享记忆</h1>
          <p className="text-sm text-ink-soft mt-2">安全审计平台 · 登录以继续</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-card rounded-[20px] p-8 shadow-[0_4px_24px_rgba(0,0,0,0.06)]">
          <div className="space-y-5">
            <div>
              <label className="block text-[13px] font-medium text-ink mb-1.5">用户名</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                autoFocus
                className="w-full text-sm px-4 py-3 rounded-xl border border-line bg-surface/60 text-ink outline-none focus:border-accent focus:bg-card focus:shadow-[0_0_0_4px_rgba(0,113,227,0.12)] transition-all"
              />
            </div>
            <div>
              <label className="block text-[13px] font-medium text-ink mb-1.5">密码</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full text-sm px-4 py-3 rounded-xl border border-line bg-surface/60 text-ink outline-none focus:border-accent focus:bg-card focus:shadow-[0_0_0_4px_rgba(0,113,227,0.12)] transition-all"
              />
            </div>
          </div>

          {error && <p className="text-[13px] text-alert mt-4">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-7 px-4 py-3 bg-accent text-white text-sm font-medium rounded-full hover:bg-accent-hover transition-colors disabled:opacity-50"
          >
            {loading ? '登录中…' : '登 录'}
          </button>
        </form>

        <p className="text-center text-xs text-ink-faint mt-8">
          Shared Memory Service Layer · v1.0
        </p>
      </motion.div>
    </div>
  )
}
