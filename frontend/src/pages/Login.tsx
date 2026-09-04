import { useState } from 'react'
import { motion } from 'framer-motion'
import { Navigate, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import BrandPanel from '../components/login/BrandPanel'
import LoginForm from '../components/login/LoginForm'

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

  return (
    <div className="min-h-screen bg-surface text-ink lg:grid lg:grid-cols-[1.1fr_0.9fr]">
      {/* 移动：压缩品牌顶栏 */}
      <div className="lg:hidden">
        <BrandPanel compact />
      </div>

      {/* 桌面：左栏品牌 */}
      <div className="hidden lg:block">
        <BrandPanel />
      </div>

      {/* 右栏 / 移动：登录卡 */}
      <div className="flex items-center justify-center px-5 py-10 sm:px-8 lg:px-12 lg:py-0">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="w-full max-w-[400px] border border-line bg-white px-7 py-9 sm:px-9"
        >
          <LoginForm
            username={username}
            password={password}
            error={error}
            loading={loading}
            onUsernameChange={setUsername}
            onPasswordChange={setPassword}
            onSubmit={handleSubmit}
          />

          <p className="mt-10 text-center text-[11px] tracking-[0.18em] text-ink-faint uppercase">
            共享记忆 · Security Audit
          </p>
        </motion.div>
      </div>
    </div>
  )
}
