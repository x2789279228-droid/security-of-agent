import { useState } from 'react'
import { motion } from 'framer-motion'
import { Navigate, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import BrandPanel from '../components/login/BrandPanel'
import RegisterForm from '../components/login/RegisterForm'

export default function Register() {
  const navigate = useNavigate()
  const token = useAuthStore((s) => s.token)
  const setAuth = useAuthStore((s) => s.setAuth)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (token) return <Navigate to="/" replace />

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const u = username.trim()
    if (!u || !password) {
      setError('请填写用户名和密码')
      return
    }
    if (password !== confirm) {
      setError('两次输入的密码不一致')
      return
    }
    if (password.length < 8) {
      setError('密码至少 8 位')
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await api.register(u, password)
      setAuth(data.access_token, data.username || u)
      navigate('/')
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : ''
      const detail = msg.replace(/^API \d+:\s*/, '')
      if (msg.includes('409') || detail.includes('已被注册')) {
        setError('用户名已被注册')
      } else if (msg.includes('429')) {
        setError('注册过于频繁，请稍后再试')
      } else if (msg.includes('Failed to fetch') || msg.includes('Network') || msg.includes('网络')) {
        setError('无法连接服务器，请稍后重试')
      } else if (detail) {
        setError(detail)
      } else {
        setError('注册失败，请稍后重试')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-surface text-ink lg:grid lg:grid-cols-[1.1fr_0.9fr]">
      <div className="lg:hidden">
        <BrandPanel compact />
      </div>
      <div className="hidden lg:block">
        <BrandPanel />
      </div>

      <div className="flex items-center justify-center px-5 py-10 sm:px-8 lg:px-12 lg:py-0">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="w-full max-w-[400px] border border-line bg-white px-7 py-9 sm:px-9"
        >
          <RegisterForm
            username={username}
            password={password}
            confirm={confirm}
            error={error}
            loading={loading}
            onUsernameChange={setUsername}
            onPasswordChange={setPassword}
            onConfirmChange={setConfirm}
            onSubmit={handleSubmit}
          />

          <p className="mt-8 text-center text-[11px] tracking-[0.18em] text-ink-faint uppercase">
            共享记忆 · Security Audit
          </p>
        </motion.div>
      </div>
    </div>
  )
}
