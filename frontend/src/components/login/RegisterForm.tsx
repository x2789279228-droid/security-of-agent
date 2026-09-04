/**
 * 注册表单 — 用户名 / 密码 / 确认密码 / 显隐 / 错误态
 */
import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '../ui/Button'

export interface RegisterFormProps {
  username: string
  password: string
  confirm: string
  error: string
  loading: boolean
  onUsernameChange: (v: string) => void
  onPasswordChange: (v: string) => void
  onConfirmChange: (v: string) => void
  onSubmit: (e: React.FormEvent) => void
}

export default function RegisterForm({
  username,
  password,
  confirm,
  error,
  loading,
  onUsernameChange,
  onPasswordChange,
  onConfirmChange,
  onSubmit,
}: RegisterFormProps) {
  const uid = useId()
  const userId = `${uid}-user`
  const passId = `${uid}-pass`
  const confirmId = `${uid}-confirm`
  const [showPassword, setShowPassword] = useState(false)
  const hasError = !!error

  return (
    <form onSubmit={onSubmit} className="w-full" noValidate>
      <h2 className="text-[22px] font-black tracking-tight text-ink">注册</h2>
      <p className="mt-1.5 text-[13px] text-ink-faint">创建账号后即可登录使用平台</p>

      <div className="mt-8">
        <label htmlFor={userId} className="block text-[12px] text-ink-faint mb-1">
          用户名
        </label>
        <input
          id={userId}
          type="text"
          name="username"
          autoComplete="username"
          autoFocus
          value={username}
          onChange={(e) => onUsernameChange(e.target.value)}
          placeholder="3–32 位字母、数字或中文"
          aria-invalid={hasError}
          className="auth-input text-[16px] lg:text-[15px]"
        />
      </div>

      <div className="mt-6">
        <label htmlFor={passId} className="block text-[12px] text-ink-faint mb-1">
          密码
        </label>
        <div className="relative">
          <input
            id={passId}
            type={showPassword ? 'text' : 'password'}
            name="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => onPasswordChange(e.target.value)}
            placeholder="至少 8 位"
            aria-invalid={hasError}
            className="auth-input text-[16px] lg:text-[15px] pr-14"
          />
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            aria-pressed={showPassword}
            aria-label={showPassword ? '隐藏密码' : '显示密码'}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-[12px] tracking-wide text-ink-faint hover:text-ink"
          >
            {showPassword ? '隐藏' : '显示'}
          </button>
        </div>
      </div>

      <div className="mt-6">
        <label htmlFor={confirmId} className="block text-[12px] text-ink-faint mb-1">
          确认密码
        </label>
        <input
          id={confirmId}
          type={showPassword ? 'text' : 'password'}
          name="confirm"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => onConfirmChange(e.target.value)}
          placeholder="再次输入密码"
          aria-invalid={hasError}
          className="auth-input text-[16px] lg:text-[15px]"
        />
      </div>

      {error && (
        <p role="alert" className="mt-4 border border-ink bg-mist px-3 py-2 text-[13px] text-ink">
          {error}
        </p>
      )}

      <Button
        type="submit"
        variant="primary"
        disabled={loading}
        className="mt-8 h-11 w-full tracking-[0.2em] disabled:opacity-40"
      >
        {loading ? '注册中…' : '创建账号'}
      </Button>

      <p className="mt-6 text-center text-[13px] text-ink-faint">
        已有账号？{' '}
        <Link to="/login" className="text-ink border-b border-ink hover:opacity-70">
          去登录
        </Link>
      </p>
    </form>
  )
}
