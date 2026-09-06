import { useLocation, useNavigate } from 'react-router-dom'
import { ROUTES } from '../lib/constants'
import { useAuthStore } from '../stores/authStore'

const tabs = [
  { path: ROUTES.HOME, label: '首页' },
  { path: ROUTES.LOGS, label: '日志中心' },
  { path: ROUTES.MONITOR, label: '监控' },
  { path: ROUTES.SECURITY_AUDIT, label: '安全审计' },
  { path: ROUTES.RESPONSE, label: '响应' },
  { path: ROUTES.OPERATIONS, label: '运营中心' },
  { path: ROUTES.SELF_PLAY, label: '自博弈' },
  { path: ROUTES.RAG, label: '知识库' },
]

export function TopNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const { username, token, logout } = useAuthStore()

  return (
    <header className="fixed top-0 left-0 right-0 z-50 h-14 bg-surface">
      <div className="page-shell h-full flex items-center justify-between">
        <button
          onClick={() => navigate(ROUTES.HOME)}
          className="text-[15px] font-black tracking-wide text-ink"
        >
          共享记忆
        </button>

        <nav className="hidden md:flex items-center gap-7">
          {tabs.map((tab) => {
            const active = location.pathname === tab.path
            return (
              <button
                key={tab.path}
                onClick={() => navigate(tab.path)}
                className={`relative text-[13px] tracking-wide transition-colors ${
                  active ? 'text-ink font-bold' : 'text-ink-faint hover:text-ink'
                }`}
              >
                {tab.label}
                {active && (
                  <span className="absolute left-0 -bottom-1 h-[2px] w-full bg-ink" aria-hidden />
                )}
              </button>
            )
          })}
        </nav>

        <div className="flex items-center gap-4 text-[12px] tracking-[0.18em]">
          {token ? (
            <>
              <span className="text-ink-faint">{username || 'admin'}</span>
              <button
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                className="text-ink hover:opacity-70"
              >
                退出
              </button>
            </>
          ) : (
            <button
              onClick={() => navigate('/login')}
              className="text-ink font-medium hover:opacity-70"
            >
              登录
            </button>
          )}
        </div>
      </div>
      <div className="h-px bg-line" />
    </header>
  )
}
