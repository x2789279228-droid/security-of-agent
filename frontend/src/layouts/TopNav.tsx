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
  { path: ROUTES.RAG, label: '知识库' },
]

export function TopNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const { username, logout } = useAuthStore()

  return (
    <header
      className="fixed top-0 left-0 right-0 z-50 h-11 border-b border-black/[0.08]"
      style={{
        background: 'rgba(251, 251, 253, 0.8)',
        backdropFilter: 'saturate(180%) blur(20px)',
        WebkitBackdropFilter: 'saturate(180%) blur(20px)',
      }}
    >
      <div className="h-full max-w-[1200px] mx-auto flex items-center justify-between px-6">
        {/* 品牌 */}
        <button
          onClick={() => navigate(ROUTES.HOME)}
          className="flex items-center gap-2 group"
        >
          <svg viewBox="0 0 24 24" className="w-4 h-4 text-ink transition-colors group-hover:text-accent" fill="currentColor">
            <path d="M12 2L4 5.5v5.1c0 4.97 3.41 9.62 8 10.9 4.59-1.28 8-5.93 8-10.9V5.5L12 2zm0 2.2l6 2.63v4.77c0 3.94-2.63 7.63-6 8.83-3.37-1.2-6-4.89-6-8.83V6.83l6-2.63zm-1 9.3l-2.5-2.5-1.4 1.4L11 16.3l5.9-5.9-1.4-1.4L11 13.5z" />
          </svg>
          <span className="text-[13px] font-semibold text-ink tracking-tight transition-colors group-hover:text-accent">
            共享记忆
          </span>
        </button>

        {/* 导航链接 — Apple 12px */}
        <nav className="hidden md:flex items-center gap-7">
          {tabs.map((tab) => {
            const active = location.pathname === tab.path
            return (
              <button
                key={tab.path}
                onClick={() => navigate(tab.path)}
                className={`text-xs transition-colors ${
                  active ? 'text-ink font-medium' : 'text-ink/70 hover:text-ink'
                }`}
              >
                {tab.label}
              </button>
            )
          })}
        </nav>

        {/* 用户区 */}
        <div className="flex items-center gap-4">
          <span className="text-xs text-ink/70">{username || 'admin'}</span>
          <button
            onClick={() => { logout(); navigate('/login') }}
            className="text-xs text-ink/50 hover:text-alert transition-colors"
          >
            退出
          </button>
        </div>
      </div>
    </header>
  )
}
