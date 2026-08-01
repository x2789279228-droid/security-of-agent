import { motion } from 'framer-motion'
import { useLocation, useNavigate } from 'react-router-dom'
import { spring, ROUTES } from '../lib/constants'

const tabs = [
  { path: ROUTES.HOME, label: '首页', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { path: ROUTES.LOGS, label: '日志中心', icon: 'M4 6h16M4 10h16M4 14h16M4 18h10' },
  { path: ROUTES.MONITOR, label: '监控', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
  { path: ROUTES.SECURITY_AUDIT, label: '安全审计', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z' },
  { path: ROUTES.RESPONSE, label: '响应引擎', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { path: ROUTES.RAG, label: '知识库', icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253' },
]

export function Sidebar() {
  const location = useLocation()
  const navigate = useNavigate()

  return (
    <aside className="fixed left-0 top-0 bottom-0 z-50 w-48 bg-white border-r border-line flex flex-col">
      <div className="px-4 pt-5 pb-4 border-b border-line">
        <p className="font-bold text-sm tracking-wide">共享记忆</p>
        <p className="text-[10px] text-ink-faint font-sans mt-0.5">Service Layer</p>
      </div>
      <nav className="flex-1 flex flex-col gap-1 p-2 mt-2">
        {tabs.map((tab) => {
          const active = location.pathname === tab.path
          return (
            <button
              key={tab.path}
              onClick={() => navigate(tab.path)}
              className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-sans font-medium transition-colors will-change-transform ${
                active
                  ? 'bg-accent/10 text-accent'
                  : 'text-ink-soft hover:bg-gray-50 hover:text-ink'
              }`}
            >
              {active && (
                <motion.div
                  layoutId="sidebar-indicator"
                  className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-full bg-accent"
                  transition={spring.stiff}
                />
              )}
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={active ? 2 : 1.5}
                strokeLinecap="round"
                strokeLinejoin="round"
                className="w-4.5 h-4.5 shrink-0"
              >
                <path d={tab.icon} />
              </svg>
              {tab.label}
            </button>
          )
        })}
      </nav>
      <div className="p-3 border-t border-line">
        <p className="text-[10px] text-ink-faint font-sans text-center">v1.0</p>
      </div>
    </aside>
  )
}
