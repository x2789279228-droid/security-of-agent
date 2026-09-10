import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { WatchShift } from '../components/ui/WatchShift'
import { ROUTES } from '../lib/constants'
import { NAV_GROUPS } from './nav'

/**
 * TopNav · 守望 v5
 *
 * 极简两行结构：
 * - 行 1（h-14）：品牌左 / 状态中 / 操作右 —— 一行解决三件事
 * - 行 2（h-10）：目录带
 *
 * 总高度从 116px 压到 76px，省 35%
 */

export function TopNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const { username, token, logout } = useAuthStore()
  const [menuOpen, setMenuOpen] = useState(false)
  const [senseOpen, setSenseOpen] = useState(false)
  const senseRef = useRef<HTMLDivElement>(null)

  const senseGroup = NAV_GROUPS.find((g) => g.title === '感知')!
  const primaryGroups = NAV_GROUPS.filter((g) => g.title !== '感知')
  const senseActive = senseGroup.items.some((i) => i.path === location.pathname)

  useEffect(() => {
    setMenuOpen(false)
    setSenseOpen(false)
  }, [location.pathname])

  useEffect(() => {
    if (!senseOpen) return
    const onDoc = (e: MouseEvent) => {
      if (!senseRef.current?.contains(e.target as Node)) setSenseOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [senseOpen])

  const go = (path: string) => {
    navigate(path)
    setMenuOpen(false)
    setSenseOpen(false)
  }

  const today = new Date().toLocaleDateString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
  })
  const weekday = new Date().toLocaleDateString('zh-CN', { weekday: 'long' })

  return (
    <header className="sticky top-0 z-40 bg-[#ecf0ee] border-b border-line">
      {/* 行 1：品牌 + 状态 + 操作 */}
      <div className="page-shell h-14 flex items-center gap-6">
        {/* 左：品牌 */}
        <button
          onClick={() => go(ROUTES.HOME)}
          aria-label="守望首页"
          className="flex items-baseline gap-3 shrink-0"
        >
          <span className="font-serif text-[20px] font-black tracking-[-0.02em] text-ink leading-none">
            守望
          </span>
          <span className="hidden md:inline font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
            Shouwang · Night Watch SOC
          </span>
        </button>

        {/* 中：状态 meta —— 一行收齐 */}
        <div className="hidden lg:flex items-center gap-5 flex-1 min-w-0 justify-center font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
          <span className="whitespace-nowrap">{today} · {weekday}</span>
          <span className="h-3 w-px bg-line" aria-hidden />
          <span className="inline-flex items-center gap-2 text-accent whitespace-nowrap">
            <span className="live-arc text-accent" aria-hidden />
            <span>Shift Active</span>
          </span>
          <WatchShift className="ml-1" />
        </div>

        {/* 右：用户操作 */}
        <div className="flex items-center gap-3 ml-auto shrink-0">
          {token ? (
            <>
              <span className="hidden sm:inline font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                {username || 'admin'}
              </span>
              <button
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                className="nav-btn"
              >
                登出
              </button>
            </>
          ) : (
            <button onClick={() => navigate('/login')} className="nav-btn">
              登录
            </button>
          )}
          <button
            type="button"
            className="lg:hidden font-mono text-[10px] tracking-[0.22em] uppercase text-ink-soft hover:text-ink border-l border-line pl-3"
            aria-expanded={menuOpen}
            aria-label={menuOpen ? '关闭目录' : '打开目录'}
            onClick={() => setMenuOpen((v) => !v)}
          >
            {menuOpen ? 'Close' : 'Menu'}
          </button>
        </div>
      </div>

      {/* 行 2：目录带 */}
      <nav className="hidden lg:block border-t border-line">
        <div className="page-shell h-10 flex items-stretch gap-0">
          {primaryGroups.map((group, gi) => (
            <div key={group.title} className="flex items-stretch">
              {gi > 0 && <span className="self-center mx-1 h-4 w-px bg-line" aria-hidden />}
              {group.items.map((item) => {
                const active = location.pathname === item.path
                return (
                  <button
                    key={item.path}
                    onClick={() => go(item.path)}
                    className={`relative px-4 text-[13px] whitespace-nowrap transition-colors ${
                      active ? 'text-ink' : 'text-ink-soft hover:text-ink'
                    }`}
                  >
                    {item.short}
                    {active && (
                      <span className="absolute inset-x-3 bottom-0 h-px bg-[#0e1a26]" />
                    )}
                  </button>
                )
              })}
            </div>
          ))}
          <span className="self-center mx-1 h-4 w-px bg-line" aria-hidden />
          <div className="relative flex items-stretch" ref={senseRef}>
            <button
              type="button"
              aria-expanded={senseOpen}
              onClick={() => setSenseOpen((v) => !v)}
              className={`relative px-4 text-[13px] whitespace-nowrap ${
                senseActive ? 'text-ink' : 'text-ink-soft hover:text-ink'
              }`}
            >
              感知
              {senseActive && (
                <span className="absolute inset-x-3 bottom-0 h-px bg-[#0e1a26]" />
              )}
            </button>
            {senseOpen && (
              <div className="absolute left-0 top-full z-50 min-w-[10rem] border border-line bg-paper py-2 shadow-[var(--shadow-2)]">
                {senseGroup.items.map((item) => {
                  const active = location.pathname === item.path
                  return (
                    <button
                      key={item.path}
                      onClick={() => go(item.path)}
                      className={`block w-full px-4 py-1.5 text-left text-[13px] ${
                        active ? 'text-ink' : 'text-ink-soft hover:text-ink'
                      }`}
                    >
                      {item.label}
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </nav>

      {menuOpen && (
        <div className="lg:hidden border-t border-line bg-surface">
          <div className="page-shell py-6">
            {NAV_GROUPS.map((group) => (
              <div key={group.title} className="mb-6">
                <p className="mb-2 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                  {group.title}
                </p>
                <div className="flex flex-col gap-1">
                  {group.items.map((item) => {
                    const active = location.pathname === item.path
                    return (
                      <button
                        key={item.path}
                        onClick={() => go(item.path)}
                        className={`py-1.5 text-left text-[16px] ${
                          active ? 'text-ink' : 'text-ink-soft'
                        }`}
                      >
                        {item.label}
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </header>
  )
}