import { Outlet, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { TopNav } from './TopNav'

export function RootLayout() {
  const location = useLocation()

  return (
    <div className="relative min-h-screen bg-surface font-sans text-ink">
      <TopNav />
      <main className="pt-14 min-h-screen">
        <AnimatePresence mode="wait">
          <Outlet key={location.pathname} />
        </AnimatePresence>
      </main>
    </div>
  )
}
