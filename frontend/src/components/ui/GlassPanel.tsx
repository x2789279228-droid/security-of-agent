import type { ReactNode } from 'react'

interface GlassPanelProps {
  children: ReactNode
  className?: string
  strong?: boolean
  onClick?: () => void
}

/** 直角线框卡片（保留原名以免改动调用方） */
export function GlassPanel({ children, className = '', strong, onClick }: GlassPanelProps) {
  return (
    <div
      onClick={onClick}
      className={`${strong ? 'mono-card-ink' : 'mono-card'} rounded-none ${className}`}
    >
      {children}
    </div>
  )
}
