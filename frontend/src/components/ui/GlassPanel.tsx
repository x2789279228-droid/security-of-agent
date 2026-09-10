import type { ReactNode } from 'react'

interface GlassPanelProps {
  children: ReactNode
  className?: string
  strong?: boolean
  onClick?: () => void
}

export function GlassPanel({ children, className = '', strong, onClick }: GlassPanelProps) {
  return (
    <div
      onClick={onClick}
      className={`${strong ? 'glass-strong' : 'glass'} ${className}`}
    >
      {children}
    </div>
  )
}
