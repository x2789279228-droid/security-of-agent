import { motion } from 'framer-motion'
import { spring } from '../../lib/constants'
import type { ServiceHealth } from '../../types'

const colors: Record<ServiceHealth, string> = {
  ok: '#10b981',
  warn: '#f59e0b',
  error: '#ef4444',
}

export function StatusDot({ health }: { health: ServiceHealth }) {
  return (
    <motion.span
      className="inline-block w-1.5 h-1.5 rounded-full"
      style={{ backgroundColor: colors[health] }}
      animate={{ scale: [1, 1.3, 1] }}
      transition={{ ...spring.stiff, repeat: health === 'warn' ? Infinity : 0, repeatDelay: 2 }}
    />
  )
}
