import { motion, useReducedMotion } from 'framer-motion'
import { spring } from '../../lib/constants'
import type { ServiceHealth } from '../../types'

const colors: Record<ServiceHealth, string> = {
  ok: '#3E7A64',
  warn: '#C08A3A',
  error: '#C23A32',
}

export function StatusDot({ health }: { health: ServiceHealth }) {
  const reduceMotion = useReducedMotion()
  const live = health !== 'ok'
  return (
    <motion.span
      className="inline-block h-2 w-2 rounded-full"
      style={{ backgroundColor: colors[health], boxShadow: `0 0 5px ${colors[health]}66` }}
      animate={reduceMotion ? { scale: 1, opacity: 1 } : { scale: live ? [1, 1.35, 1] : 1, opacity: live ? [1, 0.65, 1] : 1 }}
      transition={{ ...spring.stiff, repeat: live ? Infinity : 0, repeatDelay: health === 'warn' ? 0.8 : 0.4, duration: 1.2 }}
    />
  )
}
