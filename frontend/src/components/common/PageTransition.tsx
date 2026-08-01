import { motion } from 'framer-motion'
import { spring } from '../../lib/constants'

export function PageTransition({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -40 }}
      transition={spring.page}
      className="h-full will-change-transform"
    >
      {children}
    </motion.div>
  )
}
