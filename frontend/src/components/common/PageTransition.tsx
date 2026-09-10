import { motion } from 'framer-motion'
import { spring } from '../../lib/constants'

export function PageTransition({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={spring.page}
      className="will-change-transform"
    >
      {children}
    </motion.div>
  )
}
