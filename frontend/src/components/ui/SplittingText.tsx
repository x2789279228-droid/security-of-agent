import { motion } from 'framer-motion'
import { spring } from '../../lib/constants'

interface SplittingTextProps {
  text: string
  className?: string
  delay?: number
}

export function SplittingText({ text, className = '', delay = 0 }: SplittingTextProps) {
  const chars = text.split('')

  return (
    <span className={`inline ${className}`}>
      {chars.map((char, i) => (
        <motion.span
          key={i}
          className="inline-block"
          initial={{ opacity: 0, y: 20, rotateX: -90 }}
          animate={{ opacity: 1, y: 0, rotateX: 0 }}
          transition={{ ...spring.bouncy, delay: delay + i * 0.04 }}
        >
          {char === ' ' ? '\u00A0' : char}
        </motion.span>
      ))}
    </span>
  )
}
