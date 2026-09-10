import { motion, type HTMLMotionProps } from 'framer-motion'
import { useTilt } from '../../hooks/useTilt'

interface TiltCardProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode
  className?: string
}

export function TiltCard({ children, className = '', ...props }: TiltCardProps) {
  const { ref, style, onMouseMove, onMouseLeave } = useTilt()

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      className={`border-b border-line hover:border-accent/50 transition-colors ${className}`}
      style={style}
      {...props}
    >
      {children}
    </motion.div>
  )
}
