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
      className={`bg-card border border-line rounded-lg shadow-[0_1px_3px_rgba(0,0,0,0.03)] hover:shadow-[0_2px_8px_rgba(0,0,0,0.06)] transition-shadow will-change-transform ${className}`}
      style={style}
      {...props}
    >
      {children}
    </motion.div>
  )
}
