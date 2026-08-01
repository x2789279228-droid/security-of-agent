import { motion, type HTMLMotionProps } from 'framer-motion'
import { spring } from '../../lib/constants'

interface ButtonProps extends HTMLMotionProps<'button'> {
  variant?: 'primary' | 'ghost' | 'danger'
}

/** Apple 风胶囊按钮 */
export function Button({ variant = 'primary', className = '', children, ...props }: ButtonProps) {
  const base =
    'inline-flex items-center justify-center cursor-pointer font-sans font-normal text-sm rounded-full whitespace-nowrap transition-colors will-change-transform'

  const variants = {
    primary: 'bg-accent text-white px-5 py-2 hover:bg-accent-hover',
    ghost:
      'bg-transparent text-accent border border-accent px-5 py-2 hover:bg-accent hover:text-white',
    danger: 'bg-alert text-white px-5 py-2 hover:bg-[#ff453a]',
  }

  return (
    <motion.button
      className={`${base} ${variants[variant]} ${className}`}
      whileTap={{ scale: 0.97 }}
      transition={spring.ui}
      {...props}
    >
      {children as React.ReactNode}
    </motion.button>
  )
}

/** Apple 风文本链接（带 › 箭头） */
export function TextLink({
  children,
  className = '',
  ...props
}: HTMLMotionProps<'button'>) {
  return (
    <motion.button
      className={`inline-flex items-center gap-0.5 cursor-pointer text-sm text-link hover:underline font-sans ${className}`}
      whileTap={{ scale: 0.97 }}
      {...props}
    >
      {children as React.ReactNode}
      <span aria-hidden className="text-base leading-none translate-y-[-0.5px]">›</span>
    </motion.button>
  )
}
