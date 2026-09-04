import { motion, type HTMLMotionProps } from 'framer-motion'

interface ButtonProps extends HTMLMotionProps<'button'> {
  variant?: 'primary' | 'ghost' | 'danger' | 'outline' | 'underline'
}

/** 对齐参考图四种按钮：实心 / 描边 / 下划线 / 纯文本，全部直角 */
export function Button({ variant = 'primary', className = '', children, ...props }: ButtonProps) {
  const base =
    'inline-flex items-center justify-center cursor-pointer text-[14px] tracking-[0.12em] whitespace-nowrap transition-colors rounded-none box-border'

  const variants = {
    primary: 'h-9 bg-ink text-white px-5 hover:bg-accent-hover',
    outline: 'h-9 bg-white text-ink border-2 border-ink px-5 hover:bg-ink hover:text-white',
    underline: 'h-9 bg-transparent text-ink border-b-2 border-ink px-1 hover:opacity-70',
    ghost: 'h-9 bg-transparent text-ink px-3 hover:opacity-70',
    danger: 'h-9 bg-ink text-white px-5 hover:bg-accent-hover',
  }

  return (
    <motion.button
      className={`${base} ${variants[variant]} ${className}`}
      whileTap={{ opacity: 0.85 }}
      transition={{ duration: 0.12 }}
      {...props}
    >
      {children as React.ReactNode}
    </motion.button>
  )
}

export function TextLink({
  children,
  className = '',
  ...props
}: HTMLMotionProps<'button'>) {
  return (
    <motion.button
      className={`inline-flex items-center gap-1 cursor-pointer text-[14px] text-ink border-b-2 border-ink pb-0.5 tracking-[0.08em] ${className}`}
      whileTap={{ opacity: 0.85 }}
      {...props}
    >
      {children as React.ReactNode}
    </motion.button>
  )
}
