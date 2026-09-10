import type { ReactNode, HTMLAttributes, MouseEventHandler } from 'react'

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** 交互态：hover 边框变深室色 + 微微下沉的纸质感 */
  interactive?: boolean
  /** 背景色调，默认 'card'（纸白）；可选 'warm' 暖白 / 'mint' 薄荷 / 'peach' 淡桃 */
  tone?: 'card' | 'warm' | 'mint' | 'peach' | 'transparent' | 'paper'
  /** 阴影等级：纸面卡默认无阴影；modal/hero 才用 */
  elevation?: 0 | 1 | 2 | 3
  /** 圆角：纸面只用 2px；modal 4px */
  rounded?: 'control' | 'card' | 'modal'
  /** 点击交互（interactive 隐含 onClick 支持） */
  onClick?: MouseEventHandler<HTMLDivElement>
}

const TONE_BG: Record<NonNullable<CardProps['tone']>, string> = {
  card: 'var(--color-card)',
  paper: 'var(--color-paper)',
  warm: 'var(--color-paper-warm)',
  mint: 'var(--color-mint)',
  peach: 'var(--color-peach)',
  transparent: 'transparent',
}

const ELEVATION: Record<NonNullable<CardProps['elevation']>, string> = {
  0: 'none',
  1: 'none',
  2: 'var(--shadow-2)',
  3: 'var(--shadow-3)',
}

const RADIUS: Record<NonNullable<CardProps['rounded']>, string> = {
  control: 'var(--radius-control)',
  card: 'var(--radius-card)',
  modal: 'var(--radius-modal)',
}

function CardRoot({
  interactive = false,
  tone = 'card',
  elevation = 0,
  rounded = 'card',
  className = '',
  children,
  style,
  ...rest
}: CardProps) {
  return (
    <div
      className={`relative border border-line ${interactive ? 'card-interactive cursor-pointer' : ''} ${className}`}
      style={{
        background: TONE_BG[tone],
        borderRadius: RADIUS[rounded],
        boxShadow: ELEVATION[elevation],
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  )
}

/** 卡片头部：标题 + 元数据 + 右侧操作 */
function CardHeader({
  title,
  meta,
  extra,
  className = '',
}: {
  title: ReactNode
  meta?: ReactNode
  extra?: ReactNode
  className?: string
}) {
  return (
    <div
      className={`flex items-start justify-between gap-4 border-b border-line px-6 py-4 ${className}`}
    >
      <div className="min-w-0">
        <div className="font-serif text-[16px] font-bold text-ink leading-tight">{title}</div>
        {meta && <div className="mt-1 text-[12px] text-ink-faint">{meta}</div>}
      </div>
      {extra && <div className="shrink-0">{extra}</div>}
    </div>
  )
}

/** 卡片正文：默认 padding 20px + 16px */
function CardBody({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`px-6 py-5 ${className}`}>{children}</div>
}

/** 卡片底部：分隔线 + 操作区 */
function CardFooter({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`border-t border-line px-6 py-3.5 ${className}`}>{children}</div>
  )
}

/**
 * 卡片：守望 v3 的「平面案卷」基础件。
 * - 默认纸白底 + 1px line 边框 + 2px 圆角 + 无阴影（兑现「案卷」承诺）
 * - interactive=true：hover 边框变深室色、微微下沉（无阴影跳跃）
 * - elevation=2/3 仅在浮层 / 模态使用
 */
export const Card = Object.assign(CardRoot, {
  Header: CardHeader,
  Body: CardBody,
  Footer: CardFooter,
})
