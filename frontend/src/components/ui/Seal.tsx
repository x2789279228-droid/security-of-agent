import type { CSSProperties } from 'react'

/**
 * 印章：每页"亮色"信号的承载器。
 * - 用法 1：右上角装饰小印（`<Seal size={48} />`），opacity 0.85
 * - 用法 2：文案前的破折号（`<Seal.Rule />`），2px × 24px 红条
 *
 * 限制：每页只允许 1 处"印章红"信号，多了会冲淡案卷感。
 */

export function Seal({
  children,
  size = 48,
  rotate = -4,
  variant = 'default',
  className = '',
  style,
}: {
  children?: string
  size?: number
  rotate?: number
  /** 'default' 纸面印章 / 'dark' 深底印章（深室控制台里用） */
  variant?: 'default' | 'dark'
  className?: string
  style?: CSSProperties
}) {
  const isDark = variant === 'dark'
  return (
    <span
      className={`inline-flex items-center justify-center font-serif font-black tracking-[0.04em] select-none ${className}`}
      style={{
        width: size,
        height: size,
        fontSize: Math.round(size * 0.34),
        transform: `rotate(${rotate}deg)`,
        border: isDark
          ? `1px solid rgba(168, 57, 47, 0.7)`
          : `2px solid var(--color-seal)`,
        color: isDark ? 'rgba(168, 57, 47, 0.85)' : 'var(--color-seal)',
        background: isDark ? 'rgba(168, 57, 47, 0.06)' : 'rgba(168, 57, 47, 0.04)',
        ...style,
      }}
    >
      {children}
    </span>
  )
}

/** 印章红 24×2 短条 —— 文案前的破折号 / 章节起手 */
function SealRule({ className = '' }: { className?: string }) {
  return <span className={`seal-rule ${className}`} aria-hidden />
}

Seal.Rule = SealRule
