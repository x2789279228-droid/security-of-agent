import type { HTMLAttributes } from 'react'

export interface SurfacePanelProps extends HTMLAttributes<HTMLDivElement> {
  /** 阴影等级 0/1/2/3 */
  elevation?: 0 | 1 | 2 | 3
  /** 背景色调 */
  tone?: 'card' | 'warm' | 'mint' | 'peach' | 'transparent' | 'surface'
  /** 圆角 */
  rounded?: 'control' | 'card' | 'modal' | 'none'
  /** 边框 */
  bordered?: boolean
}

const TONE_BG: Record<NonNullable<SurfacePanelProps['tone']>, string> = {
  card: 'var(--color-card)',
  warm: 'var(--color-paper-warm)',
  mint: 'var(--color-mint)',
  peach: 'var(--color-peach)',
  surface: 'var(--color-surface)',
  transparent: 'transparent',
}

const ELEVATION: Record<NonNullable<SurfacePanelProps['elevation']>, string> = {
  0: 'none',
  1: 'var(--shadow-1)',
  2: 'var(--shadow-2)',
  3: 'var(--shadow-3)',
}

const RADIUS: Record<NonNullable<SurfacePanelProps['rounded']>, string> = {
  control: 'var(--radius-control)',
  card: 'var(--radius-card)',
  modal: 'var(--radius-modal)',
  none: '0',
}

/**
 * SurfacePanel：浅色基调下的"台面"容器。
 * - 比 Card 更通用：不强制 Header/Body/Footer 结构，只是带边框/阴影/底色的盒子
 * - 用作：模态、抽屉、详情面板、思维链容器、KPI 区底色块
 * - 替代旧的 GlassPanel（旧的 GlassPanel 已经被"掐光"，语义混淆）
 */
export function SurfacePanel({
  elevation = 1,
  tone = 'card',
  rounded = 'card',
  bordered = true,
  className = '',
  children,
  style,
  ...rest
}: SurfacePanelProps) {
  return (
    <div
      className={`relative ${bordered ? 'border border-line' : ''} ${className}`}
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
