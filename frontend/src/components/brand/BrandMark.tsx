import { BRAND } from '../../lib/brand'

type Size = 'sm' | 'md' | 'lg'

const ICON_PX: Record<Size, number> = { sm: 32, md: 44, lg: 56 }

/**
 * BrandMark · 简版守望徽记（不带外环刻度）
 * 用于顶栏/小徽位场景。纯 SVG，黛墨字 + 朱砂小方印，对比度强。
 */
export function BrandMark({
  size = 'md',
  withWordmark = false,
  stacked = false,
  className = '',
}: {
  size?: Size
  withWordmark?: boolean
  stacked?: boolean
  className?: string
}) {
  const px = ICON_PX[size]
  return (
    <span
      className={`inline-flex items-center ${stacked ? 'flex-col items-start gap-1' : 'gap-2.5'} ${className}`}
    >
      <svg
        viewBox="0 0 64 64"
        width={px}
        height={px}
        role="img"
        aria-label="守望"
      >
        {/* 主体「望」字 */}
        <text
          x="22"
          y="38"
          fill="#1c2838"
          fontSize="34"
          fontFamily="'Noto Serif SC', 'Songti SC', serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
          letterSpacing="-0.04em"
        >
          望
        </text>
        {/* 朱记「守」方印 */}
        <rect x="40" y="40" width="18" height="18" fill="#a8392f" />
        <text
          x="49"
          y="51"
          fill="#f5ecd8"
          fontSize="12"
          fontFamily="'Noto Serif SC', 'Songti SC', serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
        >
          守
        </text>
      </svg>
      {withWordmark && (
        <span
          className="block font-serif font-black tracking-tight text-ink leading-none"
          style={{ fontSize: size === 'lg' ? 28 : size === 'md' ? 18 : 15 }}
        >
          {BRAND.name}
        </span>
      )}
    </span>
  )
}