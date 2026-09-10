/**
 * BrandSeal · 守望正印
 *
 * 比 BrandCrest 更「主张」的版本：占据视觉主位的正印/朱记。
 * 用于 Login / Register 等需要强烈第一印象的位置。
 *
 * 形态：
 * - 外环：暮金 1px 细线 + 四正朱砂小标（子卯午酉）
 * - 内印：黛墨「望」字（Noto Serif SC 900），主体
 * - 朱记：右下朱砂方印「守」字，唯一暖色信号
 * - 十字瞄准：暮金极细线，居中对称
 *
 * tone:
 * - 'paper'  浅米白底 / 黛墨字 + 朱砂印章 + 暮金环
 * - 'dark'   深室底 / 暮金字 + 朱砂印章
 *
 * size 单位 px（默认 220）
 */

export type SealTone = 'paper' | 'dark'

const INK = '#1c2838'
const VERMILION = '#a8392f'
const DUSK = '#c9a574'

export function BrandSeal({
  size = 220,
  tone = 'paper',
  className = '',
  style,
}: {
  size?: number
  tone?: SealTone
  className?: string
  style?: React.CSSProperties
}) {
  const isDark = tone === 'dark'
  const charFill = isDark ? DUSK : INK
  const ringStroke = isDark ? DUSK : DUSK
  const tickColor = isDark ? 'rgba(201,165,116,0.55)' : 'rgba(201,165,116,0.85)'
  const sub = isDark ? 'rgba(201,165,116,0.55)' : 'rgba(28,40,56,0.5)'
  const sealFill = isDark ? 'rgba(168,57,47,0.85)' : VERMILION
  const innerWash = isDark ? 'rgba(201,165,116,0.04)' : 'rgba(28,40,56,0.025)'

  // 二十四向刻度
  const ticks = Array.from({ length: 24 }, (_, i) => {
    const a = (i / 24) * Math.PI * 2 - Math.PI / 2
    const isMajor = i % 6 === 0
    return { a, isMajor }
  })

  return (
    <span
      className={`inline-flex flex-col items-center ${className}`}
      style={{ lineHeight: 0, ...style }}
    >
      <svg
        viewBox="0 0 200 200"
        width={size}
        height={size}
        role="img"
        aria-label="守望正印"
      >
        {/* 圆角底：浅纸色微暖底，洗掉纯白 */}
        {tone === 'paper' && (
          <rect
            x="2"
            y="2"
            width="196"
            height="196"
            fill="#f1f4f6"
            stroke={ringStroke}
            strokeWidth="1.2"
          />
        )}
        {tone === 'dark' && (
          <rect
            x="2"
            y="2"
            width="196"
            height="196"
            fill="#0e1a26"
            stroke={ringStroke}
            strokeWidth="1.2"
          />
        )}

        {/* 内层细线圆 */}
        <circle cx="100" cy="100" r="78" fill={innerWash} stroke={ringStroke} strokeWidth="0.6" opacity="0.7" />

        {/* 二十四向刻度 */}
        {ticks.map((t, i) => {
          const r1 = t.isMajor ? 86 : 88
          const r2 = t.isMajor ? 92 : 90
          const x1 = 100 + Math.cos(t.a) * r1
          const y1 = 100 + Math.sin(t.a) * r1
          const x2 = 100 + Math.cos(t.a) * r2
          const y2 = 100 + Math.sin(t.a) * r2
          return (
            <line
              key={i}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={tickColor}
              strokeWidth={t.isMajor ? 1.4 : 0.6}
              opacity={t.isMajor ? 1 : 0.7}
            />
          )
        })}

        {/* 四正方位小标：子卯午酉 */}
        {[
          { x: 100, y: 18, label: '子' },
          { x: 182, y: 100, label: '酉' },
          { x: 100, y: 182, label: '午' },
          { x: 18, y: 100, label: '卯' },
        ].map((m, i) => (
          <text
            key={i}
            x={m.x}
            y={m.y}
            fill={sub}
            fontSize="11"
            fontFamily="'Noto Serif SC', 'Songti SC', serif"
            fontWeight="700"
            textAnchor="middle"
            dominantBaseline="central"
          >
            {m.label}
          </text>
        ))}

        {/* 中心十字瞄准（极细） */}
        <line x1="100" y1="34" x2="100" y2="46" stroke={tickColor} strokeWidth="0.5" opacity="0.6" />
        <line x1="100" y1="154" x2="100" y2="166" stroke={tickColor} strokeWidth="0.5" opacity="0.6" />
        <line x1="34" y1="100" x2="46" y2="100" stroke={tickColor} strokeWidth="0.5" opacity="0.6" />
        <line x1="154" y1="100" x2="166" y2="100" stroke={tickColor} strokeWidth="0.5" opacity="0.6" />

        {/* 中央「望」字：黛墨主体，张力来源 */}
        <text
          x="100"
          y="108"
          fill={charFill}
          fontSize="86"
          fontFamily="'Noto Serif SC', 'Songti SC', serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
          letterSpacing="-0.05em"
        >
          望
        </text>

        {/* 右上小注：「夜巡」 */}
        <text
          x="148"
          y="58"
          fill={sub}
          fontSize="7"
          fontFamily="'IBM Plex Mono', monospace"
          letterSpacing="0.22em"
          textAnchor="middle"
          dominantBaseline="central"
        >
          NIGHT · WATCH
        </text>

        {/* 左下小注：版次 */}
        <text
          x="52"
          y="148"
          fill={sub}
          fontSize="7"
          fontFamily="'IBM Plex Mono', monospace"
          letterSpacing="0.22em"
          textAnchor="middle"
          dominantBaseline="central"
        >
          MMXXVI · v4
        </text>

        {/* 朱记：右下「守」方印 —— 唯一暖色信号 */}
        <rect
          x="138"
          y="138"
          width="32"
          height="32"
          fill={sealFill}
        />
        <text
          x="154"
          y="156"
          fill="#f5ecd8"
          fontSize="20"
          fontFamily="'Noto Serif SC', 'Songti SC', serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
          letterSpacing="-0.04em"
        >
          守
        </text>
      </svg>
    </span>
  )
}