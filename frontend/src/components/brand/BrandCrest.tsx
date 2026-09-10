/**
 * BrandCrest · 守望徽记
 *
 * 整个站的母题（motif）：圆形外环 + 守字居中 + 八方刻度 + 内圈细线
 * 选用暮金描边深室底色组合；放在 Hero、Footer、Login 用作视觉锚点
 *
 * 形状灵感：
 * - 钟表面盘（夜巡感）
 * - 印章（守居中）
 * - 瞄准镜十字线（精度感）
 *
 * tone:
 * - 'dark'    深室底，暮金线条
 * - 'paper'   纸面底，黛墨线条
 * - 'outline' 透明底，深墨线条
 */

export type CrestTone = 'dark' | 'paper' | 'outline'
export type CrestSize = number

export function BrandCrest({
  size = 96,
  tone = 'dark',
  withSubtitle = false,
  style,
  className = '',
}: {
  size?: CrestSize
  tone?: CrestTone
  withSubtitle?: boolean
  style?: React.CSSProperties
  className?: string
}) {
  const stroke =
    tone === 'dark'
      ? 'rgba(201, 165, 116, 0.85)'
      : tone === 'paper'
        ? '#1c2838'
        : '#1c2838'
  const sub =
    tone === 'dark' ? 'rgba(201, 165, 116, 0.6)' : 'rgba(28, 40, 56, 0.55)'
  const seal =
    tone === 'dark' ? 'rgba(168, 57, 47, 0.7)' : 'rgba(168, 57, 47, 0.85)'
  const innerFill = tone === 'dark' ? 'rgba(201, 165, 116, 0.04)' : 'rgba(28, 40, 56, 0.02)'

  // 12 个时辰方位刻度
  const ticks = Array.from({ length: 24 }, (_, i) => {
    const a = (i / 24) * Math.PI * 2 - Math.PI / 2
    const isMajor = i % 6 === 0 // 子/卯/午/酉 四正
    const r1 = isMajor ? 38 : 40
    const r2 = isMajor ? 42 : 41
    return { a, r1, r2, isMajor }
  })

  return (
    <span
      className={`inline-flex flex-col items-center ${className}`}
      style={{ lineHeight: 0, ...style }}
    >
      <svg
        viewBox="0 0 100 100"
        width={size}
        height={size}
        role="img"
        aria-label="守望徽记"
      >
        {/* 外环 */}
        <circle
          cx="50"
          cy="50"
          r="46"
          fill={tone === 'outline' ? 'transparent' : innerFill}
          stroke={stroke}
          strokeWidth="1"
        />
        {/* 内圈细线 */}
        <circle cx="50" cy="50" r="36" fill="none" stroke={stroke} strokeWidth="0.5" opacity="0.6" />
        {/* 二十四向刻度 */}
        {ticks.map((t, i) => {
          const x1 = 50 + Math.cos(t.a) * t.r1
          const y1 = 50 + Math.sin(t.a) * t.r1
          const x2 = 50 + Math.cos(t.a) * t.r2
          const y2 = 50 + Math.sin(t.a) * t.r2
          return (
            <line
              key={i}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={stroke}
              strokeWidth={t.isMajor ? 0.8 : 0.4}
              opacity={t.isMajor ? 0.95 : 0.6}
            />
          )
        })}
        {/* 四正小标：子卯午酉 */}
        {[
          { x: 50, y: 8, label: '子' },
          { x: 92, y: 50, label: '酉' },
          { x: 50, y: 92, label: '午' },
          { x: 8, y: 50, label: '卯' },
        ].map((m, i) => (
          <text
            key={i}
            x={m.x}
            y={m.y}
            fill={sub}
            fontSize="5"
            fontFamily="serif"
            textAnchor="middle"
            dominantBaseline="central"
          >
            {m.label}
          </text>
        ))}
        {/* 中央守字 */}
        <text
          x="50"
          y="54"
          fill={stroke}
          fontSize="22"
          fontFamily="Noto Serif SC, Songti SC, serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
          letterSpacing="-0.04em"
        >
          守
        </text>
        {/* 中心十字细线 */}
        <line x1="50" y1="14" x2="50" y2="22" stroke={stroke} strokeWidth="0.4" opacity="0.55" />
        <line x1="50" y1="78" x2="50" y2="86" stroke={stroke} strokeWidth="0.4" opacity="0.55" />
        <line x1="14" y1="50" x2="22" y2="50" stroke={stroke} strokeWidth="0.4" opacity="0.55" />
        <line x1="78" y1="50" x2="86" y2="50" stroke={stroke} strokeWidth="0.4" opacity="0.55" />
        {/* 印章红小方：右下 */}
        <rect x="76" y="74" width="9" height="9" fill="none" stroke={seal} strokeWidth="0.8" />
        <text
          x="80.5"
          y="78.5"
          fill={seal}
          fontSize="5"
          fontFamily="Noto Serif SC, serif"
          fontWeight="900"
          textAnchor="middle"
          dominantBaseline="central"
        >
          望
        </text>
      </svg>
      {withSubtitle && (
        <span
          className="font-mono text-[9px] tracking-[0.32em] uppercase mt-2"
          style={{ color: sub }}
        >
          Shouwang · MMXXVI
        </span>
      )}
    </span>
  )
}