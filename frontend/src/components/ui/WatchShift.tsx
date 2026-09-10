import { useEffect, useState } from 'react'
import { useReducedMotion } from 'framer-motion'
import { formatWatchClock, watchShiftAt } from '../../lib/watchShift'

export function WatchShift({
  variant = 'compact',
  className = '',
}: {
  variant?: 'compact' | 'hero'
  className?: string
}) {
  const reduce = useReducedMotion()
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    if (reduce) return
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [reduce])

  const shift = watchShiftAt(now)
  const clock = formatWatchClock(now)
  const sec = now.getSeconds() + now.getMilliseconds() / 1000
  const deg = (sec / 60) * 360

  if (variant === 'hero') {
    return (
      <div className={`flex items-center gap-4 ${className}`}>
        <Lamp ticking={!reduce} />
        <div>
          <p className="font-serif text-[20px] font-bold leading-none text-ink">
            {shift.night ? shift.label : shift.earthly + '时'}
            <span className="ml-2 text-[14px] font-normal text-ink-faint">
              {shift.night ? `${shift.earthly}时 · 夜巡` : `${shift.label} · 白昼`}
            </span>
          </p>
          <p className="mt-1 font-mono text-[12px] tabular-nums text-ink-faint">{clock}</p>
        </div>
      </div>
    )
  }

  return (
    <span className={`inline-flex items-center gap-2 text-[12px] text-accent ${className}`} title={`${shift.earthly}时 ${shift.label}`}>
      <span className="relative h-4 w-4 shrink-0" aria-hidden>
        <svg viewBox="0 0 16 16" className="h-4 w-4">
          <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.45" />
          <line
            x1="8"
            y1="8"
            x2="8"
            y2="3.2"
            stroke="currentColor"
            strokeWidth="1"
            strokeLinecap="round"
            style={{ transform: `rotate(${deg}deg)`, transformOrigin: '8px 8px' }}
          />
        </svg>
      </span>
      <span className="font-serif">{shift.night ? shift.label : `${shift.earthly}时`}</span>
      <span className="hidden font-mono tabular-nums text-ink-faint xl:inline">{clock}</span>
    </span>
  )
}

function Lamp({ ticking }: { ticking: boolean }) {
  return (
    <svg viewBox="0 0 20 28" className="h-8 w-6 text-accent" aria-hidden>
      <path
        d="M10 2c2.2 2.4 4.2 5.2 4.2 8.2 0 1.4-.4 2.4-1 3.2H6.8c-.6-.8-1-1.8-1-3.2C5.8 7.2 7.8 4.4 10 2Z"
        fill="currentColor"
        className={ticking ? 'watch-flame' : ''}
        opacity="0.85"
      />
      <rect x="5" y="14" width="10" height="9" fill="currentColor" />
      <rect x="7.5" y="23" width="5" height="3" fill="currentColor" opacity="0.7" />
    </svg>
  )
}
