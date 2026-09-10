import { useReducedMotion } from 'framer-motion'

export type TapeItem = { id: string; text: string; tone?: 'ink' | 'alert' | 'ok' }

const TONE: Record<NonNullable<TapeItem['tone']>, string> = {
  ink: 'text-ink-soft',
  alert: 'text-alert',
  ok: 'text-ok',
}

export function DutyTape({
  items,
  className = '',
}: {
  items: TapeItem[]
  className?: string
}) {
  const reduce = useReducedMotion()

  if (!items.length) {
    return (
      <p className={`truncate text-[12px] text-ink-faint ${className}`}>灯火未熄，此刻无新事件</p>
    )
  }

  const row = (
    <>
      {items.map((it) => (
        <span key={it.id} className={`mx-6 shrink-0 ${TONE[it.tone ?? 'ink']}`}>
          {it.text}
        </span>
      ))}
    </>
  )

  if (reduce || items.length < 2) {
    return <p className={`truncate text-[12px] text-ink-soft ${className}`}>{items[0].text}</p>
  }

  return (
    <div className={`overflow-hidden ${className}`}>
      <div className="duty-tape flex w-max items-center text-[12px]">
        {row}
        {row}
      </div>
    </div>
  )
}
