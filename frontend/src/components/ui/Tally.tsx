import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from 'framer-motion'

export function Tally({
  value,
  className = '',
}: {
  value: number
  className?: string
}) {
  const reduce = useReducedMotion()
  const [shown, setShown] = useState(value)
  const fromRef = useRef(value)

  useEffect(() => {
    if (reduce || value === fromRef.current) {
      setShown(value)
      fromRef.current = value
      return
    }
    const from = fromRef.current
    const start = performance.now()
    const dur = 720
    let raf = 0
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / dur)
      const e = 1 - (1 - p) ** 3
      setShown(Math.round(from + (value - from) * e))
      if (p < 1) raf = requestAnimationFrame(step)
      else fromRef.current = value
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [value, reduce])

  return <span className={className}>{shown.toLocaleString()}</span>
}
