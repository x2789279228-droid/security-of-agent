import { useCallback, useRef } from 'react'
import { useMotionValue, useSpring, useTransform, type MotionStyle } from 'framer-motion'

interface TiltOptions {
  maxRotate?: number
}

export function useTilt(options: TiltOptions = {}) {
  const { maxRotate = 8 } = options
  const ref = useRef<HTMLDivElement>(null)
  const x = useMotionValue(0.5)
  const y = useMotionValue(0.5)
  const isHovering = useMotionValue(0)

  const rotateX = useSpring(
    useTransform(() => (y.get() - 0.5) * maxRotate * -1),
    { stiffness: 150, damping: 12, mass: 0.5 },
  )
  const rotateY = useSpring(
    useTransform(() => (x.get() - 0.5) * maxRotate),
    { stiffness: 150, damping: 12, mass: 0.5 },
  )
  const scale = useSpring(
    useTransform(() => 1 + isHovering.get() * 0.02),
    { stiffness: 300, damping: 20 },
  )

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const el = ref.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      x.set((e.clientX - rect.left) / rect.width)
      y.set((e.clientY - rect.top) / rect.height)
      isHovering.set(1)
    },
    [x, y, isHovering],
  )

  const handleMouseLeave = useCallback(() => {
    x.set(0.5)
    y.set(0.5)
    isHovering.set(0)
  }, [x, y, isHovering])

  const style: MotionStyle = {
    rotateX: rotateX as any,
    rotateY: rotateY as any,
    scale: scale as any,
    transformStyle: 'preserve-3d',
    transformPerspective: 600,
  }

  return { ref, style, onMouseMove: handleMouseMove, onMouseLeave: handleMouseLeave }
}
