export const spring = {
  ui: { type: 'spring' as const, stiffness: 300, damping: 20 },
  gentle: { type: 'spring' as const, stiffness: 200, damping: 22 },
  stiff: { type: 'spring' as const, stiffness: 400, damping: 30 },
  bouncy: { type: 'spring' as const, stiffness: 350, damping: 12 },
  tilt: { type: 'spring' as const, stiffness: 150, damping: 12, mass: 0.5 },
  page: { type: 'spring' as const, stiffness: 200, damping: 25 },
  stagger: { staggerChildren: 0.04 },
}

export const ROUTES = {
  HOME: '/',
  LOGS: '/logs',
  MONITOR: '/monitor',
  SECURITY_AUDIT: '/security-audit',
  RESPONSE: '/response',
  RAG: '/rag',
  OPERATIONS: '/operations',
} as const

/** Apple Intelligence 流动渐变 — 运营中心签名色 */
export const AI_GRADIENT = 'linear-gradient(120deg, #0A84FF 0%, #5E5CE6 26%, #BF5AF2 52%, #FF375F 76%, #FF9F0A 100%)'
export const AI_GRADIENT_STOPS = ['#0A84FF', '#5E5CE6', '#BF5AF2', '#FF375F', '#FF9F0A']
