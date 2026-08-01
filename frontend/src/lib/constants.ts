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
} as const
